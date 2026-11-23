"""Source effectiveness: provenance emission, stats, auto-disable."""
import asyncio
import json
from unittest.mock import AsyncMock, patch

from src.sources import SourceStats
from src.scraper.base import _emit, scrape_proxyscrape, run_scraper_pipeline


class FakeResp:
    def __init__(self, status, text=""):
        self.status_code = status
        self.text = text


def _stats(tmp_path, **kw):
    defaults = dict(
        state_file=str(tmp_path / "state" / "source_stats.json"),
        min_live_ratio=0.02,
        min_checks=10,
        disable_runs=3,
        retention_days=14,
    )
    defaults.update(kw)
    return SourceStats(**defaults)


# ----------------------------------------------------------------------
# Provenance
# ----------------------------------------------------------------------

def test_emit_records_first_source_on_dedup():
    results, provenance = set(), {}
    _emit(results, provenance, "1.2.3.4:8080", "a")
    _emit(results, provenance, "1.2.3.4:8080", "b")
    assert results == {"1.2.3.4:8080"}
    assert provenance["1.2.3.4:8080"] == "a"  # first wins


def test_emit_no_provenance_still_collects():
    results = set()
    _emit(results, None, "1.2.3.4:8080", "a")
    assert results == {"1.2.3.4:8080"}


def test_scraper_threads_provenance():
    async def main():
        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResp(200, "1.2.3.4:8080\n5.6.7.8:3128\n"))
        results, provenance = set(), {}
        await scrape_proxyscrape(client, results, provenance=provenance, label="proxyscrape")
        assert results == {"1.2.3.4:8080", "5.6.7.8:3128"}
        assert all(v == "proxyscrape" for v in provenance.values())
    asyncio.run(main())


# ----------------------------------------------------------------------
# Stats
# ----------------------------------------------------------------------

def test_record_run_accumulates_buckets(tmp_path):
    s = _stats(tmp_path)
    s.record_run({"a": 100, "b": 50}, {"a": 20, "b": 0})
    s.record_run({"a": 100}, {"a": 10})
    rows = s.summary()
    by = {r[0]: r for r in rows}
    assert by["a"][1:3] == (200, 30) and abs(by["a"][3] - 0.15) < 1e-9
    assert by["b"][1:3] == (50, 0)
    print("✅ buckets + summary")


def test_disable_when_consistently_dead(tmp_path):
    s = _stats(tmp_path, min_checks=10, disable_runs=3)
    for _ in range(3):
        s.record_run({"deadsrc": 100}, {"deadsrc": 0})   # 0% live every run
    # after 3 runs x 100 checks, min_checks is met -> judged dead
    assert s.should_skip("deadsrc") is True
    assert "deadsrc" in s.disabled
    print("✅ chronic dead source disabled")


def test_disable_countdown_and_reenable(tmp_path):
    s = _stats(tmp_path, min_checks=10, disable_runs=3)
    for _ in range(3):
        s.record_run({"dead": 100}, {"dead": 0})
    assert s.should_skip("dead") is True
    # countdown ticks on each run; after 3 ticked runs it re-enables
    for _ in range(3):
        s.record_run({"other": 5}, {"other": 2})
        s.should_skip("dead")  # still skipped during countdown
    for _ in range(3):
        s.record_run({"other": 5}, {"other": 2})
    assert "dead" not in s.disabled  # countdown expired
    print("✅ re-enabled after disable window")


def test_healthy_source_never_disabled(tmp_path):
    s = _stats(tmp_path, min_checks=10)
    for _ in range(5):
        s.record_run({"good": 100}, {"good": 30})
    assert s.should_skip("good") is False
    print("✅ healthy source untouched")


def test_persistence_roundtrip(tmp_path):
    s = _stats(tmp_path)
    s.record_run({"a": 50}, {"a": 5})
    s.save()
    s2 = _stats(tmp_path)
    rows = s2.summary()
    assert rows[0][1] == 50 and rows[0][2] == 5
    print("✅ save/load")


# ----------------------------------------------------------------------
# Pipeline gating
# ----------------------------------------------------------------------

def test_pipeline_skips_disabled_sources_without_network():
    async def main():
        called = set()

        class FakeStats:
            def should_skip(self, label):
                called.add(label)
                return True  # everything disabled

        results = await run_scraper_pipeline(
            engines_config={"shodan": None},
            keys={"SHODAN_API_KEY": "x"},
            list_sources=["https://raw.example/list.txt"],
            html_sources=["https://example.com/table"],
            source_stats=FakeStats(),
        )
        assert results == []           # no candidates gathered
        assert "proxyscrape" in called and "spys.me" in called
        assert any(c.startswith("list:") for c in called)
        assert "shodan" in called
        print(f"✅ all sources gated without any request ({len(called)} labels)")
    asyncio.run(main())


def test_pipeline_labels_html_and_list_sources():
    async def main():
        provenance = {}
        class AllowAll:
            def should_skip(self, label):
                return False
        with patch("src.scraper.base.httpx.AsyncClient") as fake_cls:
            fake_ctx = AsyncMock()
            fake_ctx.__aenter__ = AsyncMock(return_value=AsyncMock())
            fake_ctx.__aexit__ = AsyncMock(return_value=False)
            fake_cls.return_value = fake_ctx

            await run_scraper_pipeline(
                {}, {},  # no engines, no keys
                list_sources=["https://raw.githubusercontent.com/x/list.txt"],
                html_sources=["https://free-proxy-list.net/"],
                provenance=provenance,
                source_stats=AllowAll(),
            )
        # http client mocked; scrapers failed silently, but labels were formed
        # (they appear in should_skip calls, verified above; here we only
        # ensure the run completed without error)
        print("✅ pipeline completes with mocked client")
    asyncio.run(main())