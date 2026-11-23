import asyncio
"""Pool state regression tests: skip logic, retest cadence, revival, prune."""
import json
import time

from src.state import PoolState


def _state(tmp_path, **kw):
    defaults = dict(
        state_file=str(tmp_path / "state" / "pool_state.json"),
        max_consecutive_failures=3,
        retest_interval=4,
        retention_days=14,
    )
    defaults.update(kw)
    return PoolState(**defaults)


def test_fresh_proxy_never_skipped(tmp_path):
    ps = _state(tmp_path)
    assert ps.consider_skip("1.1.1.1:1080") is False


def test_known_dead_skipped_with_retest_cadence(tmp_path):
    ps = _state(tmp_path)
    for _ in range(3):
        ps.record_check("1.1.1.1:1080", success=False)
    assert ps.entry("1.1.1.1:1080")["consecutive_failures"] == 3

    # interval=4 -> 3 skips, then the 4th call retests
    for i in range(3):
        assert ps.consider_skip("1.1.1.1:1080") is True, f"skip {i}"
    assert ps.consider_skip("1.1.1.1:1080") is False
    assert ps.skipped_this_run == 3


def test_revival_resets_streaks(tmp_path):
    ps = _state(tmp_path)
    for _ in range(3):
        ps.record_check("1.1.1.1:1080", success=False)
    ps.record_check("1.1.1.1:1080", success=True, latency=0.42, protocol="socks5")
    e = ps.entry("1.1.1.1:1080")
    assert e["consecutive_failures"] == 0
    assert e["consecutive_success"] == 1
    assert e["best_latency"] == 0.42
    assert "socks5" in e["protocols"]
    assert ps.consider_skip("1.1.1.1:1080") is False


def test_best_latency_tracks_min(tmp_path):
    ps = _state(tmp_path)
    ps.record_check("1.1.1.1:1080", success=True, latency=1.2)
    ps.record_check("1.1.1.1:1080", success=True, latency=0.3)
    ps.record_check("1.1.1.1:1080", success=True, latency=0.9)
    assert ps.entry("1.1.1.1:1080")["best_latency"] == 0.3


def test_save_load_roundtrip(tmp_path):
    ps = _state(tmp_path)
    for _ in range(3):
        ps.record_check("1.1.1.1:1080", success=False)
    ps.record_check("2.2.2.2:8080", success=True, protocol="http")
    ps.save()

    ps2 = _state(tmp_path)
    assert set(ps2.entries) == {"1.1.1.1:1080", "2.2.2.2:8080"}
    assert ps2.entry("1.1.1.1:1080")["consecutive_failures"] == 3

    # state file is valid JSON (no tmp leftovers)
    raw = json.loads((tmp_path / "state" / "pool_state.json").read_text())
    assert raw["version"] == 1
    assert not (tmp_path / "state" / "pool_state.json.tmp").exists()


def test_prune_removes_stale_entries(tmp_path):
    ps = _state(tmp_path)
    ps.record_check("1.1.1.1:1080", success=True)
    old = "9.9.9.9:3128"
    ps.entries[old] = {"consecutive_failures": 0, "last_seen_ts": time.time() - 20 * 86400}

    removed = ps.prune()
    assert removed == 1
    assert old not in ps.entries
    assert "1.1.1.1:1080" in ps.entries


def test_stats(tmp_path):
    ps = _state(tmp_path)
    ps.record_check("1.1.1.1:1080", success=True)
    for _ in range(3):
        ps.record_check("2.2.2.2:8080", success=False)
    s = ps.stats()
    assert s["total"] == 2 and s["alive"] == 1 and s["dead"] == 1


def test_skip_does_not_refresh_last_seen(tmp_path):
    """Regression: refreshing last_seen_ts on skip defeated prune() forever."""
    ps = _state(tmp_path)
    for _ in range(3):
        ps.record_check("1.1.1.1:1080", success=False)
    before = ps.entry("1.1.1.1:1080")["last_seen_ts"]
    time.sleep(0.01)
    assert ps.consider_skip("1.1.1.1:1080") is True
    after = ps.entry("1.1.1.1:1080")["last_seen_ts"]
    assert after == before, "skip must not refresh last_seen_ts"
    assert "last_retest_ts" in ps.entry("1.1.1.1:1080")


def test_dead_entries_pruned_on_dead_clock(tmp_path):
    """Known-dead hosts expire on the short dead clock, not the 14-day one."""
    ps = _state(tmp_path, dead_retention_days=3, retention_days=14)
    for _ in range(3):
        ps.record_check("1.1.1.1:1080", success=False)
    ps.record_check("2.2.2.2:8080", success=True)
    # 1.1.1.1 died 5 days ago -> pruned; 2.2.2.2 is live -> kept
    ps.entries["1.1.1.1:1080"]["dead_since_ts"] = time.time() - 5 * 86400
    removed = ps.prune()
    assert removed == 1
    assert "1.1.1.1:1080" not in ps.entries
    assert "2.2.2.2:8080" in ps.entries


def test_dead_since_stamped_and_cleared(tmp_path):
    ps = _state(tmp_path)
    for _ in range(3):
        ps.record_check("1.1.1.1:1080", success=False)
    assert ps.entry("1.1.1.1:1080")["dead_since_ts"] is not None
    ps.record_check("1.1.1.1:1080", success=True)
    assert ps.entry("1.1.1.1:1080")["dead_since_ts"] is None


def test_legacy_dead_entry_stamped_on_retest(tmp_path):
    """Pre-existing dead entries (no dead_since_ts) get stamped when retested,
    so they expire on the dead clock instead of living forever."""
    ps = _state(tmp_path)
    ps.entries["9.9.9.9:1080"] = {
        "first_seen_ts": time.time() - 86400,
        "checks": 5, "ok_count": 0, "fail_count": 5,
        "consecutive_failures": 5, "consecutive_success": 0,
        "last_seen_ts": time.time(), "last_ok_ts": None, "dead_since_ts": None,
        "best_latency": None, "protocols": [], "retest_countdown": 0,
    }
    ps.record_check("9.9.9.9:1080", success=False)
    assert ps.entry("9.9.9.9:1080")["dead_since_ts"] is not None
    # the death stamp is preserved (not reset) across further failures
    stamp = ps.entry("9.9.9.9:1080")["dead_since_ts"]
    ps.record_check("9.9.9.9:1080", success=False)
    assert ps.entry("9.9.9.9:1080")["dead_since_ts"] == stamp


def test_max_entries_cap_evicts_dead_first(tmp_path):
    """The hard ceiling never evicts a live entry while dead ones remain."""
    ps = _state(tmp_path, max_entries=1000)
    now = time.time()
    for i in range(500):
        ps.entries[f"10.0.{i % 250}.{i}:1080"] = {
            "consecutive_failures": 0, "last_seen_ts": now,
            "dead_since_ts": None, "ok_count": 1, "last_ok_ts": now,
            "best_latency": None,
        }
    for i in range(1500):
        ps.entries[f"11.{i // 250}.{i % 250}.9:1080"] = {
            "consecutive_failures": 3, "last_seen_ts": now - i,
            "dead_since_ts": now - 86400, "ok_count": 0, "last_ok_ts": None,
            "best_latency": None,
        }
    assert len(ps.entries) == 2000
    ps.prune()
    assert len(ps.entries) == 1000
    alive = sum(1 for v in ps.entries.values() if v["consecutive_failures"] == 0)
    assert alive == 500, "cap must keep every live entry before any dead one"


def test_recently_alive_addresses(tmp_path):
    ps = _state(tmp_path)
    now = time.time()
    ps.entries["a:1080"] = {"ok_count": 3, "last_ok_ts": now - 60, "best_latency": 0.5}
    ps.entries["b:1080"] = {"ok_count": 1, "last_ok_ts": now - 30, "best_latency": 0.9}
    ps.entries["c:1080"] = {"ok_count": 5, "last_ok_ts": now - 10 * 86400, "best_latency": 0.1}
    ps.entries["d:1080"] = {"ok_count": 0, "last_ok_ts": None, "best_latency": None}
    assert ps.recently_alive_addresses(within_hours=24, limit=10) == ["b:1080", "a:1080"]
    assert ps.recently_alive_addresses(within_hours=24, limit=1) == ["b:1080"]

def test_strict_boolean_parsing(tmp_path):
    import yaml
    from src.config import load_config, _as_bool

    assert _as_bool(True) is True and _as_bool(False) is False
    assert _as_bool("false") is False and _as_bool("FALSE") is False
    assert _as_bool("true") is True and _as_bool("on") is True
    assert _as_bool("0") is False and _as_bool("1") is True
    assert _as_bool("garbage") is True  # falls back to default

    # the exact bug: quoted "false" in YAML must disable verify_exit
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("validation:\n  verify_exit: \"false\"\n")
    cfg = load_config(str(cfg_file))
    assert cfg.validation.verify_exit is False
    print("quoted-false parsed correctly:", cfg.validation.verify_exit)


def test_geoip_staleness_and_retry(tmp_path):
    import time as time_mod
    from unittest.mock import patch
    import src.validator.geo as geo_mod
    from src.validator.geo import GeoIPResolver, MAX_DOWNLOAD_ATTEMPTS

    db_path = tmp_path / "GeoLite2-Country.mmdb"

    # missing -> stale
    assert GeoIPResolver._is_stale(str(db_path)) is True
    # old file -> stale
    db_path.write_bytes(b"x")
    with patch("os.path.getmtime", return_value=time_mod.time() - 40 * 86400):
        assert GeoIPResolver._is_stale(str(db_path)) is True
    # fresh file -> not stale
    with patch("os.path.getmtime", return_value=time_mod.time() - 5 * 86400):
        assert GeoIPResolver._is_stale(str(db_path)) is False
    print("✅ staleness logic")

    # download retry: 2 failures then success
    class FakeResp:
        status_code = 200
        content = b"GEOIPDATA"

    class FakeClient:
        attempts = 0  # class-level: a fresh instance is created per attempt

        def __init__(self, *a, **k):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def get(self, *a, **k):
            FakeClient.attempts += 1
            if FakeClient.attempts < 3:
                raise OSError("network flake")
            return FakeResp()

    async def main():
        db_path.unlink()  # resolver must see a missing DB to trigger download
        with patch.object(geo_mod, "GEO_DB_PATH", str(db_path)), \
             patch.object(geo_mod, "GEO_DB_DIR", str(tmp_path)), \
             patch.object(geo_mod, "GEO_DB_URL", "https://mock"), \
             patch("src.validator.geo.httpx.AsyncClient", FakeClient):
            r = GeoIPResolver()
            await r.ensure_db_downloaded()
        assert db_path.read_bytes() == b"GEOIPDATA"
        print("✅ 2 failures -> retried -> success, tmp+replace used")

    asyncio.run(main())
