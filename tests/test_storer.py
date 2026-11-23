"""Storer regression tests: stale-file purging and split output layout."""
import os
import json
import csv

from src.validator.core import ProxyInfo
from src.storer import ProxyStorer


def _sample(addr, proto="http", anon="elite", latency=0.5, ssl=True, cc="DE", cn="Germany"):
    return ProxyInfo(addr, proto, anon, latency, ssl, cc, cn)


def test_stale_country_files_purged(tmp_path):
    countries = tmp_path / "countries"
    countries.mkdir()
    (countries / "us.txt").write_text("1.1.1.1:8080\n")  # stale from previous run
    (countries / "de.txt").write_text("2.2.2.2:8080\n")

    proxman = [  # US has ZERO proxies this run -> us.txt must disappear
        _sample("3.3.3.3:3128", cc="DE"),
        _sample("4.4.4.4:1080", proto="socks5", cc="BR", cn="Brazil"),
    ]
    ProxyStorer(str(tmp_path), ["txt"]).save_proxies(proxman)

    files = sorted(p.name for p in countries.iterdir())
    assert files == ["br.txt", "de.txt"], files
    assert (countries / "us.txt").exists() is False
    assert (countries / "de.txt").read_text().strip() == "3.3.3.3:3128"


def test_empty_run_clears_all_country_files(tmp_path):
    countries = tmp_path / "countries"
    countries.mkdir()
    (countries / "us.txt").write_text("1.1.1.1:8080\n")

    ProxyStorer(str(tmp_path), ["txt"]).save_proxies([])
    assert list(countries.iterdir()) == []


def test_split_output_layout(tmp_path):
    proxman = [
        _sample("3.3.3.3:3128", cc="DE"),
        _sample("4.4.4.4:1080", proto="socks5", cc="DE"),
        _sample("5.5.5.5:8888", proto="http", anon="anonymous", ssl=False, cc="US", cn="United States"),
    ]
    ProxyStorer(str(tmp_path), ["txt", "json", "csv"]).save_proxies(proxman)

    master = (tmp_path / "proxies.txt").read_text().splitlines()
    assert len(master) == 3

    protocols = tmp_path / "protocols"
    assert len((protocols / "http.txt").read_text().splitlines()) == 2
    assert len((protocols / "socks5.txt").read_text().splitlines()) == 1

    elite = (tmp_path / "anonymity" / "elite.txt").read_text().splitlines()
    assert elite == ["3.3.3.3:3128", "4.4.4.4:1080"]

    # SSL tunnel only contains the HTTP proxy that supports SSL
    ssl_only = (tmp_path / "ssl_only.txt").read_text().splitlines()
    assert ssl_only == ["3.3.3.3:3128"]

    country_de = (tmp_path / "countries" / "de.txt").read_text().splitlines()
    assert country_de == ["3.3.3.3:3128", "4.4.4.4:1080"]

    data = json.loads((tmp_path / "proxies.json").read_text())
    assert len(data) == 3 and data[0]["ip"] == "3.3.3.3" and data[0]["port"] == 3128

    with open(tmp_path / "proxies.csv", newline="") as f:
        rows = list(csv.reader(f))
    assert rows[0] == ["address", "ip", "port", "protocol", "anonymity", "latency",
                       "ssl_supported", "verified_exit", "premium", "country_code", "country_name",
                       "hosting", "as_name", "org", "target_ok", "target_latency"]
    assert len(rows) == 4

def test_speed_tiers_and_meta_stats(tmp_path):
    proxman = [
        ProxyInfo("3.3.3.3:3128", "http", "elite", 0.5, True, "DE", "Germany"),
        ProxyInfo("4.4.4.4:1080", "socks5", "elite", 0.3, True, "BR", "Brazil"),
        ProxyInfo("5.5.5.5:8888", "http", "anonymous", 0.9, False, "US", "United States"),
        ProxyInfo("6.6.6.6:8080", "http", "elite", 1.5, True, "IN", "India"),
    ]
    ProxyStorer(str(tmp_path), ["txt", "json"], fast_latency_threshold=0.8).save_proxies(proxman)

    fast = (tmp_path / "fast.txt").read_text().splitlines()
    assert fast == ["3.3.3.3:3128", "4.4.4.4:1080"]

    best = (tmp_path / "best.txt").read_text().splitlines()
    assert best == ["3.3.3.3:3128", "4.4.4.4:1080"]  # elite + ssl + fast

    # slow elite proxy is NOT in best/fast, anonymous 0.9s not in fast
    assert "6.6.6.6:8080" not in fast and "5.5.5.5:8888" not in fast

    # empty run clears tier files
    ProxyStorer(str(tmp_path), ["txt"], fast_latency_threshold=0.8).save_proxies([])
    assert (tmp_path / "fast.txt").read_text() == ""
    assert (tmp_path / "best.txt").read_text() == ""

    meta = json.loads((tmp_path / "meta.json").read_text())
    c = meta["counts"]
    assert c["total"] == 0 and c["fast"] == 0 and c["best"] == 0


def test_premium_tier_and_meta_stats(tmp_path):
    proxman = [
        ProxyInfo("3.3.3.3:3128", "http", "elite", 0.5, True, "DE", "Germany", verified_exit=True, premium=True),
        ProxyInfo("4.4.4.4:1080", "socks5", "elite", 0.3, True, "BR", "Brazil", verified_exit=True, premium=True),
        ProxyInfo("5.5.5.5:8888", "socks5", "elite", 0.7, True, "US", "United States", verified_exit=True),
        ProxyInfo("6.6.6.6:8080", "http", "elite", 1.5, True, "IN", "India", verified_exit=True),
    ]
    ProxyStorer(str(tmp_path), ["txt", "json"], fast_latency_threshold=0.8).save_proxies(proxman)

    # premium.txt only contains flagged entries, in feed order
    premium = (tmp_path / "premium.txt").read_text().splitlines()
    assert premium == ["3.3.3.3:3128", "4.4.4.4:1080"]

    meta = json.loads((tmp_path / "meta.json").read_text())
    assert meta["schema"] == 3
    c = meta["counts"]
    assert c["premium"] == 2
    assert c["verified"] == 4
    assert meta["quality"]["verified_ratio"] == 1.0
    assert meta["quality"]["premium_ratio"] == 0.5

    data = json.loads((tmp_path / "proxies.json").read_text())
    flags = {d["address"]: d["premium"] for d in data}
    assert flags["3.3.3.3:3128"] and flags["5.5.5.5:8888"] is False

    # empty run clears the premium file
    ProxyStorer(str(tmp_path), ["txt"]).save_proxies([])
    assert (tmp_path / "premium.txt").read_text() == ""
