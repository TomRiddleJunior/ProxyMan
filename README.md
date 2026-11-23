<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Async-asyncio-2E8B57?style=for-the-badge&logo=asyncio" alt="Async">
  <img src="https://img.shields.io/github/actions/workflow/status/TomRiddleJunior/ProxyMan/tests.yml?label=CI&style=for-the-badge" alt="CI">
  <img src="https://img.shields.io/badge/Update%20Cadence-30%20min-1E90FF?style=for-the-badge" alt="Cadence">
</p>

<h1 align="center">⚡ ProxyMan</h1>
<p align="center"><b>High-performance asynchronous proxy scraper &amp; validator pipeline.</b><br>
Harvests candidates from OSINT engines and public sources, validates them with raw-socket probes, and publishes curated elite/anonymous feeds — fully unattended.</p>

---

## 📡 Live Feeds

The curated output is published continuously to the sibling feed repository:

> **[TomRiddleJunior/ProxyMan-free-proxy-list](https://github.com/TomRiddleJunior/ProxyMan-free-proxy-list)** — refreshed every 30 minutes, best-effort (GitHub throttles frequent schedules), split by protocol, country and anonymity level, plus a `premium.txt` tier of proven-stable fast proxies.

---

## ✨ Features

| Area | Highlights |
| :--- | :--- |
| **Hybrid harvester** | OSINT search engines (Shodan, Censys, ZoomEye, FOFA, Criminal IP) + keyless sources (ProxyScrape, Geonode, Spys.me, HTML table crawlers) + curated **plain-text lists** (GitHub raw dumps, direct APIs) |
| **Commercial-grade validator** | Raw-socket engine: TCP port probe, then **SOCKS5 / SOCKS4 / HTTP probes in parallel** (SOCKS5 > SOCKS4 > HTTP precedence) |
| **Verified-only publishing** | A handshake is not aliveness: only proxies whose traffic was *proven to route* (exit IP fetched through them) are published. Handshake-only survivors are held back — they are the dead proxies that plague typical free lists |
| **Multi-endpoint exit proof** | Exit verification rotates across 4 echo endpoints (ipify / ip-api / ifconfig.me / checkip.amazonaws.com), so one flaky echo host can no longer downgrade the pool to "unverified" |
| **Honest latency** | Reported latency is the end-to-end round trip of the exit-verification request — what a consumer actually experiences — not the protocol handshake time |
| **Honest SSL flags** | TLS capability is probed (CONNECT to :443), never hardcoded — SOCKS5/SOCKS4 included |
| **👑 Premium tier** | `premium.txt`: exit-verified + 5-check stability streak + ≤ 1s RTT + TLS-capable, sorted by speed |
| **Elite-only philosophy** | Transparent & unknown proxies are strictly discarded; anonymity graded via reflected header analysis |
| **Exit-IP verification** | Each candidate's traffic is proven to route through it — our IP is fetched *through* the proxy, so real-IP leakers are dropped and the rest carry `verified_exit=true` in the feeds (SOCKS4 included, via resolved-IP CONNECT) |
| **🎯 Targeted validation** | `--target <site>` — proxies that actually *reach* a specific site are emitted to `targets/<site>.txt` (site-ready lists, sorted by target latency). See `config.yaml targets:` |
| **🏠 ASN classification** | Every published proxy is tagged **residential / datacenter / unknown** via free ip-api.com batch lookups (cached in pool state). Emits `hosting/residential.txt` + `hosting/datacenter.txt` |
| **📊 Honest quality meta** | `meta.json` now reports `survival_rate` + `churn_rate` vs the previous run's snapshot, so consumers know how much of the list actually survives a cycle |
| **Candidate hygiene** | Private/reserved IP ranges and out-of-range ports are rejected before they consume probe time |
| **Pool stability scoring** | Persistent health history — known-dead hosts are skipped on future runs (with periodic retest); streaks count *proven routing*, not handshakes; only proven proxies get published |
| **Offline GeoIP** | MaxMind GeoLite2 country lookup, auto-downloaded on first run |
| **Resilient scrapers** | Exponential backoff retries (429/5xx/network errors), content-based BeautifulSoup table parsing |
| **Split outputs** | TXT / JSON / CSV — master list plus `protocols/`, `countries/`, `anonymity/`, `ssl_only.txt`, speed tiers `fast.txt` / `best.txt`, `meta.json` live stats |
| **Fully unattended** | GitHub Actions: checker every **30 min**, harvester every **4 h**, tests on every push (private-repo minute budget is respected) |
| **Rehearsal mode** | `--dry-run` exercises the entire pipeline with synthetic results — zero network I/O |

> **Honesty note:** when the runner's public IP cannot be established, exit verification is impossible; that run degrades to handshake-validated publishing with every entry honestly flagged `verified_exit=false` (never silently). If the runner IP is known but an individual proxy cannot route traffic to any echo endpoint, it is simply not published. Feeds expose verification per-proxy in JSON/CSV and aggregated in `meta.json.counts.verified` / `meta.json.quality.verified_ratio`.

---

## 🏗️ Architecture

```
                ┌──────────────────────────────┐
                │     CONFIG (config.yaml)     │
                └──────────────┬───────────────┘
                               │
   ┌───────────────────────────▼───────────────────────────┐
   │  HARVEST  (every 2 h)                                 │
   │  OSINT engines (Shodan*, Censys, ZoomEye, FOFA*,      │
   │  Criminal IP) + keyless sources (ProxyScrape,         │
   │  Geonode, Spys.me, HTML tables)   *8 h interval       │
   └───────────────────────────┬───────────────────────────┘
                               │ candidates (IP:PORT)
   ┌───────────────────────────▼───────────────────────────┐
   │  VALIDATOR  (asyncio, up to 800 workers)              │
   │  TCP probe → SOCKS5/SOCKS4/HTTP probes in parallel    │
   │  latency · anonymity grade · SSL tunnel · GeoIP       │
   └───────────────────────────┬───────────────────────────┘
                               │ validated ProxyInfo
   ┌───────────────────────────▼───────────────────────────┐
   │  POOL STATE  (stability scoring)                      │
   │  skip known-dead · track streaks · publish proven     │
   └───────────────────────────┬───────────────────────────┘
                               │
   ┌───────────────────────────▼───────────────────────────┐
   │  STORER  →  TXT / JSON / CSV                          │
   │  master · protocols/ · countries/ · anonymity/ · ssl  │
   └───────────────────────────┬───────────────────────────┘
                               ▼
              published → ProxyMan-free-proxy-list
```

---

## 🚀 Quick Start

```bash
pip install -r requirements.txt
# or install as a package (provides the `proxyman` command):
pip install -e .

# Harvest: scrape fresh candidates + validate (API keys via env)
python main.py --mode harvest
# or, when installed as a package:
proxyman --mode harvest

# Re-validate the existing pool (what the 30-min checker does)
python main.py --mode check --output-dir ./public_list

# Rehearse the whole pipeline with synthetic results, no network
python main.py --mode check --dry-run --output-dir ./output

# Debug-level logging + persistent log file
python main.py --mode harvest --verbose --log-file proxyman.log
```

API keys are read from environment variables:

| Variable | Engine |
| :--- | :--- |
| `SHODAN_API_KEY` | Shodan (8 h tier) |
| `CENSYS_API_ID` + `CENSYS_API_SECRET` | Censys |
| `ZOOMEYE_API_KEY` | ZoomEye |
| `CRIMINALIP_API_KEY` | Criminal IP |
| `FOFA_EMAIL` + `FOFA_API_KEY` | FOFA (8 h tier) |

Keyless sources run on every harvest with no setup.
---

## ⚙️ Configuration

Everything lives in [`config.yaml`](config.yaml).

| Section | Key | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `validation` | `test_urls` | httpbin, postman-echo | Reflector endpoints for HTTP tests & anonymity grading |
| `validation` | `connect_timeout` / `read_timeout` / `timeout` | 2.5 / 4.5 / 7.0 s | Socket timeouts |
| `validation` | `max_concurrency` | 800 | Async worker pool size |
| `validation` | `verify_exit` | true | Prove traffic routes through each HTTP/SOCKS5 candidate |
| `validation` | `user_agent` | Chrome 120 | Outgoing UA string |
| `output` | `output_dir` / `formats` | `./output` / `[json, txt, csv]` | — |
| `output` | `fast_latency_threshold` | 0.8 s | Speed-tier cutoff for `fast.txt` / `best.txt` |
| `pool` | `state_file` | `./state/pool_state.json` | Persistent stability history |
| `pool` | `max_consecutive_failures` | 3 | Failures before a host is treated as dead |
| `pool` | `retest_interval` | 8 | Runs between retests of known-dead hosts |
| `pool` | `retention_days` | 14 | Forget entries older than this |
| `pool` | `min_successful_checks` | 1 | Consecutive passes required before publishing |
| `sources` | `state_file` | `./state/source_stats.json` | Per-source effectiveness history |
| `sources` | `min_live_ratio` / `min_checks` | 0.02 / 50 | Auto-disable threshold + evidence required |
| `sources` | `disable_runs` | 48 | Runs a disabled source stays skipped before a retry |
| `sources` | `retention_days` | 14 | Forget day-buckets older than this |
| `search_engines` | `<engine>.queries` | — | Per-engine search queries |
| `list_sources` | URLs | 10 curated lists | Keyless plain-text proxy lists |

> 💡 **Tip:** after the pipeline has run for a few days, raise `min_successful_checks: 2` so only twice-verified proxies enter the public feeds.

---

## 📁 Output Layout

```
output/
├── proxies.json / proxies.csv        # full structured dump
├── meta.json                         # live feed stats (drives badges, incl. verified count)
├── proxies.txt                       # master list
├── ssl_only.txt                      # HTTP proxies with SSL CONNECT
├── fast.txt                          # latency ≤ threshold
├── best.txt                          # elite + SSL + fast
├── protocols/  http.txt socks4.txt socks5.txt
├── anonymity/  elite.txt anonymous.txt
└── countries/  us.txt de.txt br.txt ...   (purged every run)
```

---

## 🧪 Testing

25-test pytest suite — no network required:

```bash
pip install -r requirements-dev.txt
pytest -q
```

Coverage: storer purge logic, pool state state machine, retry/backoff, HTML table parsing, parallel probe precedence, deterministic dry-run, and end-to-end CLI rehearsals. Runs automatically in CI on every push.

---

## 🤖 CI/CD

| Workflow | Schedule | Job |
| :--- | :--- | :--- |
| `ProxyHarvester` | every 2 h | Scrape → validate → publish |
| `ProxyChecker` | every 30 min | Re-validate pool → publish verified-only |
| `Tests` | on push | `pytest -q` |

Pool state persists between runs via GitHub Actions cache (restore/save steps), keeping history across executions without polluting git history.

---

## 📂 Project Structure

```
main.py                     # CLI entrypoint (harvest / check / dry-run)
config.yaml                 # runtime configuration
src/
├── config.py               # YAML config loader (dataclasses)
├── scraper/base.py         # OSINT + keyless scrapers, retry helper
├── validator/core.py       # raw-socket validation engine
├── validator/geo.py        # MaxMind GeoLite2 offline lookups
├── state.py                # pool stability scoring
├── sources.py               # per-source effectiveness + auto-disable
└── storer/                 # split TXT/JSON/CSV output
tests/                      # pytest suite (25 tests)
.github/workflows/          # harvester, checker, tests
```

---

## ⚠️ Notes

- Respect the ToS and rate limits of every source; the retry layer is polite backoff, not hammering.
- Transparent proxies are deliberately discarded — the feeds target elite/anonymous quality only.
- `--dry-run` does **zero** network I/O and is safe to run anywhere.