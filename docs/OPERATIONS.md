# 🛠️ ProxyMan Operations Runbook

Field notes for running this pipeline unattended. Update as reality teaches us
new failure modes — this file lives to be wrong later and corrected faster.

---

## Pipeline cadence

| Workflow | Schedule | Notes |
| :--- | :--- | :--- |
| `ProxyHarvester` | every 4 h *(interim)* | Scrape → validate → publish. Populates the pool from all sources |
| `ProxyChecker` | every 30 min *(interim)* | Re-validates the published pool in place |
| `Tests` | on push | `pytest -q`, no network required |

> **Current setup (interim):** both schedules run on GitHub Actions until the
> VPS timers take over. Harvester is at 4 h (not 2 h) so the combined spend
> fits the private 2,000-min quota, leaving the pool refilled. Estimated spend:
> checker ≈1,440 + harvester ≈270 + tests ≈15 → ≈1,725 min/mo (margin ~275).
> When the VPS is live: `deploy/setup.sh`, then workflow schedules can go
> back to manual dispatch (`gh workflow run ...`) for ~0 GitHub minutes.

If running entirely on GitHub Actions on a private repo: runs consume the
2,000 private Actions minutes/month. Watch **Settings → Billing → Actions**.

---

## Normal operation signs

- Public feed `meta.json` updates every run with fresh `generated_at`
- `counts.total` roughly stable between check runs (30-40% decay is normal —
  proxies die fast; harvest refills)
- `counts.verified` shows the honest subset that proved traffic routing
- Pool state survives between runs via Actions cache (`state/`), not git

## Warning signs

| Symptom | Likely cause | Action |
| :--- | :--- | :--- |
| `counts.total` trending to 0 | Runner IP blocked by keyless sources; harvest cron broken | Check latest Harvester logs; verify `list_sources`/`html_sources` reachable from a runner IP |
| `Verified` ≈ 0 but `total` healthy | `api.ipify.org` blocked through proxies, or `fetch_my_ip` failing | Check runner network; ipify may need a different probe host |
| Checker failing with `cannot lock ref` | Publish race (should be fixed by concurrency group + retry loop) | Re-run the workflow; report if it recurs |
| `No completion marker` in checker publish step | A run crashed mid-way (defense-in-depth worked) | Look at the failed step's logs; feeds were NOT published (correct) |
| Pool state `cold start` messages | Actions cache evicted/expired | Normal; the next 2-3 runs rebuild history |

## Local operations

```bash
# full rehearsal, zero network (uses state + storer + queue paths)
python main.py --mode check --dry-run --output-dir /tmp/out

# debug with persistent logs
python main.py --mode harvest --verbose --log-file proxyman.log

# inspect pool health
python -c "import json;m=json.load(open('meta.json'));print(m['counts'])"
```

## Environment variables

All optional; keyless sources keep the pipeline alive without them:
`SHODAN_API_KEY`, `CENSYS_API_ID` + `CENSYS_API_SECRET` (⚠️ free tier = 250
queries/month — watch usage), `ZOOMEYE_API_KEY`, `CRIMINALIP_API_KEY`,
`FOFA_EMAIL` + `FOFA_API_KEY`.

## Honest constraints

- SOCKS4 proxies: handshake-validated, **not** exit-verified (no domain CONNECT)
- `verified_exit=false` does not mean a proxy is bad — it means we could not
  prove routing through it (auth-required, ipify blocked, or runner IP unknown)
- Pool freshness beats pool size: 30-min revalidation keeps churn low