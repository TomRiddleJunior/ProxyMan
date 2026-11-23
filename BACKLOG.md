# 📌 Backlog — Deferred Work (Tier 2 & Tier 3)

> Saved on request: *"leave and note rest for later"*. Everything here stays on
> ice until explicitly picked up. The current focus is existing-code evolution.

---

## 🟡 Tier 2 — Premium features

- [ ] **Verified exit-IP check** — query the runner's public IP *through* each
      proxy; a proxy that leaks our real IP is guaranteed transparent. The
      "enterprise verified" claim.
- [ ] **Uptime % in feeds** — expose `ok_count / checks` from pool state as a
      column in proxies.json / proxies.csv so consumers can rank reliability.
- [ ] **Per-source effectiveness** — 14-day rolling live-ratio per scraper
      source; auto-disable sources that consistently yield dead candidates.
- [ ] **Failure alerts** — Telegram/Discord webhook notification when a
      pipeline run fails (now relevant for the VPS cron too).
- [ ] **Keyed-API quota guard** — ⚠️ Censys free tier is only 250 queries/month;
      track usage and auto-pause engines approaching their quota.

## 🔴 Tier 3 — Big bets

- [x] **Multi-node harvesting** — VPS deployment kit shipped in `deploy/`
      (systemd timers, runner scripts, token guide). Next: actually provision a
      VPS and point the timers at it.
- [ ] **Source protocol tags** — sources that only publish HTTP (e.g.
      proxy-list.download HTTP) should skip SOCKS probes entirely (~2× pool
      throughput on those candidates).

## 🎛️ Tuning checklist

- [ ] After the pool has run a few days: set `min_successful_checks: 2` so only
      twice-verified proxies enter the public feeds.