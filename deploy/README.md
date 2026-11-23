# 🖥️ ProxyMan VPS Deployment

> ⚠️ **ACCEPTABLE-USE WARNING.** ProxyMan validates proxies by probing hosts it
> does not own. That is effectively network probing, and most cloud providers
> (Microsoft Azure, AWS) prohibit it without prior authorization. Running this
> on a **standing cloud VM with a stable IP is a ban risk** - one abuse report
> from a target and the subscription is suspended. Azure/AWS-hosted VPSs are
> **not recommended**. If you self-host, use a provider whose AUP explicitly
> permits security/proxy research, or your own network. GitHub-hosted runners
> (ephemeral, shared IPs) are the lower-risk default.

Run the whole pipeline on your own box: **zero GitHub Actions minutes**,
full control, repo stays private. ~10 minutes of work.

## 1. Prereqs

- Any Ubuntu/Debian VPS (1 vCPU / 1 GB is plenty)
- A **fine-grained GitHub PAT** with:
  - `TomRiddleJunior/ProxyMan` — **Read-only** (clones source)
  - `TomRiddleJunior/ProxyMan-free-proxy-list` — **Read and write** (publishes feeds)

Create it at github.com/settings/personal-access-tokens (fine-grained), then:

```bash
export GH_TOKEN=github_pat_xxx
```

## 2. Deploy

```bash
ssh user@vps
sudo apt-get update && sudo apt-get install -y git curl
git clone https://github.com/TomRiddleJunior/ProxyMan.git /tmp/proxyman
cd /tmp/proxyman
GH_TOKEN=github_pat_xxx ./deploy/setup.sh
```

The script installs dependencies, clones the private repo to `/opt/proxyman`,
copies runner scripts + systemd units, and enables both timers.

## 3. Secrets (one time)

```bash
sudo nano /etc/proxyman.env   # add GH_TOKEN (+ optional API keys)
sudo systemctl restart proxyman-harvester.timer proxyman-checker.timer
```

## 4. Verify

```bash
systemctl list-timers | grep proxyman          # timers armed?
sudo journalctl -u proxyman-harvester -n 50    # first harvest logs
tail -f /var/log/proxyman/harvester.log        # or the run logs
curl -s https://raw.githubusercontent.com/TomRiddleJunior/ProxyMan-free-proxy-list/main/meta.json | head
```

## 5. What runs where

| Task | Before (GitHub Actions) | After (VPS) |
| :--- | :--- | :--- |
| Harvest every 2 h | `ProxyHarvester` schedule | `proxyman-harvester.timer` |
| Pool check every 15 min | `ProxyChecker` schedule | `proxyman-checker.timer` (cold-start guarded) |
| Tests on push | `Tests` workflow | stays on GitHub (push only) |

The GitHub workflows remain available as **manual dispatch** emergency buttons
(`gh workflow run harvester.yml`) — they just no longer hold the schedule.

## Ops cheat sheet

```bash
sudo systemctl status proxyman-harvester.service   # last run result
sudo systemctl start proxyman-harvester.service    # run now
sudo systemctl stop proxyman-harvester.timer       # pause schedule
```

Logs: `/var/log/proxyman/*.log` (systemd captures too). State lives in
`/opt/proxyman/repo/state/` and persists across runs (no cache to lose).