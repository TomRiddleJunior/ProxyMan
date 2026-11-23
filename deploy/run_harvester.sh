#!/usr/bin/env bash
# ProxyMan harvester (VPS): scrape -> validate -> publish feed.
# Mirrors .github/workflows/harvester.yml with the .complete publish gate.
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/proxyman}"
REPO_DIR="$INSTALL_DIR/repo"
FEED_URL="${FEED_REPO_URL:-https://github.com/TomRiddleJunior/ProxyMan-free-proxy-list.git}"
PY="$REPO_DIR/.venv/bin/python"

cd "$REPO_DIR"

# Cross-timer lock (shared with the checker): never run two pipeline runs at
# once - they would race on the feed clone and the pool state file.
LOCK_FILE="${LOCK_FILE:-/tmp/proxyman-run.lock}"
exec 9>"$LOCK_FILE"
if ! flock -w 180 9; then
  echo "[!] Another ProxyMan run holds the lock; skipping this cycle." >&2
  exit 0
fi

# Refresh code + deps each run (private repo, token from /etc/proxyman.env)
git pull -q origin main || true
"$REPO_DIR/.venv/bin/pip" install -q -r requirements.txt || true

# Fresh clone of the public feed repo with the token baked into origin
rm -rf public_list
git clone -q "https://x-access-token:${GH_TOKEN}@${FEED_URL#https://}" public_list

mkdir -p "$INSTALL_DIR/logs"
"$PY" main.py --mode harvest --log-file "$INSTALL_DIR/logs/harvester.log"

# Publish only when the run finished cleanly
if [ -f output/.complete ]; then
  # COLD-START / OUTAGE GUARD: never replace a healthy feed with a near-empty
  # one (fresh pool state, verification outage, runner IP unknown). A cold
  # deployment's first run has every proxy at streak 1 -> 0 publishable.
  MIN_PUBLISH_COUNT="${MIN_PUBLISH_COUNT:-25}"
  count=$(wc -l < output/proxies.txt 2>/dev/null || echo 0)
  if [ "$count" -lt "$MIN_PUBLISH_COUNT" ]; then
    echo "[!] GUARD: only $count proxies produced (< $MIN_PUBLISH_COUNT). Keeping previous feed snapshot." >&2
    exit 0
  fi

  rm -rf public_list/*
  cp -r output/* public_list/
  cp README.feed.md public_list/README.md
  cd public_list
  git add .
  git rm -q --cached .complete 2>/dev/null || true
  if git diff --cached --quiet; then
    echo "No proxy changes detected. Skipping release."
  else
    git commit -q -m "chore(harvester): VPS harvest refresh [skip ci]"
    for attempt in 1 2 3 4 5; do
      git pull -q --rebase origin main
      if git push -q origin main; then
        echo "Published successfully (attempt $attempt)."
        exit 0
      fi
      echo "Push rejected (attempt $attempt), rebasing and retrying..."
      sleep 5
    done
    echo "[!] Push failed after 5 attempts." >&2
    exit 1
  fi
else
  echo "[!] No completion marker - run did not finish cleanly. Skipping release." >&2
  exit 1
fi