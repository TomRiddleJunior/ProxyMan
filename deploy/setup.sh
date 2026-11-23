#!/usr/bin/env bash
# ProxyMan unattended deployment kit for a VPS (Ubuntu/Debian).
# Keeps the SOURCE repo private; only the feed repo is public.
#
# Pre-reqs on the VPS:
#   - a GitHub token exported as GH_TOKEN:
#       * fine-grained PAT
#       * Repository access: ProxyMan (Read-only) + ProxyMan-free-proxy-list (Read and write)
#   - or an SSH deploy key with the same access (then set REPO_URL/feed URLs to ssh://)
#
# Usage:  GH_TOKEN=ghp_xxx ./setup.sh
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/TomRiddleJunior/ProxyMan.git}"
FEED_REPO_URL="${FEED_REPO_URL:-https://github.com/TomRiddleJunior/ProxyMan-free-proxy-list.git}"
INSTALL_DIR="${INSTALL_DIR:-/opt/proxyman}"
RUN_USER="${RUN_USER:-$(id -un)}"

if [ -z "${GH_TOKEN:-}" ]; then
  echo "[!] GH_TOKEN is required (see header comment)." >&2
  exit 1
fi

echo "==> System packages"
sudo apt-get update -qq
sudo apt-get install -y -qq python3 python3-venv python3-pip git curl

echo "==> Directories"
sudo mkdir -p "$INSTALL_DIR" /var/log/proxyman
sudo chown -R "$RUN_USER" "$INSTALL_DIR" /var/log/proxyman

if [ -d "$INSTALL_DIR/repo/.git" ]; then
  (cd "$INSTALL_DIR/repo" && git pull -q)
else
  git clone "https://x-access-token:${GH_TOKEN}@${REPO_URL#https://}" "$INSTALL_DIR/repo"
fi

echo "==> Python environment"
python3 -m venv "$INSTALL_DIR/repo/.venv"
"$INSTALL_DIR/repo/.venv/bin/pip" install -q -r "$INSTALL_DIR/repo/requirements.txt"

echo "==> Runner scripts"
cp "$INSTALL_DIR/repo/deploy/run_harvester.sh" "$INSTALL_DIR/run_harvester.sh"
cp "$INSTALL_DIR/repo/deploy/run_checker.sh"    "$INSTALL_DIR/run_checker.sh"
cp "$INSTALL_DIR/repo/deploy/proxyman.env.template" /tmp/proxyman.env.new
sudo mv /tmp/proxyman.env.new /etc/proxyman.env
if [ "$RUN_USER" != "root" ]; then
  # services run as RUN_USER: it must be able to read the secrets file
  sudo chown root:"$RUN_USER" /etc/proxyman.env
  sudo chmod 640 /etc/proxyman.env
else
  sudo chmod 600 /etc/proxyman.env
fi
chmod +x "$INSTALL_DIR"/run_*.sh

echo "==> systemd units"
for unit in proxyman-harvester proxyman-checker; do
  # Run the services as the installing user (not root) so git never hits
  # "detected dubious ownership" on a non-root-owned repo checkout.
  sed "s/^#User=PLACEHOLDER/User=$RUN_USER/; s/^#Group=PLACEHOLDER/Group=$RUN_USER/" \
    "$INSTALL_DIR/repo/deploy/${unit}.service" | sudo tee "/etc/systemd/system/${unit}.service" >/dev/null
  sudo cp "$INSTALL_DIR/repo/deploy/${unit}.timer" /etc/systemd/system/
done
sudo systemctl daemon-reload
sudo systemctl enable --now proxyman-harvester.timer proxyman-checker.timer

echo ""
echo "==> DONE. NOW DO THIS BEFORE FIRST RUN:"
echo "    sudo nano /etc/proxyman.env   # set GH_TOKEN + API keys, then:"
echo "    sudo systemctl restart proxyman-harvester.timer proxyman-checker.timer"
echo ""
echo "==> Timers:"
systemctl list-timers | grep -E "proxyman|NEXT" || true