#!/usr/bin/env bash
# Update the VPS to the latest main from GitHub and restart the bot.
#
#   sudo /opt/anti-cheat/deploy.sh
#
# Only tracked files change. .env, roster.csv, the database and .venv are
# untracked, so a deploy never touches them. If the tests fail on the new
# code, the checkout is rolled back and the running bot is left alone.
set -euo pipefail

APP_DIR=/opt/anti-cheat
cd "$APP_DIR"

git fetch --quiet origin main
old=$(git rev-parse --short HEAD)
new=$(git rev-parse --short origin/main)
if [ "$old" = "$new" ]; then
    echo "Already up to date ($old)."
    exit 0
fi

git reset --hard --quiet origin/main
.venv/bin/pip install --quiet -r requirements.txt
chown -R anticheat:anticheat "$APP_DIR"

if ! sudo -u anticheat .venv/bin/python -m pytest -q -p no:cacheprovider; then
    echo "Tests failed on $new -- rolling back to $old. The bot was not restarted." >&2
    git reset --hard --quiet "$old"
    chown -R anticheat:anticheat "$APP_DIR"
    exit 1
fi

systemctl restart anti-cheat
sleep 5
if ! systemctl is-active --quiet anti-cheat; then
    echo "anti-cheat failed to start on $new. Check: journalctl -u anti-cheat -n 50" >&2
    exit 1
fi
echo "Deployed $old -> $new."
journalctl -u anti-cheat -n 5 --no-pager -o cat
