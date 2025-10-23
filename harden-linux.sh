#!/usr/bin/env bash
# harden-linux.sh - Defensive hardening for Ubuntu / Linux Mint (21.x compatible)
# Usage: sudo ./harden-linux.sh [--dry-run]
set -euo pipefail
DRYRUN=false
if [[ "${1:-}" == "--dry-run" ]]; then DRYRUN=true; fi
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG="/var/log/harden-linux-${TIMESTAMP}.log"
exec > >(tee -a "$LOG") 2>&1
echo "=== Linux Hardening Started: $TIMESTAMP ==="
echo "Dry-run: $DRYRUN"
run(){ if $DRYRUN; then echo "[DRYRUN] $*"; else echo "[RUN] $*"; eval "$@"; fi; }
run "apt-get update -y"
run "apt-get upgrade -y"
run "sed -i -E 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs"
run "sed -i -E 's/^PASS_MIN_LEN.*/PASS_MIN_LEN\t12/' /etc/login.defs"
run "apt-get install -y fail2ban || true"
run "systemctl enable --now fail2ban || true"
run "sed -i -E 's/^#?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config"
run "ufw default deny incoming"
run "ufw default allow outgoing"
run "ufw --force enable"
echo "=== Hardening Completed ==="
