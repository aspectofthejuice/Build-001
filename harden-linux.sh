#!/usr/bin/env bash
# harden-linux.sh - Comprehensive hardening for Ubuntu / Linux Mint (21.x+)
# Usage: sudo ./harden-linux.sh [--dry-run]
set -euo pipefail

DRYRUN=false
if [[ "${1:-}" == "--dry-run" ]]; then DRYRUN=true; fi

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG="/var/log/harden-linux-${TIMESTAMP}.log"
exec > >(tee -a "$LOG") 2>&1
echo "=== Linux Hardening Started: $TIMESTAMP ==="
echo "Dry-run: $DRYRUN"

run() { if $DRYRUN; then echo "[DRYRUN] $*"; else echo "[RUN] $*"; eval "$@"; fi; }

# 1️⃣ System Updates
run "apt-get update -y && apt-get upgrade -y"

# 2️⃣ Password Policies
run "sed -i -E 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs"
run "sed -i -E 's/^PASS_MIN_LEN.*/PASS_MIN_LEN\t12/' /etc/login.defs"

# 3️⃣ Lock root SSH login & enforce SSH best practices
run "sed -i -E 's/^#?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config"
run "sed -i -E 's/^#?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config"
run "sed -i -E 's/^#?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config"
run "systemctl restart sshd"

# 4️⃣ Install & enable Fail2Ban
run "apt-get install -y fail2ban || true"
run "systemctl enable --now fail2ban || true"

# 5️⃣ Configure UFW firewall
run "ufw default deny incoming"
run "ufw default allow outgoing"
run "ufw allow ssh"
run "ufw --force enable"

# 6️⃣ Disable unused network services
for svc in avahi-daemon cups rpcbind; do
  run "systemctl disable --now $svc || true"
done

# 7️⃣ Secure shared memory (protects against tmpfs exploits)
if ! grep -q "tmpfs /run/shm" /etc/fstab; then
  echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" | tee -a /etc/fstab
  run "mount -o remount /run/shm"
fi

# 8️⃣ Enable unattended security upgrades
run "apt-get install -y unattended-upgrades apt-listchanges"
run "dpkg-reconfigure -plow unattended-upgrades"

# 9️⃣ Apply kernel & network hardening (sysctl)
cat <<EOF >/etc/sysctl.d/99-hardening.conf
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_redirects=0
kernel.randomize_va_space=2
EOF
run "sysctl -p /etc/sysctl.d/99-hardening.conf"

# 🔟 Auditd (security logging)
run "apt-get install -y auditd audispd-plugins"
run "systemctl enable --now auditd"

# 1️⃣1️⃣ Rootkit detection
run "apt-get install -y rkhunter chkrootkit"
run "rkhunter --update"
run "rkhunter --propupd || true"

# 1️⃣2️⃣ File permissions cleanup
run "chmod 600 /boot/grub/grub.cfg || true"
run "chmod 640 /etc/shadow || true"
run "chmod 640 /etc/gshadow || true"

echo "=== Hardening Completed Successfully ==="
echo "Log saved to: $LOG"
echo "Consider rebooting to apply all kernel-level changes."
