#!/usr/bin/env bash
# One-time hardening + Docker install for a fresh Hetzner Cloud Ubuntu server (24.04+ / 26.04).
# Run as root:  bash server-setup.sh
#
# Safe for servers you currently reach with a root PASSWORD: SSH password login is
# only disabled when an SSH key is already installed, so you can never lock yourself out.
set -euo pipefail
DEPLOY_USER="${DEPLOY_USER:-kidguard}"
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get -y upgrade
apt-get install -y ca-certificates curl git ufw fail2ban unattended-upgrades

# Automatic security updates
dpkg-reconfigure -f noninteractive unattended-upgrades

# Docker Engine + Compose v2. Ubuntu's own packages support new releases on day one;
# fall back to Docker's official installer if they are unavailable.
if ! command -v docker >/dev/null 2>&1; then
  if ! apt-get install -y docker.io docker-compose-v2; then
    curl -fsSL https://get.docker.com | sh
  fi
fi
systemctl enable --now docker
docker compose version

# Non-root deploy user with Docker access
id "$DEPLOY_USER" >/dev/null 2>&1 || adduser --disabled-password --gecos "" "$DEPLOY_USER"
usermod -aG docker "$DEPLOY_USER"
install -d -m 755 -o "$DEPLOY_USER" -g "$DEPLOY_USER" /opt/kidguard

# Copy root's SSH keys (if any) to the deploy user
if [ -s /root/.ssh/authorized_keys ]; then
  install -d -m 700 -o "$DEPLOY_USER" -g "$DEPLOY_USER" "/home/$DEPLOY_USER/.ssh"
  install -m 600 -o "$DEPLOY_USER" -g "$DEPLOY_USER" /root/.ssh/authorized_keys "/home/$DEPLOY_USER/.ssh/authorized_keys"
  # Keys exist: turn off password logins (the #1 target of SSH brute force).
  cat > /etc/ssh/sshd_config.d/10-kidguard.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
EOF
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
  echo "SSH: key login only (password login disabled)."
else
  echo "WARNING: no SSH key installed for root. Password login left ON so you are not locked out."
  echo "         Add a key (see README step 2) and re-run this script to disable passwords."
fi

# Firewall: only SSH + HTTP(S). PostgreSQL and the AI service are never exposed.
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp
ufw --force enable

# Ban IPs that keep failing SSH logins
systemctl enable --now fail2ban

# 2 GB swap: needed on 2 GB servers for Docker image builds
if ! swapon --show | grep -q swapfile; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

echo
echo "Done. If the login banner said 'System restart required', run: reboot"
