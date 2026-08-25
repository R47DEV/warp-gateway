#!/bin/bash

# ==========================================
# WARP Gateway Enterprise Installer & UI Setup
# developer : @R47DEV      Version : 1.0.1
# https://github.com/R47DEV/warp-gateway
# ==========================================

set -e

# Formatting & Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check root privilege
if [ "$EUID" -ne 0 ]; then
  log_error "This script must be run as root!"
  exit 1
fi

clear
echo -e "${PURPLE}===================================================${NC}"
echo -e "${PURPLE}   WARP Enterprise Gateway & UI Setup Script       ${NC}"
echo -e "${PURPLE}   Developer : @R47DEV      Version : 1.0.1       ${NC}"
echo -e "${PURPLE}   https://github.com/R47DEV/warp-gateway       ${NC}"
echo -e "${PURPLE}===================================================${NC}"
sleep 1

# 1. Dependency & Package Installation
log_info "Updating system packages and installing required dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt update -y || { log_warn "Apt update failed, attempting automatic fix..."; apt update --fix-missing -y; }

apt install -y curl gnupg lsb-release iptables iproute2 dnsutils python3 python3-pip iptables-persistent net-tools bsdextrautils bsdmainutils speedtest-cli conntrack || {
    log_error "Failed to install required dependencies."
    exit 1
}
log_success "Dependencies installed successfully."

# 2. Kernel IP Forwarding Setup
log_info "Configuring IPv4 Packet Forwarding..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null

if ! grep -q "^net.ipv4.ip_forward = 1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
fi
sysctl -p >/dev/null 2>&1 || log_warn "Minor warning during sysctl reload, continuing..."
log_success "IP Forwarding enabled successfully."

# 3. Cloudflare WARP Installation
log_info "Verifying Cloudflare Repository and GPG Key..."
mkdir -p /usr/share/keyrings

curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg || {
    log_error "Failed to download Cloudflare GPG Key! Check network connection."
    exit 1
}

echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ jammy main" | tee /etc/apt/sources.list.d/cloudflare-warp.list >/dev/null

log_info "Installing Cloudflare WARP package..."
apt update -y
apt install -y cloudflare-warp || {
    log_error "Cloudflare WARP installation failed!"
    exit 1
}

# WARP Self-Recovery Registration
log_info "Registering WARP Client..."
warp-cli --accept-tos registration new 2>/dev/null || warp-cli --accept-tos register 2>/dev/null || log_warn "WARP is already registered or in auto-recovery mode."
warp-cli --accept-tos mode warp 2>/dev/null || true
log_success "Cloudflare WARP Engine initialized."

# 4. NAT / Masquerade Routing Rules
log_info "Configuring IPTables Routing and NAT Rules..."
iptables -t nat -C POSTROUTING -o CloudflareWARP -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o CloudflareWARP -j MASQUERADE
DEFAULT_IFACE=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n 1)
if [ -n "$DEFAULT_IFACE" ] && [ "$DEFAULT_IFACE" != "CloudflareWARP" ]; then
    iptables -t nat -C POSTROUTING -o "$DEFAULT_IFACE" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$DEFAULT_IFACE" -j MASQUERADE
fi
iptables -t nat -C POSTROUTING -m addrtype ! --dst-type LOCAL -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -m addrtype ! --dst-type LOCAL -j MASQUERADE 2>/dev/null || true
iptables -C FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -C FORWARD -j ACCEPT 2>/dev/null || iptables -A FORWARD -j ACCEPT

netfilter-persistent save >/dev/null 2>&1 || log_warn "Minor warning during iptables persistence save."
log_success "Routing Network Firewall rules applied."

# 5. Python Flask Web UI & Dashboard Engine
log_info "Setting up Modern Web UI Environment..."
pip3 install flask werkzeug >/dev/null 2>&1 || apt install -y python3-flask

mkdir -p /opt/warpgateway

if [ -f /opt/warpgateway/credentials.json ] && [ -f /opt/warpgateway/config.py ]; then
    log_info "Existing installation detected. Preserving credentials & system settings..."
    EXISTING_USER=$(python3 -c "import json; print(json.load(open('/opt/warpgateway/credentials.json')).get('username', 'admin'))" 2>/dev/null || echo "admin")
    UI_USER="$EXISTING_USER"
    UI_PASS="[Unchanged - Existing Password Retained]"
else
    echo -e "${YELLOW}---------------------------------------------------${NC}"
    echo -e "${YELLOW}   Dashboard Admin Credentials Setup               ${NC}"
    echo -e "${YELLOW}---------------------------------------------------${NC}"

    # Generate Secure Random Fallback Credentials
    RANDOM_USER="admin_$(head -c 4 /dev/urandom | hexdump -e '4/1 "%02x"')"
    RANDOM_PASS="$(head -c 8 /dev/urandom | hexdump -e '8/1 "%02x"')"

    if [ -t 0 ]; then
        read -p "Enter Admin Username [Default: ${RANDOM_USER}]: " INPUT_USER
        UI_USER=${INPUT_USER:-$RANDOM_USER}

        read -sp "Enter Admin Password [Default: ${RANDOM_PASS}]: " INPUT_PASS
        echo ""
        UI_PASS=${INPUT_PASS:-$RANDOM_PASS}
    else
        log_warn "Non-interactive shell detected. Generated secure random credentials."
        UI_USER=$RANDOM_USER
        UI_PASS=$RANDOM_PASS
    fi

    GEN_KEY=$(head -c 16 /dev/urandom | hexdump -e '16/1 "%02x"' 2>/dev/null || echo "warp_default_secret_key_99")

    # config.py holds the Flask secret key
    cat << EOF > /opt/warpgateway/config.py
SECRET_KEY = "${GEN_KEY}"
EOF

    # Seed the credentials file with a securely hashed password.
    python3 - "$UI_USER" "$UI_PASS" << 'PYEOF'
import sys, json
from werkzeug.security import generate_password_hash

username, password = sys.argv[1], sys.argv[2]
data = {"username": username, "password_hash": generate_password_hash(password)}
with open("/opt/warpgateway/credentials.json", "w") as f:
    json.dump(data, f, indent=2)
PYEOF

    chmod 600 /opt/warpgateway/credentials.json
fi

# Create Application Source Code
# ---------------------------------------------------------------------------
# app.py is no longer embedded in this installer. It is pulled fresh from the
# official GitHub repository every time this script runs, so the dashboard
# always ships whatever is currently published in the repo. WARP_GATEWAY_REF
# can be exported before running this script to pin a specific branch/tag/
# commit (e.g. WARP_GATEWAY_REF=v1.2.0 ./install.sh); it defaults to "main".
# ---------------------------------------------------------------------------
WARP_GATEWAY_REPO="R47DEV/warp-gateway"
WARP_GATEWAY_REF="${WARP_GATEWAY_REF:-main}"
APP_PY_URL="https://raw.githubusercontent.com/${WARP_GATEWAY_REPO}/${WARP_GATEWAY_REF}/app.py"

log_info "Fetching latest app.py from ${WARP_GATEWAY_REPO}@${WARP_GATEWAY_REF}..."

# Always remove any previous copy first so a stale/broken file can never linger.
rm -f /opt/warpgateway/app.py

curl -fsSL "$APP_PY_URL" -o /opt/warpgateway/app.py || {
    log_error "Failed to download app.py from GitHub (${APP_PY_URL}). Check network connectivity or the repository/branch name."
    exit 1
}

# Sanity checks: make sure we actually received Python source and not an
# empty file, a GitHub 404 page, or a truncated download.
if [ ! -s /opt/warpgateway/app.py ]; then
    log_error "Downloaded app.py is empty. Aborting."
    exit 1
fi

if ! head -n 1 /opt/warpgateway/app.py | grep -q "^import\|^#!/usr/bin/env python"; then
    log_error "Downloaded app.py does not look like valid Python source (possibly an error page). Aborting."
    exit 1
fi

if ! python3 -m py_compile /opt/warpgateway/app.py 2>/dev/null; then
    log_error "Downloaded app.py failed Python syntax validation. Aborting."
    exit 1
fi
rm -rf /opt/warpgateway/__pycache__

log_success "app.py downloaded and validated ($(wc -l < /opt/warpgateway/app.py) lines)."

# 6. Systemd Self-Healing Service Setup
log_info "Configuring Auto-Start & Self-Healing Service..."

cat << EOF > /etc/systemd/system/warpgateway.service
[Unit]
Description=Enterprise WARP Gateway Service & Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/warpgateway
ExecStart=/usr/bin/python3 /opt/warpgateway/app.py
Restart=always
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable warpgateway >/dev/null 2>&1
systemctl restart warpgateway

IP_ADDR=$(hostname -I | awk '{print $1}')

echo -e "${GREEN}===================================================${NC}"
echo -e "${GREEN}      Installation Completed Successfully!        ${NC}"
echo -e "${GREEN}===================================================${NC}"
echo -e "${BLUE}Dashboard URL:${NC} http://${IP_ADDR}:8080"
echo -e "${BLUE}Username:${NC} ${UI_USER}"
echo -e "${BLUE}Password:${NC} ${UI_PASS}"
echo -e "${YELLOW}You can change these credentials any time from the Admin Settings page.${NC}"
echo -e "${GREEN}===================================================${NC}"
