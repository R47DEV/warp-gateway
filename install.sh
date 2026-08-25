#!/bin/bash

# ==========================================
# WARP Gateway Enterprise Installer & UI Setup
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
echo -e "${PURPLE}===================================================${NC}"
sleep 1

# 1. Dependency & Package Installation
log_info "Updating system packages and installing required dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt update -y || { log_warn "Apt update failed, attempting automatic fix..."; apt update --fix-missing -y; }

apt install -y curl gnupg lsb-release iptables python3 python3-pip iptables-persistent net-tools bsdextrautils bsdmainutils || {
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
iptables -C FORWARD -i CloudflareWARP -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i CloudflareWARP -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -C FORWARD -j ACCEPT 2>/dev/null || iptables -A FORWARD -j ACCEPT

netfilter-persistent save >/dev/null 2>&1 || log_warn "Minor warning during iptables persistence save."
log_success "Routing Network Firewall rules applied."

# 5. Python Flask Web UI & Dashboard Engine
log_info "Setting up Modern Web UI Environment..."
pip3 install flask >/dev/null 2>&1 || apt install -y python3-flask

mkdir -p /opt/warpgateway

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

cat << EOF > /opt/warpgateway/config.py
ADMIN_USER = "${UI_USER}"
ADMIN_PASS = "${UI_PASS}"
SECRET_KEY = "${GEN_KEY}"
EOF

# Create Application Source Code
cat << 'EOF' > /opt/warpgateway/app.py
import subprocess
import os
import json
from flask import Flask, render_template_string, request, redirect, url_for, session, jsonify
import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WARP Gateway Pro Control</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
        body { background: #0f172a; color: #f8fafc; display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; }
        .glass-card { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 20px; padding: 40px; width: 100%; max-width: 500px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); }
        h1 { font-size: 24px; font-weight: 700; margin-bottom: 8px; text-align: center; color: #38bdf8; }
        p.subtitle { text-align: center; color: #94a3b8; font-size: 14px; margin-bottom: 30px; }
        
        .status-badge { display: flex; align-items: center; justify-content: space-between; background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 16px; margin-bottom: 24px; }
        .status-indicator { display: flex; align-items: center; gap: 10px; font-weight: 600; font-size: 16px; }
        .dot { width: 12px; height: 12px; border-radius: 50%; }
        .dot.on { background: #22c55e; box-shadow: 0 0 10px #22c55e; }
        .dot.off { background: #ef4444; box-shadow: 0 0 10px #ef4444; }
        
        .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 24px; }
        .info-box { background: #0f172a; border-radius: 10px; padding: 12px; font-size: 13px; border: 1px solid #1e293b; }
        .info-box span { display: block; color: #64748b; font-size: 11px; margin-bottom: 4px; }
        .info-box strong { color: #e2e8f0; word-break: break-all; }

        .btn { width: 100%; padding: 14px; border: none; border-radius: 12px; font-weight: 600; font-size: 16px; cursor: pointer; transition: all 0.3s ease; text-decoration: none; display: block; text-align: center; margin-bottom: 12px; }
        .btn-connect { background: #0284c7; color: white; }
        .btn-connect:hover { background: #0369a1; }
        .btn-disconnect { background: #dc2626; color: white; }
        .btn-disconnect:hover { background: #b91c1c; }
        .btn-logout { background: transparent; color: #64748b; border: 1px solid #334155; font-size: 13px; padding: 8px; }
        .btn-logout:hover { color: #94a3b8; background: #1e293b; }

        .input-group { margin-bottom: 16px; }
        .input-group label { display: block; color: #94a3b8; font-size: 13px; margin-bottom: 6px; }
        .input-group input { width: 100%; padding: 12px; background: #0f172a; border: 1px solid #334155; border-radius: 10px; color: white; outline: none; }
        .input-group input:focus { border-color: #38bdf8; }
        .error-msg { color: #ef4444; font-size: 13px; text-align: center; margin-bottom: 12px; }
    </style>
</head>
<body>
    <div class="glass-card">
        <h1>WARP Sub-Router</h1>
        <p class="subtitle">Gateway Management Control Panel</p>

        {% if not session.get('logged_in') %}
            {% if error %}<div class="error-msg">{{ error }}</div>{% endif %}
            <form method="POST" action="/login">
                <div class="input-group">
                    <label>Admin Username</label>
                    <input type="text" name="username" required>
                </div>
                <div class="input-group">
                    <label>Password</label>
                    <input type="password" name="password" required>
                </div>
                <button type="submit" class="btn btn-connect">Secure Login</button>
            </form>
        {% else %}
            <div class="status-badge">
                <div class="status-indicator">
                    <div class="dot {{ 'on' if is_connected else 'off' }}"></div>
                    <span>{{ 'CONNECTED (ENCRYPTED)' if is_connected else 'DISCONNECTED (DIRECT)' }}</span>
                </div>
            </div>

            <div class="info-grid">
                <div class="info-box"><span>Gateway IP</span><strong>{{ gateway_ip }}</strong></div>
                <div class="info-box"><span>Public WAN IP</span><strong>{{ public_ip }}</strong></div>
            </div>

            {% if is_connected %}
                <a href="/toggle/off" class="btn btn-disconnect">Turn Off WARP Gateway</a>
            {% else %}
                <a href="/toggle/on" class="btn btn-connect">Turn On WARP Gateway</a>
            {% endif %}

            <a href="/logout" class="btn btn-logout">Logout System</a>
        {% endif %}
    </div>
</body>
</html>
"""

def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return res.stdout.strip()
    except Exception as e:
        return str(e)

def get_public_ip():
    return run_cmd("curl -s --max-time 3 https://api.ipify.org || echo 'Unknown'")

@app.route('/')
def home():
    if not session.get('logged_in'):
        return render_template_string(HTML_TEMPLATE, error=None)
    
    status_out = run_cmd("warp-cli --accept-tos status")
    is_connected = "Connected" in status_out
    pub_ip = get_public_ip()
    gw_ip = run_cmd("hostname -I | awk '{print $1}'")

    return render_template_string(HTML_TEMPLATE, is_connected=is_connected, public_ip=pub_ip, gateway_ip=gw_ip)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    if username == config.ADMIN_USER and password == config.ADMIN_PASS:
        session['logged_in'] = True
        return redirect(url_for('home'))
    return render_template_string(HTML_TEMPLATE, error="Invalid Username or Password!")

@app.route('/toggle/<action>')
def toggle(action):
    if not session.get('logged_in'):
        return redirect(url_for('home'))
    if action == "on":
        run_cmd("warp-cli --accept-tos connect")
    elif action == "off":
        run_cmd("warp-cli --accept-tos disconnect")
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
EOF

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
echo -e "${GREEN}===================================================${NC}"
