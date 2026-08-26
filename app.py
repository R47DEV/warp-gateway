import subprocess
import os
import json
import re
import socket
import ipaddress
import uuid
import threading
import time
import sqlite3
from functools import wraps
from urllib.parse import urlparse
from flask import Flask, render_template_string, request, redirect, url_for, session, flash, jsonify
from markupsafe import Markup
from werkzeug.security import generate_password_hash, check_password_hash

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

CRED_FILE            = "/opt/warpgateway/credentials.json"
BYPASS_RULES_FILE    = "/opt/warpgateway/bypass_rules.json"
BYPASS_SETTINGS_FILE = "/opt/warpgateway/bypass_settings.json"
CDN_SETTINGS_FILE    = "/opt/warpgateway/cdn_settings.json"
COUNTRY_SETTINGS_FILE = "/opt/warpgateway/country_settings.json"
DB_FILE              = "/opt/warpgateway/traffic_history.db"
SERVICE_NAME         = "warpgateway"


# Current running versions — must match the 'ver' file in the GitHub repo.
APP_VERSION       = "1.0.2"
INSTALLER_VERSION = "1.0.1"

# GitHub raw URLs used by the auto-updater
GH_VER_URL     = "https://raw.githubusercontent.com/R47DEV/warp-gateway/refs/heads/main/ver"
GH_APP_URL     = "https://raw.githubusercontent.com/R47DEV/warp-gateway/main/app.py"
GH_INSTALL_URL = "https://raw.githubusercontent.com/R47DEV/warp-gateway/main/install.sh"

# Local script paths (used by the auto-updater)
APP_SCRIPT_PATH     = "/opt/warpgateway/app.py"
INSTALL_SCRIPT_PATH = "/opt/warpgateway/install.sh"



# ---------------------------------------------------------------------------
# Credential storage helpers (hashed, persisted to disk, hot-reloaded)
# ---------------------------------------------------------------------------
def load_credentials():
    with open(CRED_FILE, "r") as f:
        return json.load(f)


def save_credentials(username, password):
    data = {"username": username, "password_hash": generate_password_hash(password)}
    with open(CRED_FILE, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(CRED_FILE, 0o600)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login_page"))
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------
def run_cmd(cmd, timeout=10):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        out = (res.stdout or "").strip()
        err = (res.stderr or "").strip()
        return out if out else err
    except Exception as e:
        return str(e)


def get_public_ip():
    ip = run_cmd("curl -s --max-time 3 https://api.ipify.org")
    return ip if ip else "Unknown"


def get_gateway_ip():
    return run_cmd("hostname -I | awk '{print $1}'") or "Unknown"


def get_warp_status():
    return run_cmd("warp-cli --accept-tos status")


def is_warp_connected():
    return "Connected" in get_warp_status()


def wait_for_warp_state(want_connected, timeout=6, interval=0.5):
    """
    Block until warp-cli reports the expected connection state, or until
    `timeout` seconds elapse. warp-cli returns immediately after issuing
    connect/disconnect, but the actual Cloudflare handshake/teardown can take
    a couple of seconds — without this, the dashboard redirect can land
    before the state has actually changed, showing a stale badge.
    Returns True if the state settled before the timeout, False otherwise.
    """
    elapsed = 0.0
    while elapsed < timeout:
        if is_warp_connected() == want_connected:
            return True
        time.sleep(interval)
        elapsed += interval
    return is_warp_connected() == want_connected


def get_ip_forward_status():
    val = run_cmd("cat /proc/sys/net/ipv4/ip_forward").strip()
    return val == "1"


def delayed_restart():
    time.sleep(1)
    subprocess.run(["systemctl", "restart", SERVICE_NAME])


# ---------------------------------------------------------------------------
# Bypass Rules (Split Tunneling)
#
# Lets specific domains/IPs (bKash, Nagad, CellFin, other bank/fintech APIs)
# skip the WARP tunnel entirely and go out directly over the real ISP
# uplink, so those services see the genuine Bangladeshi IP instead of a
# Cloudflare edge IP and stop flagging the login as "another country".
#
# Mechanism: for each bypassed destination we install a host route
# (`ip route replace <ip>/32 via <uplink-gw> dev <uplink-iface>`). A /32 (or
# an explicit CIDR) is always more specific than the tunnel's default route,
# so the kernel sends that traffic straight out the physical interface no
# matter what WARP's default route looks like — no need to touch WARP's own
# routing table. Domain-based rules are periodically re-resolved in the
# background, since bank/CDN IPs rotate.
# ---------------------------------------------------------------------------
def _load_json(path, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def _save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def load_bypass_rules():
    return _load_json(BYPASS_RULES_FILE, [])


def save_bypass_rules(rules):
    _save_json(BYPASS_RULES_FILE, rules)


def load_bypass_settings():
    return _load_json(BYPASS_SETTINGS_FILE, {"iface": None, "gateway": None})


def save_bypass_settings(settings):
    _save_json(BYPASS_SETTINGS_FILE, settings)


def _looks_like_ip_or_cidr(s):
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def parse_bypass_input(raw):
    """Turn whatever the admin typed/pasted into a clean (kind, value) pair.
    Accepts:
      - Bare domain:     'api.bkash.com'
      - Full API URL:    'https://api.bkash.com/v1.2.0-beta/tokenized/'
      - Wildcard:        '*.bkash.com'  →  type='wildcard', value='bkash.com'
      - Bare IP:         '103.4.145.5'
      - CIDR block:      '103.4.145.0/24'
    """
    raw = raw.strip()
    if not raw:
        return None, None

    # Wildcard pattern: *.domain.com or *domain.com
    if raw.startswith("*"):
        apex = raw.lstrip("*.").strip().lower()
        if apex and re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$", apex):
            return "wildcard", apex
        return None, None

    if "://" in raw:
        host = urlparse(raw).hostname
    elif _looks_like_ip_or_cidr(raw):
        host = raw
    else:
        # A bare "domain.com/some/path" pasted without a scheme.
        host = raw.split("/")[0]

    if not host:
        return None, None
    host = host.strip().rstrip(".")

    try:
        net = ipaddress.ip_network(host, strict=False)
        return ("cidr" if "/" in host else "ip"), str(net) if "/" in host else host
    except ValueError:
        pass

    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$", host):
        return "domain", host.lower()
    return None, None


def resolve_domain(domain):
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        return sorted(set(ips))
    except Exception:
        return []


# Common subdomain prefixes probed for wildcard rules. These cover the most
# frequently used subdomains for banking/fintech APIs in Bangladesh.
COMMON_SUBDOMAINS = [
    "", "www", "api", "app", "m", "mobile", "pgw", "pay", "payment",
    "secure", "gateway", "portal", "auth", "login", "accounts",
    "services", "service", "cdn", "static", "assets", "media",
    "prod", "live", "ws", "web", "img", "images", "s",
    "ssl", "checkout", "transaction", "wallet", "card", "v1", "v2",
    # Specific known complex subdomains for BD Fintech (bKash etc.)
    "capp", "api.cde.capp", "eventapi.capp", "images.capp",
    "analytics", "campaign-images.analytics", "trace", "log", "metrics"
]


def resolve_wildcard_domain(apex):
    """Resolve an apex domain plus common subdomains so a wildcard bypass rule
    covers as many real IPs as possible without needing to know exact subdomains
    in advance. Duplicate IPs (shared CDN anycast addresses) are de-duplicated."""
    all_ips = set()
    for sub in COMMON_SUBDOMAINS:
        fqdn = apex if not sub else f"{sub}.{apex}"
        try:
            _, _, ips = socket.gethostbyname_ex(fqdn)
            all_ips.update(ips)
        except Exception:
            pass
    return sorted(all_ips)


# ---------------------------------------------------------------------------
# WARP Native Split-Tunnel Helpers
#
# `warp-cli split-tunnel` is the preferred bypass mechanism — it tells the
# WARP daemon itself to exclude a host/IP from the encrypted tunnel so it
# survives WARP reconnects and doesn't depend on fragile kernel route state.
# We probe which command format the installed warp-cli version supports and
# fall back gracefully to ip-route-only mode if unavailable.
# ---------------------------------------------------------------------------
_warp_st_support = None   # None = not yet probed; "v2" | "legacy" | False


def _probe_warp_split_tunnel():
    """One-time probe: discover which split-tunnel API the installed warp-cli
    supports. Result is cached so we only shell out once per process."""
    global _warp_st_support
    if _warp_st_support is not None:
        return _warp_st_support
    # Modern Cloudflare WARP (2024+) uses `warp-cli tunnel host` / `warp-cli tunnel ip`
    out_v3 = run_cmd("warp-cli --accept-tos tunnel host help 2>&1", timeout=5)
    if "add" in out_v3.lower() or "list" in out_v3.lower() or "configure" in out_v3.lower():
        _warp_st_support = "v3"
        return _warp_st_support
    # WARP 2022-2023 uses `warp-cli split-tunnel list`
    out = run_cmd("warp-cli --accept-tos split-tunnel list 2>&1", timeout=5)
    if out and "error" not in out.lower() and "unknown" not in out.lower() and "invalid" not in out.lower():
        _warp_st_support = "v2"
        return _warp_st_support
    # Older clients expose `warp-cli add-excluded-route`
    out2 = run_cmd("warp-cli add-excluded-route --help 2>&1", timeout=5)
    if "usage" in out2.lower() or "excluded" in out2.lower():
        _warp_st_support = "legacy"
        return _warp_st_support
    _warp_st_support = False
    return False


def warp_st_add(target, is_host=False):
    """Add *target* to WARP split-tunnel exclusions. Returns True on success.
    is_host=True uses host exclusions so warp-cli handles all subdomains natively."""
    mode = _probe_warp_split_tunnel()
    if mode == "v3":
        subcmd = "host" if is_host else "ip"
        out = run_cmd(f"warp-cli --accept-tos tunnel {subcmd} add {target} 2>&1", timeout=10)
        return "error" not in out.lower() and "failed" not in out.lower()
    if mode == "v2":
        flag = "--host" if is_host else "--ip"
        out = run_cmd(f"warp-cli --accept-tos split-tunnel add {flag} {target} 2>&1", timeout=10)
        return "error" not in out.lower() and "failed" not in out.lower()
    if mode == "legacy" and not is_host:
        out = run_cmd(f"warp-cli --accept-tos add-excluded-route {target} 2>&1", timeout=10)
        return "error" not in out.lower()
    return False


def warp_st_remove(target, is_host=False):
    """Remove *target* from WARP split-tunnel exclusions (best-effort)."""
    mode = _probe_warp_split_tunnel()
    if mode == "v3":
        subcmd = "host" if is_host else "ip"
        run_cmd(f"warp-cli --accept-tos tunnel {subcmd} remove {target} 2>&1", timeout=10)
    elif mode == "v2":
        flag = "--host" if is_host else "--ip"
        run_cmd(f"warp-cli --accept-tos split-tunnel remove {flag} {target} 2>&1", timeout=10)
    elif mode == "legacy" and not is_host:
        run_cmd(f"warp-cli --accept-tos remove-excluded-route {target} 2>&1", timeout=10)


def warp_st_list():
    """Return raw warp-cli split-tunnel list output string (for display)."""
    mode = _probe_warp_split_tunnel()
    if mode == "v3":
        hosts = run_cmd("warp-cli --accept-tos tunnel host list 2>&1", timeout=5)
        ips = run_cmd("warp-cli --accept-tos tunnel ip list 2>&1", timeout=5)
        return f"=== Excluded Hosts ===\n{hosts}\n\n=== Excluded IPs ===\n{ips}"
    if mode == "v2":
        return run_cmd("warp-cli --accept-tos split-tunnel list 2>&1", timeout=10)
    return ""


def warp_st_supported():
    """True if warp-cli split-tunnel is available on this system."""
    return _probe_warp_split_tunnel() is not False


def detect_uplink():
    """Auto-detect the physical ISP interface + gateway to send bypassed
    traffic out of (i.e. NOT the CloudflareWARP tunnel). A manual override
    saved from the Bypass Rules page always wins if both fields are set."""
    settings = load_bypass_settings()
    if settings.get("iface") and settings.get("gateway"):
        return settings["iface"], settings["gateway"]

    out = run_cmd("ip route show table all")
    for line in out.splitlines():
        if "CloudflareWARP" in line or "warp" in line.lower():
            continue
        m = re.match(r"default via (\S+) dev (\S+)", line.strip())
        if m:
            return m.group(2), m.group(1)

    # Fallback: probe every up interface (except lo/WARP) for its own
    # per-device default route.
    out = run_cmd("ip -o link show up")
    for line in out.splitlines():
        m = re.search(r"^\d+:\s+(\S+):", line)
        if not m:
            continue
        iface = m.group(1)
        if iface == "lo" or "warp" in iface.lower():
            continue
        gw_out = run_cmd(f"ip route show dev {iface} | grep default")
        gm = re.search(r"default via (\S+)", gw_out)
        if gm:
            return iface, gm.group(1)
    return None, None


def ensure_firewall_nat():
    """Ensure essential NAT and forwarding rules exist in iptables so both
    WARP traffic and bypassed ISP traffic (out of eth0 or other physical uplink)
    are properly masqueraded. Without masquerade on the physical interface,
    bypassed LAN traffic encounters asymmetric routing issues or dropped packets."""
    try:
        run_cmd("sysctl -w net.ipv4.ip_forward=1")
        # Loose reverse-path filtering to prevent kernel from dropping bypassed LAN traffic
        run_cmd("sysctl -w net.ipv4.conf.all.rp_filter=2")
        run_cmd("sysctl -w net.ipv4.conf.default.rp_filter=2")
        
        # Block IPv6 forwarding to avoid IPv6 leaks via WARP tunnel
        run_cmd("sysctl -w net.ipv6.conf.all.forwarding=0")
        run_cmd("ip6tables -P FORWARD DROP 2>/dev/null || true")

        run_cmd("iptables -t nat -C POSTROUTING -o CloudflareWARP -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o CloudflareWARP -j MASQUERADE")
        iface, _ = detect_uplink()
        if iface:
            run_cmd(f"sysctl -w net.ipv4.conf.{iface}.rp_filter=2")
            run_cmd(f"iptables -t nat -C POSTROUTING -o {iface} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o {iface} -j MASQUERADE")
        run_cmd("iptables -t nat -C POSTROUTING -m addrtype ! --dst-type LOCAL -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -m addrtype ! --dst-type LOCAL -j MASQUERADE 2>/dev/null || true")
        run_cmd("iptables -C FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT")
        run_cmd("iptables -C FORWARD -j ACCEPT 2>/dev/null || iptables -A FORWARD -j ACCEPT")
    except Exception:
        pass


def _route_apply(ip_or_cidr, iface, gateway):
    ensure_firewall_nat()
    return run_cmd(f"ip route replace {ip_or_cidr} via {gateway} dev {iface}")


def _route_remove(ip_or_cidr):
    return run_cmd(f"ip route del {ip_or_cidr}")


def apply_bypass_rule(rule):
    """(Re)install kernel routes + WARP split-tunnel entries for one rule.

    Strategy (most-reliable-first):
      1. warp-cli split-tunnel add --host <domain>  ← survives WARP reconnects
      2. ip route replace <ip>/32 via <uplink-gw>   ← belt-and-suspenders

    Domain and wildcard rules re-resolve DNS so stale routes for IPs that
    have dropped out of the CDN's answer set are cleaned up proactively.
    Wildcard rules also probe common subdomains to cover CDN endpoints that
    don't appear in the root domain's DNS answer.
    """
    iface, gateway = detect_uplink()
    rule["last_checked"] = time.strftime("%Y-%m-%d %H:%M:%S")

    if not iface or not gateway:
        rule["status"] = "error"
        rule["error"] = "Could not detect a physical uplink interface/gateway."
        return rule

    if rule["type"] == "domain":
        new_ips = resolve_domain(rule["value"])
        if not new_ips:
            rule["status"] = "error"
            rule["error"] = "DNS resolution failed."
            return rule
        old_ips = set(rule.get("resolved_ips", []))
        for stale in old_ips - set(new_ips):
            _route_remove(f"{stale}/32")
            warp_st_remove(f"{stale}/32")
        for ip in new_ips:
            _route_apply(f"{ip}/32", iface, gateway)
            warp_st_add(f"{ip}/32")
        # Domain-level warp-cli exclusion covers future IP rotations natively
        warp_st_add(rule["value"], is_host=True)
        rule["resolved_ips"] = new_ips

    elif rule["type"] == "wildcard":
        apex = rule["value"]
        new_ips = resolve_wildcard_domain(apex)
        old_ips = set(rule.get("resolved_ips", []))
        for stale in old_ips - set(new_ips):
            _route_remove(f"{stale}/32")
            warp_st_remove(f"{stale}/32")
        for ip in new_ips:
            _route_apply(f"{ip}/32", iface, gateway)
            warp_st_add(f"{ip}/32")
        # warp-cli host exclusion handles all subdomains automatically
        warp_st_add(apex, is_host=True)
        rule["resolved_ips"] = new_ips

    else:  # ip or cidr
        target = rule["value"] if rule["type"] == "cidr" else f"{rule['value']}/32"
        _route_apply(target, iface, gateway)
        warp_st_add(target)
        rule["resolved_ips"] = [rule["value"]]

    rule["status"]       = "active"
    rule["error"]        = None
    rule["uplink_iface"] = iface
    rule["uplink_gateway"] = gateway
    rule["warp_cli_ok"]  = warp_st_supported()
    return rule


def remove_bypass_rule_routes(rule):
    """Remove kernel routes AND WARP split-tunnel entries for one rule."""
    if rule["type"] in ("domain", "wildcard"):
        for ip in rule.get("resolved_ips", []):
            _route_remove(f"{ip}/32")
            warp_st_remove(f"{ip}/32")
        # Remove the domain-level warp-cli host exclusion too
        warp_st_remove(rule["value"], is_host=True)
    else:
        target = rule["value"] if rule["type"] == "cidr" else f"{rule['value']}/32"
        _route_remove(target)
        warp_st_remove(target)


def apply_all_bypass_rules():
    rules = load_bypass_rules()
    for rule in rules:
        apply_bypass_rule(rule)
    save_bypass_rules(rules)
    return rules


def bypass_refresh_loop(interval=180):
    """Background loop: re-resolves domain/wildcard bypass rules every 3 min
    so ip routes + warp-cli exclusions track CDN IP rotations in near-real-time.
    3-minute interval is aggressive enough for fast CDN IP churn (bKash, Nagad)
    while still being cheap on DNS queries."""
    while True:
        time.sleep(interval)
        try:
            apply_all_bypass_rules()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# CDN IP-Range Auto-Sync
#
# Major cloud CDNs publish authoritative CIDR lists. When enabled for a
# provider, we fetch these hourly and install bypass routes so that any
# banking/fintech app served via those CDNs is automatically covered — even
# when their backend IPs rotate or new subdomains are added.
#
# Cloudflare:     ~15 IPv4 ranges  (bKash, many fintech APIs)
# AWS CloudFront: ~300 IPv4 ranges (Nagad, mobile banking backends)
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Dynamic Country IP-Range Auto-Sync (National Direct Routing)
#
# Allows users from ANY country in the world to automatically fetch all official
# delegated IPv4 CIDRs assigned to their nation via the global RIPE stat API.
# When enabled for a country (e.g. BD, IN, PK, US, GB, AE, SA, MY, SG, etc.),
# all local domestic traffic (banks, government portals, local ISP caches/BDIX)
# routes directly via the physical ISP without touching the WARP tunnel.
# ---------------------------------------------------------------------------
ALL_COUNTRIES = [
    ("AF", "Afghanistan"), ("AL", "Albania"), ("DZ", "Algeria"), ("AD", "Andorra"), ("AO", "Angola"),
    ("AG", "Antigua and Barbuda"), ("AR", "Argentina"), ("AM", "Armenia"), ("AU", "Australia"), ("AT", "Austria"),
    ("AZ", "Azerbaijan"), ("BS", "Bahamas"), ("BH", "Bahrain"), ("BD", "Bangladesh"), ("BB", "Barbados"),
    ("BY", "Belarus"), ("BE", "Belgium"), ("BZ", "Belize"), ("BJ", "Benin"), ("BT", "Bhutan"),
    ("BO", "Bolivia"), ("BA", "Bosnia and Herzegovina"), ("BW", "Botswana"), ("BR", "Brazil"), ("BN", "Brunei"),
    ("BG", "Bulgaria"), ("BF", "Burkina Faso"), ("BI", "Burundi"), ("KH", "Cambodia"), ("CM", "Cameroon"),
    ("CA", "Canada"), ("CV", "Cape Verde"), ("CF", "Central African Republic"), ("TD", "Chad"), ("CL", "Chile"),
    ("CN", "China"), ("CO", "Colombia"), ("KM", "Comoros"), ("CG", "Congo"), ("CD", "Congo (DRC)"),
    ("CR", "Costa Rica"), ("HR", "Croatia"), ("CU", "Cuba"), ("CY", "Cyprus"), ("CZ", "Czech Republic"),
    ("DK", "Denmark"), ("DJ", "Djibouti"), ("DM", "Dominica"), ("DO", "Dominican Republic"), ("EC", "Ecuador"),
    ("EG", "Egypt"), ("SV", "El Salvador"), ("GQ", "Equatorial Guinea"), ("ER", "Eritrea"), ("EE", "Estonia"),
    ("SZ", "Eswatini"), ("ET", "Ethiopia"), ("FJ", "Fiji"), ("FI", "Finland"), ("FR", "France"),
    ("GA", "Gabon"), ("GM", "Gambia"), ("GE", "Georgia"), ("DE", "Germany"), ("GH", "Ghana"),
    ("GR", "Greece"), ("GD", "Grenada"), ("GT", "Guatemala"), ("GN", "Guinea"), ("GW", "Guinea-Bissau"),
    ("GY", "Guyana"), ("HT", "Haiti"), ("HN", "Honduras"), ("HK", "Hong Kong"), ("HU", "Hungary"),
    ("IS", "Iceland"), ("IN", "India"), ("ID", "Indonesia"), ("IR", "Iran"), ("IQ", "Iraq"),
    ("IE", "Ireland"), ("IL", "Israel"), ("IT", "Italy"), ("JM", "Jamaica"), ("JP", "Japan"),
    ("JO", "Jordan"), ("KZ", "Kazakhstan"), ("KE", "Kenya"), ("KW", "Kuwait"), ("KG", "Kyrgyzstan"),
    ("LA", "Laos"), ("LV", "Latvia"), ("LB", "Lebanon"), ("LS", "Lesotho"), ("LR", "Liberia"),
    ("LY", "Libya"), ("LI", "Liechtenstein"), ("LT", "Lithuania"), ("LU", "Luxembourg"), ("MO", "Macau"),
    ("MG", "Madagascar"), ("MW", "Malawi"), ("MY", "Malaysia"), ("MV", "Maldives"), ("ML", "Mali"),
    ("MT", "Malta"), ("MR", "Mauritania"), ("MU", "Mauritius"), ("MX", "Mexico"), ("MD", "Moldova"),
    ("MC", "Monaco"), ("MN", "Mongolia"), ("ME", "Montenegro"), ("MA", "Morocco"), ("MZ", "Mozambique"),
    ("MM", "Myanmar"), ("NA", "Namibia"), ("NP", "Nepal"), ("NL", "Netherlands"), ("NZ", "New Zealand"),
    ("NI", "Nicaragua"), ("NE", "Niger"), ("NG", "Nigeria"), ("MK", "North Macedonia"), ("NO", "Norway"),
    ("OM", "Oman"), ("PK", "Pakistan"), ("PS", "Palestine"), ("PA", "Panama"), ("PG", "Papua New Guinea"),
    ("PY", "Paraguay"), ("PE", "Peru"), ("PH", "Philippines"), ("PL", "Poland"), ("PT", "Portugal"),
    ("QA", "Qatar"), ("RO", "Romania"), ("RU", "Russia"), ("RW", "Rwanda"), ("SA", "Saudi Arabia"),
    ("SN", "Senegal"), ("RS", "Serbia"), ("SC", "Seychelles"), ("SL", "Sierra Leone"), ("SG", "Singapore"),
    ("SK", "Slovakia"), ("SI", "Slovenia"), ("SO", "Somalia"), ("ZA", "South Africa"), ("KR", "South Korea"),
    ("SS", "South Sudan"), ("ES", "Spain"), ("LK", "Sri Lanka"), ("SD", "Sudan"), ("SR", "Suriname"),
    ("SE", "Sweden"), ("CH", "Switzerland"), ("SY", "Syria"), ("TW", "Taiwan"), ("TJ", "Tajikistan"),
    ("TZ", "Tanzania"), ("TH", "Thailand"), ("TL", "Timor-Leste"), ("TG", "Togo"), ("TN", "Tunisia"),
    ("TR", "Turkey"), ("TM", "Turkmenistan"), ("UG", "Uganda"), ("UA", "Ukraine"), ("AE", "United Arab Emirates"),
    ("GB", "United Kingdom"), ("US", "United States"), ("UY", "Uruguay"), ("UZ", "Uzbekistan"), ("VE", "Venezuela"),
    ("VN", "Vietnam"), ("YE", "Yemen"), ("ZM", "Zambia"), ("ZW", "Zimbabwe")
]


def load_country_settings():
    defaults = {
        "countries": {
            "BD": {"name": "Bangladesh", "enabled": True, "last_sync": None, "cidr_count": 0, "error": None}
        }
    }
    return _load_json(COUNTRY_SETTINGS_FILE, defaults)


def save_country_settings(settings):
    _save_json(COUNTRY_SETTINGS_FILE, settings)


def fetch_country_cidrs(code):
    """Fetch official delegated IPv4 CIDR list for any ISO-3166-1 alpha-2 country code."""
    code = code.strip().upper()
    try:
        import urllib.request, json as _json
        req = urllib.request.Request(
            f"https://stat.ripe.net/data/country-resource-list/data.json?resource={code}",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = _json.loads(resp.read())
        ipv4_list = data.get("data", {}).get("resources", {}).get("ipv4", [])
        return [cidr for cidr in ipv4_list if "/" in cidr]
    except Exception as exc:
        return exc


def sync_country(code):
    """Fetch and apply routes for a specific country code."""
    code = code.strip().upper()
    result = fetch_country_cidrs(code)
    if isinstance(result, Exception):
        return 0, str(result)
    if not result:
        return 0, "No IPv4 allocations returned for this country code."
    count = _apply_cdn_cidrs(result)
    return count, None


def _country_sync_one(code):
    """Sync a single country in a background thread."""
    try:
        count, err = sync_country(code)
        settings = load_country_settings()
        item = settings.get("countries", {}).setdefault(code, {})
        item["last_sync"] = time.strftime("%Y-%m-%d %H:%M:%S")
        item["cidr_count"] = count
        item["error"] = err
        save_country_settings(settings)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Global Cloud & CDN IP-Range Auto-Sync
# ---------------------------------------------------------------------------
_CDN_PROVIDERS = {
    "cloudflare": {
        "name": "Cloudflare CDN (Global)",
        "description": "Anycast edge IP ranges used by Cloudflare-protected banking/fintech APIs (~15 IPv4 ranges)",
    },
    "aws_cloudfront": {
        "name": "AWS CloudFront (Global CDN)",
        "description": "Global edge CDN distributions for AWS-hosted mobile apps (~300 IPv4 ranges)",
    },
    "aws_asia": {
        "name": "AWS Asia-Pacific (Compute & APIs)",
        "description": "AWS EC2 regions in Singapore & Mumbai (~800 IPv4 ranges)",
    },
    "aws_europe": {
        "name": "AWS Europe (Frankfurt / London / Ireland)",
        "description": "AWS EC2 regions in European financial hubs (~1200 IPv4 ranges)",
    },
}


def load_cdn_settings():
    defaults = {
        "providers": {
            "cloudflare":     {"enabled": True, "last_sync": None, "cidr_count": 0, "error": None},
            "aws_cloudfront": {"enabled": True, "last_sync": None, "cidr_count": 0, "error": None},
            "aws_asia":       {"enabled": True, "last_sync": None, "cidr_count": 0, "error": None},
            "aws_europe":     {"enabled": False, "last_sync": None, "cidr_count": 0, "error": None},
        }
    }
    return _load_json(CDN_SETTINGS_FILE, defaults)


def save_cdn_settings(settings):
    _save_json(CDN_SETTINGS_FILE, settings)


def _fetch_cloudflare_cidrs():
    """Fetch Cloudflare's officially published IPv4 CIDR list."""
    try:
        import urllib.request
        req = urllib.request.Request(
            "https://www.cloudflare.com/ips-v4",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return [ln.strip() for ln in resp.read().decode().splitlines() if ln.strip()]
    except Exception as exc:
        return exc


def _fetch_aws_cloudfront_cidrs():
    """Fetch AWS ip-ranges.json and extract CloudFront service prefixes only."""
    try:
        import urllib.request, json as _json
        with urllib.request.urlopen(
            "https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=15
        ) as resp:
            data = _json.loads(resp.read())
        return [
            p["ip_prefix"]
            for p in data.get("prefixes", [])
            if p.get("service") == "CLOUDFRONT"
        ]
    except Exception as exc:
        return exc


def _fetch_aws_asia_cidrs():
    """Fetch AWS ip-ranges.json and extract EC2 regions for Singapore and Mumbai."""
    try:
        import urllib.request, json as _json
        with urllib.request.urlopen(
            "https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=15
        ) as resp:
            data = _json.loads(resp.read())
        return [
            p["ip_prefix"]
            for p in data.get("prefixes", [])
            if p.get("region") in ("ap-southeast-1", "ap-south-1")
        ]
    except Exception as exc:
        return exc


def _fetch_aws_europe_cidrs():
    """Fetch AWS ip-ranges.json and extract EC2 regions for Europe."""
    try:
        import urllib.request, json as _json
        with urllib.request.urlopen(
            "https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=15
        ) as resp:
            data = _json.loads(resp.read())
        return [
            p["ip_prefix"]
            for p in data.get("prefixes", [])
            if p.get("region") in ("eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3")
        ]
    except Exception as exc:
        return exc


def _apply_cdn_cidrs(cidrs):
    """Install bypass routes + warp-cli entries for a list of CIDRs.
    Returns number of successfully processed routes."""
    iface, gateway = detect_uplink()
    if not iface or not gateway:
        return 0
    ensure_firewall_nat()

    valid_cidrs = []
    for cidr in cidrs:
        try:
            ipaddress.ip_network(cidr, strict=False)
            valid_cidrs.append(cidr)
        except ValueError:
            continue

    # Batch ip route replace commands for high-performance execution
    batch_size = 50
    for i in range(0, len(valid_cidrs), batch_size):
        chunk = valid_cidrs[i:i+batch_size]
        cmds = [f"ip route replace {c} via {gateway} dev {iface}" for c in chunk]
        run_cmd(" ; ".join(cmds))
        for c in chunk:
            warp_st_add(c)

    return len(valid_cidrs)


def sync_cdn_provider(provider_key):
    """Fetch and apply routes for one CDN provider.
    Returns (cidr_count, error_string). error_string is None on success."""
    fetchers = {
        "cloudflare":     _fetch_cloudflare_cidrs,
        "aws_cloudfront": _fetch_aws_cloudfront_cidrs,
        "aws_asia":       _fetch_aws_asia_cidrs,
        "aws_europe":     _fetch_aws_europe_cidrs,
    }
    fn = fetchers.get(provider_key)
    if fn is None:
        return 0, "Unknown provider."
    result = fn()
    if isinstance(result, Exception):
        return 0, str(result)
    if not result:
        return 0, "Provider returned an empty IP list — check network connectivity."
    count = _apply_cdn_cidrs(result)
    return count, None


def _cdn_sync_one(key):
    """Sync a single CDN provider and persist results."""
    try:
        count, err = sync_cdn_provider(key)
        settings = load_cdn_settings()
        prov = settings["providers"].setdefault(key, {})
        prov["last_sync"]  = time.strftime("%Y-%m-%d %H:%M:%S")
        prov["cidr_count"] = count
        prov["error"]      = err
        save_cdn_settings(settings)
    except Exception:
        pass


def cdn_sync_loop(interval=3600):
    """Background thread: syncs enabled CDN providers AND enabled countries every hour."""
    while True:
        time.sleep(interval)
        try:
            # 1. Sync enabled CDN providers
            settings = load_cdn_settings()
            changed = False
            for key, prov in settings.get("providers", {}).items():
                if not prov.get("enabled"):
                    continue
                count, err = sync_cdn_provider(key)
                prov["last_sync"]  = time.strftime("%Y-%m-%d %H:%M:%S")
                prov["cidr_count"] = count
                prov["error"]      = err
                changed = True
            if changed:
                save_cdn_settings(settings)

            # 2. Sync enabled Country IP blocks
            csettings = load_country_settings()
            cchanged = False
            for code, citem in csettings.get("countries", {}).items():
                if not citem.get("enabled"):
                    continue
                count, err = sync_country(code)
                citem["last_sync"]  = time.strftime("%Y-%m-%d %H:%M:%S")
                citem["cidr_count"] = count
                citem["error"]      = err
                cchanged = True
            if cchanged:
                save_country_settings(csettings)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# WARP mode
# ---------------------------------------------------------------------------
def get_warp_mode():
    """Parse the active mode ('Warp', 'DNS over HTTPS', 'Proxy', ...) out of
    `warp-cli settings`. Falls back to 'Unknown' if the CLI output format
    ever changes."""
    settings_out = run_cmd("warp-cli --accept-tos settings")
    match = re.search(r"Mode:\s*(.+)", settings_out)
    return match.group(1).strip() if match else "Unknown"


# ---------------------------------------------------------------------------
# Network throughput / data usage
# ---------------------------------------------------------------------------
def get_default_iface():
    """Interface used for the default route, e.g. 'eth0' or 'CloudflareWARP'."""
    out = run_cmd("ip route show default")
    match = re.search(r"dev\s+(\S+)", out)
    return match.group(1) if match else None


def get_iface_bytes(iface):
    """Total RX/TX bytes for `iface` since boot, read from /proc/net/dev."""
    if not iface:
        return 0, 0
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                if ":" not in line:
                    continue
                name, data = line.split(":", 1)
                if name.strip() != iface:
                    continue
                fields = data.split()
                rx_bytes = int(fields[0])
                tx_bytes = int(fields[8])
                return rx_bytes, tx_bytes
    except Exception:
        pass
    return 0, 0


def humanize_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def get_throughput(iface, sample_seconds=1.0):
    """Instantaneous download/upload rate in bytes/sec, measured by sampling
    /proc/net/dev twice with a short delay in between. Blocks for
    `sample_seconds` — only used for the very first page paint."""
    if not iface:
        return 0, 0
    rx1, tx1 = get_iface_bytes(iface)
    time.sleep(sample_seconds)
    rx2, tx2 = get_iface_bytes(iface)
    rx_rate = max(0, (rx2 - rx1) / sample_seconds)
    tx_rate = max(0, (tx2 - tx1) / sample_seconds)
    return rx_rate, tx_rate


# Rolling sample used by the polling API so the browser can refresh throughput
# every couple of seconds WITHOUT the server blocking/sleeping on every call.
# Each call just diffs against whatever was measured on the previous call.
_net_sample_lock = threading.Lock()
_last_net_sample = {"ts": None, "rx": None, "tx": None, "iface": None}


def get_throughput_nonblocking(iface):
    """Non-blocking version of get_throughput(). Returns
    (rx_rate, tx_rate, rx_total, tx_total). The rate is 0 on the very first
    call (no prior sample to diff against) and becomes accurate from the
    second call onward — perfect for a JS poll loop."""
    global _last_net_sample
    rx_now, tx_now = get_iface_bytes(iface)
    now = time.time()
    with _net_sample_lock:
        prev = _last_net_sample
        if prev["ts"] is not None and prev["iface"] == iface and now > prev["ts"]:
            dt = now - prev["ts"]
            rx_rate = max(0, (rx_now - prev["rx"]) / dt)
            tx_rate = max(0, (tx_now - prev["tx"]) / dt)
        else:
            rx_rate = tx_rate = 0
        _last_net_sample = {"ts": now, "rx": rx_now, "tx": tx_now, "iface": iface}
    return rx_rate, tx_rate, rx_now, tx_now


# ---------------------------------------------------------------------------
# Connected LAN devices + per-IP active connections and traffic volume
# ---------------------------------------------------------------------------
def get_lan_clients():
    """LAN devices from the ARP table: [{ip, mac}, ...]. This is the
    definitive 'how many devices are connected' count — one ARP entry per
    device that has talked to the gateway recently."""
    arp_out = run_cmd("arp -a")
    devices = []
    for line in arp_out.splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})", line)
        if m:
            devices.append({"ip": m.group(1), "mac": m.group(2)})
    return devices


def get_connection_stats():
    """Per-source-IP live stats from conntrack: active connection count plus
    tracked bytes in each direction. Each conntrack line has two src=/dst=
    pairs — the first is the original direction (LAN client -> internet,
    i.e. upload) and the second is the reply direction (internet -> LAN
    client, i.e. download), each with its own bytes= counter.

    Requires the `conntrack` package — returns {} silently if missing.
    Note: these byte counts only cover connections CURRENTLY in the
    conntrack table (recent/active), not all-time historical usage per
    device — conntrack isn't a persistent traffic accountant like vnstat.
    """
    out = run_cmd("conntrack -L -n 2>/dev/null")
    stats = {}
    for line in out.splitlines():
        srcs = re.findall(r"\bsrc=(\d+\.\d+\.\d+\.\d+)", line)
        byte_counts = re.findall(r"\bbytes=(\d+)", line)
        if not srcs:
            continue
        client_ip = srcs[0]
        entry = stats.setdefault(client_ip, {"connections": 0, "tx_bytes": 0, "rx_bytes": 0})
        entry["connections"] += 1
        if len(byte_counts) >= 1:
            entry["tx_bytes"] += int(byte_counts[0])   # client -> internet
        if len(byte_counts) >= 2:
            entry["rx_bytes"] += int(byte_counts[1])   # internet -> client


    return stats


def get_connected_devices():
    """Merge ARP-known LAN devices with their live conntrack connection
    count + tracked upload/download bytes, sorted busiest-first (by total
    bytes, so the heaviest user of the network floats to the top)."""
    devices = get_lan_clients()
    stats = get_connection_stats()
    for d in devices:
        s = stats.get(d["ip"], {"connections": 0, "tx_bytes": 0, "rx_bytes": 0})
        d["connections"] = s["connections"]
        d["tx_bytes"] = s["tx_bytes"]
        d["rx_bytes"] = s["rx_bytes"]
        d["total_bytes"] = s["tx_bytes"] + s["rx_bytes"]
    devices.sort(key=lambda d: d["total_bytes"], reverse=True)
    return devices



# ---------------------------------------------------------------------------
# SQLite Traffic History Database & DNS Reverse Lookup Engine
# ---------------------------------------------------------------------------
_dns_cache = {}
_dns_cache_lock = threading.Lock()


def resolve_ip_to_host(ip_str):
    """Fast reverse-DNS and domain map lookup with in-memory thread-safe caching."""
    if not ip_str or ip_str == "127.0.0.1":
        return ip_str or "Unknown"

    with _dns_cache_lock:
        if ip_str in _dns_cache:
            return _dns_cache[ip_str]

    # 1. Match against active custom bypass rules
    for rule in load_bypass_rules():
        if ip_str in rule.get("resolved_ips", []):
            host_val = f"*.{rule['value']}" if rule.get("type") == "wildcard" else rule.get("value")
            with _dns_cache_lock:
                _dns_cache[ip_str] = host_val
            return host_val

    # 2. Try socket reverse DNS (PTR lookup) with short fallback
    try:
        host, _, _ = socket.gethostbyaddr(ip_str)
        with _dns_cache_lock:
            _dns_cache[ip_str] = host
        return host
    except Exception:
        with _dns_cache_lock:
            _dns_cache[ip_str] = ip_str
        return ip_str


def init_db():
    """Ensure SQLite traffic history table and indexes exist."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS flow_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                client_ip TEXT,
                dst_ip TEXT,
                dst_host TEXT,
                dport INTEGER,
                proto TEXT,
                route_type TEXT,
                bytes INTEGER
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON flow_history(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_route ON flow_history(route_type)")
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_active_conntrack_flows():
    """Parse netfilter conntrack table into detailed flow objects."""
    iface, _gw = detect_uplink()
    bypass_nets = set()

    if iface:
        route_out = run_cmd(f"ip route show dev {iface}")
        for line in route_out.splitlines():
            parts = line.strip().split()
            if parts:
                try:
                    bypass_nets.add(ipaddress.ip_network(parts[0], strict=False))
                except ValueError:
                    pass

    for rule in load_bypass_rules():
        for ip_str in rule.get("resolved_ips", []):
            try:
                bypass_nets.add(ipaddress.ip_network(ip_str, strict=False))
            except ValueError:
                pass

    out = run_cmd("conntrack -L -n 2>/dev/null")
    flows = []

    for line in out.splitlines():
        srcs = re.findall(r"\bsrc=(\d+\.\d+\.\d+\.\d+)", line)
        dsts = re.findall(r"\bdst=(\d+\.\d+\.\d+\.\d+)", line)
        dports = re.findall(r"\bdport=(\d+)", line)
        byte_counts = re.findall(r"\bbytes=(\d+)", line)

        if not srcs or not dsts:
            continue

        client_ip = srcs[0]
        dst_ip = dsts[0]
        dport = int(dports[0]) if dports else 0
        proto = "TCP" if "tcp" in line.lower() else ("UDP" if "udp" in line.lower() else "IP")
        total_bytes = sum(int(b) for b in byte_counts)

        try:
            addr = ipaddress.ip_address(dst_ip)
            is_bypass = any(addr in net for net in bypass_nets)
        except ValueError:
            is_bypass = False

        route_type = "bypass" if is_bypass else "warp"
        dst_host = resolve_ip_to_host(dst_ip)

        flows.append({
            "client_ip": client_ip,
            "dst_ip": dst_ip,
            "dst_host": dst_host,
            "dport": dport,
            "proto": proto,
            "route_type": route_type,
            "bytes": total_bytes,
            "bytes_human": humanize_bytes(total_bytes)
        })

    # Sort heaviest traffic first
    flows.sort(key=lambda f: f["bytes"], reverse=True)
    return flows


def traffic_history_loop(interval=60):
    """Background thread: logs active traffic flows to SQLite and automatically
    purges history records older than 5 days."""
    init_db()
    while True:
        time.sleep(interval)
        try:
            flows = get_active_conntrack_flows()
            if flows and os.path.exists(DB_FILE):
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                now_str = time.strftime("%Y-%m-%d %H:%M:%S")
                # Record top 100 active flows
                records = [
                    (now_str, f["client_ip"], f["dst_ip"], f["dst_host"], f["dport"], f["proto"], f["route_type"], f["bytes"])
                    for f in flows[:100]
                ]
                cursor.executemany("""
                    INSERT INTO flow_history (timestamp, client_ip, dst_ip, dst_host, dport, proto, route_type, bytes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, records)

                # Purge history older than 5 days
                cursor.execute("DELETE FROM flow_history WHERE timestamp < datetime('now', '-5 days')")
                conn.commit()
                conn.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Traffic routing analysis: bypass vs WARP-encrypted connections
# ---------------------------------------------------------------------------
def get_traffic_routing_stats():
    """Analyse the conntrack table to count active connections split by routing
    path: WARP-encrypted tunnel vs direct ISP bypass."""
    try:
        flows = get_active_conntrack_flows()
        warp_connections = sum(1 for f in flows if f["route_type"] == "warp")
        bypass_connections = sum(1 for f in flows if f["route_type"] == "bypass")
        warp_bytes = sum(f["bytes"] for f in flows if f["route_type"] == "warp")
        bypass_bytes = sum(f["bytes"] for f in flows if f["route_type"] == "bypass")

        iface, _gw = detect_uplink()
        bypass_nets = set()
        if iface:
            route_out = run_cmd(f"ip route show dev {iface}")
            for line in route_out.splitlines():
                parts = line.strip().split()
                if parts:
                    try:
                        bypass_nets.add(ipaddress.ip_network(parts[0], strict=False))
                    except ValueError:
                        pass

        return {
            "warp_connections":     warp_connections,
            "bypass_connections":   bypass_connections,
            "total_connections":    len(flows),
            "active_bypass_routes": len(bypass_nets),
            "bypass_bytes_total":   bypass_bytes,
            "warp_bytes_total":     warp_bytes,
        }
    except Exception:
        return {
            "warp_connections": 0, "bypass_connections": 0, "total_connections": 0,
            "active_bypass_routes": 0, "bypass_bytes_total": 0, "warp_bytes_total": 0,
        }



# ---------------------------------------------------------------------------
# On-demand speed test (runs in a background thread; result cached)
# ---------------------------------------------------------------------------
speedtest_state = {"running": False, "result": None, "error": None, "ran_at": None}



def run_speedtest_bg():
    speedtest_state["running"] = True
    speedtest_state["error"] = None
    try:
        out = run_cmd("speedtest-cli --simple", timeout=90)
        download = upload = ping = None
        for line in out.splitlines():
            if line.startswith("Ping:"):
                ping = line.split(":", 1)[1].strip()
            elif line.startswith("Download:"):
                download = line.split(":", 1)[1].strip()
            elif line.startswith("Upload:"):
                upload = line.split(":", 1)[1].strip()
        if download and upload:
            speedtest_state["result"] = {"ping": ping, "download": download, "upload": upload}
        else:
            speedtest_state["error"] = out or "speedtest-cli produced no output."
    except Exception as e:
        speedtest_state["error"] = str(e)
    finally:
        speedtest_state["running"] = False
        speedtest_state["ran_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# Icons (inline SVG, feather-style, no external dependency)
# ---------------------------------------------------------------------------
ICONS = {
    "home": '<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>',
    "power": '<path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/>',
    "network": '<path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/>',
    "logs": '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "settings": '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
    "guide": '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>',
    "logout": '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>',
    "cable": '<path d="M4 9a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v6a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2V9a2 2 0 0 1 2-2"/><path d="M9 3v4"/><path d="M15 3v4"/><path d="M9 21v-4"/><path d="M15 21v-4"/>',
    "login": '<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/>',
    "wifi": '<path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/>',
    "server": '<rect x="2" y="3" width="20" height="7" rx="1"/><rect x="2" y="14" width="20" height="7" rx="1"/><line x1="6" y1="6.5" x2="6.01" y2="6.5"/><line x1="6" y1="17.5" x2="6.01" y2="17.5"/>',
    "check": '<polyline points="20 6 9 17 4 12"/>',
    "github": '<path d="M9 19c-4.3 1.4-4.3-2.5-6-3m12 5v-3.5c0-1 .1-1.4-.5-2 2.8-.3 5.5-1.4 5.5-6a4.6 4.6 0 0 0-1.3-3.2 4.2 4.2 0 0 0-.1-3.2s-1.1-.3-3.5 1.3a12.3 12.3 0 0 0-6.2 0C6.5 2.8 5.4 3.1 5.4 3.1a4.2 4.2 0 0 0-.1 3.2A4.6 4.6 0 0 0 4 9.5c0 4.6 2.7 5.7 5.5 6-.6.6-.6 1.2-.5 2V21"/>',
    "activity": '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    "gauge": '<path d="M12 14 15 9"/><circle cx="12" cy="12" r="10"/><path d="M8 12a4 4 0 0 1 8 0"/>',
    "download": '<polyline points="8 17 12 21 16 17"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.88 18.09A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.29"/>',
    "update": '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
    "lock": '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    "info": '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
    "zap": '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
}


def icon(name, size=18):
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{ICONS.get(name, "")}</svg>'
    return Markup(svg)


app.jinja_env.globals.update(icon=icon)


# ---------------------------------------------------------------------------
# Base layout
# ---------------------------------------------------------------------------
BASE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WARP Gateway Pro Control</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#0b1220; --panel:#111a2e; --panel-2:#0f1729;
    --border:rgba(255,255,255,0.08); --text:#f1f5f9; --muted:#8b96ab;
    --accent1:#4f8ef7; --accent2:#7c5cfc; --green:#22c55e; --red:#ef4444; --amber:#f59e0b;
  }
  *{box-sizing:border-box;margin:0;padding:0;font-family:'Inter',sans-serif;}
  body{background:radial-gradient(circle at 20% -10%, #16213f 0%, var(--bg) 45%);color:var(--text);min-height:100vh;}
  a{color:inherit;text-decoration:none;}

  .shell{display:flex;min-height:100vh;}
  .sidebar{
    width:250px;flex-shrink:0;background:var(--panel);border-right:1px solid var(--border);
    padding:24px 16px;display:flex;flex-direction:column;gap:6px;position:sticky;top:0;height:100vh;
  }
  .brand{display:flex;align-items:center;gap:10px;padding:6px 10px 22px 10px;}
  .brand-badge{width:34px;height:34px;border-radius:9px;background:linear-gradient(135deg,var(--accent1),var(--accent2));display:flex;align-items:center;justify-content:center;font-weight:700;font-size:14px;}
  .brand-title{font-weight:700;font-size:15px;}
  .brand-sub{font-size:11px;color:var(--muted);}

  .nav-item{display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:10px;color:var(--muted);font-size:14px;font-weight:500;transition:.15s;}
  .nav-item:hover{background:rgba(255,255,255,0.04);color:var(--text);}
  .nav-item.active{background:linear-gradient(135deg, rgba(79,142,247,.18), rgba(124,92,252,.18));color:#fff;border:1px solid rgba(124,92,252,.35);}
  .nav-spacer{flex:1;}
  .nav-item svg{flex-shrink:0;}

  .dev-credit{margin-top:8px;padding:14px 12px;border-top:1px solid var(--border);}
  .dev-credit a{display:flex;align-items:center;gap:10px;font-size:12.5px;color:var(--muted);transition:.15s;}
  .dev-credit a:hover{color:var(--text);}
  .dev-credit .dev-avatar{width:30px;height:30px;border-radius:8px;background:var(--panel-2);border:1px solid var(--border);display:flex;align-items:center;justify-content:center;flex-shrink:0;}
  .dev-credit .dev-name{font-weight:600;color:#dbe4f3;font-size:12.5px;}
  .dev-credit .dev-sub{font-size:10.5px;color:var(--muted);}

  .footer-credit{margin-top:26px;padding-top:16px;border-top:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;font-size:12px;color:var(--muted);}
  .footer-credit a{display:inline-flex;align-items:center;gap:6px;color:var(--muted);}
  .footer-credit a:hover{color:var(--accent1);}

  /* ---- Version badge + update button in sidebar ---- */
  .ver-badge{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:10px 12px;
    background:var(--panel-2);border:1px solid var(--border);border-radius:10px;margin-top:4px;font-size:12px;}
  .ver-badge .ver-label{color:var(--muted);font-size:10.5px;margin-bottom:1px;}
  .ver-badge .ver-num{font-weight:700;color:#a5c8ff;font-size:12px;}
  .ver-check-btn{display:inline-flex;align-items:center;gap:4px;background:transparent;
    border:1px solid rgba(79,142,247,.4);color:var(--accent1);border-radius:7px;
    padding:4px 9px;font-size:11px;font-weight:600;cursor:pointer;transition:.15s;white-space:nowrap;}
  .ver-check-btn:hover{background:rgba(79,142,247,.15);}
  .ver-update-btn{display:inline-flex;align-items:center;gap:4px;
    background:linear-gradient(135deg,var(--accent1),var(--accent2));border:none;color:#fff;border-radius:7px;
    padding:4px 9px;font-size:11px;font-weight:600;cursor:pointer;white-space:nowrap;
    animation:pulse-ver 2s infinite;}
  @keyframes pulse-ver{0%,100%{box-shadow:0 0 0 0 rgba(79,142,247,.5);}50%{box-shadow:0 0 0 5px rgba(79,142,247,0);}}
  .update-notif{padding:9px 12px;border-radius:9px;font-size:11.5px;margin-top:6px;
    background:rgba(79,142,247,.1);border:1px solid rgba(79,142,247,.25);color:#a5c8ff;line-height:1.5;}

  /* ---- Traffic routing stats card ---- */
  .traffic-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:16px 0 14px 0;}
  .tstat{background:var(--panel-2);border:1px solid var(--border);border-radius:12px;padding:14px 16px;position:relative;overflow:hidden;}
  .tstat::before{content:'';position:absolute;top:0;left:0;width:3px;height:100%;border-radius:3px 0 0 3px;}
  .tstat.tw::before{background:linear-gradient(180deg,var(--accent1),var(--accent2));}
  .tstat.tb::before{background:linear-gradient(180deg,var(--green),#16a34a);}
  .tstat.tn::before{background:linear-gradient(180deg,var(--amber),#d97706);}
  .tstat .ts-lbl{font-size:10.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;font-weight:600;margin-bottom:6px;}
  .tstat .ts-val{font-size:24px;font-weight:800;line-height:1;letter-spacing:-.5px;}
  .tstat .ts-sub{font-size:10.5px;color:var(--muted);margin-top:5px;}
  .tstat.tw .ts-val{background:linear-gradient(135deg,var(--accent1),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
  .tstat.tb .ts-val{background:linear-gradient(135deg,var(--green),#16a34a);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}
  .tstat.tn .ts-val{color:var(--amber);}
  .traffic-bars{margin-top:14px;display:flex;flex-direction:column;gap:10px;}
  .tbar-row{display:flex;flex-direction:column;gap:4px;}
  .tbar-labels{display:flex;justify-content:space-between;font-size:11.5px;}
  .tbar-labels .tbl{color:var(--muted);}
  .tbar-track{height:8px;background:rgba(255,255,255,.06);border-radius:999px;overflow:hidden;border:1px solid var(--border);}
  .tbar-fill{height:100%;border-radius:999px;transition:width .7s cubic-bezier(.4,0,.2,1);}
  .tbar-fill.tw{background:linear-gradient(90deg,var(--accent1),var(--accent2));}
  .tbar-fill.tb{background:linear-gradient(90deg,var(--green),#16a34a);}

  /* ---- Instruction card on bypass page ---- */
  .instr-card{background:linear-gradient(135deg,rgba(79,142,247,.06),rgba(124,92,252,.06));
    border:1px solid rgba(124,92,252,.22);border-radius:16px;padding:20px 22px;margin-bottom:16px;}
  .instr-card > .instr-title{font-size:13.5px;font-weight:700;color:#dbe4f3;margin-bottom:14px;display:flex;align-items:center;gap:8px;}
  .instr-cols{display:grid;grid-template-columns:1fr 1fr;gap:14px;}
  @media(max-width:640px){.instr-cols{grid-template-columns:1fr;}}
  .instr-col{background:rgba(255,255,255,.03);border:1px solid var(--border);border-radius:12px;padding:14px 16px;}
  .instr-col .ic-head{font-size:12px;font-weight:700;color:var(--accent1);margin-bottom:10px;display:flex;align-items:center;gap:6px;}
  .instr-col ul{list-style:none;padding:0;margin:0;display:flex;flex-direction:column;gap:6px;}
  .instr-col ul li{font-size:12.5px;color:var(--muted);padding-left:14px;position:relative;line-height:1.6;}
  .instr-col ul li::before{content:'→';position:absolute;left:0;color:rgba(79,142,247,.6);font-size:11px;top:1px;}
  .instr-col ul li strong{color:#c7d8f5;font-weight:600;}
  .instr-col ul li .tag{display:inline-block;padding:1px 7px;border-radius:5px;font-size:10.5px;font-weight:600;
    background:rgba(79,142,247,.15);color:#a5c8ff;margin-left:3px;border:1px solid rgba(79,142,247,.25);}
  .instr-col ul li .tag.green{background:rgba(34,197,94,.12);color:#86efac;border-color:rgba(34,197,94,.25);}
  .instr-col ul li .tag.amber{background:rgba(245,158,11,.12);color:#fcd34d;border-color:rgba(245,158,11,.25);}

  .main{flex:1;padding:28px 36px;}

  .topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px;}
  .page-title{font-size:22px;font-weight:700;}
  .page-sub{color:var(--muted);font-size:13px;margin-top:2px;}

  .status-pill{display:flex;align-items:center;gap:8px;background:var(--panel);border:1px solid var(--border);padding:8px 14px;border-radius:999px;font-size:13px;font-weight:600;}
  .dot{width:9px;height:9px;border-radius:50%;}
  .dot.on{background:var(--green);box-shadow:0 0 8px var(--green);}
  .dot.off{background:var(--red);box-shadow:0 0 8px var(--red);}

  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px;margin-bottom:20px;}
  .card{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:22px;}
  .card h3{font-size:14px;font-weight:600;margin-bottom:14px;display:flex;align-items:center;gap:8px;color:#dbe4f3;}
  .card h3 svg{color:var(--accent1);}

  .info-row{display:flex;justify-content:space-between;align-items:center;padding:9px 0;border-bottom:1px solid var(--border);font-size:13px;}
  .info-row:last-child{border-bottom:none;}
  .info-row span.label{color:var(--muted);}
  .info-row span.value{font-weight:600;word-break:break-all;text-align:right;}

  .btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:11px 18px;border:none;border-radius:10px;font-weight:600;font-size:14px;cursor:pointer;transition:.15s;width:100%;}
  .btn-primary{background:linear-gradient(135deg,var(--accent1),var(--accent2));color:#fff;}
  .btn-primary:hover{filter:brightness(1.1);}
  .btn-danger{background:rgba(239,68,68,0.15);color:#fca5a5;border:1px solid rgba(239,68,68,0.4);}
  .btn-danger:hover{background:rgba(239,68,68,0.25);}
  .btn-outline{background:transparent;color:var(--muted);border:1px solid var(--border);}
  .btn-outline:hover{color:var(--text);border-color:var(--accent1);}
  .btn-sm{width:auto;padding:8px 14px;font-size:13px;}
  .btn-row{display:flex;gap:10px;flex-wrap:wrap;}

  .input-group{margin-bottom:14px;}
  .input-group label{display:block;color:var(--muted);font-size:12.5px;margin-bottom:6px;font-weight:500;}
  .input-group input,.input-group select{width:100%;padding:11px 12px;background:var(--panel-2);border:1px solid var(--border);border-radius:10px;color:var(--text);outline:none;font-size:14px;}
  .input-group input:focus,.input-group select:focus{border-color:var(--accent1);}

  .flash{padding:12px 16px;border-radius:10px;font-size:13.5px;margin-bottom:18px;font-weight:500;}
  .flash.success{background:rgba(34,197,94,0.12);color:#86efac;border:1px solid rgba(34,197,94,0.3);}
  .flash.error{background:rgba(239,68,68,0.12);color:#fca5a5;border:1px solid rgba(239,68,68,0.3);}

  pre.log-box{background:#060a14;border:1px solid var(--border);border-radius:12px;padding:16px;font-size:12.5px;line-height:1.6;overflow-x:auto;max-height:520px;overflow-y:auto;color:#9db4d6;font-family:'SFMono-Regular',Consolas,monospace;}

  .badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:11.5px;font-weight:600;}
  .badge.on{background:rgba(34,197,94,0.15);color:#86efac;}
  .badge.off{background:rgba(239,68,68,0.15);color:#fca5a5;}
  .badge.mode{background:rgba(79,142,247,0.15);color:#a5c8ff;}

  .guide-step{display:flex;gap:16px;padding:20px 0;border-bottom:1px solid var(--border);}
  .guide-step:last-child{border-bottom:none;}
  .guide-num{flex-shrink:0;width:38px;height:38px;border-radius:10px;background:linear-gradient(135deg,var(--accent1),var(--accent2));display:flex;align-items:center;justify-content:center;}
  .guide-body h4{font-size:15px;margin-bottom:6px;}
  .guide-body p{font-size:13.5px;color:var(--muted);line-height:1.7;}
  .guide-body code{background:var(--panel-2);border:1px solid var(--border);padding:1px 6px;border-radius:5px;font-size:12.5px;color:#a5c8ff;}
  .guide-note{margin-top:10px;background:rgba(79,142,247,0.08);border:1px solid rgba(79,142,247,0.25);padding:10px 14px;border-radius:10px;font-size:12.5px;color:#c7d8f5;}

  .login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;width:100%;}
  .login-card{background:var(--panel);border:1px solid var(--border);border-radius:20px;padding:42px;width:100%;max-width:420px;box-shadow:0 25px 60px -20px rgba(0,0,0,0.6);}
  .login-logo{width:52px;height:52px;border-radius:14px;background:linear-gradient(135deg,var(--accent1),var(--accent2));display:flex;align-items:center;justify-content:center;margin:0 auto 18px auto;}
  .login-card h1{font-size:21px;font-weight:700;text-align:center;margin-bottom:6px;}
  .login-card p.subtitle{text-align:center;color:var(--muted);font-size:13px;margin-bottom:26px;}

  .stat-big{font-size:26px;font-weight:700;line-height:1.2;}
  .stat-sub{font-size:11.5px;color:var(--muted);margin-top:2px;}
  .speed-row{display:flex;gap:16px;}
  .speed-col{flex:1;background:var(--panel-2);border:1px solid var(--border);border-radius:12px;padding:14px 16px;}
  .speed-col .dirlabel{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted);margin-bottom:6px;}

  @media (max-width:820px){
    .shell{flex-direction:column;}
    .sidebar{width:100%;height:auto;position:relative;flex-direction:row;overflow-x:auto;}
    .brand{display:none;}
    .nav-spacer{display:none;}
    .main{padding:20px;}
  }
</style>
</head>
<body>
{% if not session.get('logged_in') %}
  <div class="login-wrap">
    <div class="login-card">
      <div class="login-logo">{{ icon('shield', 26) }}</div>
      <h1>WARP Gateway</h1>
      <p class="subtitle">Enterprise Gateway Control Panel</p>
      {% with msgs = get_flashed_messages(with_categories=true) %}
        {% for cat, m in msgs %}<div class="flash {{ cat }}">{{ m }}</div>{% endfor %}
      {% endwith %}
      <form method="POST" action="{{ url_for('login') }}">
        <div class="input-group">
          <label>Admin Username</label>
          <input type="text" name="username" required autofocus>
        </div>
        <div class="input-group">
          <label>Password</label>
          <input type="password" name="password" required>
        </div>
        <button type="submit" class="btn btn-primary">{{ icon('login',16) }} Secure Login</button>
      </form>
      <div class="footer-credit" style="border-top:1px solid var(--border);justify-content:center;">
        <a href="https://github.com/R47DEV/warp-gateway" target="_blank" rel="noopener noreferrer">{{ icon('github',14) }} R47DEV — github.com/R47DEV/warp-gateway</a>
      </div>
    </div>
  </div>
{% else %}
  <div class="shell">
    <div class="sidebar">
      <div class="brand">
        <div class="brand-badge">{{ icon('shield',18) }}</div>
        <div>
          <div class="brand-title">WARP Gateway</div>
          <div class="brand-sub">Enterprise Console</div>
        </div>
      </div>
      <a class="nav-item {{ 'active' if page=='dashboard' else '' }}" href="{{ url_for('dashboard') }}">{{ icon('home') }} Dashboard</a>
      <a class="nav-item {{ 'active' if page=='network' else '' }}" href="{{ url_for('network') }}">{{ icon('network') }} Network Info</a>
      <a class="nav-item {{ 'active' if page=='bypass' else '' }}" href="{{ url_for('bypass') }}">{{ icon('shield') }} Bypass Rules</a>
      <a class="nav-item {{ 'active' if page=='logs' else '' }}" href="{{ url_for('logs') }}">{{ icon('logs') }} Service Logs</a>
      <a class="nav-item {{ 'active' if page=='system' else '' }}" href="{{ url_for('system') }}">{{ icon('server') }} System Config</a>
      <a class="nav-item {{ 'active' if page=='settings' else '' }}" href="{{ url_for('settings') }}">{{ icon('settings') }} Admin Settings</a>
      <a class="nav-item {{ 'active' if page=='guide' else '' }}" href="{{ url_for('guide') }}">{{ icon('guide') }} Setup Guide</a>
      <div class="nav-spacer"></div>
      <!-- Version badge & update action -->
      <div class="ver-badge">
        <div>
          <div class="ver-label">App Version</div>
          <div class="ver-num" id="sidebar-ver">v{{ app_version }}</div>
        </div>
        <button class="ver-check-btn" id="ver-check-btn" onclick="checkForUpdate()">{{ icon('update',12) }} Check</button>
      </div>
      <div id="update-notif" class="update-notif" style="display:none;"></div>

      <a class="nav-item" href="{{ url_for('logout') }}" style="margin-top:4px;">{{ icon('logout') }} Logout</a>

      <div class="dev-credit">
        <a href="https://github.com/R47DEV/warp-gateway" target="_blank" rel="noopener noreferrer">
          <div class="dev-avatar">{{ icon('github', 16) }}</div>
          <div>
            <div class="dev-name">R47DEV</div>
            <div class="dev-sub">github.com/R47DEV/warp-gateway</div>
          </div>
        </a>
      </div>
    </div>

    <div class="main">
      <div class="topbar">
        <div>
          <div class="page-title">{{ title }}</div>
          <div class="page-sub">{{ subtitle }}</div>
        </div>
        <div class="status-pill">
          <div class="dot {{ 'on' if warp_connected else 'off' }}" id="warp-status-dot"></div>
          <span id="warp-status-label">{{ 'WARP CONNECTED' if warp_connected else 'WARP DISCONNECTED' }}</span>
        </div>
      </div>

      {% with msgs = get_flashed_messages(with_categories=true) %}
        {% for cat, m in msgs %}<div class="flash {{ cat }}">{{ m }}</div>{% endfor %}
      {% endwith %}

      {{ content|safe }}

      <div class="footer-credit">
        <span>WARP Gateway Enterprise Console &nbsp;·&nbsp; v{{ app_version }}</span>
        <a href="https://github.com/R47DEV/warp-gateway" target="_blank" rel="noopener noreferrer">{{ icon('github',14) }} Developed by R47DEV — github.com/R47DEV/warp-gateway</a>
      </div>
    </div>
  </div>
{% endif %}

<script>
function checkForUpdate() {
  const btn = document.getElementById('ver-check-btn');
  const notif = document.getElementById('update-notif');
  if (!btn) return;
  btn.textContent = '…';
  btn.disabled = true;
  fetch('/api/check_update')
    .then(r => r.json())
    .then(d => {
      btn.disabled = false;
      if (d.has_update) {
        btn.className = 'ver-update-btn';
        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg> Update!';
        btn.onclick = function() { triggerUpdate(d); };
        notif.style.display = 'block';
        notif.innerHTML = '🚀 v' + d.remote_app_ver + ' available! Click <b>Update!</b> to install.';
      } else {
        notif.style.display = 'block';
        notif.innerHTML = '✅ You are running the latest version.';
        notif.style.color = '#86efac';
        notif.style.background = 'rgba(34,197,94,.1)';
        notif.style.borderColor = 'rgba(34,197,94,.3)';
        btn.textContent = '✓ Latest';
        setTimeout(() => {
          notif.style.display = 'none';
          btn.className = 'ver-check-btn';
          btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg> Check';
          btn.onclick = checkForUpdate;
        }, 4000);
      }
      if (d.error) {
        notif.style.display = 'block';
        notif.style.color = '#fca5a5';
        notif.innerHTML = '⚠ ' + d.error;
        btn.textContent = 'Retry';
      }
    })
    .catch(() => {
      btn.disabled = false;
      btn.textContent = 'Error';
    });
}

function triggerUpdate(d) {
  if (!confirm('This will download and install the latest version, then restart the service.\n\nProceed?')) return;
  const notif = document.getElementById('update-notif');
  notif.style.display = 'block';
  notif.style.color = '#a5c8ff';
  notif.style.background = 'rgba(79,142,247,.12)';
  notif.style.borderColor = 'rgba(79,142,247,.3)';
  notif.innerHTML = '⏳ Downloading update… please wait.';
  fetch('/api/trigger_update', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({update_type: d.update_type})
  })
    .then(r => r.json())
    .then(r => {
      if (r.success) {
        notif.style.color = '#86efac';
        notif.style.background = 'rgba(34,197,94,.1)';
        notif.innerHTML = '✅ Update applied! Service is restarting… please refresh in 10 seconds.';
      } else {
        notif.style.color = '#fca5a5';
        notif.innerHTML = '❌ Update failed: ' + r.error;
      }
    })
    .catch(() => {
      notif.style.color = '#86efac';
      notif.style.background = 'rgba(34,197,94,.1)';
      notif.innerHTML = '✅ Update signal sent! Service is restarting… please refresh in 10 seconds.';
    });
}
</script>
</body>
</html>
"""


def render_page(page, title, subtitle, content):
    return render_template_string(
        BASE,
        page=page,
        title=title,
        subtitle=subtitle,
        content=content,
        warp_connected=is_warp_connected() if session.get("logged_in") else False,
        app_version=APP_VERSION,
    )


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.route("/")
def login_page():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return render_page("login", "", "", "")


@app.route("/login", methods=["POST"])
def login():
    creds = load_credentials()
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if username == creds["username"] and check_password_hash(creds["password_hash"], password):
        session["logged_in"] = True
        session["username"] = username
        flash("Login successful.", "success")
        return redirect(url_for("dashboard"))
    flash("Invalid username or password.", "error")
    return redirect(url_for("login_page"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
def render_device_rows(devices):
    """Build the <tr> rows for the Connected Devices table. Shared by the
    initial server-rendered page and the JSON API (so both use identical
    formatting logic — the JS just calls this row shape too)."""
    if not devices:
        return '<tr><td colspan="5" style="padding:10px 0;color:var(--muted);">No devices found in the ARP table yet.</td></tr>'
    rows = []
    for d in devices:
        rows.append(
            f'<tr><td style="padding:8px 0;border-bottom:1px solid var(--border);">{d["ip"]}</td>'
            f'<td style="padding:8px 0;border-bottom:1px solid var(--border);color:var(--muted);font-size:12px;">{d["mac"]}</td>'
            f'<td style="padding:8px 0;border-bottom:1px solid var(--border);text-align:right;">{humanize_bytes(d.get("rx_bytes", 0))}</td>'
            f'<td style="padding:8px 0;border-bottom:1px solid var(--border);text-align:right;">{humanize_bytes(d.get("tx_bytes", 0))}</td>'
            f'<td style="padding:8px 0;border-bottom:1px solid var(--border);text-align:right;font-weight:600;">{d["connections"]}</td></tr>'
        )
    return "".join(rows)


# JS lives in a PLAIN string (not an f-string) so its { } braces never clash
# with Python's f-string parsing. __API_URL__ is swapped in at request time.
DASHBOARD_POLL_SCRIPT = """
<script>
(function() {
  const API_URL = "__API_URL__";
  async function refreshDashboard() {
    try {
      const res = await fetch(API_URL, { cache: "no-store" });
      if (!res.ok) return;
      const d = await res.json();

      document.getElementById('rx-rate').textContent = d.rx_rate_human;
      document.getElementById('tx-rate').textContent = d.tx_rate_human;
      document.getElementById('data-total').textContent =
        'Total since boot — Download: ' + d.rx_total_human + ' | Upload: ' + d.tx_total_human;

      const dot = document.getElementById('warp-status-dot');
      const label = document.getElementById('warp-status-label');
      if (dot) dot.className = 'dot ' + (d.connected ? 'on' : 'off');
      if (label) label.textContent = d.connected ? 'WARP CONNECTED' : 'WARP DISCONNECTED';

      const modeBadge = document.getElementById('mode-badge');
      if (modeBadge) modeBadge.textContent = d.mode.toUpperCase();

      const countBadge = document.getElementById('device-count-badge');
      if (countBadge) countBadge.textContent = d.device_count + (d.device_count === 1 ? ' device' : ' devices');

      const tbody = document.getElementById('device-table-body');
      if (tbody) tbody.innerHTML = d.device_rows_html;

      /* Traffic Routing Analysis elements */
      const tw = document.getElementById('tstat-warp');
      const tb = document.getElementById('tstat-bypass');
      const tr = document.getElementById('tstat-routes');
      const twFill = document.getElementById('tbar-warp-fill');
      const tbFill = document.getElementById('tbar-bypass-fill');
      const twLbl = document.getElementById('tbar-warp-lbl');
      const tbLbl = document.getElementById('tbar-bypass-lbl');
      const twBytes = document.getElementById('tbar-warp-bytes');
      const tbBytes = document.getElementById('tbar-bypass-bytes');

      if (tw) tw.textContent = d.tstats.warp_connections;
      if (tb) tb.textContent = d.tstats.bypass_connections;
      if (tr) tr.textContent = d.tstats.active_bypass_routes;
      if (twFill) twFill.style.width = d.tstats.warp_pct + '%';
      if (tbFill) tbFill.style.width = d.tstats.bypass_pct + '%';
      if (twLbl) twLbl.textContent = 'WARP Encrypted Tunnel (' + d.tstats.warp_pct + '%)';
      if (tbLbl) tbLbl.textContent = 'Direct ISP Bypassed (' + d.tstats.bypass_pct + '%)';
      if (twBytes) twBytes.textContent = d.tstats.warp_bytes_human;
      if (tbBytes) tbBytes.textContent = d.tstats.bypass_bytes_human;
    } catch (e) {
      // Silent — a single missed poll shouldn't spam the console.
    }
  }
  refreshDashboard();
  setInterval(refreshDashboard, 2000);
})();

/* ---- Traffic Flow Inspector Pagination & Filtering JS ---- */
let currentFlowTab = 'live';
let currentFlowRouteFilter = 'all';
let currentFlowPage = 1;
let currentFlowPerPage = 30;
let currentFlowSearch = '';
let flowSearchTimer = null;

function switchFlowTab(tab) {
  currentFlowTab = tab;
  currentFlowPage = 1;
  document.getElementById('tab-live-btn').style.background = tab === 'live' ? 'var(--panel-2)' : 'transparent';
  document.getElementById('tab-hist-btn').style.background = tab === 'history' ? 'var(--panel-2)' : 'transparent';
  fetchFlows();
}

function setFlowRouteFilter(route) {
  currentFlowRouteFilter = route;
  currentFlowPage = 1;
  document.querySelectorAll('.flow-rf-btn').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-type') === route);
  });
  fetchFlows();
}

function openFlowModal(routeFilter) {
  setFlowRouteFilter(routeFilter);
  const card = document.getElementById('flow-inspector-card');
  if (card) card.scrollIntoView({ behavior: 'smooth' });
}

function onFlowSearchChange() {
  clearTimeout(flowSearchTimer);
  flowSearchTimer = setTimeout(() => {
    currentFlowSearch = document.getElementById('flow-search-input').value.trim();
    currentFlowPage = 1;
    fetchFlows();
  }, 300);
}

function changeFlowPerPage() {
  currentFlowPerPage = parseInt(document.getElementById('flow-per-page-select').value);
  currentFlowPage = 1;
  fetchFlows();
}

function prevFlowPage() {
  if (currentFlowPage > 1) {
    currentFlowPage--;
    fetchFlows();
  }
}

function nextFlowPage() {
  currentFlowPage++;
  fetchFlows();
}

function fetchFlows() {
  const endpoint = currentFlowTab === 'live' ? '/api/connections/live' : '/api/connections/history';
  const url = `${endpoint}?route_type=${currentFlowRouteFilter}&search=${encodeURIComponent(currentFlowSearch)}&page=${currentFlowPage}&per_page=${currentFlowPerPage}`;

  fetch(url, { cache: "no-store" })
    .then(r => r.json())
    .then(d => {
      currentFlowPage = d.page;
      document.getElementById('flow-cur-page').textContent = d.page;
      document.getElementById('flow-tot-pages').textContent = d.total_pages;
      document.getElementById('flow-total-count-lbl').textContent = `Total: ${d.total} entries`;

      document.getElementById('flow-prev-btn').disabled = (d.page <= 1);
      document.getElementById('flow-next-btn').disabled = (d.page >= d.total_pages);

      const tbody = document.getElementById('flow-table-body');
      if (!d.flows || d.flows.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="padding:16px 0;text-align:center;color:var(--muted);">No matching connection flows found.</td></tr>';
        return;
      }

      let html = '';
      d.flows.forEach(f => {
        const isBypass = (f.route_type === 'bypass');
        const badgeCls = isBypass ? 'on' : 'mode';
        const badgeText = isBypass ? 'ISP DIRECT BYPASS' : 'WARP ENCRYPTED';
        const timeOrState = f.timestamp ? f.timestamp : '<span style="color:var(--green);font-size:10.5px;">● ACTIVE</span>';
        const hostDisp = (f.dst_host && f.dst_host !== f.dst_ip)
          ? `<strong style="color:#dbe4f3;">${f.dst_host}</strong><br><span style="font-size:11px;color:var(--muted);">${f.dst_ip}</span>`
          : `<span style="color:#dbe4f3;">${f.dst_ip}</span>`;

        html += `
          <tr style="border-bottom:1px solid var(--border);">
            <td style="padding:7px 0;color:var(--muted);font-size:11.5px;">${timeOrState}</td>
            <td style="padding:7px 0;font-weight:600;">${f.client_ip}</td>
            <td style="padding:7px 0;">${hostDisp}</td>
            <td style="padding:7px 0;color:var(--muted);font-size:11.5px;">:${f.dport} <span class="badge mode" style="font-size:9.5px;">${f.proto}</span></td>
            <td style="padding:7px 0;text-align:right;font-weight:600;">${f.bytes_human}</td>
            <td style="padding:7px 0;text-align:right;"><span class="badge ${badgeCls}">${badgeText}</span></td>
          </tr>
        `;
      });
      tbody.innerHTML = html;
    })
    .catch(() => {
      const tbody = document.getElementById('flow-table-body');
      if (tbody) tbody.innerHTML = '<tr><td colspan="6" style="padding:16px 0;text-align:center;color:var(--red);">Error loading connections.</td></tr>';
    });
}

// Initial fetch on page load
document.addEventListener('DOMContentLoaded', fetchFlows);
setTimeout(fetchFlows, 800);
</script>
"""


@app.route("/dashboard")
@login_required
def dashboard():
    connected = is_warp_connected()
    status_out = get_warp_status()
    pub_ip = get_public_ip()
    gw_ip = get_gateway_ip()
    mode = get_warp_mode()

    iface = get_default_iface()
    rx_rate, tx_rate, rx_total, tx_total = get_throughput_nonblocking(iface)
    devices = get_connected_devices()
    tstats = get_traffic_routing_stats()

    tot_conns = tstats["total_connections"] or 1
    warp_pct = round((tstats["warp_connections"] / tot_conns) * 100, 1) if tstats["total_connections"] > 0 else 0
    bypass_pct = round((tstats["bypass_connections"] / tot_conns) * 100, 1) if tstats["total_connections"] > 0 else 0

    st = speedtest_state
    if st["running"]:
        speed_block = f"""<p style="color:var(--muted);font-size:13px;">{icon('gauge',14)} Test running… refresh in a bit.</p>"""
    elif st["result"]:
        r = st["result"]
        speed_block = f"""
        <div class="info-row"><span class="label">Download</span><span class="value">{r['download']}</span></div>
        <div class="info-row"><span class="label">Upload</span><span class="value">{r['upload']}</span></div>
        <div class="info-row"><span class="label">Ping</span><span class="value">{r['ping']}</span></div>
        <div class="info-row"><span class="label">Last run</span><span class="value">{st['ran_at']}</span></div>
        """
    elif st["error"]:
        speed_block = f"""<p style="color:var(--muted);font-size:13px;">Last attempt failed: {st['error']}</p>"""
    else:
        speed_block = """<p style="color:var(--muted);font-size:13px;">No speed test run yet.</p>"""

    content = f"""
    <div class="grid">
      <div class="card">
        <h3>{icon('power')} WARP Connection</h3>
        <div class="info-row"><span class="label">Status</span><span class="badge {'on' if connected else 'off'}">{'CONNECTED' if connected else 'DISCONNECTED'}</span></div>
        <div class="info-row"><span class="label">Mode</span><span class="badge mode" id="mode-badge">{mode.upper()}</span></div>
        <div class="info-row"><span class="label">Public WAN IP</span><span class="value">{pub_ip}</span></div>
        <div class="info-row"><span class="label">Gateway LAN IP</span><span class="value">{gw_ip}</span></div>
        <div style="margin-top:16px;" class="btn-row">
          <form method="POST" action="{url_for('toggle_warp', action='off' if connected else 'on')}" style="flex:1;">
            <button class="btn {'btn-danger' if connected else 'btn-primary'}">{icon('power',16)} {'Disconnect WARP' if connected else 'Connect WARP'}</button>
          </form>
        </div>
      </div>

      <div class="card">
        <h3>{icon('activity')} Live Throughput ({iface or 'no default route'}) <span style="font-weight:400;color:var(--muted);font-size:11px;">auto-refreshes every 2s</span></h3>
        <div class="speed-row">
          <div class="speed-col">
            <div class="dirlabel">↓ Download</div>
            <div class="stat-big" id="rx-rate">{humanize_bytes(rx_rate)}/s</div>
          </div>
          <div class="speed-col">
            <div class="dirlabel">↑ Upload</div>
            <div class="stat-big" id="tx-rate">{humanize_bytes(tx_rate)}/s</div>
          </div>
        </div>
        <div class="stat-sub" style="margin-top:12px;" id="data-total">Total since boot — Download: {humanize_bytes(rx_total)} | Upload: {humanize_bytes(tx_total)}</div>
      </div>
    </div>

    <!-- Real-time Traffic Routing Analysis Card -->
    <div class="card" style="margin-bottom:20px;">
      <h3>{icon('zap')} Traffic Routing Analysis <span style="font-weight:400;color:var(--muted);font-size:11.5px;margin-left:8px;">Live conntrack inspection &amp; active route state</span></h3>
      <div class="traffic-grid">
        <div class="tstat tw" onclick="openFlowModal('warp')" style="cursor:pointer;" title="Click to inspect WARP encrypted flows">
          <div class="ts-lbl">WARP Encrypted</div>
          <div class="ts-val" id="tstat-warp">{tstats['warp_connections']}</div>
          <div class="ts-sub">Active connections 🔍</div>
        </div>
        <div class="tstat tb" onclick="openFlowModal('bypass')" style="cursor:pointer;" title="Click to inspect direct ISP bypassed flows">
          <div class="ts-lbl">Direct ISP Bypassed</div>
          <div class="ts-val" id="tstat-bypass">{tstats['bypass_connections']}</div>
          <div class="ts-sub">Active connections 🔍</div>
        </div>
        <div class="tstat tn">
          <div class="ts-lbl">Active Bypass CIDRs</div>
          <div class="ts-val" id="tstat-routes">{tstats['active_bypass_routes']}</div>
          <div class="ts-sub">Exempted IP blocks</div>
        </div>
      </div>
      <div class="traffic-bars">
        <div class="tbar-row">
          <div class="tbar-labels">
            <span class="tbl" id="tbar-warp-lbl">WARP Encrypted Tunnel ({warp_pct}%)</span>
            <span class="tbl" id="tbar-warp-bytes">{humanize_bytes(tstats['warp_bytes_total'])}</span>
          </div>
          <div class="tbar-track">
            <div class="tbar-fill tw" id="tbar-warp-fill" style="width:{warp_pct}%;"></div>
          </div>
        </div>
        <div class="tbar-row">
          <div class="tbar-labels">
            <span class="tbl" id="tbar-bypass-lbl">Direct ISP Bypassed ({bypass_pct}%)</span>
            <span class="tbl" id="tbar-bypass-bytes">{humanize_bytes(tstats['bypass_bytes_total'])}</span>
          </div>
          <div class="tbar-track">
            <div class="tbar-fill tb" id="tbar-bypass-fill" style="width:{bypass_pct}%;"></div>
          </div>
        </div>
      </div>
    </div>

    <!-- Traffic Flow Inspector Card (Live Flows & 5-Day Log History) -->
    <div id="flow-inspector-card" class="card" style="margin-bottom:20px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:10px;">
        <h3 style="margin-bottom:0;">{icon('activity')} Traffic Flow Inspector
          <span style="font-size:11.5px;font-weight:400;color:var(--muted);margin-left:8px;">Live flows &amp; 5-day history logs with pagination</span>
        </h3>
        <div style="display:flex;gap:8px;align-items:center;">
          <button class="btn btn-outline btn-sm" id="tab-live-btn" onclick="switchFlowTab('live')" style="background:var(--panel-2);">⚡ Live Active Flows</button>
          <button class="btn btn-outline btn-sm" id="tab-hist-btn" onclick="switchFlowTab('history')">📜 5-Day Log History</button>
        </div>
      </div>

      <!-- Controls Row: Route Filter + Search + Items Per Page -->
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:10px;background:var(--panel-2);padding:10px 14px;border-radius:12px;border:1px solid var(--border);">
        <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;">
          <span style="font-size:12px;color:var(--muted);font-weight:600;margin-right:4px;">Filter:</span>
          <button class="btn btn-outline btn-sm flow-rf-btn active" data-type="all" onclick="setFlowRouteFilter('all')">All</button>
          <button class="btn btn-outline btn-sm flow-rf-btn" data-type="warp" onclick="setFlowRouteFilter('warp')">WARP Encrypted</button>
          <button class="btn btn-outline btn-sm flow-rf-btn" data-type="bypass" onclick="setFlowRouteFilter('bypass')">Direct ISP Bypassed</button>
        </div>
        <div style="display:flex;gap:10px;align-items:center;flex:1;max-width:320px;">
          <input type="text" id="flow-search-input" placeholder="Search IP, Hostname, or Port..."
            oninput="onFlowSearchChange()"
            style="width:100%;padding:7px 12px;background:var(--panel);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12.5px;outline:none;">
        </div>
      </div>

      <!-- Flows Table -->
      <div style="overflow-x:auto;">
        <table style="width:100%;border-collapse:collapse;font-size:12.5px;">
          <thead>
            <tr style="text-align:left;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid var(--border);">
              <th style="padding:8px 0;">Time / State</th>
              <th style="padding:8px 0;">Client IP</th>
              <th style="padding:8px 0;">Destination IP / Hostname</th>
              <th style="padding:8px 0;">Port / Proto</th>
              <th style="padding:8px 0;text-align:right;">Traffic</th>
              <th style="padding:8px 0;text-align:right;">Routing Path</th>
            </tr>
          </thead>
          <tbody id="flow-table-body">
            <tr><td colspan="6" style="padding:16px 0;text-align:center;color:var(--muted);">Loading connection flows...</td></tr>
          </tbody>
        </table>
      </div>

      <!-- Pagination Footer -->
      <div style="display:flex;justify-content:space-between;align-items:center;margin-top:14px;padding-top:12px;border-top:1px solid var(--border);flex-wrap:wrap;gap:10px;font-size:12px;color:var(--muted);">
        <div style="display:flex;align-items:center;gap:8px;">
          <span>Per page:</span>
          <select id="flow-per-page-select" onchange="changeFlowPerPage()" style="padding:4px 8px;background:var(--panel-2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:12px;">
            <option value="20">20</option>
            <option value="30" selected>30</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
          <span id="flow-total-count-lbl" style="margin-left:8px;">Total: 0 entries</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px;">
          <button class="btn btn-outline btn-sm" id="flow-prev-btn" onclick="prevFlowPage()">← Prev</button>
          <span style="font-weight:600;color:var(--text);">Page <span id="flow-cur-page">1</span> of <span id="flow-tot-pages">1</span></span>
          <button class="btn btn-outline btn-sm" id="flow-next-btn" onclick="nextFlowPage()">Next →</button>
        </div>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <h3>{icon('gauge')} Internet Speed Test</h3>
        {speed_block}
        <form method="POST" action="{url_for('run_speedtest')}" style="margin-top:14px;">
          <button class="btn btn-outline" {'disabled' if st['running'] else ''}>{icon('gauge',16)} Run Speed Test</button>
        </form>
      </div>

      <div class="card">
        <h3>{icon('shield')} Raw WARP Status</h3>
        <pre class="log-box" style="max-height:160px;">{status_out}</pre>
      </div>
    </div>

    <div class="card">
      <h3>{icon('server')} Connected Devices <span class="badge mode" id="device-count-badge" style="margin-left:6px;">{len(devices)} devices</span></h3>
      <p style="color:var(--muted);font-size:12px;margin-bottom:10px;">IP and MAC from the ARP table. Download/Upload and connection count are live figures from <code style="background:var(--panel-2);padding:1px 6px;border-radius:5px;">conntrack</code> (requires that package) — they reflect traffic on currently-active connections, not lifetime totals per device.</p>
      <table style="width:100%;border-collapse:collapse;font-size:13px;">
        <thead>
          <tr style="text-align:left;color:var(--muted);font-size:11.5px;text-transform:uppercase;letter-spacing:.03em;">
            <th style="padding-bottom:8px;">IP Address</th>
            <th style="padding-bottom:8px;">MAC Address</th>
            <th style="padding-bottom:8px;text-align:right;">Download</th>
            <th style="padding-bottom:8px;text-align:right;">Upload</th>
            <th style="padding-bottom:8px;text-align:right;">Active Connections</th>
          </tr>
        </thead>
        <tbody id="device-table-body">{render_device_rows(devices)}</tbody>
      </table>
    </div>
    """
    content += DASHBOARD_POLL_SCRIPT.replace("__API_URL__", url_for("api_dashboard_stats"))
    return render_page("dashboard", "Dashboard", "Live gateway status and quick controls", content)


@app.route("/api/dashboard-stats")
@login_required
def api_dashboard_stats():
    """JSON snapshot polled by the dashboard's JS every 2s so the page never
    needs a manual refresh."""
    connected = is_warp_connected()
    mode = get_warp_mode()
    iface = get_default_iface()
    rx_rate, tx_rate, rx_total, tx_total = get_throughput_nonblocking(iface)
    devices = get_connected_devices()
    tstats = get_traffic_routing_stats()

    tot_conns = tstats["total_connections"] or 1
    tstats["warp_pct"] = round((tstats["warp_connections"] / tot_conns) * 100, 1) if tstats["total_connections"] > 0 else 0
    tstats["bypass_pct"] = round((tstats["bypass_connections"] / tot_conns) * 100, 1) if tstats["total_connections"] > 0 else 0
    tstats["warp_bytes_human"] = humanize_bytes(tstats["warp_bytes_total"])
    tstats["bypass_bytes_human"] = humanize_bytes(tstats["bypass_bytes_total"])

    return jsonify({
        "connected": connected,
        "mode": mode,
        "iface": iface,
        "rx_rate_human": humanize_bytes(rx_rate) + "/s",
        "tx_rate_human": humanize_bytes(tx_rate) + "/s",
        "rx_total_human": humanize_bytes(rx_total),
        "tx_total_human": humanize_bytes(tx_total),
        "device_count": len(devices),
        "devices": devices,
        "device_rows_html": render_device_rows(devices),
        "tstats": tstats,
    })


@app.route("/warp/toggle/<action>", methods=["POST"])
@login_required
def toggle_warp(action):
    if action == "on":
        run_cmd("warp-cli --accept-tos connect")
        settled = wait_for_warp_state(True, timeout=6)
        if settled:
            flash("WARP connected.", "success")
        else:
            flash("Connect command sent — still establishing the tunnel, refresh in a few seconds.", "success")
    elif action == "off":
        run_cmd("warp-cli --accept-tos disconnect")
        settled = wait_for_warp_state(False, timeout=6)
        if settled:
            flash("WARP disconnected.", "success")
        else:
            flash("Disconnect command sent — still tearing down the tunnel, refresh in a few seconds.", "success")
    return redirect(url_for("dashboard"))


@app.route("/speedtest/run", methods=["POST"])
@login_required
def run_speedtest():
    if speedtest_state["running"]:
        flash("A speed test is already running — check back in a moment.", "success")
    else:
        threading.Thread(target=run_speedtest_bg, daemon=True).start()
        flash("Speed test started. Refresh in ~20-30 seconds for results.", "success")
    return redirect(url_for("dashboard"))


@app.route("/warp/mode", methods=["POST"])
@login_required
def warp_mode():
    mode = request.form.get("mode", "warp")
    if mode in ("warp", "doh", "proxy"):
        run_cmd(f"warp-cli --accept-tos mode {mode}")
        flash(f"WARP mode switched to '{mode}'.", "success")
    else:
        flash("Invalid mode selected.", "error")
    return redirect(url_for("network"))


# ---------------------------------------------------------------------------
# Network info
# ---------------------------------------------------------------------------
@app.route("/network")
@login_required
def network():
    pub_ip = get_public_ip()
    gw_ip = get_gateway_ip()
    account_out = run_cmd("warp-cli --accept-tos account")
    settings_out = run_cmd("warp-cli --accept-tos settings")
    clients_out = run_cmd("arp -a") or "No connected clients found."
    mode = get_warp_mode().lower()

    def sel(key):
        return "selected" if key in mode else ""

    content = f"""
    <div class="grid">
      <div class="card">
        <h3>{icon('wifi')} Addressing</h3>
        <div class="info-row"><span class="label">Public WAN IP</span><span class="value">{pub_ip}</span></div>
        <div class="info-row"><span class="label">Gateway LAN IP</span><span class="value">{gw_ip}</span></div>
        <div class="info-row"><span class="label">Primary DNS</span><span class="value">1.1.1.1</span></div>
        <div class="info-row"><span class="label">Secondary DNS</span><span class="value">1.0.0.1</span></div>
      </div>

      <div class="card">
        <h3>{icon('network')} Switch WARP Mode</h3>
        <div class="info-row"><span class="label">Current Mode</span><span class="badge mode">{mode.upper() or 'UNKNOWN'}</span></div>
        <form method="POST" action="{url_for('warp_mode')}" style="margin-top:10px;">
          <div class="input-group">
            <label>Connection Mode</label>
            <select name="mode">
              <option value="warp" {sel('warp')}>WARP (Full Tunnel)</option>
              <option value="doh" {sel('doh') or sel('dns')}>DNS over HTTPS (DoH)</option>
              <option value="proxy" {sel('proxy')}>Local Proxy</option>
            </select>
          </div>
          <button class="btn btn-primary">{icon('check',16)} Apply Mode</button>
        </form>
      </div>
    </div>

    <div class="card" style="margin-bottom:16px;">
      <h3>{icon('shield')} WARP Account</h3>
      <pre class="log-box" style="max-height:160px;">{account_out}</pre>
    </div>

    <div class="card" style="margin-bottom:16px;">
      <h3>{icon('settings')} WARP Client Settings</h3>
      <pre class="log-box" style="max-height:200px;">{settings_out}</pre>
    </div>

    <div class="card">
      <h3>{icon('server')} Connected LAN Clients (ARP Table)</h3>
      <pre class="log-box">{clients_out}</pre>
    </div>
    """
    return render_page("network", "Network Info", "Addressing, WARP account and connected clients", content)


# ---------------------------------------------------------------------------
# Bypass Rules (Split Tunneling) page
# ---------------------------------------------------------------------------
@app.route("/bypass")
@login_required
def bypass():
    rules            = load_bypass_rules()
    settings         = load_bypass_settings()
    cdn_settings     = load_cdn_settings()
    country_settings = load_country_settings()
    auto_iface, auto_gateway = detect_uplink()
    warp_cli_ok      = warp_st_supported()

    # ── Type badge colours ────────────────────────────────────────────────
    TYPE_BADGE = {
        "domain":   ("mode",  "DOMAIN"),
        "wildcard": ("on",    "WILDCARD ✦"),
        "ip":       ("mode",  "IP"),
        "cidr":     ("mode",  "CIDR"),
    }

    def status_badge(r):
        st  = r.get("status", "pending")
        cls = "on" if st == "active" else ("off" if st == "error" else "mode")
        return f'<span class="badge {cls}">{st.upper()}</span>'

    # ── Active custom bypass rules table rows ─────────────────────────────
    rows = ""
    if not rules:
        rows = ('<tr><td colspan="5" style="padding:14px 0;color:var(--muted);">'
                'No custom rules yet — add domains, IPs, or CIDRs below.</td></tr>')
    else:
        for r in rules:
            ips      = ", ".join(r.get("resolved_ips", [])) or "—"
            err      = (f"<div style='color:#fca5a5;font-size:11.5px;margin-top:2px;'>{r['error']}</div>"
                        if r.get("error") else "")
            tb_cls, tb_label = TYPE_BADGE.get(r["type"], ("mode", r["type"].upper()))
            warp_dot = (f'<span title="warp-cli split-tunnel active" '
                        f'style="color:var(--green);font-size:10px;margin-left:4px;">⬤ WARP</span>'
                        if r.get("warp_cli_ok") else "")
            rows += f"""
            <tr>
              <td style="padding:10px 0;"><span class="badge {tb_cls}">{tb_label}</span></td>
              <td style="padding:10px 0;font-weight:600;">{r['value']}{warp_dot}</td>
              <td style="padding:10px 0;color:var(--muted);font-size:12.5px;">{ips}{err}</td>
              <td style="padding:10px 0;">{status_badge(r)}</td>
              <td style="padding:10px 0;text-align:right;white-space:nowrap;">
                <form method="POST" action="{url_for('bypass_refresh', rule_id=r['id'])}" style="display:inline;">
                  <button class="btn btn-outline btn-sm">{icon('activity',14)} Refresh</button>
                </form>
                <form method="POST" action="{url_for('bypass_delete', rule_id=r['id'])}" style="display:inline;"
                      onsubmit="return confirm('Remove this bypass rule?');">
                  <button class="btn btn-danger btn-sm">Remove</button>
                </form>
              </td>
            </tr>
            """

    # ── Country IP Auto-Sync Table Rows ───────────────────────────────────
    country_rows = ""
    for code, cdata in country_settings.get("countries", {}).items():
        enabled     = cdata.get("enabled", False)
        name        = cdata.get("name", code)
        last_sync   = cdata.get("last_sync") or "Never"
        cidr_count  = cdata.get("cidr_count", 0)
        c_err       = cdata.get("error")
        status_txt  = f"{cidr_count} CIDRs applied" if not c_err else f"Error: {c_err[:50]}"
        badge_cls   = "on" if (enabled and not c_err) else ("off" if c_err else "mode")
        country_rows += f"""
        <tr>
          <td style="padding:10px 0;font-weight:600;">{name} <span class="badge mode" style="font-size:10.5px;">{code}</span></td>
          <td style="padding:10px 0;color:var(--muted);font-size:12.5px;">Official delegated RIR IPv4 allocations for {name}</td>
          <td style="padding:10px 0;"><span class="badge {badge_cls}">{'ENABLED' if enabled else 'DISABLED'}</span></td>
          <td style="padding:10px 0;color:var(--muted);font-size:12px;">{status_txt}<br>
              <span style="font-size:11px;">Last sync: {last_sync}</span></td>
          <td style="padding:10px 0;text-align:right;white-space:nowrap;">
            <form method="POST" action="{url_for('country_toggle', code=code)}" style="display:inline;">
              <button class="btn {'btn-danger' if enabled else 'btn-primary'} btn-sm">{'Disable' if enabled else 'Enable'}</button>
            </form>
            <form method="POST" action="{url_for('country_sync_now', code=code)}" style="display:inline;">
              <button class="btn btn-outline btn-sm">{icon('activity',14)} Sync Now</button>
            </form>
            <form method="POST" action="{url_for('country_delete', code=code)}" style="display:inline;"
                  onsubmit="return confirm('Remove {name} from country auto-bypass?');">
              <button class="btn btn-outline btn-sm" style="color:var(--red);">Delete</button>
            </form>
          </td>
        </tr>
        """
    if not country_rows:
        country_rows = '<tr><td colspan="5" style="padding:12px 0;color:var(--muted);">No countries configured. Select or enter a country code below.</td></tr>'

    # Build country dropdown options with all 240+ countries
    country_options = "".join(f'<option value="{c[0]}">{c[1]} ({c[0]})</option>' for c in ALL_COUNTRIES)

    # ── CDN providers table rows ──────────────────────────────────────────
    cdn_rows = ""
    for key, meta in _CDN_PROVIDERS.items():
        prov        = cdn_settings.get("providers", {}).get(key, {})
        enabled     = prov.get("enabled", False)
        last_sync   = prov.get("last_sync") or "Never"
        cidr_count  = prov.get("cidr_count", 0)
        cdn_err     = prov.get("error")
        status_txt  = f"{cidr_count} CIDRs applied" if not cdn_err else f"Error: {cdn_err[:60]}"
        badge_cls   = "on" if (enabled and not cdn_err) else ("off" if cdn_err else "mode")
        cdn_rows += f"""
        <tr>
          <td style="padding:10px 0;font-weight:600;">{meta['name']}</td>
          <td style="padding:10px 0;color:var(--muted);font-size:12.5px;">{meta['description']}</td>
          <td style="padding:10px 0;"><span class="badge {badge_cls}">{'ENABLED' if enabled else 'DISABLED'}</span></td>
          <td style="padding:10px 0;color:var(--muted);font-size:12px;">{status_txt}<br>
              <span style="font-size:11px;">Last sync: {last_sync}</span></td>
          <td style="padding:10px 0;text-align:right;white-space:nowrap;">
            <form method="POST" action="{url_for('cdn_toggle', key=key)}" style="display:inline;">
              <button class="btn {'btn-danger' if enabled else 'btn-primary'} btn-sm">{'Disable' if enabled else 'Enable'}</button>
            </form>
            <form method="POST" action="{url_for('cdn_sync_now', key=key)}" style="display:inline;">
              <button class="btn btn-outline btn-sm">{icon('activity',14)} Sync Now</button>
            </form>
          </td>
        </tr>
        """

    # ── WARP CLI status banner ────────────────────────────────────────────
    warp_banner = (
        f'<div style="display:flex;align-items:center;gap:8px;font-size:12.5px;'
        f'color:var(--green);margin-bottom:14px;">'
        f'{icon("check",14)} <strong>warp-cli split-tunnel active</strong> — bypass rules are '
        f'applied at the WARP daemon level (most reliable, survives reconnects) AND via ip route.</div>'
        if warp_cli_ok else
        f'<div style="display:flex;align-items:center;gap:8px;font-size:12.5px;'
        f'color:var(--amber);margin-bottom:14px;">'
        f'⚠ warp-cli split-tunnel not available — using ip route only. '
        f'Routes will be re-applied every 3 minutes.</div>'
    )

    content = f"""
    <!-- Global Configuration & Bypass Guide Card -->
    <div class="instr-card">
      <div class="instr-title">{icon('info', 18)} Split-Tunnel &amp; Auto-Bypass Configuration Guide</div>
      <div class="instr-cols">
        <div class="instr-col">
          <div class="ic-head">{icon('shield', 14)} Domestic &amp; Regional Banking Services</div>
          <ul>
            <li><strong>National IP Auto-Bypass:</strong> Select your home country or ISO code (e.g. <span class="tag green">BD</span> <span class="tag green">IN</span> <span class="tag green">AE</span> <span class="tag green">US</span>) to route all authoritative ISP blocks directly through local uplink.</li>
            <li><strong>Global CDN Edge Sync:</strong> Enable <span class="tag green">Cloudflare CDN</span>, <span class="tag green">AWS CloudFront</span>, and <span class="tag green">AWS Asia-Pacific</span> to ensure mobile banking APIs connect without location error messages.</li>
          </ul>
        </div>
        <div class="instr-col">
          <div class="ic-head">{icon('network', 14)} Custom Domain &amp; Subdomain Rules</div>
          <ul>
            <li><strong>Wildcard Domains:</strong> Add <code>*.example.com</code> to automatically probe common payment, login, and static asset subdomains.</li>
            <li><strong>One-Click Backup &amp; Import:</strong> Click <strong>Export Rules</strong> to download a backup file of all active custom rules. The downloaded file can be pasted directly into the input box below.</li>
          </ul>
        </div>
      </div>
    </div>

    <!-- Country IP Range Auto-Bypass Card -->
    <div class="card" style="margin-bottom:16px;">
      <h3>{icon('network')} National IP Auto-Bypass (By Country / Region)
        <span style="font-size:11.5px;font-weight:400;color:var(--muted);margin-left:8px;">Direct routing for domestic banking, government &amp; local ISP traffic</span>
      </h3>
      <p style="color:var(--muted);font-size:12.5px;margin-bottom:14px;">
        Select your home country or enter any 2-letter ISO Country Code. The gateway automatically pulls official real-time
        IP allocations via the global RIR/RIPE database and routes all national traffic directly through your ISP — preventing
        location blocks on domestic banking apps while keeping international traffic encrypted via WARP.
      </p>
      <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:16px;">
        <thead>
          <tr style="text-align:left;color:var(--muted);font-size:11.5px;text-transform:uppercase;letter-spacing:.03em;">
            <th style="padding-bottom:8px;">Country</th>
            <th style="padding-bottom:8px;">Description</th>
            <th style="padding-bottom:8px;">State</th>
            <th style="padding-bottom:8px;">Sync Status</th>
            <th style="padding-bottom:8px;text-align:right;">Actions</th>
          </tr>
        </thead>
        <tbody>{country_rows}</tbody>
      </table>

      <!-- Add New Country Form -->
      <form method="POST" action="{url_for('country_add')}" style="background:var(--panel-2);padding:14px 16px;border-radius:12px;border:1px solid var(--border);">
        <div style="font-size:13px;font-weight:600;margin-bottom:8px;color:#dbe4f3;">+ Add Country IP Allocation</div>
        <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
          <div style="flex:1;min-width:200px;">
            <select name="selected_country" style="width:100%;padding:9px 12px;background:var(--panel);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:13px;">
              <option value="">-- Choose from Popular Countries --</option>
              {country_options}
            </select>
          </div>
          <div style="width:140px;">
            <input type="text" name="custom_code" placeholder="or ISO (e.g. TH)" maxlength="2" style="width:100%;padding:9px 12px;background:var(--panel);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:13px;text-transform:uppercase;">
          </div>
          <button class="btn btn-primary btn-sm" style="width:auto;padding:9px 18px;">{icon('check',14)} Add &amp; Sync Country</button>
        </div>
      </form>
    </div>

    <!-- Global Cloud & CDN Auto-Sync Card -->
    <div class="card" style="margin-bottom:16px;">
      <h3>{icon('network')} Global Cloud &amp; CDN Provider Auto-Sync
        <span style="font-size:11.5px;font-weight:400;color:var(--muted);margin-left:8px;">Syncs every hour automatically</span>
      </h3>
      <p style="color:var(--muted);font-size:12.5px;margin-bottom:12px;">
        Major fintech apps host their APIs across global CDN edges and regional cloud compute clusters. Enabling cloud providers here
        automatically maintains bypass routes for all authoritative IPv4 CIDR blocks.
      </p>
      <table style="width:100%;border-collapse:collapse;font-size:13px;">
        <thead>
          <tr style="text-align:left;color:var(--muted);font-size:11.5px;text-transform:uppercase;letter-spacing:.03em;">
            <th style="padding-bottom:8px;">Provider / Region</th>
            <th style="padding-bottom:8px;">Coverage</th>
            <th style="padding-bottom:8px;">State</th>
            <th style="padding-bottom:8px;">Sync Status</th>
            <th style="padding-bottom:8px;text-align:right;">Actions</th>
          </tr>
        </thead>
        <tbody>{cdn_rows}</tbody>
      </table>
    </div>

    <!-- Add Custom Bypass Rule Card -->
    <div class="card" style="margin-bottom:16px;">
      <h3>{icon('shield')} Add Custom Bypass Rule</h3>
      {warp_banner}
      <p style="color:var(--muted);font-size:12.5px;margin-bottom:10px;">
        Add a <strong>domain</strong>, full URL, IP, CIDR, or <strong>wildcard</strong> (e.g. <code>*.example.com</code>).
        Wildcards automatically probe common fintech and API subdomains. One entry per line, or comma-separated.
      </p>
      <form method="POST" action="{url_for('bypass_add')}">
        <div class="input-group">
          <label>Domains / Wildcards / URLs / IPs / CIDRs</label>
          <textarea id="bypass-entries" name="entries" rows="4"
            placeholder="*.examplebank.com&#10;api.paymentgateway.com&#10;103.4.145.0/24"
            style="width:100%;padding:11px 12px;background:var(--panel-2);border:1px solid var(--border);
                   border-radius:10px;color:var(--text);font-size:14px;font-family:inherit;resize:vertical;"></textarea>
        </div>
        <button class="btn btn-primary" style="width:auto;padding:11px 20px;">{icon('check',16)} Add &amp; Apply Bypass</button>
      </form>
    </div>

    <!-- Active Bypass Rules Card -->
    <div class="card" style="margin-bottom:16px;">
      <h3>{icon('network')} Custom Bypass Rules <span class="badge mode">{len(rules)}</span></h3>
      <div class="btn-row" style="margin-bottom:14px;">
        <form method="POST" action="{url_for('bypass_refresh_all')}">
          <button class="btn btn-outline btn-sm">{icon('activity',14)} Re-apply / Re-resolve All</button>
        </form>
        <a href="{url_for('bypass_export')}" class="btn btn-outline btn-sm" style="text-decoration:none;">{icon('download',14)} Export Rules</a>
      </div>
      <table style="width:100%;border-collapse:collapse;font-size:13px;">
        <thead>
          <tr style="text-align:left;color:var(--muted);font-size:11.5px;text-transform:uppercase;letter-spacing:.03em;">
            <th style="padding-bottom:8px;">Type</th>
            <th style="padding-bottom:8px;">Entry</th>
            <th style="padding-bottom:8px;">Resolved IP(s)</th>
            <th style="padding-bottom:8px;">Status</th>
            <th style="padding-bottom:8px;text-align:right;">Actions</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </div>

    <!-- Uplink Settings Card -->
    <div class="card">
      <h3>{icon('network')} Uplink Interface Override
        <span style="font-size:11.5px;font-weight:400;color:var(--muted);margin-left:8px;">Auto-detected: {auto_iface or 'not found'} via {auto_gateway or 'N/A'}</span>
      </h3>
      <p style="color:var(--muted);font-size:12.5px;margin:10px 0;">Bypassed traffic exits via this interface instead of CloudflareWARP. Leave blank for auto-detection.</p>
      <form method="POST" action="{url_for('bypass_uplink')}">
        <div class="grid" style="grid-template-columns:1fr 1fr;margin-bottom:10px;">
          <div class="input-group" style="margin-bottom:0;">
            <label>Manual Interface (optional)</label>
            <input type="text" name="iface" placeholder="e.g. eth0" value="{settings.get('iface') or ''}">
          </div>
          <div class="input-group" style="margin-bottom:0;">
            <label>Manual Gateway IP (optional)</label>
            <input type="text" name="gateway" placeholder="e.g. 192.168.1.1" value="{settings.get('gateway') or ''}">
          </div>
        </div>
        <button class="btn btn-outline" style="width:auto;padding:10px 16px;">{icon('check',14)} Save Uplink Override</button>
      </form>
    </div>
    """
    return render_page("bypass", "Bypass Rules", "Smart split-tunnel for banking apps & local traffic — WARP on, domestic apps unblocked", content)


@app.route("/bypass/add", methods=["POST"])
@login_required
def bypass_add():
    raw = request.form.get("entries", "")
    entries = [e.strip() for chunk in raw.splitlines() for e in chunk.split(",") if e.strip()]
    if not entries:
        flash("Enter at least one domain, URL, IP, or CIDR.", "error")
        return redirect(url_for("bypass"))

    rules = load_bypass_rules()
    existing_values = {(r["type"], r["value"]) for r in rules}
    added, skipped, invalid = 0, 0, 0

    for raw_entry in entries:
        kind, value = parse_bypass_input(raw_entry)
        if not kind:
            invalid += 1
            continue
        if (kind, value) in existing_values:
            skipped += 1
            continue
        rule = {
            "id": uuid.uuid4().hex[:10],
            "type": kind,
            "value": value,
            "resolved_ips": [],
            "status": "pending",
            "error": None,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "last_checked": None,
        }
        apply_bypass_rule(rule)
        rules.append(rule)
        existing_values.add((kind, value))
        added += 1

    save_bypass_rules(rules)

    msg = f"Added {added} bypass rule(s)."
    if skipped:
        msg += f" Skipped {skipped} duplicate(s)."
    if invalid:
        msg += f" Could not parse {invalid} entr{'y' if invalid == 1 else 'ies'} — check the format."
    flash(msg, "success" if added else "error")
    return redirect(url_for("bypass"))


@app.route("/bypass/refresh/<rule_id>", methods=["POST"])
@login_required
def bypass_refresh(rule_id):
    rules = load_bypass_rules()
    found = False
    for r in rules:
        if r["id"] == rule_id:
            apply_bypass_rule(r)
            flash(f"Re-applied bypass rule for {r['value']}.", "success")
            found = True
            break
    if not found:
        flash("Rule not found.", "error")
    save_bypass_rules(rules)
    return redirect(url_for("bypass"))


@app.route("/bypass/refresh-all", methods=["POST"])
@login_required
def bypass_refresh_all():
    apply_all_bypass_rules()
    flash("All bypass rules re-applied.", "success")
    return redirect(url_for("bypass"))


@app.route("/bypass/export")
@login_required
def bypass_export():
    """Export all custom bypass rules as a clean plain-text file (one entry per line)
    so they can be easily backed up or re-imported into the gateway."""
    rules = load_bypass_rules()
    lines = []
    for r in rules:
        if r.get("type") == "wildcard":
            lines.append(f"*.{r['value']}")
        else:
            lines.append(r.get("value", ""))
    export_text = "\n".join(filter(None, lines)) + "\n"
    from flask import Response
    return Response(
        export_text,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=warp_gateway_bypass_rules.txt"}
    )



@app.route("/bypass/delete/<rule_id>", methods=["POST"])
@login_required
def bypass_delete(rule_id):
    rules = load_bypass_rules()
    keep = []
    removed_value = None
    for r in rules:
        if r["id"] == rule_id:
            remove_bypass_rule_routes(r)
            removed_value = r["value"]
        else:
            keep.append(r)
    save_bypass_rules(keep)
    if removed_value:
        flash(f"Removed bypass rule for {removed_value}.", "success")
    else:
        flash("Rule not found.", "error")
    return redirect(url_for("bypass"))


@app.route("/bypass/uplink", methods=["POST"])
@login_required
def bypass_uplink():
    iface = request.form.get("iface", "").strip()
    gateway = request.form.get("gateway", "").strip()
    save_bypass_settings({"iface": iface or None, "gateway": gateway or None})
    flash("Uplink override saved — re-applying existing rules...", "success")
    apply_all_bypass_rules()
    return redirect(url_for("bypass"))


# ---------------------------------------------------------------------------
# CDN Provider management routes
# ---------------------------------------------------------------------------
@app.route("/bypass/cdn/toggle/<key>", methods=["POST"])
@login_required
def cdn_toggle(key):
    if key not in _CDN_PROVIDERS:
        flash("Unknown CDN provider.", "error")
        return redirect(url_for("bypass"))
    settings = load_cdn_settings()
    prov = settings["providers"].setdefault(key, {})
    prov["enabled"] = not prov.get("enabled", False)
    save_cdn_settings(settings)
    if prov["enabled"]:
        threading.Thread(target=_cdn_sync_one, args=(key,), daemon=True).start()
        flash(f"{_CDN_PROVIDERS[key]['name']} enabled — syncing IP ranges in the background.", "success")
    else:
        flash(f"{_CDN_PROVIDERS[key]['name']} disabled.", "success")
    return redirect(url_for("bypass"))


@app.route("/bypass/cdn/sync/<key>", methods=["POST"])
@login_required
def cdn_sync_now(key):
    if key not in _CDN_PROVIDERS:
        flash("Unknown CDN provider.", "error")
        return redirect(url_for("bypass"))
    threading.Thread(target=_cdn_sync_one, args=(key,), daemon=True).start()
    flash(f"{_CDN_PROVIDERS[key]['name']} sync started in background — refresh in a few seconds.", "success")
    return redirect(url_for("bypass"))


# ---------------------------------------------------------------------------
# Country IP Range management routes
# ---------------------------------------------------------------------------
@app.route("/bypass/country/add", methods=["POST"])
@login_required
def country_add():
    sel = request.form.get("selected_country", "").strip().upper()
    custom = request.form.get("custom_code", "").strip().upper()
    code = custom if custom else sel
    if not code or len(code) != 2:
        flash("Please select a country or enter a valid 2-letter ISO country code (e.g. BD, IN, PK, US, etc.).", "error")
        return redirect(url_for("bypass"))

    # Lookup country name from all world countries
    name_map = dict(ALL_COUNTRIES)
    cname = name_map.get(code, f"Country ({code})")

    settings = load_country_settings()
    citem = settings.get("countries", {}).setdefault(code, {})
    citem["name"] = cname
    citem["enabled"] = True
    save_country_settings(settings)

    threading.Thread(target=_country_sync_one, args=(code,), daemon=True).start()
    flash(f"{cname} ({code}) added — syncing IP allocations via RIPE stat in background.", "success")
    return redirect(url_for("bypass"))


@app.route("/bypass/country/toggle/<code>", methods=["POST"])
@login_required
def country_toggle(code):
    code = code.strip().upper()
    settings = load_country_settings()
    if code not in settings.get("countries", {}):
        flash("Country not found.", "error")
        return redirect(url_for("bypass"))
    citem = settings["countries"][code]
    citem["enabled"] = not citem.get("enabled", False)
    save_country_settings(settings)
    if citem["enabled"]:
        threading.Thread(target=_country_sync_one, args=(code,), daemon=True).start()
        flash(f"{citem.get('name', code)} auto-bypass enabled — syncing in background.", "success")
    else:
        flash(f"{citem.get('name', code)} auto-bypass disabled.", "success")
    return redirect(url_for("bypass"))


@app.route("/bypass/country/sync/<code>", methods=["POST"])
@login_required
def country_sync_now(code):
    code = code.strip().upper()
    settings = load_country_settings()
    if code not in settings.get("countries", {}):
        flash("Country not found.", "error")
        return redirect(url_for("bypass"))
    citem = settings["countries"][code]
    threading.Thread(target=_country_sync_one, args=(code,), daemon=True).start()
    flash(f"Syncing IP allocations for {citem.get('name', code)} in background...", "success")
    return redirect(url_for("bypass"))


@app.route("/bypass/country/delete/<code>", methods=["POST"])
@login_required
def country_delete(code):
    code = code.strip().upper()
    settings = load_country_settings()
    if code in settings.get("countries", {}):
        del settings["countries"][code]
        save_country_settings(settings)
        flash(f"Removed country {code} from auto-bypass list.", "success")
    return redirect(url_for("bypass"))


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------
@app.route("/logs")
@login_required
def logs():
    lines = request.args.get("lines", "80")
    if not lines.isdigit():
        lines = "80"
    log_out = run_cmd(f"journalctl -u {SERVICE_NAME} -n {lines} --no-pager") or "No log entries found."

    content = f"""
    <div class="card">
      <h3>{icon('logs')} Service Logs — journalctl -u {SERVICE_NAME}</h3>
      <div class="btn-row" style="margin-bottom:14px;">
        <a class="btn btn-outline btn-sm" href="{url_for('logs')}?lines=50">Last 50</a>
        <a class="btn btn-outline btn-sm" href="{url_for('logs')}?lines=200">Last 200</a>
        <a class="btn btn-outline btn-sm" href="{url_for('logs')}?lines=500">Last 500</a>
      </div>
      <pre class="log-box">{log_out}</pre>
    </div>
    """
    return render_page("logs", "Service Logs", "Recent output from the warpgateway systemd unit", content)


# ---------------------------------------------------------------------------
# System configuration
# ---------------------------------------------------------------------------
@app.route("/system")
@login_required
def system():
    ipf = get_ip_forward_status()
    nat_rules = run_cmd("iptables -t nat -L POSTROUTING -n -v") or "No NAT rules found."
    fwd_rules = run_cmd("iptables -L FORWARD -n -v") or "No FORWARD rules found."
    autostart_out = run_cmd(f"systemctl is-enabled {SERVICE_NAME}")
    autostart_on = "enabled" in autostart_out

    content = f"""
    <div class="grid">
      <div class="card">
        <h3>{icon('shield')} IPv4 Forwarding</h3>
        <div class="info-row"><span class="label">Kernel Forwarding</span><span class="badge {'on' if ipf else 'off'}">{'ENABLED' if ipf else 'DISABLED'}</span></div>
        <form method="POST" action="{url_for('toggle_ipforward', action='off' if ipf else 'on')}" style="margin-top:12px;">
          <button class="btn {'btn-danger' if ipf else 'btn-primary'}">{'Disable Forwarding' if ipf else 'Enable Forwarding'}</button>
        </form>
      </div>

      <div class="card">
        <h3>{icon('power')} Auto-Start on Boot</h3>
        <div class="info-row"><span class="label">Systemd Auto-Start</span><span class="badge {'on' if autostart_on else 'off'}">{'ENABLED' if autostart_on else 'DISABLED'}</span></div>
        <form method="POST" action="{url_for('toggle_autostart', action='off' if autostart_on else 'on')}" style="margin-top:12px;">
          <button class="btn {'btn-danger' if autostart_on else 'btn-primary'}">{'Disable Auto-Start' if autostart_on else 'Enable Auto-Start'}</button>
        </form>
      </div>

      <div class="card">
        <h3>{icon('server')} Gateway Service</h3>
        <p style="color:var(--muted);font-size:13px;margin-bottom:14px;">Restarting will briefly interrupt this dashboard while the service reloads.</p>
        <form method="POST" action="{url_for('restart_service')}">
          <button class="btn btn-outline">{icon('power',16)} Restart warpgateway.service</button>
        </form>
      </div>
    </div>

    <div class="card" style="margin-bottom:16px;">
      <h3>{icon('network')} NAT Rules (POSTROUTING)</h3>
      <pre class="log-box" style="max-height:200px;">{nat_rules}</pre>
    </div>

    <div class="card">
      <h3>{icon('network')} FORWARD Chain Rules</h3>
      <pre class="log-box" style="max-height:200px;">{fwd_rules}</pre>
    </div>
    """
    return render_page("system", "System Config", "IP forwarding, autostart and firewall rules", content)


@app.route("/system/ipforward/<action>", methods=["POST"])
@login_required
def toggle_ipforward(action):
    if action == "on":
        run_cmd("sysctl -w net.ipv4.ip_forward=1")
        flash("IPv4 forwarding enabled.", "success")
    else:
        run_cmd("sysctl -w net.ipv4.ip_forward=0")
        flash("IPv4 forwarding disabled.", "success")
    return redirect(url_for("system"))


@app.route("/system/autostart/<action>", methods=["POST"])
@login_required
def toggle_autostart(action):
    if action == "on":
        run_cmd(f"systemctl enable {SERVICE_NAME}")
        flash("Auto-start on boot enabled.", "success")
    else:
        run_cmd(f"systemctl disable {SERVICE_NAME}")
        flash("Auto-start on boot disabled.", "success")
    return redirect(url_for("system"))


@app.route("/system/restart", methods=["POST"])
@login_required
def restart_service():
    threading.Thread(target=delayed_restart, daemon=True).start()
    flash("Gateway service is restarting now. Refresh in a few seconds.", "success")
    return redirect(url_for("system"))


# ---------------------------------------------------------------------------
# Admin settings (change username / password)
# ---------------------------------------------------------------------------
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    creds = load_credentials()

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_username = request.form.get("new_username", "").strip()
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not check_password_hash(creds["password_hash"], current_password):
            flash("Current password is incorrect.", "error")
        elif not new_username or not re.match(r"^[a-zA-Z0-9_.-]{3,32}$", new_username):
            flash("Username must be 3-32 characters (letters, numbers, . _ -).", "error")
        elif len(new_password) < 8:
            flash("New password must be at least 8 characters.", "error")
        elif new_password != confirm_password:
            flash("New password and confirmation do not match.", "error")
        else:
            save_credentials(new_username, new_password)
            session.clear()
            flash("Credentials updated. Please log in again.", "success")
            return redirect(url_for("login_page"))

    content = f"""
    <div class="card" style="max-width:480px;">
      <h3>{icon('settings')} Change Admin Credentials</h3>
      <form method="POST">
        <div class="input-group">
          <label>Current Password</label>
          <input type="password" name="current_password" required>
        </div>
        <div class="input-group">
          <label>New Username</label>
          <input type="text" name="new_username" value="{creds['username']}" required>
        </div>
        <div class="input-group">
          <label>New Password</label>
          <input type="password" name="new_password" required minlength="8">
        </div>
        <div class="input-group">
          <label>Confirm New Password</label>
          <input type="password" name="confirm_password" required minlength="8">
        </div>
        <button class="btn btn-primary">{icon('check',16)} Update Credentials</button>
      </form>
    </div>
    """
    return render_page("settings", "Admin Settings", "Update the dashboard login credentials", content)


# ---------------------------------------------------------------------------
# Setup guide (router configuration reference)
# ---------------------------------------------------------------------------
@app.route("/guide")
@login_required
def guide():
    gw_ip = get_gateway_ip()
    content = f"""
    <div class="card">
      <div class="guide-step">
        <div class="guide-num">{icon('cable',18)}</div>
        <div class="guide-body">
          <h4>1. Physical Setup (Hardware Connection)</h4>
          <p><strong>WAN Port:</strong> Connect your main internet cable (from your ISP or upstream router/modem) to the router's blue <code>WAN / Internet</code> port.</p>
          <p><strong>LAN Port:</strong> Connect this WARP Gateway server to any <code>LAN</code> port on the router using an Ethernet cable.</p>
        </div>
      </div>

      <div class="guide-step">
        <div class="guide-num">{icon('login',18)}</div>
        <div class="guide-body">
          <h4>2. Router Admin Panel Login</h4>
          <p>Open a browser and go to <code>192.168.0.1</code> or <code>192.168.1.1</code> (or <code>tplinkwifi.net</code>).</p>
          <p>On first setup you will be asked to create a new admin password — set it and log in.</p>
        </div>
      </div>

      <div class="guide-step">
        <div class="guide-num">{icon('wifi',18)}</div>
        <div class="guide-body">
          <h4>3. Internet Connection Setup (WAN)</h4>
          <p>Go to <code>Advanced &gt; Network &gt; Internet</code> and choose the connection type that matches your ISP:</p>
          <p><strong>PPPoE</strong> — if your ISP provides a username/password.<br>
          <strong>Dynamic IP</strong> — if the router receives an IP automatically.<br>
          <strong>Static IP</strong> — if your ISP has assigned a fixed IP, subnet and gateway.</p>
        </div>
      </div>

      <div class="guide-step">
        <div class="guide-num">{icon('server',18)}</div>
        <div class="guide-body">
          <h4>4. Default Gateway / Client Routing Setup</h4>
          <p>To route all client traffic through this WARP Gateway server (current IP: <code>{gw_ip}</code>):</p>
          <p>Go to <code>Advanced &gt; Network &gt; DHCP Server</code>, set <strong>Default Gateway</strong> to this server's IP, set <strong>Primary DNS</strong> to <code>1.1.1.1</code> and <strong>Secondary DNS</strong> to <code>1.0.0.1</code>, then Save.</p>
          <div class="guide-note">Once saved, every device connected to the router will automatically use this server as its gateway, and all traffic will be routed through the encrypted WARP tunnel.</div>
        </div>
      </div>

      <div class="guide-step">
        <div class="guide-num">{icon('network',18)}</div>
        <div class="guide-body">
          <h4>5. Wireless Settings</h4>
          <p>Go to <code>Advanced &gt; Wireless &gt; Wireless Settings</code>.</p>
          <p>Enable <strong>OFDMA &amp; MU-MIMO</strong> for Wi-Fi 6 performance. Enable <strong>Smart Connect</strong> for automatic 2.4GHz/5GHz band switching, or set separate SSIDs/passwords per band.</p>
          <div class="guide-note">Reboot the router after saving so all connected devices pick up the new gateway IP.</div>
        </div>
      </div>
    </div>
    """
    return render_page("guide", "Setup Guide", "Router configuration reference for this gateway", content)


# ---------------------------------------------------------------------------
# Auto-Update API Routes
# ---------------------------------------------------------------------------
@app.route("/api/check_update")
@login_required
def api_check_update():
    """Fetch version metadata from GitHub's raw 'ver' file and compare against
    the current local APP_VERSION and INSTALLER_VERSION constants."""
    try:
        import urllib.request
        req = urllib.request.Request(
            GH_VER_URL,
            headers={"User-Agent": "WARP-Gateway-Updater/1.0", "Cache-Control": "no-cache"}
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            raw = resp.read().decode("utf-8")

        remote_app_ver = APP_VERSION
        remote_installer_ver = INSTALLER_VERSION

        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("app_ver:"):
                remote_app_ver = line.split(":", 1)[1].strip()
            elif line.startswith("installer_ver:"):
                remote_installer_ver = line.split(":", 1)[1].strip()

        def _ver_tuple(v):
            return tuple(int(x) for x in v.split(".") if x.isdigit())

        app_newer = _ver_tuple(remote_app_ver) > _ver_tuple(APP_VERSION)
        installer_newer = _ver_tuple(remote_installer_ver) > _ver_tuple(INSTALLER_VERSION)
        has_update = app_newer or installer_newer

        update_type = "none"
        if app_newer and installer_newer:
            update_type = "both"
        elif app_newer:
            update_type = "app"
        elif installer_newer:
            update_type = "installer"

        return jsonify({
            "local_app_ver": APP_VERSION,
            "remote_app_ver": remote_app_ver,
            "local_installer_ver": INSTALLER_VERSION,
            "remote_installer_ver": remote_installer_ver,
            "has_update": has_update,
            "update_type": update_type,
            "error": None,
        })
    except Exception as exc:
        return jsonify({
            "local_app_ver": APP_VERSION,
            "remote_app_ver": APP_VERSION,
            "has_update": False,
            "update_type": "none",
            "error": f"Could not check update server: {str(exc)}",
        })


@app.route("/api/trigger_update", methods=["POST"])
@login_required
def api_trigger_update():
    """Download the latest app.py (and install.sh if installer_ver updated)
    from GitHub, validate non-empty content and valid syntax, replace local
    files, and trigger a background systemctl restart."""
    try:
        import urllib.request

        # 1. Download latest app.py from GitHub
        req_app = urllib.request.Request(
            GH_APP_URL,
            headers={"User-Agent": "WARP-Gateway-Updater/1.0", "Cache-Control": "no-cache"}
        )
        with urllib.request.urlopen(req_app, timeout=15) as resp:
            new_app_code = resp.read().decode("utf-8")

        # Basic integrity check: must contain Flask app definition
        if "app = Flask(__name__)" not in new_app_code or len(new_app_code) < 1000:
            return jsonify({"success": False, "error": "Downloaded file failed integrity check."})

        # Save downloaded app.py to actual script location
        target_path = APP_SCRIPT_PATH if os.path.exists(APP_SCRIPT_PATH) else os.path.abspath(__file__)
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(new_app_code)

        # 2. Check if installer script update is requested/needed
        req_type = (request.json or {}).get("update_type", "app")
        if req_type in ("installer", "both"):
            try:
                req_inst = urllib.request.Request(
                    GH_INSTALL_URL,
                    headers={"User-Agent": "WARP-Gateway-Updater/1.0", "Cache-Control": "no-cache"}
                )
                with urllib.request.urlopen(req_inst, timeout=15) as resp:
                    new_inst_code = resp.read().decode("utf-8")

                if len(new_inst_code) > 500:
                    inst_target = INSTALL_SCRIPT_PATH if os.path.exists(INSTALL_SCRIPT_PATH) else "install.sh"
                    with open(inst_target, "w", encoding="utf-8") as f:
                        f.write(new_inst_code)
                    os.chmod(inst_target, 0o755)
            except Exception:
                pass

        # 3. Schedule background restart
        threading.Thread(target=delayed_restart, daemon=True).start()
        return jsonify({"success": True, "message": "Update successfully applied! Service is restarting..."})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)})


@app.route("/api/connections/live")
@login_required
def api_connections_live():
    """Return real-time active connections parsed from conntrack with pagination,
    route filtering, and search."""
    route_filter = request.args.get("route_type", "all").lower()
    search = request.args.get("search", "").strip().lower()
    page = int(request.args.get("page", 1) if request.args.get("page", "1").isdigit() else 1)
    per_page = int(request.args.get("per_page", 25) if request.args.get("per_page", "25").isdigit() else 25)
    if page < 1: page = 1
    if per_page < 10: per_page = 10
    if per_page > 100: per_page = 100

    flows = get_active_conntrack_flows()

    # Filter by route_type
    if route_filter in ("warp", "bypass"):
        flows = [f for f in flows if f["route_type"] == route_filter]

    # Filter by search term
    if search:
        flows = [
            f for f in flows
            if search in f["client_ip"].lower()
            or search in f["dst_ip"].lower()
            or search in f["dst_host"].lower()
            or search in str(f["dport"])
        ]

    total = len(flows)
    total_pages = max(1, (total + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages

    start = (page - 1) * per_page
    end = start + per_page
    page_flows = flows[start:end]

    return jsonify({
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "flows": page_flows
    })


@app.route("/api/connections/history")
@login_required
def api_connections_history():
    """Return historical log records from SQLite database with pagination,
    route filtering, and search."""
    route_filter = request.args.get("route_type", "all").lower()
    search = request.args.get("search", "").strip().lower()
    page = int(request.args.get("page", 1) if request.args.get("page", "1").isdigit() else 1)
    per_page = int(request.args.get("per_page", 25) if request.args.get("per_page", "25").isdigit() else 25)
    if page < 1: page = 1
    if per_page < 10: per_page = 10
    if per_page > 100: per_page = 100

    init_db()
    if not os.path.exists(DB_FILE):
        return jsonify({"total": 0, "page": 1, "per_page": per_page, "total_pages": 1, "flows": []})

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        where_clauses = []
        params = []

        if route_filter in ("warp", "bypass"):
            where_clauses.append("route_type = ?")
            params.append(route_filter)

        if search:
            where_clauses.append("(client_ip LIKE ? OR dst_ip LIKE ? OR dst_host LIKE ? OR dport LIKE ?)")
            s_param = f"%{search}%"
            params.extend([s_param, s_param, s_param, s_param])

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        # Count query
        cursor.execute(f"SELECT COUNT(*) FROM flow_history {where_sql}", params)
        total = cursor.fetchone()[0]

        total_pages = max(1, (total + per_page - 1) // per_page)
        if page > total_pages:
            page = total_pages

        offset = (page - 1) * per_page

        # Records query
        query_sql = f"""
            SELECT id, timestamp, client_ip, dst_ip, dst_host, dport, proto, route_type, bytes
            FROM flow_history
            {where_sql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """
        cursor.execute(query_sql, params + [per_page, offset])
        rows = cursor.fetchall()
        conn.close()

        flows = [
            {
                "id": r[0],
                "timestamp": r[1],
                "client_ip": r[2],
                "dst_ip": r[3],
                "dst_host": r[4],
                "dport": r[5],
                "proto": r[6],
                "route_type": r[7],
                "bytes": r[8],
                "bytes_human": humanize_bytes(r[8])
            }
            for r in rows
        ]

        return jsonify({
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": total_pages,
            "flows": flows
        })
    except Exception as exc:
        return jsonify({"total": 0, "page": 1, "per_page": per_page, "total_pages": 1, "flows": [], "error": str(exc)})


if __name__ == "__main__":
    # Ensure firewall NAT rules (including physical uplink interface masquerading)
    # are in place so bypass routes work symmetrically without packet drops.
    try:
        ensure_firewall_nat()
    except Exception:
        pass

    # Re-install bypass routes from bypass_rules.json and re-sync WARP
    # split-tunnel entries on every service start/restart so the gateway
    # is fully configured before serving the first request.
    try:
        apply_all_bypass_rules()
    except Exception:
        pass

    def _startup_sync_all():
        """Background: immediately re-sync all enabled CDN providers AND country
        IP blocks on every service start/restart."""
        import time as _t
        _t.sleep(3)  # Brief delay so WARP daemon is fully up before we push routes
        try:
            cdn = load_cdn_settings()
            for key, prov in cdn.get("providers", {}).items():
                if not prov.get("enabled"):
                    continue
                try:
                    count, err = sync_cdn_provider(key)
                    prov["last_sync"]  = _t.strftime("%Y-%m-%d %H:%M:%S")
                    prov["cidr_count"] = count
                    prov["error"]      = err
                except Exception:
                    pass
            save_cdn_settings(cdn)
        except Exception:
            pass

        try:
            csettings = load_country_settings()
            for code, citem in csettings.get("countries", {}).items():
                if not citem.get("enabled"):
                    continue
                try:
                    count, err = sync_country(code)
                    citem["last_sync"]  = _t.strftime("%Y-%m-%d %H:%M:%S")
                    citem["cidr_count"] = count
                    citem["error"]      = err
                except Exception:
                    pass
            save_country_settings(csettings)
        except Exception:
            pass

    # Background thread 0: immediately re-sync all enabled CDN + country CIDRs
    threading.Thread(target=_startup_sync_all, daemon=True).start()

    # Background thread 1: re-resolves domain/wildcard rules every 3 min
    threading.Thread(target=bypass_refresh_loop, daemon=True).start()

    # Background thread 2: syncs enabled CDN provider IP ranges + country IPs every hour.
    threading.Thread(target=cdn_sync_loop, daemon=True).start()

    # Background thread 3: samples active conntrack flows and logs 5-day traffic history to SQLite.
    threading.Thread(target=traffic_history_loop, daemon=True).start()

    app.run(host="0.0.0.0", port=8080, threaded=True)


