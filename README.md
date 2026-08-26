<p align="center">
  <img src="logo.png" width="240" alt="WARP Gateway Logo">
</p>

# 🛡️ WARP Gateway & Enterprise Sub-Router Engine

[![Version](https://img.shields.io/badge/version-1.0.2-blue.svg)](https://github.com/R47DEV/warp-gateway)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)

**WARP Gateway** is an enterprise-grade, automated Linux installation script and web application that transforms any Ubuntu LXC Container, Virtual Machine, or Server into a dedicated Cloudflare WARP Sub-Router and Encrypted Network Gateway.

It features a modern, Glassmorphism-styled Web Dashboard with live traffic analytics, dynamic split-tunneling for domestic banking apps, global RIR/CDN auto-sync, custom wildcard bypass rules, 5-day historical connection logging, date/time traffic flow filtering, and one-click in-app auto-updating.

---

## 🌟 Key Features

* **⚡ One-Command Automated Setup:** Complete automated installation of Cloudflare WARP, kernel packet forwarding, sysctl optimization, and IPTables NAT masquerading.
* **🔒 Secured Web Dashboard:** Session-based authentication protecting the web management console (`/opt/warpgateway/credentials.json`).
* **📊 Real-Time Traffic Routing Analytics:** Live `conntrack` inspection displaying active connection counts, byte throughput, and percentage distribution between **WARP Encrypted Tunnel** vs **Direct ISP Bypassed** traffic.
* **📜 5-Day Historical Connection Logging & Inspector:** SQLite-backed connection logger capturing client IP, destination IP/domain, port, protocol, and route type with date/time filters (`Today`, `Yesterday`, `Last 24 Hours`, or `Custom Date`) and pagination (20/30/50/100 per page).
* **📱 Connected Devices Request Counter:** Monitors connected ARP table devices and displays total connection requests sent over the last 5 days alongside live active connections.
* **🌍 National IP Auto-Bypass (240+ Countries):** Automatic real-time IPv4 allocation sync via RIPE stat for any country (e.g. BD, IN, AE, US, GB), routing domestic banking, government, and ISP traffic directly to avoid geo-blocks.
* **☁️ Global Cloud & CDN Provider Auto-Sync:** Automated hourly sync for authoritative IP ranges across **Cloudflare CDN (Global)**, **AWS CloudFront (Global CDN)**, **AWS Asia-Pacific**, and **AWS Europe**.
* **🔀 Custom Split-Tunneling & Wildcard Rules:** Add domains, full URLs, IPs, CIDRs, or wildcard patterns (e.g. `*.example.com`). Wildcards automatically probe common payment and API subdomains.
* **📥 One-Click Bypass Rules Export & Backup:** Export all custom bypass rules into a clean plain-text file (`warp_gateway_bypass_rules.txt`) for one-click backup and easy re-importing.
* **🔄 Built-In Auto-Updater & Version Checker:** Automated version checking against GitHub releases with non-blocking status notifications, toast alerts, and background service restarts.
* **🛡️ Non-Destructive Update Installer:** Installer automatically detects existing setups and preserves admin credentials and system configuration during upgrades.
* **🛠️ Self-Healing Service:** Systemd daemon (`warpgateway.service`) with auto-restart and startup sync to ensure bypass routes survive server or WARP daemon reboots.

---

## 📐 Architecture & Routing Flow

```text
                                ┌───► Bypassed Traffic (Banking/CDNs/National IPs) ───► Local ISP Gateway ───► Internet (Direct)
[ LAN Devices ] ──► [ WARP Gateway ]
(PC, TV, Phone)     (IP Forwarding & NAT)
                                └───► International Encrypted Traffic ───────────────► Cloudflare WARP ──────► Internet (Encrypted)
```

1. **Smart Packet Classification:** Incoming LAN traffic is inspected against kernel host routes and WARP split-tunnel exclusions.
2. **Domestic & Financial Bypass:** Traffic targeting national IP blocks or enabled CDN edge ranges is routed directly via the physical uplink interface (`eth0`, `wlan0`, etc.) using NAT masquerading.
3. **Encrypted Tunneling:** All other international internet traffic is securely encrypted and tunneled through Cloudflare WARP.

---

## 🖥️ System Requirements

* **Operating System:** Ubuntu 22.04 LTS (Recommended) or Debian 11/12
* **Supported Environments:** Proxmox LXC Container (TUN/TAP enabled), KVM VM, Dedicated Server, or Raspberry Pi.
* **Resource Footprint:** 
  * CPU: 1 Core
  * RAM: 256 MB (512 MB recommended)
  * Disk: 6 GB

---

## 🚀 One-Line Quick Installation

Run the following command on your target Linux system as `root`:

```bash
apt update && apt upgrade -y && apt install curl -y && curl -sSL https://raw.githubusercontent.com/R47DEV/warp-gateway/main/install.sh | bash
```

> **Note during first installation:** The installer will prompt you to set an **Admin Username** and **Password** for accessing the Web Control Panel. Subsequent re-runs or updates automatically preserve existing credentials.

---

## 🔧 Proxmox LXC Prerequisites

If installing inside a Proxmox LXC container, ensure **TUN/TAP** and **Nesting** are enabled. Add the following lines to your container configuration on the Proxmox Host shell (`/etc/pve/lxc/<CONTAINER_ID>.conf`):

```bash
echo "lxc.cgroup2.devices.allow: c 10:200 rwm" >> /etc/pve/lxc/<CONTAINER_ID>.conf
echo "lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file" >> /etc/pve/lxc/<CONTAINER_ID>.conf
echo "features: nesting=1" >> /etc/pve/lxc/<CONTAINER_ID>.conf
```

*(Replace `<CONTAINER_ID>` with your LXC ID, e.g., `104`)*

---

## 📱 Web Dashboard Overview

After installation, open your browser and navigate to:
```text
http://<GATEWAY_IP>:8080
```

### Dashboard Tabs & Controls
* **Dashboard:** Real-time WARP connection status, WAN/LAN IP display, live bandwidth throughput graphs, speed test, traffic routing analysis card, and 5-day Traffic Flow Inspector with date/time filters.
* **Bypass Rules:** Configure **National IP Auto-Bypass**, toggle **Global CDN Provider Sync**, add custom domains/wildcards, and export rule backups.
* **Network Info:** Detailed interfaces, WARP client account information, and connected LAN client table with 5-day request counters.
* **Service Logs:** Embedded `journalctl` log viewer for real-time troubleshooting.
* **Admin Settings:** Change dashboard credentials and update system preferences.

---

## 🌐 Configuring LAN Client Devices (Sub-Router Setup)

To route client devices (Smart TVs, Mobile Phones, PCs, Gaming Consoles) through the WARP Gateway:

1. Open your device's **Network Settings**.
2. Change IP Configuration from **DHCP** to **Static**.
3. Set the **Default Gateway / Router IP** to your **WARP Gateway IP** (e.g. `192.168.1.222`).
4. Set DNS to your preferred server (e.g. `1.1.1.1` or `8.8.8.8`).

---

## 📄 License

Distributed under the Apache-2.0 License. See `LICENSE` for more information.
