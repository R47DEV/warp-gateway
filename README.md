

# 🛡️ WARP Gateway & Sub-Router Engine

**WARP Gateway** is an enterprise-grade, automated Linux installation script that transforms any Ubuntu LXC Container, Virtual Machine, or Server into a dedicated Cloudflare WARP Sub-Router and Encrypted Network Gateway. 

It comes with a built-in modern, Glassmorphism-styled Web Dashboard secured with admin credentials to easily toggle Cloudflare WARP encryption **ON/OFF** for your local network traffic.

---

## 🌟 Key Features

* **⚡ One-Command Installation:** Fully automated setup of Cloudflare WARP, kernel network forwarding, and firewall NAT rules.
* **🔒 Secured Web Dashboard:** Session-based Admin Authentication protects against unauthorized access.
* **🎨 Glassmorphism UI:** Modern, dark-themed responsive UI displaying live Public WAN IP, Gateway IP, and Connection Status.
* **🛠️ Self-Healing Service:** Integrated `systemd` daemon that automatically recovers and restarts the service if disrupted.
* **🔀 Sub-Router Capability:** Route traffic from any device on your Local Network (LAN) through this Gateway by simply changing their Default Gateway IP.
* **🛡️ Non-Destructive Cleanup:** Lightweight footprint designed for clean isolated containers like Proxmox LXC.

---

## 📐 Architecture & How It Works


```

[ LAN Devices ] ---> [ WARP Sub-Router (This Gateway) ] ---> [ Cloudflare WARP Network ] ---> [ Internet ]
(PC, TV, Phone)        (IP Forwarding & NAT Enabled)         (Encrypted WAN Tunnel)

```

1. **IP Forwarding & NAT:** The gateway routes incoming traffic from local client devices through its `CloudflareWARP` network interface using IPTables Masquerading.
2. **One-Click Toggle:** When WARP is turned **ON** via the Web UI, all client traffic routed through this gateway is encrypted and anonymized. When turned **OFF**, traffic passes directly through standard ISP WAN routing.

---

## 🖥️ System Requirements

* **Operating System:** Ubuntu 22.04 LTS (Recommended) 
* **Supported Environments:** Proxmox LXC Container (Privileged with TUN/TAP enabled > [Unprivieged contaner Uncheck]), KVM VM, Dedicated Server, or Raspberry Pi.
* **Resource Footprint:** 
  * CPU: 1 Core
  * RAM: 256 MB (512 MB recommended)
  * Disk: 6 GB

---

## 🚀 One-Line Quick Installation

Run the following command on your target Ubuntu/Debian system as `root`:

```bash
apt update && apt upgrade -y && apt install curl -y && curl -sSL [https://raw.githubusercontent.com/R47DEV/warp-gateway/main/install.sh](https://raw.githubusercontent.com/R47DEV/warp-gateway/main/install.sh) | bash

```

> **Note during installation:** The installer will prompt you to set an **Admin Username** and **Password** for accessing the Web Control Panel.

---

## 🔧 Proxmox LXC Prerequisites

If installing inside a Proxmox LXC container, ensure **TUN/TAP** and **Nesting** are enabled before starting the container. Run these lines on your Proxmox Host shell:

```bash
echo "lxc.cgroup2.devices.allow: c 10:200 rwm" >> /etc/pve/lxc/<CONTAINER_ID>.conf
echo "lxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file" >> /etc/pve/lxc/<CONTAINER_ID>.conf
echo "features: nesting=1" >> /etc/pve/lxc/<CONTAINER_ID>.conf

```

*(Replace `<CONTAINER_ID>` with your LXC ID, e.g., `104`)*

---

## 📱 How to Use the Web Dashboard

1. After installation, access the Web Dashboard from your browser:
```text
http://<GATEWAY_IP>:8080

```


2. Log in using your configured **Admin Credentials**.
3. **Control Status:**
* **Turn ON WARP Gateway:** Connects to Cloudflare WARP. Your network traffic is now routed through Cloudflare's secure tunnel.
* **Turn OFF WARP Gateway:** Disconnects WARP. Traffic routes directly via your local standard ISP connection.



---

## 🌐 Configuring Client Devices (Sub-Router Setup)

To route a specific device's internet traffic (e.g., Smart TV, PC, Mobile) through this WARP Gateway:

1. Open your device's **Network Settings**.
2. Change IP Configuration from **DHCP** to **Static**.
3. Set the **Default Gateway / Router IP** to your **WARP Gateway IP** (e.g., your WARP Gateway web ui ip `192.168.0.222`).
4. Set DNS to your preferred server (e.g., `1.1.1.1` or AdGuard Home IP).

---

## 📄 License

Distributed under the Apache-2.0 License. See `LICENSE` for more information.

