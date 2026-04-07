# Home SOC — Network Security Monitor
### Project Specification v3.0 — Hardened Edition

> **Authored from the perspective of a home cybersecurity architect.**
> This is a ground-up revision of v2.0 incorporating: hardened OS, inline gateway topology, NordVPN integration, a safe kill-switch engine, three development phases (DEV/TEST/PROD), and WSL-first local development support. Claude Code must read this entire document before writing a single line of code.

---

## 0. Development Phases — Gate Model

The project is divided into three phases. **No phase may begin until the previous phase has been explicitly approved by the owner.** Claude Code is responsible for implementing DEV and TEST. PROD deployment is owner-gated.

```
┌──────────────────────────────────────────────────────────────────┐
│  PHASE 1 — DEV                                                   │
│  Environment: WSL2 on Windows (Ubuntu 22.04 or 24.04)           │
│  Purpose: Full stack running locally, simulated data, no        │
│           hardware dependencies                                  │
│  Exit gate: Owner reviews dashboard, alerts, and kill-switch    │
│             logic in simulation — signs off to move to TEST     │
├──────────────────────────────────────────────────────────────────┤
│  PHASE 2 — TEST                                                  │
│  Environment: Mini PC on real home network, real traffic,       │
│               real Suricata/Zeek/CrowdSec, real Telegram alerts │
│  Purpose: Validate all sensors against live network data        │
│  Exit gate: Owner validates alerts are accurate, no false       │
│             positives on normal usage, kill-switch tested safely│
├──────────────────────────────────────────────────────────────────┤
│  PHASE 3 — PROD                                                  │
│  Environment: Mini PC hardened, inline gateway topology,        │
│               NordVPN live, auto kill-switch armed              │
│  Purpose: 24/7 production operation                             │
│  Entry: Only after explicit owner sign-off on TEST              │
└──────────────────────────────────────────────────────────────────┘
```

### Phase flags in `.env`

```env
PHASE=DEV          # DEV | TEST | PROD
SIMULATE=true      # true in DEV, false in TEST/PROD
AUTO_KILL_ON_CRITICAL=false   # false in DEV/TEST, owner decides for PROD
```

The backend reads `PHASE` at startup and adjusts behaviour:
- `DEV`: uses simulated sensor data, disables all real hardware calls, runs on localhost
- `TEST`: uses real sensors, Telegram alerts active, kill-switch always requires manual confirmation regardless of `AUTO_KILL_ON_CRITICAL`
- `PROD`: full operation, all features live

---

## 1. Threat Model

The following threats are in scope, ordered by real-world frequency:

**Tier 1 — Daily automated attacks**
- Botnet port scans probing SSH, RDP, Telnet, admin panel default ports
- Credential stuffing against router admin interfaces
- DNS hijacking via malicious DHCP responses
- IoT exploitation targeting default credentials on cameras, smart plugs, TVs

**Tier 2 — Targeted intrusion**
- ARP poisoning / man-in-the-middle on the LAN
- Rogue Wi-Fi AP impersonating your SSID
- VPN traffic correlation / deanonymisation by ISP
- Supply-chain compromise of a software package phoning home

**Tier 3 — Data exfiltration (worst case)**
- Compromised device silently sending data outbound
- Ransomware lateral movement across LAN devices
- Cryptomining malware consuming bandwidth and CPU

**What NordVPN addresses:** Outbound privacy — hides your real IP, encrypts traffic to ISP. It does NOT protect against Tier 1 or Tier 2 (those originate inside the LAN). The SOC handles Tier 1–3 independently.

---

## 2. Architecture

### 2.1 Production topology (PROD phase)

```
[ISP Modem / ONT]
        │
        │ eth0 — raw WAN
        ▼
┌────────────────────────────────────────────┐
│         Mini PC — Security Gateway          │
│                                            │
│  ┌──────────────────────────────────────┐  │
│  │ Layer 1: nftables firewall           │  │
│  │ Layer 2: Suricata IDS/IPS (inline)   │  │
│  │ Layer 3: Zeek (protocol logging)     │  │
│  │ Layer 4: CrowdSec (community intel)  │  │
│  │ Layer 5: Pi-hole + Unbound (DNS)     │  │
│  │ Layer 6: NordVPN (WAN encryption)    │  │
│  │ Layer 7: Kill-switch engine          │  │
│  └──────────────────────────────────────┘  │
│                                            │
│  SOC Backend (FastAPI :8000)               │
│  SOC Dashboard (nginx :3000)               │
│  WireGuard VPN (:51820)                    │
│  Uptime Kuma (:3002)                       │
│  Restic backup (cron)                      │
└────────────────────────────────────────────┘
        │ eth1 — clean monitored LAN
        ▼
[Home Router / Wi-Fi AP] ←── [Hombli Smart Plug]
        │                    (between wall socket
        │                     and router PSU)
        ▼
[All home devices — phones, laptops, IoT, TV]
```

**Critical constraint:** The mini PC's own power supply is plugged directly into the wall, NOT through the Hombli plug. The mini PC stays alive and continues monitoring after the router kill.

### 2.2 DEV topology (WSL)

```
[WSL2 Ubuntu on Windows]
        │
  Docker Compose network
        │
  ┌─────┴──────────────────────────────────┐
  │  home-soc-backend   (FastAPI :8000)    │
  │  home-soc-frontend  (nginx :3000)      │
  │  home-soc-simulator (fake events)      │
  │  pihole             (:8080 admin)      │
  │  uptime-kuma        (:3002)            │
  └────────────────────────────────────────┘
        │
  Browser on Windows → http://localhost:3000
```

No Suricata, Zeek, CrowdSec, WireGuard, NordVPN, or tinytuya in DEV — all replaced by the simulator.

---

## 3. Repository Structure

```
home-soc/
├── README.md
├── HOME_SOC_SPEC.md              ← this file
├── .env.example                  ← template, copy to .env
├── .env                          ← never committed (in .gitignore)
├── .gitignore
│
├── docker-compose.yml            ← DEV phase (WSL)
├── docker-compose.test.yml       ← TEST phase overrides
│
├── backend/
│   ├── main.py                   ← FastAPI entry point
│   ├── config.py                 ← env-based config, phase-aware
│   ├── database.py               ← SQLite via aiosqlite
│   ├── models.py                 ← Pydantic schemas
│   ├── phase.py                  ← phase detection helpers
│   ├── routers/
│   │   ├── events.py             ← GET /events, SSE /events/stream
│   │   ├── devices.py            ← GET /devices, POST /devices/{mac}/whitelist
│   │   ├── metrics.py            ← GET /metrics
│   │   ├── plug.py               ← POST /plug/on|off, GET /plug/status
│   │   ├── telegram.py           ← POST /telegram/webhook (bot commands)
│   │   └── nordvpn.py            ← GET /vpn/status (PROD only)
│   ├── sensors/
│   │   ├── base.py               ← abstract sensor class
│   │   ├── suricata.py           ← tail /var/log/suricata/fast.log
│   │   ├── fail2ban.py           ← tail /var/log/fail2ban.log
│   │   ├── zeek.py               ← tail Zeek TSV logs
│   │   ├── crowdsec.py           ← poll CrowdSec local API
│   │   ├── arp_scan.py           ← arp-scan device discovery
│   │   ├── traffic.py            ← /proc/net/dev interface stats
│   │   └── nordvpn_sensor.py     ← nordvpn status polling
│   ├── simulator/
│   │   ├── engine.py             ← generates realistic fake events (DEV)
│   │   └── scenarios.py          ← attack scenario definitions
│   ├── alerting/
│   │   ├── telegram.py           ← Telegram Bot API (alerts + commands)
│   │   └── severity.py           ← scoring rules + kill-switch logic
│   ├── integrations/
│   │   ├── tuya_plug.py          ← tinytuya Hombli control
│   │   └── nordvpn.py            ← nordvpn CLI wrapper
│   └── requirements.txt
│
├── frontend/
│   ├── package.json
│   ├── vite.config.ts
│   ├── index.html
│   └── src/
│       ├── main.tsx
│       ├── App.tsx
│       ├── api/client.ts
│       ├── components/
│       │   ├── Header.tsx         ← shows phase badge (DEV/TEST/PROD)
│       │   ├── MetricCard.tsx
│       │   ├── IncidentFeed.tsx
│       │   ├── DeviceList.tsx
│       │   ├── ThreatBars.tsx
│       │   ├── TrafficSparkline.tsx
│       │   ├── HistogramChart.tsx
│       │   ├── PlugControl.tsx
│       │   ├── VpnStatus.tsx      ← NordVPN connection badge
│       │   └── PhaseWarning.tsx   ← yellow banner in DEV/TEST
│       ├── hooks/
│       │   ├── useEvents.ts
│       │   ├── useDevices.ts
│       │   ├── useMetrics.ts
│       │   └── useVpnStatus.ts
│       └── styles/dashboard.css
│
├── scripts/
│   ├── dev/
│   │   └── start_wsl.sh          ← one-command DEV startup in WSL
│   ├── install/
│   │   ├── install.sh            ← master install (TEST/PROD)
│   │   ├── setup_system.sh       ← apt, sysctl, OS hardening
│   │   ├── setup_hardening.sh    ← SSH, nftables, AppArmor, auditd
│   │   ├── setup_suricata.sh
│   │   ├── setup_zeek.sh
│   │   ├── setup_fail2ban.sh
│   │   ├── setup_crowdsec.sh
│   │   ├── setup_pihole.sh
│   │   ├── setup_nordvpn.sh      ← NordVPN NordLynx setup
│   │   ├── setup_ntopng.sh
│   │   ├── setup_backend.sh
│   │   ├── setup_frontend.sh
│   │   ├── setup_nginx.sh
│   │   ├── setup_wireguard.sh    ← admin remote access VPN
│   │   ├── setup_homeassistant.sh
│   │   ├── setup_uptime_kuma.sh
│   │   ├── setup_restic.sh
│   │   └── wireguard_add_client.sh
│   ├── maintenance/
│   │   ├── watchdog.sh           ← service health check (cron)
│   │   ├── nordvpn_watchdog.sh   ← VPN reconnect watchdog
│   │   └── soc-backup.sh         ← Restic backup script
│   └── systemd/
│       ├── home-soc-backend.service
│       ├── home-soc-watchdog.service
│       └── home-soc-watchdog.timer
│
└── config/
    ├── nginx.conf
    ├── nftables.conf             ← full firewall ruleset
    ├── sysctl-hardening.conf     ← kernel parameters
    ├── suricata/suricata.yaml
    ├── fail2ban/jail.local
    ├── unbound/pi-hole.conf
    └── apparmor/                 ← profiles for SOC services
```

---

## 4. Phase 1 — DEV on WSL

### 4.1 Prerequisites on Windows

1. Install WSL2: `wsl --install` in PowerShell (admin)
2. Install Ubuntu 24.04 from the Microsoft Store
3. Install Docker Desktop for Windows — enable WSL2 backend
4. Clone the repo inside WSL: `git clone https://github.com/YOUR_USERNAME/home-soc.git`

### 4.2 One-command startup

```bash
cd home-soc
cp .env.example .env
# Edit .env: set PHASE=DEV, SIMULATE=true, add your Telegram bot token
bash scripts/dev/start_wsl.sh
```

`start_wsl.sh` does:
```bash
#!/bin/bash
set -e
echo "=== Home SOC — DEV mode on WSL ==="
docker compose up --build -d
echo ""
echo "Dashboard:   http://localhost:3000"
echo "Pi-hole:     http://localhost:8080/admin"
echo "Uptime Kuma: http://localhost:3002"
echo ""
echo "Logs: docker compose logs -f backend"
echo "Stop: docker compose down"
```

### 4.3 Docker Compose (DEV)

```yaml
# docker-compose.yml
version: "3.9"

services:
  backend:
    build: ./backend
    ports:
      - "8000:8000"
    volumes:
      - ./backend:/app
      - soc-data:/data
    environment:
      - PHASE=DEV
      - SIMULATE=true
      - DATABASE_PATH=/data/soc.db
    env_file: .env
    restart: unless-stopped

  frontend:
    build: ./frontend
    ports:
      - "3000:80"
    depends_on:
      - backend
    restart: unless-stopped

  pihole:
    image: pihole/pihole:latest
    ports:
      - "8080:80"
      - "53:53/udp"
    environment:
      WEBPASSWORD: "changeme"
    volumes:
      - pihole-data:/etc/pihole
    restart: unless-stopped

  uptime-kuma:
    image: louislam/uptime-kuma:1
    ports:
      - "3002:3001"
    volumes:
      - kuma-data:/app/data
    restart: unless-stopped

volumes:
  soc-data:
  pihole-data:
  kuma-data:
```

### 4.4 Simulator — what it generates

The simulator (`backend/simulator/engine.py`) runs when `SIMULATE=true` and generates realistic events at randomised intervals. It covers every threat category:

```python
SCENARIOS = [
    # (category, severity, interval_range_seconds, description_template)
    ("BRUTE_FORCE", "CRITICAL", (30, 120),
        "SSH brute-force — {count} attempts in 60s from {src_ip}"),
    ("PORT_SCAN", "WARNING", (60, 300),
        "Port scan detected — {port_count} ports probed from {src_ip}"),
    ("ROGUE_DEVICE", "WARNING", (300, 900),
        "Unknown device joined network — MAC {mac} IP {ip}"),
    ("DNS_ANOMALY", "INFO", (120, 600),
        "DNS query to flagged domain: {domain}"),
    ("TRAFFIC_ANOMALY", "WARNING", (600, 1800),
        "Outbound traffic spike — {volume} MB from {src_ip} in 10min"),
    ("ARP_SPOOF", "CRITICAL", (1800, 7200),
        "ARP spoofing detected — MAC mismatch on {ip}"),
    ("DDOS", "CRITICAL", (3600, 14400),
        "SYN flood from {src_ip} — {pps} packets/s"),
    ("C2_CONTACT", "CRITICAL", (7200, 86400),
        "Known C2 IP contacted: {ip} ({country})"),
    ("VPN_DROP", "WARNING", (1800, 7200),
        "NordVPN tunnel dropped — reconnecting"),
]
```

The simulator also generates fake device lists, fake traffic sparkline data, and fake NordVPN status — everything the dashboard needs to look fully operational without any real hardware.

### 4.5 DEV phase checklist (owner must verify before moving to TEST)

- [ ] Dashboard loads at http://localhost:3000 and shows live simulated events
- [ ] Incident feed scrolls in real time with all severity levels
- [ ] Metric cards update as new events arrive
- [ ] Telegram alerts fire for WARNING and CRITICAL events (requires real bot token in .env)
- [ ] Telegram `/status` command returns current threat level
- [ ] Kill-switch UI shows ARM → ARMED → triggered flow (simulated, no real plug)
- [ ] Telegram `/kill` sends pre-warning message and counts down
- [ ] Telegram `/cancel` aborts the kill within the 30-second window
- [ ] Telegram `/restore` simulates plug restore
- [ ] Pi-hole admin accessible at http://localhost:8080
- [ ] Uptime Kuma accessible at http://localhost:3002
- [ ] NordVPN status badge shows "SIMULATED" in DEV mode
- [ ] Phase banner shows "DEV — SIMULATED DATA" clearly on dashboard

---

## 5. Phase 2 — TEST on Real Hardware

### 5.1 TEST phase differences from PROD

| Feature | TEST | PROD |
|---------|------|------|
| Suricata | Real, passive (alert only) | Real, inline (can drop) |
| Kill-switch auto | ALWAYS manual confirm | Owner's choice |
| NordVPN | Optional | Required |
| nftables | Monitoring mode | Full enforcement |
| Inline gateway | Not required | Required (dual NIC) |
| GeoIP blocking | Off | On |

In TEST phase, the mini PC is connected to the network **passively** — plugged into a switch port, not inline between modem and router. This means Suricata sees traffic via promiscuous mode but cannot drop it. The kill-switch still operates via the Hombli plug.

### 5.2 TEST installation

```bash
# On the mini PC, after Ubuntu Server 24.04 is installed
git clone https://github.com/YOUR_USERNAME/home-soc.git /opt/home-soc
cd /opt/home-soc
cp .env.example .env
# Edit .env: PHASE=TEST, SIMULATE=false, add all real credentials
bash scripts/install/install.sh
```

### 5.3 TEST phase checklist (owner must verify before moving to PROD)

- [ ] Real Suricata events appear in the dashboard within 5 minutes of network activity
- [ ] SSH brute-force test (from a second machine): `for i in {1..20}; do ssh invalid@soc-box; done` — verify CRITICAL alert fires on Telegram
- [ ] Port scan test: `nmap -sS 192.168.1.1` — verify WARNING alert fires
- [ ] New device test: connect a new device to Wi-Fi — verify ROGUE_DEVICE WARNING fires
- [ ] Telegram `/status` returns real threat level, real VPN status, real plug state
- [ ] Telegram `/kill` — test with `/cancel` within 30 seconds (abort test)
- [ ] Hombli plug physically cuts router power when `/kill` confirmed (test once, carefully)
- [ ] Telegram `/restore` restores router power
- [ ] Pi-hole DNS working for all devices (check in router DHCP settings)
- [ ] WireGuard VPN: connect from mobile outside home network, verify dashboard accessible
- [ ] Uptime Kuma alerts fire when backend is stopped manually
- [ ] Restic backup runs and produces encrypted archive
- [ ] No false positives on normal browsing, streaming, gaming for 48 hours
- [ ] Owner sign-off: _______________________ Date: _____________

---

## 6. Phase 3 — PROD

PROD phase is identical to TEST with the following additional steps:

1. Mini PC moved to **inline gateway position** (between modem and router, using both NICs)
2. Suricata switched to **inline IPS mode** (can actively drop malicious packets)
3. NordVPN enabled on WAN interface
4. nftables full enforcement with GeoIP blocking enabled
5. `AUTO_KILL_ON_CRITICAL` set to owner's preference in `.env`
6. SSH access locked to WireGuard tunnel only (no direct LAN SSH)

---

## 7. OS Hardening (TEST + PROD)

Automated in `scripts/install/setup_hardening.sh`.

### 7.1 SSH hardening

```
# /etc/ssh/sshd_config
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
MaxAuthTries 3
LoginGraceTime 20
AllowUsers soc-admin
X11Forwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
```

Owner generates key on their machine before install:
```bash
ssh-keygen -t ed25519 -C "home-soc-admin"
# Public key path goes into .env as SSH_PUBLIC_KEY
# Install script writes it to /home/soc-admin/.ssh/authorized_keys
```

### 7.2 nftables firewall

```
# /etc/nftables.conf
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    ct state invalid drop
    iif lo accept
    ip protocol icmp limit rate 5/second accept
    tcp dport 22 ip saddr 192.168.1.0/24 accept   # SSH from LAN only
    tcp dport 3000 ip saddr 192.168.1.0/24 accept  # Dashboard
    tcp dport 8080 ip saddr 192.168.1.0/24 accept  # Pi-hole admin
    tcp dport 8123 ip saddr 192.168.1.0/24 accept  # Home Assistant
    udp dport 51820 accept                          # WireGuard
    udp dport 53 ip saddr 192.168.1.0/24 accept    # DNS (Pi-hole)
    drop
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    ct state invalid drop
    iif eth0 oif eth1 ct state new accept   # WAN → LAN
    iif eth1 oif eth0 accept                # LAN → WAN (Suricata inspects)
  }
  chain output {
    type filter hook output priority 0; policy accept;
  }
}

table ip nat {
  chain postrouting {
    type nat hook postrouting priority 100;
    # In PROD with NordVPN:
    oif "nordlynx" masquerade
    # In TEST without NordVPN:
    # oif eth0 masquerade
  }
}
```

### 7.3 Kernel hardening (sysctl)

```
# /etc/sysctl.d/99-soc-hardening.conf
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.suid_dumpable = 0
```

### 7.4 Automatic security updates

```bash
sudo apt-get install -y unattended-upgrades
# Configure: security updates only, auto-reboot at 3:30am if required
sudo tee /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
```

### 7.5 System watchdog (hardware)

Prevents kernel hangs from leaving the system unresponsive:
```
# /etc/systemd/system.conf additions
RuntimeWatchdogSec=30
RebootWatchdogSec=10min
```

### 7.6 Disable unused services

```bash
sudo systemctl disable --now bluetooth avahi-daemon cups snapd ModemManager
sudo systemctl mask bluetooth avahi-daemon cups snapd ModemManager
```

---

## 8. NordVPN Integration

### 8.1 Role in the architecture

NordVPN encrypts **all outbound traffic** from every device on your home network. Installed on the mini PC at the WAN interface level, it acts as a whole-home VPN without requiring the app on any device.

Suricata and Zeek inspect traffic **before** it enters the NordVPN tunnel — you retain full visibility of what your devices are actually doing.

### 8.2 Installation (`scripts/install/setup_nordvpn.sh`)

```bash
#!/bin/bash
# Requires NORDVPN_TOKEN in .env
source /opt/home-soc/.env

# Install NordVPN Linux client
sh <(curl -sSf https://downloads.nordcdn.com/apps/linux/install.sh)
usermod -aG nordvpn $USER

# Login with access token
nordvpn login --token "$NORDVPN_TOKEN"

# Configure
nordvpn set technology nordlynx   # WireGuard-based protocol
nordvpn set firewall off           # nftables handles firewall
nordvpn set killswitch on          # NordVPN's software kill-switch as extra layer
nordvpn set autoconnect on
nordvpn set dns off                # Pi-hole handles all DNS
nordvpn set notify off

# Connect
nordvpn connect

# Update nftables to route through nordlynx
# (setup_nginx.sh will also update nginx configs)
sed -i 's/oif eth0 masquerade/oif "nordlynx" masquerade/' /etc/nftables.conf
nft -f /etc/nftables.conf

echo "NordVPN connected. Status:"
nordvpn status
```

### 8.3 `.env` variables for NordVPN

```env
NORDVPN_TOKEN=your_nordvpn_access_token
NORDVPN_COUNTRY=Switzerland          # preferred server country
```

### 8.4 NordVPN watchdog (`scripts/maintenance/nordvpn_watchdog.sh`)

Runs every 5 minutes via cron. Reconnects if dropped and sends Telegram alert:

```bash
#!/bin/bash
source /opt/home-soc/.env

STATUS=$(nordvpn status 2>/dev/null | grep "Status:" | awk '{print $2}')

if [ "$STATUS" != "Connected" ]; then
  nordvpn connect --country "$NORDVPN_COUNTRY" 2>/dev/null
  sleep 10
  NEW_STATUS=$(nordvpn status | grep "Status:" | awk '{print $2}')
  
  if [ "$NEW_STATUS" = "Connected" ]; then
    MSG="⚠️ NordVPN dropped and was reconnected at $(date +%H:%M:%S)"
  else
    MSG="🔴 NordVPN FAILED to reconnect at $(date +%H:%M:%S) — your traffic is unprotected"
  fi
  
  curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d chat_id="${TELEGRAM_CHAT_ID}" \
    -d text="$MSG"
fi
```

```
# /etc/cron.d/nordvpn-watchdog
*/5 * * * * soc-admin /opt/home-soc/scripts/maintenance/nordvpn_watchdog.sh
```

### 8.5 NordVPN and intrusion detection nuance

When NordVPN is active, Suricata's `HOME_NET` should include both the LAN subnet and the VPN tunnel subnet:

```yaml
# config/suricata/suricata.yaml
vars:
  address-groups:
    HOME_NET: "[192.168.1.0/24, 10.5.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
```

---

## 9. Kill-Switch Engine — Full Specification

### 9.1 Physical setup

```
Wall socket A ──► [Hombli Smart Plug] ──► [Router power supply]
Wall socket B ──► [Mini PC power supply]
```

The mini PC has its own dedicated power circuit, never through the Hombli plug. After the kill, the mini PC continues running, logging, and alerting.

### 9.2 Kill-switch decision flow

```
New event arrives at severity scorer
           │
    Score ≥ CRITICAL?
           │ No ──► Log + Telegram INFO/WARNING alert
           │ Yes
           ▼
    Is source IP in whitelist?
           │ Yes ──► Suppress kill, log as suppressed
           │ No
           ▼
    Is this a duplicate kill trigger within 10 min?
           │ Yes ──► Suppress (anti-loop)
           │ No
           ▼
    Send Telegram pre-warning:
    "🔴 CRITICAL — [description]
     Source: [IP] ([country])
     Auto-kill in 30s. Reply /cancel to abort."
           │
    Start 30-second countdown
    Poll Telegram for /cancel command
           │
    /cancel received? ──► Abort, log cancellation
           │ No
           ▼
    PHASE == TEST? ──► Skip auto-kill, require manual /kill
           │ No (PROD)
           ▼
    AUTO_KILL_ON_CRITICAL == false?
           │ Yes ──► Send manual kill button, wait for /kill command
           │ No
           ▼
    Ping 1.1.1.1 — is internet reachable?
           │ No ──► Network already down, skip plug kill, log
           │ Yes
           ▼
    Send final Telegram (wait for HTTP 200):
    "🔴 Cutting router power NOW. Use /restore to reconnect."
           │
    plug_off() via tinytuya
           │
    Log kill event to SQLite:
    { timestamp, event_id, source_ip, rule, phase, confirmed_by }
           │
    Dashboard: show "🔴 NETWORK KILLED — use /restore or manual plug"
           │
    Continue monitoring on mini PC
```

### 9.3 Telegram bot commands

Implement a webhook receiver in `backend/routers/telegram.py`:

| Command | Phase | Action |
|---------|-------|--------|
| `/status` | all | Threat level, VPN status, plug state, uptime |
| `/events` | all | Last 10 events with severity |
| `/kill` | TEST/PROD | Manual kill trigger (goes through 30s countdown) |
| `/cancel` | TEST/PROD | Abort pending kill |
| `/restore` | TEST/PROD | Turn router power back on |
| `/arm` | PROD | Enable AUTO_KILL_ON_CRITICAL |
| `/disarm` | PROD | Disable AUTO_KILL_ON_CRITICAL |
| `/whitelist <ip>` | all | Add IP to suppression list |
| `/vpn` | TEST/PROD | NordVPN status and current server |
| `/phase` | all | Show current phase (DEV/TEST/PROD) |
| `/help` | all | List all commands |

### 9.4 Kill-switch safety invariants (never bypass)

1. Never kill if the Telegram confirmation message failed to deliver
2. Never kill if source IP is whitelisted
3. Never kill more than once per 10 minutes (prevents kill-loop)
4. In TEST phase, always require manual `/kill` confirmation, ignore `AUTO_KILL_ON_CRITICAL`
5. Always log full event context before any kill action
6. After `plug_on()`, wait 45 seconds for router boot before clearing KILLED state
7. After restore, run a connectivity check before setting threat level back to normal

---

## 10. Backend Specification

### 10.1 Technology stack
- Python 3.11+, FastAPI, aiosqlite, uvicorn, httpx, tinytuya

### 10.2 Environment variables (`.env.example`)

```env
# ── Phase ──────────────────────────────────────────────────────
PHASE=DEV                          # DEV | TEST | PROD
SIMULATE=true                      # true only in DEV

# ── Network ────────────────────────────────────────────────────
NETWORK_INTERFACE=eth0             # monitored interface
HOME_NETWORK_CIDR=192.168.1.0/24

# ── Telegram ───────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN=xxxx:yyyy
TELEGRAM_CHAT_ID=123456789
TELEGRAM_WEBHOOK_SECRET=random_secret_string

# ── Hombli / Tuya ──────────────────────────────────────────────
TUYA_DEVICE_ID=abc123
TUYA_LOCAL_KEY=xxxx
TUYA_IP=192.168.1.50

# ── NordVPN ────────────────────────────────────────────────────
NORDVPN_TOKEN=your_nordvpn_access_token
NORDVPN_COUNTRY=Switzerland

# ── Kill-switch ────────────────────────────────────────────────
AUTO_KILL_ON_CRITICAL=false
KILL_COOLDOWN_SECONDS=600
KILL_COUNTDOWN_SECONDS=30

# ── Alerting thresholds ────────────────────────────────────────
SSH_BRUTE_THRESHOLD=10
PORT_SCAN_THRESHOLD=50
ALERT_COOLDOWN_SECONDS=300

# ── SSH (used by hardening script) ────────────────────────────
SSH_PUBLIC_KEY=ssh-ed25519 AAAA...your_public_key

# ── Backup (Restic + Backblaze B2) ────────────────────────────
RESTIC_PASSWORD=strong_random_password
B2_ACCOUNT_ID=your_b2_account_id
B2_ACCOUNT_KEY=your_b2_app_key
```

### 10.3 Severity scoring rules

```
CRITICAL (triggers kill-switch flow):
  ├── SSH brute-force: ≥ SSH_BRUTE_THRESHOLD failed attempts in 60s from same IP
  ├── SYN flood: > 1000 pps to single host
  ├── ARP spoofing: ARP reply MAC doesn't match known mapping
  ├── Known C2/malware IP contacted (abuse.ch blocklist)
  └── Suricata ET/EXPLOIT rule match (exploit attempt, not scan)

WARNING (alert only):
  ├── Port scan: > PORT_SCAN_THRESHOLD unique ports in 30s
  ├── New/unknown device joined the network
  ├── DNS query to flagged domain
  ├── Outbound volume > 500 MB in 10 min from single host
  ├── Router admin panel login failure
  ├── NordVPN dropped
  └── CrowdSec community block hit (community-flagged IP)

INFO (log only, no alert unless debug mode):
  ├── Any other Suricata alert not matching above
  ├── ICMP activity
  └── Auto-resolved events
```

### 10.4 Data models

```python
class Event(BaseModel):
    id: int
    timestamp: datetime
    severity: Literal["INFO", "WARNING", "CRITICAL"]
    category: Literal[
        "BRUTE_FORCE", "PORT_SCAN", "DDOS", "ARP_SPOOF",
        "DNS_ANOMALY", "ROGUE_DEVICE", "TRAFFIC_ANOMALY",
        "C2_CONTACT", "VPN_DROP", "OTHER"
    ]
    source_ip: str | None
    destination_ip: str | None
    description: str
    source: str              # "suricata" | "fail2ban" | "zeek" | "crowdsec" | "arp" | "simulator"
    raw: str | None
    alerted: bool
    resolved: bool
    suppressed: bool         # True if whitelisted

class Device(BaseModel):
    mac: str
    ip: str
    hostname: str | None
    vendor: str | None
    first_seen: datetime
    last_seen: datetime
    is_known: bool
    is_online: bool

class KillEvent(BaseModel):
    id: int
    timestamp: datetime
    trigger_event_id: int
    phase: str
    cancelled: bool
    cancel_timestamp: datetime | None
    executed: bool
    execute_timestamp: datetime | None
    restored_at: datetime | None
    notes: str | None
```

### 10.5 API endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/events` | List events (`limit`, `severity`, `since`) |
| GET | `/events/stream` | SSE — live event stream |
| GET | `/devices` | List devices |
| POST | `/devices/{mac}/whitelist` | Whitelist a device |
| GET | `/metrics` | Dashboard summary metrics |
| GET | `/traffic` | Last 60s of packets/s readings |
| POST | `/plug/on` | Turn router power on |
| POST | `/plug/off` | Turn router power off |
| GET | `/plug/status` | `{"state": "on"|"off"|"unknown"}` |
| GET | `/vpn/status` | NordVPN connection status |
| POST | `/telegram/webhook` | Telegram bot command webhook |
| GET | `/health` | `{"status": "ok", "phase": "DEV"}` |
| GET | `/phase` | Current phase info |

---

## 11. Frontend — Dashboard Specification

### 11.1 Phase awareness

The dashboard shows a prominent banner in DEV and TEST:

- **DEV**: yellow banner — "⚠️ DEV MODE — Simulated data only"
- **TEST**: orange banner — "🔶 TEST MODE — Real sensors, kill-switch requires manual confirmation"
- **PROD**: no banner

The phase badge also appears in the header next to the system name.

### 11.2 NordVPN status widget

A small badge in the header shows:
- 🟢 **VPN: Connected** (green, shows country)
- 🔴 **VPN: Disconnected** (red, pulsing)
- 🔵 **VPN: Simulated** (blue, DEV mode)

### 11.3 Kill-switch UI

The Hombli plug control panel shows three states:

```
[ARM KILL-SWITCH]     ← default, grey
      ↓ click
[● ARMED — tap to kill now]  ← amber, pulsing
      ↓ confirm dialog
[KILL IN PROGRESS...]  ← red, countdown
      ↓
[🔴 ROUTER OFFLINE — tap to restore]  ← red solid
      ↓ click
[RESTORING...]  ← animating
```

In TEST phase, the ARM button is labelled "TEST KILL (manual only)" and shows a warning dialog explaining the kill will be real.

### 11.4 Layout (1280×800 target — Fire HD 8)

```
┌──────────────────────────────────────────────────────┐
│ ● HOME SOC [DEV]  VPN: 🟢 CH  NordLynx    03:42 UTC │
│ ⚠️  DEV MODE — Simulated data                        │
├──────────────────────────────────────────────────────┤
│ [MEDIUM]   [14 events]   [8 devices]   [3 blocked]   │
├──────────────────────┬──────────┬────────────────────┤
│ INCIDENT FEED        │ TRAFFIC  │ DEVICES            │
│ 🔴 SSH brute-force   │ ~chart~  │ ● router           │
│ 🟡 Port scan         │          │ ● desktop          │
│ 🟡 Unknown device    │ THREATS  │ ● macbook          │
│ 🔵 DNS flagged       │ bars     │ ● phone            │
│                      │          │ ⚠ unknown          │
│                      │ 24H HIST │                    │
│                      │ ~chart~  │ [ARM KILL-SWITCH]  │
│                      │          │ VPN: 🟢 Connected  │
└──────────────────────┴──────────┴────────────────────┘
│ sensor: localhost:8000  phase:DEV  suricata:SIM       │
└──────────────────────────────────────────────────────┘
```

---

## 12. Integrated Tool Stack (TEST + PROD)

### 12.1 Suricata

Run in inline IPS mode in PROD (alert-only in TEST):
- Interface: `eth0` (WAN in PROD), promiscuous on LAN interface in TEST
- Rulesets: `emerging-exploit`, `emerging-malware`, `emerging-scan`, `emerging-dos`, `emerging-botnet`
- Update: `suricata-update` weekly via cron
- Output: `fast.log` (tailed by sensor) + `eve.json` (for future Grafana integration)

### 12.2 Zeek

Logs all protocol activity to `/opt/zeek/logs/current/`:
- `dns.log` → flag queries to blocklisted domains
- `conn.log` → flag long-duration or high-volume connections
- `ssl.log` → flag self-signed or expired certificates from external hosts
- `files.log` → flag executable file transfers

### 12.3 CrowdSec

Parses logs from Suricata, Fail2ban, nginx and blocks IPs via nftables bouncer.
Community blocklist automatically blocks IPs currently attacking other CrowdSec users worldwide.

### 12.4 Pi-hole + Unbound

DNS sinkhole for all LAN devices. Unbound runs as local recursive resolver on port 5335.
Additional blocklists beyond defaults:
```
https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
https://urlhaus.abuse.ch/downloads/hostfile/
https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt
```

DNSSEC validation enabled in Unbound. DNS-over-TLS fallback to Quad9 (9.9.9.9:853).

### 12.5 WireGuard (admin remote access)

Separate from NordVPN. Used by the owner to SSH into the mini PC and access the dashboard remotely. Install script generates a QR code for the owner's phone.

### 12.6 Home Assistant

Exposes SOC threat level as a sensor. Triggers automations (e.g. flash entrance light red on CRITICAL). Optional — can be disabled without affecting core SOC.

### 12.7 Uptime Kuma

Monitors: SOC backend, SOC dashboard, Pi-hole, NordVPN connectivity, Home Assistant. Sends Telegram alert if anything goes down — independently of the main SOC backend.

### 12.8 Restic (encrypted backup)

Daily 3am backup to Backblaze B2 (free tier: 10 GB):
- `/opt/home-soc/backend/soc.db`
- `/etc/pihole`
- `/etc/wireguard`
- `/home/homeassistant/.homeassistant`

Retention: 7 daily, 4 weekly, 6 monthly.

---

## 13. Service Resilience

### 13.1 All services restart automatically

```ini
# All systemd service files include:
[Service]
Restart=always
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5
ExecStopPost=/opt/home-soc/scripts/maintenance/service_alert.sh %n
```

`service_alert.sh` sends a Telegram message if a service fails 5 times in 60 seconds.

### 13.2 Software watchdog (runs every minute)

```bash
# scripts/maintenance/watchdog.sh
# systemd timer calls this every 60 seconds
CRITICAL_SERVICES="suricata zeek crowdsec pihole-FTL nginx home-soc-backend"
for svc in $CRITICAL_SERVICES; do
  if ! systemctl is-active --quiet $svc; then
    systemctl restart $svc
    sleep 5
    if ! systemctl is-active --quiet $svc; then
      # Alert only if restart also failed
      curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d chat_id="${TELEGRAM_CHAT_ID}" \
        -d text="🚨 $svc is DOWN and failed to restart"
    fi
  fi
done
```

### 13.3 SSD health monitoring

```bash
# Weekly SMART test via cron
0 2 * * 0 root smartctl -t short /dev/nvme0n1 2>/dev/null
5 2 * * 0 root smartctl -H /dev/nvme0n1 | grep -v PASSED | \
  xargs -I{} curl -s "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
  -d chat_id="${TELEGRAM_CHAT_ID}" -d text="⚠️ SSD SMART warning: {}"
```

---

## 14. Full Install Script (`scripts/install/install.sh`)

```bash
#!/bin/bash
set -e
source /opt/home-soc/.env

echo "=== Home SOC v3.0 — Phase: $PHASE ==="
echo "Running on: $(hostname) $(uname -r)"
echo ""

# System
bash scripts/install/setup_system.sh
bash scripts/install/setup_hardening.sh

# Detection stack
bash scripts/install/setup_suricata.sh
bash scripts/install/setup_zeek.sh
bash scripts/install/setup_fail2ban.sh
bash scripts/install/setup_crowdsec.sh

# DNS
bash scripts/install/setup_pihole.sh

# VPN (PROD only)
if [ "$PHASE" = "PROD" ]; then
  bash scripts/install/setup_nordvpn.sh
fi

# Traffic visibility
bash scripts/install/setup_ntopng.sh

# SOC application
bash scripts/install/setup_backend.sh
bash scripts/install/setup_frontend.sh
bash scripts/install/setup_nginx.sh

# Admin remote access
bash scripts/install/setup_wireguard.sh

# Smart home
bash scripts/install/setup_homeassistant.sh

# Monitoring + backup
bash scripts/install/setup_uptime_kuma.sh
bash scripts/install/setup_restic.sh

# Watchdog timer
sudo cp scripts/systemd/home-soc-watchdog.service /etc/systemd/system/
sudo cp scripts/systemd/home-soc-watchdog.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now home-soc-watchdog.timer

echo ""
echo "=== Install complete — Phase: $PHASE ==="
echo ""
echo "  SOC Dashboard      → http://$(hostname -I | awk '{print $1}'):3000"
echo "  Pi-hole Admin      → http://$(hostname -I | awk '{print $1}'):8080/admin"
echo "  ntopng             → http://$(hostname -I | awk '{print $1}'):3001"
echo "  Uptime Kuma        → http://$(hostname -I | awk '{print $1}'):3002"
echo "  Home Assistant     → http://$(hostname -I | awk '{print $1}'):8123"
echo ""
echo "Next steps:"
if [ "$PHASE" = "TEST" ]; then
  echo "  1. Set mini PC IP as DNS server in your router DHCP settings"
  echo "  2. Run: bash scripts/install/wireguard_add_client.sh my-phone"
  echo "  3. Test: ssh brute-force and port scan from a second machine"
  echo "  4. Complete TEST phase checklist in HOME_SOC_SPEC.md §5.3"
fi
if [ "$PHASE" = "PROD" ]; then
  echo "  1. Move mini PC inline between modem and router (eth0=WAN, eth1=LAN)"
  echo "  2. Forward UDP 51820 on router for WireGuard"
  echo "  3. Run: nordvpn connect"
  echo "  4. Verify NordVPN in dashboard header"
fi
```

---

## 15. Service Port Map

| Service | Port | Access |
|---------|------|--------|
| SOC Dashboard (nginx) | 3000 | LAN only |
| SOC Backend (FastAPI) | 8000 | Internal, proxied via `/api/` |
| Pi-hole Admin | 8080 | LAN only |
| Pi-hole DNS | 53 | All LAN devices |
| Unbound | 5335 | Internal (Pi-hole only) |
| ntopng | 3001 | LAN only |
| Uptime Kuma | 3002 | LAN only |
| Home Assistant | 8123 | LAN only |
| WireGuard (admin) | 51820/UDP | Requires router port forward |

---

## 16. Known Constraints

- **Dual NIC required for PROD inline mode.** Single-NIC machines work in TEST (promiscuous/passive) but cannot drop traffic.
- **Kill disconnects the Pi in passive topology.** In TEST mode where the Pi is not inline, cutting the router via Hombli also drops the Pi's Wi-Fi connection. In PROD inline mode, the Pi has its own WAN/LAN path and is unaffected.
- **NordVPN changes external IP.** Suricata's HOME_NET must include the VPN subnet. The nordvpn_sensor.py reads the current server IP and updates the config automatically.
- **tinytuya requires same subnet.** The Hombli plug and mini PC must be on the same LAN. No VLAN separation between them.
- **WSL2 networking limitations in DEV.** Docker containers in WSL2 use a virtual network — port scanning tests and ARP monitoring will not work in DEV. This is expected and handled by the simulator.
- **SMART monitoring requires NVMe device at `/dev/nvme0n1`.** Adjust path in watchdog if using SATA SSD (`/dev/sda`).

---

## 17. Glossary

| Term | Meaning |
|------|---------|
| IDS | Intrusion Detection System — passively alerts |
| IPS | Intrusion Prevention System — actively blocks |
| Inline mode | Mini PC sits between modem and router, all traffic passes through it |
| Passive mode | Mini PC connected to a switch port, sees traffic via promiscuous mode |
| nftables | Modern Linux firewall framework, replaces iptables |
| Suricata | Open-source IDS/IPS — deep packet inspection against rule sets |
| Zeek | Network analysis framework — full protocol logging |
| CrowdSec | Collaborative IPS — community-shared blocklists |
| Fail2ban | Bans IPs after repeated failed logins |
| Pi-hole | DNS sinkhole — blocks ads, trackers, malware domains |
| Unbound | Self-hosted recursive DNS resolver |
| NordLynx | NordVPN's WireGuard-based protocol |
| tinytuya | Python library for local LAN control of Tuya/Hombli devices |
| WireGuard | Modern VPN — used here for admin remote access (separate from NordVPN) |
| SSE | Server-Sent Events — HTTP streaming for the live dashboard feed |
| Restic | Encrypted deduplicated backup tool |
| Uptime Kuma | Self-hosted uptime monitor |
| Kill-switch | Cuts router power via smart plug to isolate the home network |
| PHASE | DEV / TEST / PROD — controls which features are active |
| WSL2 | Windows Subsystem for Linux v2 — used for DEV phase |

---

*Home SOC Project · v3.0 · Authored with Claude*
