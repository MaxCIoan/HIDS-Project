# 🛡️ HIDS — Host Intrusion Detection System
## Ubuntu 24.04.4 LTS — Complete Guide for Beginners — v2

---

## Table of Contents

1. [What Is a HIDS?](#1-what-is-a-hids)
2. [Project Architecture](#2-project-architecture)
3. [Installation](#3-installation)
4. [Configuration (config.conf)](#4-configuration-configconf)
5. [The Baseline — Core Concept](#5-the-baseline--core-concept)
6. [Modules in Detail](#6-modules-in-detail)
7. [Essential Commands](#7-essential-commands)
8. [Systemd Automation](#8-systemd-automation)
9. [Email Alerts (msmtp + Gmail)](#9-email-alerts-msmtp--gmail)
10. [Network Monitoring (lab-net)](#10-network-monitoring-lab-net)
11. [Port Classification](#11-port-classification)
12. [Interpreting the Output](#12-interpreting-the-output)
13. [Reducing False Positives](#13-reducing-false-positives)
14. [Test Scenarios](#14-test-scenarios)
15. [Maintenance & Best Practices](#15-maintenance--best-practices)
16. [Glossary](#16-glossary)

---

## 1. What Is a HIDS?

### Definition

A **HIDS** (Host Intrusion Detection System) is a security tool that continuously monitors a machine to detect any suspicious or abnormal activity. Unlike a firewall that blocks threats at the perimeter, a HIDS operates from within — watching what actually happens on the OS.

### HIDS vs NIDS

| Feature | HIDS | NIDS |
|---|---|---|
| **Location** | On the monitored machine | On the network |
| **What it sees** | Processes, files, users, local logs | Network packets |
| **Examples** | Our HIDS, OSSEC, Wazuh, Tripwire | Suricata, Snort, Zeek |
| **Strength** | Full OS-level visibility | Global network traffic view |
| **Weakness** | Blind to encrypted network traffic | Blind to what happens inside the OS |

> **Key insight:** NIDS sees the packets. HIDS sees what those packets triggered.
> An attacker using stolen credentials bypasses NIDS entirely — only HIDS will
> catch them modifying `/etc/passwd` once inside.

### What Our HIDS Monitors

Our HIDS monitors **7 critical areas**:

```
🛡️ HIDS v2
├── ♥  mod_health.sh       → CPU, RAM, Disk, Swap, I/O, File Descriptors
├── 📈 mod_history.sh      → Historical trends, sparklines, drift detection (NEW)
├── 👤 mod_users.sh        → Sessions, logins, sudo, accounts, groups, SSH keys
├── ⚡ mod_process.sh      → Processes, full port inventory + classification (ENHANCED)
├── 🔒 mod_integrity.sh    → File hashes, SUID, world-writable, crontabs, LD_PRELOAD
├── 🌐 mod_network_scan.sh → Metasploitable scan, new hosts, port changes
└── 📋 mod_alert.sh        → JSON log, report, Gmail digest
```

### How It Works

```
INITIAL STATE (clean system)
         ↓
    BASELINE (snapshot)
         ↓
    PERIODIC SCAN (every 5 min)
         ↓
    COMPARISON vs BASELINE
         ↓
    ALERT if difference detected
```

1. Take a **baseline snapshot** of the system when it is clean
2. At each scan, compare the current state against that snapshot
3. If something changed → **ALERT**

---

## 2. Project Architecture

### File Structure

```
/opt/hids/                          ← Main directory
├── hids.sh                         ← Main entry point (orchestrator)
├── config.conf                     ← ALL configuration lives here
├── baseline.sh                     ← Snapshot & diff engine
├── live_monitor.sh                 ← Real-time dashboard
├── lib/
│   └── lib_utils.sh                ← Shared library (common functions)
└── modules/
    ├── mod_health.sh               ← Module 1: System Health
    ├── mod_history.sh              ← Module 2: Health History & Trends (NEW)
    ├── mod_users.sh                ← Module 3: User Activity
    ├── mod_process.sh              ← Module 4: Process & Network (ENHANCED)
    ├── mod_integrity.sh            ← Module 5: File Integrity
    ├── mod_network_scan.sh         ← Module 6: Network Scan (lab-net)
    └── mod_alert.sh                ← Module 7: Alert Aggregation & Reporting

/var/lib/hids/                      ← Persistent data
├── baseline/                       ← Reference snapshots
│   ├── file_hashes.db              ← SHA256 hashes of watched files
│   ├── suid_binaries.list          ← Known SUID/SGID binaries
│   ├── users.list                  ← User accounts snapshot
│   ├── groups.list                 ← Groups snapshot
│   ├── listening_ports.list        ← Listening ports snapshot
│   ├── health_averages.conf        ← System health reference values
│   ├── crontabs.db                 ← Crontab hashes
│   └── meta.conf                   ← Metadata (date, host, version)
├── history/                        ← Trend data (NEW — mod_history)
│   ├── cpu.csv                     ← CPU load time series
│   ├── ram.csv                     ← RAM usage time series
│   └── disk.csv                    ← Disk usage time series
├── network_baseline/               ← Per-host network baselines
│   └── 192_168_0_21_ports.list     ← Metasploitable open ports
├── whitelist_suid.conf             ← Allowed SUID binaries
├── whitelist_ports.conf            ← Allowed ports (optional)
└── alert_state.db                  ← Alert deduplication state

/var/log/hids/                      ← Logs
├── alerts.json                     ← NDJSON alert log
├── report.txt                      ← Human-readable last run report
└── cron.log                        ← Automated execution log

/etc/systemd/system/                ← Automation
├── hids.service                    ← Systemd service
└── hids.timer                      ← Timer (every 5 minutes)

/etc/msmtprc                        ← Gmail email configuration
```

### Execution Flow

```
sudo /opt/hids/hids.sh
        ↓
   [Root check]
        ↓
   [Load config.conf]
        ↓
   [Check dependencies]
        ↓
   [Baseline exists?]
   ├── NO  → Create automatically
   └── YES → Continue
        ↓
   mod_health.sh     → System health
        ↓
   mod_history.sh    → Record data point, analyze trends (NEW)
        ↓
   mod_users.sh      → User activity
        ↓
   mod_process.sh    → Processes & network (ENHANCED)
        ↓
   mod_integrity.sh  → File integrity
        ↓
   mod_network_scan.sh → lab-net scan
        ↓
   mod_alert.sh      → Summary + Email if CRITICAL
        ↓
   [Write report.txt]
```

---

## 3. Installation

### Prerequisites

```bash
# Check required tools
for cmd in ss sha256sum find stat awk sort uniq wc who last nmap gum; do
    command -v "$cmd" &>/dev/null && echo "✅ $cmd" || echo "❌ MISSING: $cmd"
done

# Install required tools
sudo apt install gawk nmap -y

# Install gum (professional visual interface)
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://repo.charm.sh/apt/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/charm.gpg
echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" | sudo tee /etc/apt/sources.list.d/charm.list
sudo apt update && sudo apt install gum -y
gum --version
```

> ⚠️ **Critical — gawk vs mawk:**
> Ubuntu 24.04 uses `mawk` by default. `mawk` does **NOT** support `match()`
> with array capture groups, which our alert modules require.
> Always install `gawk` explicitly — `awk --version` must show `GNU Awk`, not `mawk`.

### Installation Steps

```bash
# 1. Create directory structure
sudo mkdir -p /opt/hids/lib /opt/hids/modules
sudo mkdir -p /var/lib/hids /var/log/hids
sudo mkdir -p /var/lib/hids/network_baseline

# 2. Copy files (from project folder)
cd ~/hids_project

sudo cp hids.sh config.conf baseline.sh live_monitor.sh /opt/hids/
sudo cp lib/lib_utils.sh /opt/hids/lib/

sudo cp modules/mod_health.sh       /opt/hids/modules/
sudo cp modules/mod_history.sh      /opt/hids/modules/   # NEW
sudo cp modules/mod_users.sh        /opt/hids/modules/
sudo cp modules/mod_process.sh      /opt/hids/modules/   # ENHANCED
sudo cp modules/mod_integrity.sh    /opt/hids/modules/
sudo cp modules/mod_alert.sh        /opt/hids/modules/
sudo cp modules/mod_network_scan.sh /opt/hids/modules/

# 3. Apply permissions
sudo chmod +x /opt/hids/hids.sh /opt/hids/baseline.sh /opt/hids/live_monitor.sh
sudo chmod +x /opt/hids/modules/*.sh
sudo chown -R root:root /opt/hids /var/lib/hids /var/log/hids
sudo chmod 750 /opt/hids /var/lib/hids /var/log/hids
sudo chmod 640 /opt/hids/config.conf

# 4. Create initial baseline (on a CLEAN system)
sudo /opt/hids/hids.sh --baseline

# 5. First scan
sudo /opt/hids/hids.sh
```

---

## 4. Configuration (config.conf)

> ⚠️ **Golden Rule: Never edit the module scripts directly.**
> All configuration lives in `/opt/hids/config.conf` only.

```bash
sudo nano /opt/hids/config.conf
```

```bash
# ============================================================
# GENERAL
# ============================================================
HIDS_DATA_DIR="/var/lib/hids"
HIDS_OUTPUT_DIR="/var/log/hids"
ALERT_LOG="${HIDS_OUTPUT_DIR}/alerts.json"
ALERT_STATE_FILE="${HIDS_DATA_DIR}/alert_state.db"
REPORT_FILE="${HIDS_OUTPUT_DIR}/report.txt"
HIDS_HOSTNAME=""                       # Leave empty = auto-detected
ALERT_EMAIL="your@gmail.com"           # Email for CRITICAL alerts
MAIL_CMD="msmtp"                       # Email command

# ============================================================
# MODULE 1: SYSTEM HEALTH
# ============================================================
LOAD_MULTIPLIER=2.0        # Alert if load > 2 × number of cores
THRESHOLD_RAM_MB=512       # Alert if available RAM < 512 MB
THRESHOLD_DISK_PCT=85      # Alert if disk used > 85%
THRESHOLD_SWAP_PCT=70      # Alert if swap used > 70%
THRESHOLD_IOWAIT_PCT=30    # Alert if I/O wait > 30%
THRESHOLD_FD_COUNT=65000   # Alert if file descriptors > 65000
# NEW in v2: exclude mounted ISOs from disk alerts
DISK_EXCLUDE_MOUNTPOINTS="/media"

# ============================================================
# MODULE 2 (was 2, now 3): USER ACTIVITY
# ============================================================
THRESHOLD_FAILED_LOGINS=5              # Alert if >5 SSH failures from one IP
OFF_HOURS=""                           # Off-hours (empty = disabled)
TRUSTED_SSH_SOURCES="192.168.1.0/24"   # Trusted SSH subnets
SENSITIVE_GROUPS="sudo,wheel,docker,adm,shadow,disk"

# ============================================================
# MODULE 4: PROCESS & NETWORK (ENHANCED in v2)
# ============================================================
SUSPICIOUS_PATHS="/tmp,/var/tmp,/dev/shm,/run/shm"
WHITELIST_PORTS="22,53,80,443,631,5353,3306,5432"
# Note: unwhitelisted ports show as REVIEW — nothing is hidden
WHITELIST_SUSPICIOUS_PROCS="snapd-desktop-i,ps"
ALERT_OUTBOUND_PORTS="4444,1337,31337,8080,9090,6666,6667"
THRESHOLD_PROC_CPU=90
THRESHOLD_PROC_MEM=50

# ============================================================
# MODULE 5: FILE INTEGRITY
# ============================================================
# ⚠️  CRITICAL: one path per line — IFS=$'\n\t' breaks space-splitting
INTEGRITY_WATCH="
/etc/passwd
/etc/shadow
/etc/group
/etc/gshadow
/etc/sudoers
/etc/ssh/sshd_config
/etc/hosts
/etc/crontab
/etc/fstab
"
INTEGRITY_WATCH_DIRS="
/etc/sudoers.d
/etc/pam.d
/etc/cron.d
/etc/cron.daily
/etc/cron.hourly
"
# Note: /etc/systemd/system excluded — snap creates dynamic unit files there
INTEGRITY_RECENT_MINUTES=15
SUID_SCAN_EXCLUDE="/proc /sys /dev /run /snap"
```

---

## 5. The Baseline — Core Concept

### What Is a Baseline?

The baseline is a **snapshot of the system's known-good state** taken at a specific moment. It is the reference against which every subsequent scan is compared.

```
BASELINE (known-good state)          CURRENT SCAN
/etc/passwd → hash: abc123           /etc/passwd → hash: xyz789
/etc/shadow → hash: def456      vs   /etc/shadow → hash: def456
26 SUID binaries known               27 SUID binaries found
Ports: 22, 53, 80, 443               Ports: 22, 53, 80, 443, 9999
         ↓                                    ↓
         └──────── DIFF ────────────→ CRITICAL: hash_mismatch /etc/passwd
                                      CRITICAL: new_suid_binary
                                      CRITICAL: new_port_detected
```

### Baseline Commands

```bash
# Create/recreate the full baseline
sudo /opt/hids/hids.sh --baseline

# Check baseline status
sudo /opt/hids/hids.sh --status

# View baseline metadata
sudo cat /var/lib/hids/baseline/meta.conf

# Count hashed files
sudo wc -l /var/lib/hids/baseline/file_hashes.db

# Delete baseline (if corrupted)
sudo rm -rf /var/lib/hids/baseline
sudo /opt/hids/hids.sh --baseline
```

### When to Re-Baseline?

| Situation | Action |
|---|---|
| After `apt upgrade` | **Always re-baseline** |
| After installing software | Re-baseline |
| After intentional config change | Re-baseline |
| After adding a user | Re-baseline |
| After whitelisting a false positive | Re-baseline |
| **If intrusion suspected** | **NEVER re-baseline — preserve evidence** |

---

## 6. Modules in Detail

### Module 1 — System Health (mod_health.sh)

**What it monitors:** CPU load, RAM, disk, swap, I/O wait, file descriptors, uptime.

**Data sources:**
- CPU load → `/proc/loadavg`
- RAM → `/proc/meminfo`
- Disk → `df --output=pcent,target`
- I/O wait → `/proc/stat` (2 samples, delta calculation)
- File descriptors → `/proc/sys/fs/file-nr`
- Uptime → `/proc/uptime`

```bash
sudo bash /opt/hids/modules/mod_health.sh
```

**Key thresholds (in config.conf):**
- `LOAD_MULTIPLIER=2.0` → alert if load > 2 × nproc
- `THRESHOLD_RAM_MB=512` → alert if available RAM < 512 MB
- `THRESHOLD_DISK_PCT=85` → alert if disk > 85%
- `DISK_EXCLUDE_MOUNTPOINTS="/media"` → ignore mounted ISOs **(NEW)**

---

### Module 2 — Health History & Trends (mod_history.sh) 🆕

**What it monitors:** Historical trends for CPU, RAM, and disk usage over time.

**This module answers:** *"Is something slowly getting worse on this system?"*

**Data sources:**
- `/proc/loadavg` → CPU load
- `/proc/meminfo` → RAM usage
- `df /` → Disk usage
- Stored in `/var/lib/hids/history/*.csv` (epoch, timestamp, value)

```bash
# Full analysis with sparkline charts
sudo bash /opt/hids/modules/mod_history.sh

# View raw historical data
sudo bash /opt/hids/modules/mod_history.sh --show cpu  --last 20
sudo bash /opt/hids/modules/mod_history.sh --show ram  --last 20
sudo bash /opt/hids/modules/mod_history.sh --show disk --last 20
```

**How it works:**
- Records one data point per scan
- Keeps last **288 points = 24 hours** of rolling history (auto-rotated)
- Calculates **linear regression** over the last 12 points (1-hour window)
- Classifies trend: `rising` / `falling` / `stable`
- Draws **ASCII sparkline charts**: `▁▂▃▄▅▆▇█`
- Projects **ETA to disk full** at current growth rate

**Alert thresholds:**

| Metric | WARN | CRITICAL |
|---|---|---|
| CPU Load | Trending up toward 80% of limit | Trending up > 80% of limit |
| RAM Usage | Trending up, > 70% used | Trending up, > 85% used |
| Disk (/) | Trending up, > 70% of threshold | Trending up, > threshold |

---

### Module 3 — User Activity (mod_users.sh)

**What it monitors:** Sessions, failed logins, sudo activity, user accounts, group membership, SSH keys.

**Data sources:**
- Active sessions → `who(1)` → `/var/run/utmp`
- Login history → `last(1)` → `/var/log/wtmp`
- Failed SSH logins → `journalctl -u sshd` / `/var/log/auth.log`
- Sudo activity → `journalctl` / `/var/log/auth.log`
- User accounts → `/etc/passwd`, `/etc/group`
- SSH keys → `~/.ssh/authorized_keys` (mtime check)

```bash
sudo bash /opt/hids/modules/mod_users.sh
```

**Session classification:**
- `denis@login` → ✅ OK — Local physical session (keyboard/screen)
- `denis@pts/2` from remote IP → ⚠️ REVIEW — Remote SSH session to monitor
- Unknown remote IP → 🚨 ALERT — Untrusted remote session

---

### Module 4 — Process & Network Audit (mod_process.sh) 🔧 Enhanced

**What it monitors:** Suspicious processes, full port inventory with enriched details, established connections.

**Data sources:**
- Processes → `/proc/[pid]/exe`, `/proc/[pid]/status`, `/proc/[pid]/environ`
- Listening ports → `ss -tulnpe` (protocol, address, port, UID, cgroup)
- Established connections → `ss -tunpe state established`

```bash
sudo bash /opt/hids/modules/mod_process.sh
```

**Process checks:**
- Executables running from suspicious paths (`/tmp`, `/dev/shm`, `/var/tmp`)
- Processes with deleted binaries (`/proc/[pid]/exe (deleted)`)
- Root processes running from home directories
- Top 10 CPU/RAM consumers with full details

**Port inventory (NEW in v2):**

Every port is displayed with: Protocol, Local Address:Port, Service/Cgroup, UID, Username, Description.

| Status | Meaning |
|---|---|
| ✅ OK | Whitelisted / known-good service |
| ⚠️ REVIEW | Not in whitelist — investigate |
| 🚨 ALERT | Known dangerous port (backdoor, C2, Telnet...) |

Nothing is hidden — all ports are always visible.

---

### Module 5 — File Integrity (mod_integrity.sh)

**What it monitors:** SHA256 hashes of critical files, SUID binaries, world-writable files, crontabs, LD_PRELOAD injection.

**Data sources:**
- File hashes → `sha256sum` on `INTEGRITY_WATCH` list
- SUID binaries → `find / -perm /6000`
- World-writable → `find -perm -o+w`
- Crontabs → `sha256sum /etc/crontab /etc/cron.d/*`
- LD_PRELOAD → `/proc/[pid]/environ`

```bash
sudo bash /opt/hids/modules/mod_integrity.sh
```

> ⚠️ **Critical — IFS bug:** Paths in `INTEGRITY_WATCH` must be **one per line**.
> Space-separated paths = "Hashed 0 files" bug. This is a known gotcha with `IFS=$'\n\t'`.

---

### Module 6 — Network Scan (mod_network_scan.sh)

**What it monitors:** Active hosts on lab-net, port changes on Metasploitable, established connections.

**Data sources:**
- Host discovery → `nmap -sn 192.168.0.0/24`
- Port scan → `nmap -sT --open -p-`
- Connections → `ss -tnp | grep 192.168.0`

```bash
sudo bash /opt/hids/modules/mod_network_scan.sh
```

---

### Module 7 — Alert Aggregation (mod_alert.sh)

**What it does:** Aggregates all alerts from the current run, generates the summary report, and sends a Gmail digest when CRITICAL alerts are found.

**Alert log format:** NDJSON — one JSON object per line in `/var/log/hids/alerts.json`

```json
{
  "timestamp": "2026-04-15T10:17:11Z",
  "severity":  "CRITICAL",
  "module":    "mod_integrity",
  "event":     "hash_mismatch",
  "detail":    "File modified since baseline: /etc/passwd",
  "target":    "/etc/passwd",
  "host":      "ubuntu1",
  "pid":       null
}
```

---

## 7. Essential Commands

### Scanning

```bash
# Full one-shot scan
sudo /opt/hids/hids.sh

# Real-time dashboard (Ctrl+C to exit)
sudo /opt/hids/hids.sh --live

# Recreate baseline
sudo /opt/hids/hids.sh --baseline

# Baseline status + recent alerts
sudo /opt/hids/hids.sh --status
```

### Alert Queries

```bash
# All CRITICAL alerts
sudo /opt/hids/hids.sh --query --severity CRITICAL

# All WARN alerts
sudo /opt/hids/hids.sh --query --severity WARN

# Filter by module
sudo /opt/hids/hids.sh --query --module mod_integrity

# Last 20 entries
sudo /opt/hids/hids.sh --query --last 20

# Combined filter
sudo /opt/hids/hids.sh --query --severity CRITICAL --last 10

# Manual grep
sudo grep 'CRITICAL' /var/log/hids/alerts.json | wc -l
sudo tail -f /var/log/hids/alerts.json   # Follow live
```

### Individual Modules

```bash
sudo bash /opt/hids/modules/mod_health.sh
sudo bash /opt/hids/modules/mod_history.sh
sudo bash /opt/hids/modules/mod_history.sh --show cpu  --last 20
sudo bash /opt/hids/modules/mod_history.sh --show ram  --last 20
sudo bash /opt/hids/modules/mod_history.sh --show disk --last 20
sudo bash /opt/hids/modules/mod_users.sh
sudo bash /opt/hids/modules/mod_process.sh
sudo bash /opt/hids/modules/mod_integrity.sh
sudo bash /opt/hids/modules/mod_network_scan.sh
```

### Logs & Reports

```bash
sudo cat /var/log/hids/report.txt              # Last run report
sudo cat /var/log/hids/alerts.json             # Full alert log
sudo truncate -s 0 /var/log/hids/alerts.json   # Clear alert log
sudo ls -la /var/lib/hids/baseline/            # Inspect baseline
sudo wc -l /var/lib/hids/baseline/file_hashes.db  # Hashed files count
ls /var/lib/hids/history/                      # Trend data files
tail -20 /var/lib/hids/history/cpu.csv         # Raw CPU trend data
```

---

## 8. Systemd Automation

### The Two Unit Files

```bash
# /etc/systemd/system/hids.service
[Unit]
Description=HIDS One-shot scan
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/hids/hids.sh --once
StandardOutput=journal
StandardError=journal
```

```bash
# /etc/systemd/system/hids.timer
[Unit]
Description=HIDS scan every 5 minutes

[Timer]
OnBootSec=2min           # First scan 2 minutes after boot
OnUnitActiveSec=5min     # Then every 5 minutes
Unit=hids.service

[Install]
WantedBy=timers.target
```

### Management Commands

```bash
# Install and activate
sudo systemctl daemon-reload
sudo systemctl enable --now hids.timer

# Status checks
sudo systemctl status hids.timer          # Timer status + next run
sudo systemctl status hids.service        # Last scan result

# Logs
sudo journalctl -u hids.service -n 50     # Last 50 log lines
sudo journalctl -u hids.service -f        # Follow live
sudo journalctl -u hids.service --since today

# Control
sudo systemctl start hids.service         # Trigger manual scan
sudo systemctl stop hids.timer            # Pause automation
sudo systemctl disable hids.timer         # Disable at boot
```

---

## 9. Email Alerts (msmtp + Gmail)

### Installation

```bash
sudo apt install msmtp msmtp-mta -y
sudo touch /var/log/msmtp.log && sudo chmod 666 /var/log/msmtp.log
```

### Gmail App Password

1. Go to: https://myaccount.google.com/apppasswords
2. 2-Step Verification must be enabled
3. App name: `HIDS Ubuntu` → **Create**
4. Copy the 16-character code (shown **only once**)

> ⚠️ Use this code in the config — **NOT** your regular Gmail password.

### Configuration

```bash
sudo nano /etc/msmtprc
```

```
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        /var/log/msmtp.log

account        gmail
host           smtp.gmail.com
port           587
from           YOUR@gmail.com
user           YOUR@gmail.com
password       XXXX XXXX XXXX XXXX

account default : gmail
```

```bash
sudo chmod 600 /etc/msmtprc   # Protect — contains password!

# Test
echo 'HIDS Test' | sudo msmtp YOUR@gmail.com

# Enable in config.conf
# ALERT_EMAIL="YOUR@gmail.com"
# MAIL_CMD="msmtp"
```

### Email Behaviour

- Sent automatically when a scan finds at least 1 **CRITICAL** alert
- Content: host, timestamp, CRITICAL count, full details of each finding
- WARN alerts do **not** trigger emails (JSON log only)

---

## 10. Network Monitoring (lab-net)

### Architecture

| Machine | IP | Role |
|---|---|---|
| Ubuntu HIDS | 192.168.0.41 | Monitoring machine |
| Metasploitable 2 | 192.168.0.21 | Intentionally vulnerable target |

### Dangerous Metasploitable Ports

| Port | Service | Vulnerability |
|---|---|---|
| 21/tcp | vsftpd 2.3.4 | Backdoor — opens shell on port 6200 |
| 23/tcp | Telnet | Cleartext credentials |
| 1524/tcp | Bindshell | Root shell — **zero authentication** |
| 6667/tcp | UnrealIRCd | Backdoor — remote command execution |
| 512-514/tcp | rsh/rlogin | Very weak authentication |
| 2121/tcp | ProFTPD 1.3.1 | Known vulnerabilities |

### Network Commands

```bash
# Discover hosts on lab-net
sudo nmap -sn 192.168.0.0/24

# Full scan of Metasploitable
sudo nmap -sV -O 192.168.0.21

# Fast full port scan
sudo nmap -sT --open -p- --min-rate 1000 -T4 192.168.0.21

# Active connections to lab-net
ss -tnp | grep '192.168.0'

# View Metasploitable port baseline
cat /var/lib/hids/network_baseline/192_168_0_21_ports.list

# Reset network baseline for a host
rm /var/lib/hids/network_baseline/192_168_0_21_ports.list
```

---

## 11. Port Classification

### Philosophy — Show Everything

`mod_process.sh` displays **every** listening port with full details. Nothing is hidden. Ports are classified to guide investigation — not to silence them.

### Classification Levels

| Status | Color | Meaning | Action |
|---|---|---|---|
| ✅ OK | Green | Whitelisted / known-good service | Documented — no action |
| ⚠️ REVIEW | Orange | Not in whitelist — unusual | Investigate and verify |
| 🚨 ALERT | Red | Known dangerous port | Immediate investigation |

### Information Shown per Port

For each port, the HIDS displays:
- **Protocol** (tcp/udp)
- **Local address** and port number
- **Service name** from systemd cgroup
- **UID** and **username** of the owning process
- **PID** and process name
- **Plain-English description** of the service

### Known ALERT Ports (built-in knowledge base)

| Port | Service | Why Dangerous |
|---|---|---|
| 23 | Telnet | Cleartext credentials |
| 1524 | Bindshell | Root shell — no authentication |
| 4444 | Metasploit | Default C2 listener |
| 6667 | IRC/UnrealIRCd | Botnet communication |
| 1337 | L33T | Hacker/C2 convention |
| 31337 | Back Orifice | Classic backdoor |
| 9090 | Common RAT | Remote Access Trojan |
| 514 | RSH | Dangerous legacy remote shell |
| 1099 | Java RMI | Exploitable Java registry |

### Whitelisting Ports

```bash
# In config.conf (ports show as OK, NOT hidden)
WHITELIST_PORTS="22,53,80,443,631,5353,3306"

# Or one per line in whitelist file
echo '8080' | sudo tee -a /var/lib/hids/whitelist_ports.conf
```

---

## 12. Interpreting the Output

### Severity Levels

| Level | Meaning | Required Action |
|---|---|---|
| 🚨 `CRITICAL` | Active compromise indicator or dangerous misconfiguration | Investigate **immediately** |
| ⚠️ `WARN` | Anomaly worth investigating — may be legitimate | Review within hours |
| ℹ️ `INFO` | Informational — recorded but not surfaced by default | Audit log only |

### Common CRITICAL Alerts Explained

| Alert | What It Means | What To Do |
|---|---|---|
| `hash_mismatch /etc/passwd` | User accounts file was modified | Check for new/modified accounts |
| `new_suid_binary` | New SUID binary appeared | Identify and verify if legitimate |
| `executable_in_tmp` | Executable in `/tmp` or `/dev/shm` | Identify and remove if malicious |
| `brute_force` | > 5 failed logins from one IP | Block IP with `ufw` / `fail2ban` |
| `uid0_duplicate` | Multiple UID 0 accounts | Remove illegitimate root account immediately |
| `authorized_keys_modified` | SSH key added unexpectedly | Remove suspicious key |
| `ld_preload_env` | Library injection in process | Identify and kill if unknown |
| `new_port_detected` (network) | New port on Metasploitable | Check if legitimate service |
| `cpu_trend_critical` (history) | CPU steadily rising | Check for cryptominer |
| `ram_trend_critical` (history) | RAM steadily filling | Check for memory leak |
| `disk_trend_critical` (history) | Disk filling fast | Free space + check ETA |
| `dangerous_port` (process) | Known backdoor port open | Immediate investigation |

### Reading the JSON Alert Log

```bash
# All CRITICAL alerts
sudo /opt/hids/hids.sh --query --severity CRITICAL

# Filter by module
sudo /opt/hids/hids.sh --query --module mod_integrity

# Last 20 entries
sudo /opt/hids/hids.sh --query --last 20

# With jq (if installed)
sudo cat /var/log/hids/alerts.json | jq 'select(.severity=="CRITICAL")'
```

---

## 13. Reducing False Positives

### Common False Positives and Solutions

| False Positive | Root Cause | Solution |
|---|---|---|
| `snap-*.mount` detected as modified | snap dynamically manages `/etc/systemd/system/` | Remove `/etc/systemd/system` from `INTEGRITY_WATCH_DIRS` |
| `LD_PRELOAD snapd-desktop-i` | snap uses LD_PRELOAD legitimately | Whitelist regex in `mod_integrity.sh` |
| `ps` at 100% CPU | HIDS itself uses `ps` to scan | Add `ps` to `WHITELIST_SUSPICIOUS_PROCS` |
| avahi-daemon dynamic UDP ports | mDNS uses random ports (50815, 47460...) | These show as REVIEW — visible, not hidden |
| ISO mounted at 100% disk | Mounted CD/ISO is read-only and appears full | `DISK_EXCLUDE_MOUNTPOINTS="/media"` (**NEW**) |
| Hashed 0 files | `IFS=$'\n\t'` breaks space-separated paths | One path per line in `INTEGRITY_WATCH` |
| `mawk` syntax error | mawk lacks `match()` with array capture | `sudo apt install gawk -y` |
| Network scan integer error | `grep -c` returns multi-line on empty input | Add `\| tr -d '[:space:]'` + `$(( n + 0 ))` |
| `cups/subscriptions.conf` modified | CUPS updates this file automatically | Remove from watch or exclude specifically |

### False Positive Workflow

```
False positive identified
        ↓
Is it REALLY legitimate?
├── YES → Whitelist or adjust threshold
└── NO  → Investigate as a real alert
        ↓
Whitelist (choose method):
├── Port    → Add to WHITELIST_PORTS in config.conf
├── Process → Add to WHITELIST_SUSPICIOUS_PROCS
├── SUID    → Add to whitelist_suid.conf
└── System change → Re-baseline
        ↓
Re-run scan to verify
sudo /opt/hids/hids.sh
```

### Whitelisting Commands

```bash
# Whitelist a SUID binary
echo '/usr/bin/newbinary' | sudo tee -a /var/lib/hids/whitelist_suid.conf

# Whitelist a port (shows as OK, NOT hidden)
echo '8080' | sudo tee -a /var/lib/hids/whitelist_ports.conf

# Whitelist a process (in config.conf)
WHITELIST_SUSPICIOUS_PROCS="snapd-desktop-i,ps,my-process"

# Always re-baseline after whitelisting
sudo /opt/hids/hids.sh --baseline
```

---

## 14. Test Scenarios

> ⚠️ **Run these tests ONLY on your own lab VM. Never on a production system.**

### Test 1 — Modified Critical File

```bash
# Simulate a backdoor account
sudo echo "backdoor:x:0:0::/root:/bin/bash" >> /etc/passwd

# Run HIDS
sudo /opt/hids/hids.sh
# Expected: CRITICAL — hash_mismatch on /etc/passwd + uid0_duplicate
# + Email sent to your Gmail

# Cleanup
sudo sed -i '/backdoor/d' /etc/passwd
sudo /opt/hids/hids.sh --baseline
```

### Test 2 — Malicious Process in /tmp

```bash
# Simulate malware in /tmp
cp /usr/bin/python3 /tmp/malware
chmod +x /tmp/malware
/tmp/malware -c "import time; time.sleep(300)" &

# Run HIDS
sudo /opt/hids/hids.sh
# Expected: CRITICAL — executable_in_tmp + suspicious_path_process

# Cleanup
kill %1
rm /tmp/malware
```

### Test 3 — New Open Port (local)

```bash
# Open a port that is not whitelisted
python3 -m http.server 9999 &

# Run HIDS
sudo /opt/hids/hids.sh
# Expected: REVIEW — port 9999 appears in port inventory

# Cleanup
kill %1
```

### Test 4 — SSH Brute Force (from another machine)

```bash
# From Metasploitable or another machine:
for i in {1..10}; do
    ssh wrong_user@192.168.0.41 2>/dev/null || true
done

# Run HIDS from Ubuntu
sudo /opt/hids/hids.sh
# Expected: CRITICAL — brute_force from source IP
```

### Test 5 — New Port on Metasploitable

```bash
# Connect to Metasploitable root shell
nc 192.168.0.21 1524

# From Metasploitable shell, open a new port
nc -lvp 9999 &

# Run network scan from Ubuntu
sudo bash /opt/hids/modules/mod_network_scan.sh
# Expected: CRITICAL — new_port_detected: 9999/tcp on 192.168.0.21
```

### Test 6 — Historical Trends (mod_history)

```bash
# After several automatic scans, view trend sparklines
sudo bash /opt/hids/modules/mod_history.sh

# View raw data
sudo bash /opt/hids/modules/mod_history.sh --show cpu --last 10
sudo bash /opt/hids/modules/mod_history.sh --show ram --last 10
```

---

## 15. Maintenance & Best Practices

### Recommended Daily Routine

```bash
# Check timer status
sudo systemctl status hids.timer

# Check today's alerts
sudo journalctl -u hids.service --since "today" | grep -E "CRITICAL|WARN"

# Read last report
sudo cat /var/log/hids/report.txt

# Check trends
sudo bash /opt/hids/modules/mod_history.sh
```

### Recommended Weekly Routine

```bash
# Check log sizes
du -sh /var/log/hids/
du -sh /var/log/msmtp.log
ls /var/lib/hids/history/ && wc -l /var/lib/hids/history/cpu.csv

# Check baseline age
sudo cat /var/lib/hids/baseline/meta.conf

# Review all CRITICAL alerts from the week
sudo /opt/hids/hids.sh --query --severity CRITICAL --last 100
```

### Log Rotation

```bash
# Keep last 1000 alert lines
sudo tail -1000 /var/log/hids/alerts.json > /tmp/alerts_trim.json
sudo mv /tmp/alerts_trim.json /var/log/hids/alerts.json

# Clear msmtp log
sudo truncate -s 0 /var/log/msmtp.log

# Reset trend history (optional)
rm /var/lib/hids/history/*.csv
```

### After a System Update

```bash
# Always do in this order:
sudo apt update && sudo apt upgrade -y
sudo /opt/hids/hids.sh --baseline
sudo /opt/hids/hids.sh
# Verify the result is clean
```

### Backup Configuration

```bash
# Backup config, baseline, and whitelists
sudo tar czf /home/denis/hids_backup_$(date +%Y%m%d).tar.gz \
    /opt/hids/config.conf \
    /var/lib/hids/baseline/ \
    /var/lib/hids/whitelist_suid.conf \
    /var/lib/hids/whitelist_ports.conf \
    /etc/msmtprc

echo "Backup created: hids_backup_$(date +%Y%m%d).tar.gz"
```

### Restore a Baseline

```bash
sudo tar xzf /home/denis/hids_backup_20260415.tar.gz -C /
```

---

## 16. Glossary

| Term | Definition |
|---|---|
| **HIDS** | Host Intrusion Detection System — monitors the machine from within |
| **NIDS** | Network Intrusion Detection System — monitors network traffic |
| **Baseline** | Snapshot of known-good system state used as comparison reference |
| **SHA256** | Cryptographic hash — unique fingerprint of a file's content |
| **SUID** | Set User ID — runs a file with its owner's privileges (escalation risk) |
| **SGID** | Set Group ID — similar to SUID but for the group |
| **World-writable** | File/directory modifiable by any user — dangerous |
| **LD_PRELOAD** | Env variable to preload libraries — exploited by rootkits |
| **C2** | Command and Control — attacker's remote control server |
| **Brute force** | Attack trying many passwords until finding the correct one |
| **Privilege escalation** | Gaining higher privileges than originally granted |
| **Persistence** | Technique allowing malware to survive reboots |
| **Whitelist** | List of known-legitimate items explicitly excluded from alerts |
| **False positive** | Alert triggered by legitimate activity |
| **IFS** | Internal Field Separator — bash field split character |
| **systemd** | Linux service manager and init system |
| **Timer** | Systemd unit that triggers a service on a schedule |
| **msmtp** | Lightweight SMTP client for Linux terminal email |
| **gum** | Charm.sh CLI tool for professional terminal UIs |
| **gawk** | GNU Awk — required (mawk lacks advanced regex features) |
| **mawk** | Default awk on Ubuntu 24.04 — insufficient, replace with gawk |
| **journalctl** | Systemd journal log viewer |
| **ss** | Socket statistics tool — replaces netstat |
| **cgroup** | Linux control group — systemd uses these to track which service owns a port |
| **Sparkline** | Compact ASCII trend chart in one line: ▁▂▃▄▅▆▇█ |
| **Deduplication** | Alert only once on persistent conditions to prevent alert fatigue |
| **Linear regression** | Math method to calculate slope/trend of a data series |
| **ETA** | Estimated Time to Arrival — projected disk-full time at current growth |
| **nmap** | Network scanner — host discovery and port scanning |
| **lab-net** | Isolated virtual network (192.168.0.0/24) used for testing |
| **Metasploitable** | Intentionally vulnerable VM for pentesting practice |

---

## Quick Reference — Important Files

| File | Role |
|---|---|
| `/opt/hids/hids.sh` | Main entry point |
| `/opt/hids/config.conf` | **ALL** configuration |
| `/opt/hids/modules/mod_history.sh` | Trend analysis module **(NEW)** |
| `/opt/hids/modules/mod_process.sh` | Port inventory module **(ENHANCED)** |
| `/var/lib/hids/baseline/` | Reference snapshot data |
| `/var/lib/hids/history/` | Trend CSV data **(NEW)** |
| `/var/log/hids/alerts.json` | NDJSON alert log |
| `/var/log/hids/report.txt` | Human-readable last scan report |
| `/etc/msmtprc` | Email configuration **(PROTECT — contains password)** |
| `/etc/systemd/system/hids.timer` | Automatic scheduling |
| `/var/lib/hids/whitelist_suid.conf` | Allowed SUID binaries |
| `/var/lib/hids/whitelist_ports.conf` | Allowed ports |

---

*Guide written April 15, 2026 — Ubuntu 24.04.4 LTS*
*HIDS Version 2.0 — BeCode Security Lab Project*
