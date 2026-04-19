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
8. [Health History & Trend Analysis](#8-health-history--trend-analysis)
9. [Port Classification (mod_process)](#9-port-classification-mod_process)
10. [Systemd Automation](#10-systemd-automation)
11. [Email Alerts (msmtp + Gmail)](#11-email-alerts-msmtp--gmail)
12. [Network Monitoring (lab-net)](#12-network-monitoring-lab-net)
13. [Interpreting the Output](#13-interpreting-the-output)
14. [Reducing False Positives](#14-reducing-false-positives)
15. [Test Scenarios](#15-test-scenarios)
16. [Troubleshooting](#16-troubleshooting)
17. [Maintenance & Best Practices](#17-maintenance--best-practices)
18. [Complete Command Reference](#18-complete-command-reference)
19. [Known Bug Fixes (v2)](#19-known-bug-fixes-v2)
20. [Glossary](#20-glossary)
21. [Quick Reference & Checklists](#21-quick-reference--checklists)

---

## 1. What Is a HIDS?

### Definition

A **HIDS** (Host Intrusion Detection System) is a security tool that continuously monitors a machine to detect any suspicious or abnormal activity. Unlike a firewall that blocks threats at the perimeter, a HIDS operates from within — watching what actually happens on the OS after a connection is established.

This makes it the **only tool capable of detecting post-exploitation activity**: what an attacker does once they are already inside the system.

### HIDS vs NIDS

| Feature | HIDS | NIDS |
|---|---|---|
| **Location** | On the monitored machine | On the network |
| **What it sees** | Processes, files, users, local logs, OS state | Network packets in transit |
| **Examples** | Our HIDS, OSSEC, Wazuh, Tripwire | Suricata, Snort, Zeek |
| **Strength** | Full OS-level visibility | Global network traffic view |
| **Weakness** | Blind to encrypted network traffic | Blind to what happens inside the OS |

> **Key insight:** NIDS sees the packets. HIDS sees what those packets triggered.
> An attacker using stolen credentials bypasses NIDS entirely — only HIDS will
> catch them modifying `/etc/passwd` once inside.

**Practical example:**
1. Attacker connects via SSH using stolen credentials (encrypted — NIDS sees nothing)
2. Once inside, attacker runs: `echo "backdoor:x:0:0::/root:/bin/bash" >> /etc/passwd`
3. NIDS still sees nothing. Our HIDS detects the SHA256 hash change on `/etc/passwd` within 5 minutes and fires **CRITICAL**.

**Complementarity:** In a real environment, HIDS and NIDS work together:
- NIDS catches network-level attacks (port scans, exploit attempts)
- HIDS catches post-exploitation (file changes, new processes, persistence mechanisms)

### What Our HIDS Monitors — 7 Modules

```
🛡️ HIDS v2
├── ♥  mod_health.sh       → CPU, RAM, Disk, Swap, I/O, File Descriptors, Uptime
├── 📈 mod_history.sh      → Historical trends, sparklines, drift detection (NEW v2)
├── 👤 mod_users.sh        → Sessions, logins, sudo, accounts, groups, SSH keys
├── ⚡ mod_process.sh      → Full port inventory (OK/REVIEW/ALERT), process STAT/TIME/exe (ENHANCED v2)
├── 🔒 mod_integrity.sh    → SHA256 hashes, SUID, world-writable, crontabs, LD_PRELOAD
├── 🌐 mod_network_scan.sh → All lab-net hosts auto-discovered, per-host port baseline (FIXED v2)
└── 📋 mod_alert.sh        → JSON log, report, Gmail digest CRITICAL+WARN (UPDATED v2)
```

### How It Works

```
INITIAL STATE (clean system)
         ↓
    BASELINE (snapshot of files, ports, users, SUID...)
         ↓
    PERIODIC SCAN (every 5 minutes via systemd timer)
         ↓
    COMPARISON vs BASELINE
         ↓
    ALERT if difference detected → JSON log + Gmail email
```

1. Take a **baseline snapshot** of the system when it is clean and known-good
2. At each scan, compare the current state against that snapshot
3. If something changed → **ALERT** (CRITICAL or WARN depending on severity)

---

## 2. Project Architecture

### File Structure

```
/opt/hids/                          ← Main installation directory
├── hids.sh                         ← Main entry point (orchestrator)
├── config.conf                     ← ALL configuration lives here
├── baseline.sh                     ← Snapshot & diff engine
├── live_monitor.sh                 ← Real-time dashboard
├── lib/
│   └── lib_utils.sh                ← Shared library (alerts, colors, dedup)
└── modules/
    ├── mod_health.sh               ← Module 1: System Health
    ├── mod_history.sh              ← Module 2: Health History & Trends (NEW v2)
    ├── mod_users.sh                ← Module 3: User Activity
    ├── mod_process.sh              ← Module 4: Process & Network (ENHANCED v2)
    ├── mod_integrity.sh            ← Module 5: File Integrity
    ├── mod_network_scan.sh         ← Module 6: Network Scan (FIXED v2)
    └── mod_alert.sh                ← Module 7: Alert Aggregation & Reporting (UPDATED v2)

/var/lib/hids/                      ← Persistent data
├── baseline/                       ← Reference snapshots
│   ├── file_hashes.db              ← SHA256 hashes of watched files
│   ├── suid_binaries.list          ← Known SUID/SGID binaries at baseline time
│   ├── users.list                  ← User accounts snapshot
│   ├── groups.list                 ← Group memberships snapshot
│   ├── listening_ports.list        ← Listening ports snapshot
│   ├── health_averages.conf        ← System health reference values
│   ├── crontabs.db                 ← Crontab hashes
│   └── meta.conf                   ← Metadata (date, host, HIDS version)
├── history/                        ← Trend data (NEW v2)
│   ├── cpu.csv                     ← CPU load time series (epoch,timestamp,value)
│   ├── ram.csv                     ← RAM usage time series
│   └── disk.csv                    ← Disk usage time series
├── network_baseline/               ← Per-host network baselines (FIXED v2)
│   ├── 192_168_0_21_ports.list     ← Metasploitable open ports
│   └── 192_168_0_31_ports.list     ← Colleague VM open ports
├── whitelist_suid.conf             ← Allowed SUID binaries
├── whitelist_ports.conf            ← Allowed ports (optional)
└── alert_state.db                  ← Alert deduplication state

/var/log/hids/                      ← Logs
├── alerts.json                     ← NDJSON alert log (one JSON object per line)
├── report.txt                      ← Human-readable last run report
└── cron.log                        ← Automated execution log

/etc/systemd/system/                ← Automation
├── hids.service                    ← Systemd service
└── hids.timer                      ← Timer (every 5 minutes)

/etc/msmtprc                        ← Gmail email configuration (protect this file!)
```

### Execution Flow

```
sudo /opt/hids/hids.sh
        ↓
   [Root check — must run as root]
        ↓
   [Load config.conf]
        ↓
   [Check dependencies: gawk, gum, nmap, ss...]
        ↓
   [Baseline exists?]
   ├── NO  → Create automatically
   └── YES → Continue
        ↓
   mod_health.sh     → CPU, RAM, disk, I/O checks
        ↓
   mod_history.sh    → Record data point, calculate trends (NEW v2)
        ↓
   mod_users.sh      → Sessions, failed logins, accounts, SSH keys
        ↓
   mod_process.sh    → Processes, full port inventory with classification
        ↓
   mod_integrity.sh  → SHA256 hashes, SUID, world-writable, crontabs
        ↓
   mod_network_scan.sh → Discover all hosts, scan ports, compare baseline
        ↓
   mod_alert.sh      → Summary + Email if CRITICAL or WARN (v2)
        ↓
   [Write report.txt]
```

### Data Sources per Module

| Module | Data Source | File / Command |
|---|---|---|
| mod_health | CPU load | `/proc/loadavg` |
| mod_health | RAM usage | `/proc/meminfo` |
| mod_health | Disk usage | `df --output=pcent,target` |
| mod_health | I/O wait | `/proc/stat` (2 samples, delta) |
| mod_health | File descriptors | `/proc/sys/fs/file-nr` |
| mod_history | CPU/RAM/Disk trends | Same as health + CSV in `/var/lib/hids/history/` |
| mod_users | Active sessions | `who(1)` → `/var/run/utmp` |
| mod_users | Login history | `last(1)` → `/var/log/wtmp` |
| mod_users | Failed SSH logins | `journalctl -u sshd` / `/var/log/auth.log` |
| mod_users | Sudo activity | `journalctl` / `/var/log/auth.log` |
| mod_process | Running processes | `/proc/[pid]/exe`, `/proc/[pid]/status` |
| mod_process | Listening ports + cgroup | `ss -tulnpe` (includes UID and systemd cgroup) |
| mod_process | Established connections | `ss -tunpe state established` |
| mod_integrity | File hashes | `sha256sum` on `INTEGRITY_WATCH` |
| mod_integrity | SUID/SGID binaries | `find / -perm /6000` |
| mod_integrity | LD_PRELOAD injection | `/proc/[pid]/environ` |
| mod_network_scan | Active hosts | `nmap -sn 192.168.0.0/24` |
| mod_network_scan | Open ports | `nmap -sT --open -p-` (per discovered host) |

> **Why `ss -tulnpe` is important:** It shows not just the port, but the exact process owning it, its UID, and the systemd cgroup responsible. This makes port ownership unambiguous and impossible to spoof via process name alone.

---

## 3. Installation

### Prerequisites

```bash
# Check all required tools
for cmd in ss sha256sum find stat awk sort uniq wc who last nmap; do
    command -v "$cmd" &>/dev/null && echo "✅ $cmd" || echo "❌ MISSING: $cmd"
done
```

> ⚠️ **Critical — gawk vs mawk:**
> Ubuntu 24.04 uses `mawk` by default. `mawk` does **NOT** support `match()`
> with array capture groups, which our alert modules require.
> Always install `gawk` explicitly — `awk --version` must show `GNU Awk`, not `mawk`.

```bash
# Install gawk (REQUIRED) and nmap
sudo apt install gawk nmap -y
awk --version | head -1   # Must show: GNU Awk 5.x
```

### Install gum (Visual Interface)

`gum` provides the professional terminal UI — borders, colored badges, tables, spinners.

```bash
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://repo.charm.sh/apt/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/charm.gpg
echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" | sudo tee /etc/apt/sources.list.d/charm.list
sudo apt update && sudo apt install gum -y
gum --version
```

### Installation Steps

```bash
# 1. Create directory structure
sudo mkdir -p /opt/hids/lib /opt/hids/modules
sudo mkdir -p /var/lib/hids /var/log/hids
sudo mkdir -p /var/lib/hids/network_baseline   # NEW v2 — per-host baselines
sudo mkdir -p /var/lib/hids/history            # NEW v2 — trend data

# 2. Copy files (from project folder)
cd ~/hids_project

sudo cp hids.sh config.conf baseline.sh live_monitor.sh /opt/hids/
sudo cp lib/lib_utils.sh /opt/hids/lib/

sudo cp modules/mod_health.sh       /opt/hids/modules/
sudo cp modules/mod_history.sh      /opt/hids/modules/   # NEW v2
sudo cp modules/mod_users.sh        /opt/hids/modules/
sudo cp modules/mod_process.sh      /opt/hids/modules/   # ENHANCED v2
sudo cp modules/mod_integrity.sh    /opt/hids/modules/
sudo cp modules/mod_alert.sh        /opt/hids/modules/   # UPDATED v2
sudo cp modules/mod_network_scan.sh /opt/hids/modules/   # FIXED v2

# 3. Apply permissions
sudo chmod +x /opt/hids/hids.sh /opt/hids/baseline.sh /opt/hids/live_monitor.sh
sudo chmod +x /opt/hids/modules/*.sh
sudo chown -R root:root /opt/hids /var/lib/hids /var/log/hids
sudo chmod 750 /opt/hids /var/lib/hids /var/log/hids
sudo chmod 640 /opt/hids/config.conf

# 4. Create initial baseline (on a CLEAN, KNOWN-GOOD system)
sudo /opt/hids/hids.sh --baseline

# 5. First scan — should show CRITICAL: 0, WARN: 0
sudo /opt/hids/hids.sh
```

---

## 4. Configuration (config.conf)

> ⚠️ **Golden Rule: Never edit the module scripts directly.**
> All configuration lives in `/opt/hids/config.conf` only.
> Open with: `sudo nano /opt/hids/config.conf`

### Complete Configuration Reference

```bash
# ============================================================
# GENERAL
# ============================================================
HIDS_DATA_DIR="/var/lib/hids"
HIDS_OUTPUT_DIR="/var/log/hids"
ALERT_LOG="${HIDS_OUTPUT_DIR}/alerts.json"
ALERT_STATE_FILE="${HIDS_DATA_DIR}/alert_state.db"
REPORT_FILE="${HIDS_OUTPUT_DIR}/report.txt"
WHITELIST_PORTS_FILE="${HIDS_DATA_DIR}/whitelist_ports.conf"
WHITELIST_SUID_FILE="${HIDS_DATA_DIR}/whitelist_suid.conf"
HIDS_HOSTNAME=""                       # Leave empty = auto-detected
ALERT_EMAIL="your@gmail.com"           # Email for alerts (CRITICAL + WARN in v2)
MAIL_CMD="msmtp"                       # Email command

# ============================================================
# MODULE 1: SYSTEM HEALTH
# ============================================================
LOAD_MULTIPLIER=2.0        # Alert if load > 2 × nproc (2 cores → alert if load > 4.00)
THRESHOLD_RAM_MB=512       # Alert if available RAM < 512 MB
THRESHOLD_DISK_PCT=85      # Alert if disk used > 85%
THRESHOLD_SWAP_PCT=70      # Alert if swap used > 70%
THRESHOLD_IOWAIT_PCT=30    # Alert if I/O wait > 30%
THRESHOLD_FD_COUNT=65000   # Alert if file descriptors > 65000
# NEW in v2: exclude mounted ISOs/CDs from disk alerts
DISK_EXCLUDE_MOUNTPOINTS="/media"

# ============================================================
# MODULE 3: USER ACTIVITY
# ============================================================
THRESHOLD_FAILED_LOGINS=5              # Alert if >5 SSH failures from one IP
OFF_HOURS=""                           # Off-hours alert hours e.g. "0,1,2,3,22,23"
TRUSTED_SSH_SOURCES="192.168.1.0/24"   # Trusted SSH subnets (empty = flag all remote)
SENSITIVE_GROUPS="sudo,wheel,docker,adm,shadow,disk"  # Group changes trigger CRITICAL

# ============================================================
# MODULE 4: PROCESS & NETWORK (ENHANCED v2)
# ============================================================
SUSPICIOUS_PATHS="/tmp,/var/tmp,/dev/shm,/run/shm"
WHITELIST_PORTS="22,53,80,443,631,5353,3306,5432"
# Note: unwhitelisted ports show as REVIEW — nothing is hidden
WHITELIST_SUSPICIOUS_PROCS="snapd-desktop-i,ps"
ALERT_OUTBOUND_PORTS="4444,1337,31337,8080,9090,6666,6667"
THRESHOLD_PROC_CPU=90      # Alert if a process uses > 90% CPU
THRESHOLD_PROC_MEM=50      # Alert if a process uses > 50% RAM

# ============================================================
# MODULE 5: FILE INTEGRITY
# ============================================================
# ⚠️ CRITICAL: One path per line!
# The HIDS uses IFS=$'\n\t' — space-separated paths = "Hashed 0 files" bug
INTEGRITY_WATCH="
/etc/passwd
/etc/shadow
/etc/group
/etc/gshadow
/etc/sudoers
/etc/ssh/sshd_config
/etc/hosts
/etc/crontab
/etc/ld.so.conf
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

INTEGRITY_DEPTH=3
INTEGRITY_RECENT_MINUTES=15   # Alert if watched file modified in last N minutes
# NEW in v2: exclude auto-updated runtime files from recent modification check
INTEGRITY_RECENT_EXCLUDE="/etc/cups,/root/.lesshst"
SUID_SCAN_PATHS="/"
SUID_SCAN_EXCLUDE="/proc /sys /dev /run /snap /media"
WORLD_WRITABLE_SCAN="/etc /tmp /var /home"
```

### Why These Watched Files?

| File | Why It Matters |
|---|---|
| `/etc/passwd` | User accounts — attackers add backdoor root accounts here |
| `/etc/shadow` | Password hashes — primary target for offline cracking attacks |
| `/etc/sudoers` | Who can run commands as root — privilege escalation vector |
| `/etc/ssh/sshd_config` | SSH config — attackers may enable root login or weaken auth |
| `/etc/hosts` | Local DNS resolution — can redirect legitimate domains to attacker servers |
| `/etc/crontab` | Scheduled tasks — most common persistence mechanism |
| `/etc/fstab` | Disk mounts — modifications can expose sensitive partitions |

---

## 5. The Baseline — Core Concept

### What Is a Baseline?

The baseline is a **complete snapshot of the system's known-good state** taken at a specific moment. It is the reference against which every subsequent scan is compared. Any difference = potential anomaly = alert.

```
BASELINE (known-good state)          CURRENT SCAN
/etc/passwd → hash: abc123           /etc/passwd → hash: xyz789  ← CHANGED!
/etc/shadow → hash: def456      vs   /etc/shadow → hash: def456
26 SUID binaries known               27 SUID binaries found      ← NEW!
Ports: 22, 53, 80, 443               Ports: 22, 53, 80, 443, 9999 ← NEW!
         ↓                                    ↓
         └──────── DIFF ────────────→ CRITICAL: hash_mismatch /etc/passwd
                                      CRITICAL: new_suid_binary
                                      CRITICAL: new_port_detected
```

### What the Baseline Contains

| File | Content |
|---|---|
| `file_hashes.db` | SHA256 hashes of all INTEGRITY_WATCH and INTEGRITY_WATCH_DIRS files |
| `suid_binaries.list` | All SUID/SGID binaries known at baseline time |
| `listening_ports.list` | All open ports at baseline time |
| `users.list` | All user accounts at baseline time |
| `groups.list` | All group memberships at baseline time |
| `crontabs.db` | Hashes of all crontab files |
| `meta.conf` | Timestamp, hostname, HIDS version |

### Baseline Commands

```bash
# Create/recreate the full baseline (run on CLEAN system)
sudo /opt/hids/hids.sh --baseline

# Check baseline status and age
sudo /opt/hids/hids.sh --status
sudo cat /var/lib/hids/baseline/meta.conf

# Inspect baseline contents
sudo ls -la /var/lib/hids/baseline/
sudo wc -l /var/lib/hids/baseline/file_hashes.db  # Count hashed files

# Delete and recreate (use only if corrupted)
sudo rm -rf /var/lib/hids/baseline
sudo /opt/hids/hids.sh --baseline
```

### When to Re-Baseline?

| Situation | Action | Reason |
|---|---|---|
| After `apt upgrade` | ✅ **Always re-baseline** | Updated binaries → new hashes |
| After installing software | ✅ Re-baseline | New SUID binaries possible |
| After intentional config change | ✅ Re-baseline | Accept the new known-good state |
| After adding a user | ✅ Re-baseline | New account is now legitimate |
| After whitelisting a false positive | ✅ Re-baseline | Confirm new clean state |
| **Intrusion suspected** | ❌ **NEVER re-baseline** | Preserve forensic evidence! |

> ⚠️ **The baseline is your forensic reference.** If you re-baseline after a compromise,
> you destroy the evidence of what changed. Never re-baseline if something looks wrong.

---

## 6. Modules in Detail

### Module 1 — System Health (mod_health.sh)

**What it monitors:** CPU load, RAM, disk, swap, I/O wait, file descriptors, uptime.

**Data sources:**
- CPU load → `/proc/loadavg`
- RAM → `/proc/meminfo`
- Disk → `df --output=pcent,target`
- I/O wait → `/proc/stat` (2 samples, delta calculation — avoids stale cached values)
- File descriptors → `/proc/sys/fs/file-nr`
- Uptime → `/proc/uptime`

```bash
sudo bash /opt/hids/modules/mod_health.sh
```

**Key thresholds (all tunable in config.conf):**
- `LOAD_MULTIPLIER=2.0` → alert if load > 2 × nproc (2 cores: alert if load > 4.00)
- `THRESHOLD_RAM_MB=512` → alert if available RAM < 512 MB
- `THRESHOLD_DISK_PCT=85` → alert if any disk > 85%
- `DISK_EXCLUDE_MOUNTPOINTS="/media"` → ignore mounted ISOs **(NEW v2)**
- `THRESHOLD_SWAP_PCT=70` → alert if swap > 70%
- `THRESHOLD_IOWAIT_PCT=30` → alert if I/O wait > 30%
- `THRESHOLD_FD_COUNT=65000` → alert if file descriptors > 65000

---

### Module 2 — Health History & Trends (mod_history.sh) 🆕 NEW v2

**What it monitors:** Historical trends for CPU, RAM, and disk usage over time.

**This module answers:** *"Is something slowly getting worse on this system?"*

**Use cases:**
- Detect a cryptominer slowly consuming CPU over hours
- Detect a memory leak gradually filling RAM
- Detect a log file or database eating disk space
- Correlate the exact moment of a spike with other events

```bash
# Full analysis with sparkline charts
sudo bash /opt/hids/modules/mod_history.sh

# View raw historical data
sudo bash /opt/hids/modules/mod_history.sh --show cpu  --last 20
sudo bash /opt/hids/modules/mod_history.sh --show ram  --last 20
sudo bash /opt/hids/modules/mod_history.sh --show disk --last 20
```

**How it works:**
- Records one data point per scan → stored in `/var/lib/hids/history/*.csv`
- CSV format: `epoch_seconds,human_timestamp,value`
- Keeps last **288 points = 24 hours** of rolling history (auto-rotated)
- Calculates **linear regression** over the last 12 points (1-hour window) to find slope
- Classifies trend: `rising` / `falling` / `stable`
- Draws **ASCII sparkline charts**: `▁▂▃▄▅▆▇█`
- Projects **ETA to disk full** at current growth rate

**Alert thresholds:**

| Metric | WARN | CRITICAL |
|---|---|---|
| CPU Load | Trending up toward 80% of limit | Trending up > 80% of limit |
| RAM Usage | Trending up, > 70% used | Trending up, > 85% used |
| Disk (/) | Trending up, > 70% of threshold | Trending up, > threshold (85%) |

**Maintenance commands:**
```bash
tail -20 /var/lib/hids/history/cpu.csv     # Raw CPU trend data
wc -l /var/lib/hids/history/cpu.csv        # Number of recorded data points
rm /var/lib/hids/history/*.csv             # Reset all trend history
```

---

### Module 3 — User Activity (mod_users.sh)

**What it monitors:** Sessions, failed logins, sudo activity, user accounts, group membership, SSH keys.

**Data sources:**
- Active sessions → `who(1)` → `/var/run/utmp`
- Login history → `last(1)` → `/var/log/wtmp`
- Failed SSH logins → `journalctl -u sshd` / `/var/log/auth.log`
- Sudo activity → `journalctl` / `/var/log/auth.log`
- User accounts → `/etc/passwd` (compared to baseline)
- Group memberships → `/etc/group` (compared to baseline)
- SSH keys → `~/.ssh/authorized_keys` (mtime check vs baseline)

```bash
sudo bash /opt/hids/modules/mod_users.sh
```

**Session classification (FIXED in v2 — physical sessions no longer flagged):**

| Session | Source | Classification | Why |
|---|---|---|---|
| `denis@seat0` | `login` (physical keyboard) | ✅ OK | Local physical session |
| `denis@:0` | `:0` (display manager) | ✅ OK | Local graphical session |
| `denis@pts/2` | `local` | ✅ OK | Local terminal |
| `denis@pts/1` | Remote IP | ⚠️ REVIEW | Remote SSH — monitor |
| `root@pts/0` | Any remote IP | 🚨 CRITICAL | Remote root login |

**What triggers alerts:**
- More than `THRESHOLD_FAILED_LOGINS=5` failed logins from one IP → CRITICAL `brute_force`
- New user account vs baseline → CRITICAL `new_user_account`
- Sensitive group membership change → CRITICAL `group_change`
- SSH authorized_keys modified → CRITICAL `authorized_keys_modified`
- Remote root login → CRITICAL `root_remote_login`

---

### Module 4 — Process & Network Audit (mod_process.sh) 🔧 Enhanced v2

**What it monitors:** Suspicious processes, full port inventory with enriched details, established connections, resource consumers.

**Data sources:**
- Processes → `/proc/[pid]/exe`, `/proc/[pid]/status`, `/proc/[pid]/environ`
- Listening ports → `ss -tulnpe` (protocol, address, port, UID, cgroup)
- Established connections → `ss -tunpe state established`

```bash
sudo bash /opt/hids/modules/mod_process.sh
```

**Process checks:**
- Executables running from suspicious paths (`/tmp`, `/dev/shm`, `/var/tmp`, `/run/shm`)
- Processes with deleted binaries (`/proc/[pid]/exe (deleted)` — common malware tactic)
- Root processes running from home directories
- Top 10 CPU/RAM consumers with full enriched details **(ENHANCED in v2):**
  - PID, Name, CPU%, MEM%, User
  - **STAT** — process state (S=sleeping, R=running, Z=zombie!, D=uninterruptible!)
  - **START** — process start time
  - **TIME** — cumulative CPU time used
  - **↳ exe** — full binary path from `/proc/[pid]/exe` (cannot be spoofed by renaming)

> **Why exe path matters:** A malware renamed to `sshd` will fool name-based detection.
> But `/proc/[pid]/exe` will show `/tmp/sshd` or `/dev/shm/sshd` — the real path.

**Port inventory:**
Every port is displayed. Nothing is hidden. See [Section 9 — Port Classification](#9-port-classification-mod_process).

---

### Module 5 — File Integrity (mod_integrity.sh)

**What it monitors:** SHA256 hashes of critical files, SUID binaries, world-writable files, crontabs, LD_PRELOAD injection.

**Data sources:**
- File hashes → `sha256sum` on all `INTEGRITY_WATCH` and `INTEGRITY_WATCH_DIRS` files
- SUID/SGID binaries → `find / -perm /6000`
- World-writable files → `find -perm -o+w` in `/etc`, `/tmp`, `/var`, `/home`
- Crontabs → `sha256sum` on `/etc/crontab` and all cron directories
- LD_PRELOAD injection → `/proc/[pid]/environ` for every running process

```bash
sudo bash /opt/hids/modules/mod_integrity.sh
```

> ⚠️ **Critical — IFS Bug:** Paths in `INTEGRITY_WATCH` must be **one per line**.
> Space-separated paths on one line = "Hashed 0 files" bug (caused by `IFS=$'\n\t'`).
> This is the most common configuration mistake.

**LD_PRELOAD detection explained:**
LD_PRELOAD is a Linux environment variable that loads a library before all others.
Rootkits use it to intercept system calls and hide processes, files, or network connections.
Our HIDS scans `/proc/[pid]/environ` for every process looking for unexpected LD_PRELOAD entries.

---

### Module 6 — Network Scan (mod_network_scan.sh) 🔧 Fixed v2

**What it monitors:** All active hosts on lab-net (auto-discovered), port changes on every monitored host, established connections to lab-net.

**v2 fix:** The scan now auto-discovers ALL hosts on `192.168.0.0/24` and creates
a separate port baseline per host. Previously only Metasploitable (.21) was scanned.
Now both `.21` and `.31` (and any new host) are automatically monitored.

**How it works:**
- `nmap -sn 192.168.0.0/24` → discovers all active hosts (excludes our own IP)
- For each host: `nmap -sT --open -p-` → full port scan
- Compares with per-host baseline in `/var/lib/hids/network_baseline/`
- New port → CRITICAL: `new_port_detected`
- Closed port → WARN: `port_closed`
- New unknown host on network → WARN: `new_host_detected`

```bash
sudo bash /opt/hids/modules/mod_network_scan.sh
```

---

### Module 7 — Alert Aggregation (mod_alert.sh) 🔧 Updated v2

**What it does:** Aggregates all alerts from the current run, generates the summary report, sends Gmail digest.

**v2 update:** Now sends email for both **CRITICAL and WARN** alerts (previously CRITICAL only).

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

**Deduplication:** The engine tracks which alerts have already been reported using `alert_state.db`.
If the same condition persists across multiple scans, it alerts only once — preventing **alert fatigue**
(the tendency to ignore all alerts when there are too many repetitions).

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
# By severity
sudo /opt/hids/hids.sh --query --severity CRITICAL
sudo /opt/hids/hids.sh --query --severity WARN

# By module
sudo /opt/hids/hids.sh --query --module mod_integrity
sudo /opt/hids/hids.sh --query --module mod_process
sudo /opt/hids/hids.sh --query --module mod_network_scan

# By count
sudo /opt/hids/hids.sh --query --last 20

# Combined filters
sudo /opt/hids/hids.sh --query --severity CRITICAL --last 10

# Manual grep on the JSON log
sudo grep 'CRITICAL' /var/log/hids/alerts.json | wc -l
sudo tail -f /var/log/hids/alerts.json   # Follow live

# With jq (if installed)
sudo cat /var/log/hids/alerts.json | jq 'select(.severity=="CRITICAL")'
sudo cat /var/log/hids/alerts.json | jq 'select(.event=="brute_force")'
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
sudo cat /var/log/hids/report.txt              # Human-readable last run report
sudo cat /var/log/hids/alerts.json             # Full NDJSON alert log
sudo truncate -s 0 /var/log/hids/alerts.json   # Clear alert log
sudo ls -la /var/lib/hids/baseline/            # Inspect baseline files
sudo wc -l /var/lib/hids/baseline/file_hashes.db  # Number of hashed files
sudo cat /var/lib/hids/baseline/meta.conf      # Baseline date and version
ls /var/lib/hids/history/                      # Trend data files
tail -20 /var/lib/hids/history/cpu.csv         # Raw CPU trend data
wc -l /var/lib/hids/history/ram.csv            # Number of trend data points
```

### Whitelists

```bash
# Whitelist a SUID binary
echo '/usr/bin/newbinary' | sudo tee -a /var/lib/hids/whitelist_suid.conf

# Whitelist a port (shows as OK — NOT hidden from inventory)
echo '8080' | sudo tee -a /var/lib/hids/whitelist_ports.conf
# Or in config.conf: WHITELIST_PORTS="22,53,80,443,631,8080"

# Whitelist a process from suspicious path check
# In config.conf: WHITELIST_SUSPICIOUS_PROCS="snapd-desktop-i,ps"

# Exclude files from recent modification detection (NEW v2)
# In config.conf: INTEGRITY_RECENT_EXCLUDE="/etc/cups,/root/.lesshst"

# Always re-baseline after whitelisting
sudo /opt/hids/hids.sh --baseline
```

---

## 8. Health History & Trend Analysis

`mod_history.sh` records CPU load, RAM usage, and disk usage at every scan run.
It detects dangerous trends over time — a cryptominer slowly consuming CPU, a
memory leak filling RAM, or a growing log file eating disk space.

### How Trend Detection Works

Every scan appends one CSV row to each metric file:

```
# Format: epoch_seconds,human_timestamp,value
1744721700,2026-04-15 10:15:00,0.45
1744722000,2026-04-15 10:20:00,0.52
1744722300,2026-04-15 10:25:00,1.23
```

The module then:
1. Reads the last 12 points (= 1 hour of data)
2. Applies **linear regression** to calculate the slope (is the line going up or down?)
3. Classifies: `rising` / `falling` / `stable`
4. Compares the current value against thresholds
5. Emits WARN or CRITICAL if both trend and value are dangerous

**Linear regression for beginners:** It fits a line through the last 12 data points.
If that line slopes upward, the trend is "rising". A single spike won't trigger it —
the trend must be sustained over at least an hour.

### ASCII Sparklines

The visual output looks like this:

```
CPU Load Trend (last 48 scans × 5min = ~240min)

▁▁▁▁▁▁▁▁▁▂▂▃▄▅▆▇█████████████████████████████████

Min: 0.05  Max: 3.79  Threshold: 4.0  nproc: 2
```

Each `▁` to `█` character represents one data point mapped to a height between 1 and 8.

### Trend Alert Thresholds

| Metric | WARN | CRITICAL |
|---|---|---|
| CPU Load | Trending up toward 80% of limit | Trending up > 80% of limit |
| RAM Usage | Trending up, > 70% used | Trending up, > 85% used |
| Disk (/) | Trending up, > 70% of threshold | Trending up, > threshold (85%) |

### Commands

```bash
# Full analysis with sparkline charts
sudo bash /opt/hids/modules/mod_history.sh

# View raw historical data
sudo bash /opt/hids/modules/mod_history.sh --show cpu  --last 20
sudo bash /opt/hids/modules/mod_history.sh --show ram  --last 20
sudo bash /opt/hids/modules/mod_history.sh --show disk --last 20

# Raw CSV data
tail -20 /var/lib/hids/history/cpu.csv
wc -l /var/lib/hids/history/cpu.csv   # Max 288 points (24h)

# Reset all history
rm /var/lib/hids/history/*.csv
```

---

## 9. Port Classification (mod_process)

### Philosophy — Show Everything

`mod_process.sh` displays **every** listening port with full details. Nothing is hidden.
Ports are classified to guide investigation — not to silence alerts or hide information.

> **Key principle:** Whitelisting a port changes its **status label** from REVIEW to OK.
> It does **NOT** hide the port from the inventory. Everything is always visible.

### Classification Levels

| Status | Color | Meaning | Action |
|---|---|---|---|
| ✅ OK | Green | Whitelisted / known-good service | Documented — no action |
| ⚠️ REVIEW | Orange | Not in whitelist — unusual port | Investigate and verify |
| 🚨 ALERT | Red | Known dangerous port | Immediate investigation |

### Information Shown per Port

For each listening port, the HIDS displays:
- **Protocol** (tcp/udp)
- **Local address** and port number (which interface is listening)
- **Service/cgroup** — the systemd service responsible (from `ss -tulnpe`)
- **UID** and **username** of the owning socket
- **PID** and process name
- **Plain-English description** of the service

### Information Shown per Process

For each top consumer process:
- **PID, Name, CPU%, MEM%, User**
- **STAT** — process state code:
  - `S` = Sleeping (normal idle process)
  - `R` = Running (actively using CPU)
  - `D` = Uninterruptible sleep (waiting for I/O — investigate if stuck)
  - `Z` = Zombie (finished but not reaped — investigate parent process!)
  - `T` = Stopped, `I` = Idle kernel thread
- **START** — time or date the process was started
- **TIME** — cumulative CPU time consumed since start
- **↳ exe** — full binary path from `/proc/[pid]/exe` (one line below the process row)

### Known ALERT Ports (built-in knowledge base)

| Port | Service | Why Dangerous |
|---|---|---|
| 23 | Telnet | Cleartext credentials — all data including passwords visible on wire |
| 1524 | Bindshell | Root shell — **zero authentication required** |
| 4444 | Metasploit | Default Metasploit Framework listener port |
| 6667 | IRC/botnet | Classic botnet C2 communication channel |
| 1337 | L33T/C2 | Hacker convention — commonly used by backdoors |
| 31337 | Back Orifice | Classic 1990s backdoor — still used today |
| 9090 | Common RAT | Remote Access Trojan convention |
| 514 | RSH | Dangerous legacy remote shell — no encryption |
| 1099 | Java RMI | Exploitable Java registry — remote code execution |

### Whitelisting Ports

```bash
# In config.conf (ports show as OK — still visible in inventory)
WHITELIST_PORTS="22,53,80,443,631,5353,3306,8080"

# Or add one port per line to the whitelist file
echo '8080' | sudo tee -a /var/lib/hids/whitelist_ports.conf
```

---

## 10. Systemd Automation

### The Two Unit Files

| File | Purpose |
|---|---|
| `/etc/systemd/system/hids.service` | Defines HOW to run the scan |
| `/etc/systemd/system/hids.timer` | Defines WHEN — every 5 minutes |

### File Contents

```ini
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

```ini
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
sudo systemctl status hids.timer          # Timer status + time until next run
sudo systemctl status hids.service        # Last scan result + exit code

# View logs
sudo journalctl -u hids.service -n 50     # Last 50 log lines
sudo journalctl -u hids.service -f        # Follow live
sudo journalctl -u hids.service --since today

# Control
sudo systemctl start hids.service         # Trigger a manual scan immediately
sudo systemctl stop hids.timer            # Pause automation
sudo systemctl disable hids.timer         # Disable at boot
```

---

## 11. Email Alerts (msmtp + Gmail)

### Installation

```bash
sudo apt install msmtp msmtp-mta -y
sudo touch /var/log/msmtp.log && sudo chmod 666 /var/log/msmtp.log
```

### Gmail App Password

1. Go to: https://myaccount.google.com/apppasswords
2. 2-Step Verification **must** be enabled on your Google account
3. App name: `HIDS Ubuntu` → **Create**
4. Copy the 16-character code — it is shown **only once!**

> ⚠️ Use this App Password in the config — **NOT** your regular Gmail password.
> An App Password is a revocable token. If exposed (e.g. in a screenshot),
> revoke it immediately at `myaccount.google.com/apppasswords` and generate a new one.

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
password       XXXX XXXX XXXX XXXX   ← your App Password here

account default : gmail
```

```bash
sudo chmod 600 /etc/msmtprc    # CRITICAL — file contains your password
sudo chown root:root /etc/msmtprc

# Test the configuration
echo 'HIDS Test Email' | sudo msmtp YOUR@gmail.com
sudo cat /var/log/msmtp.log | tail -3   # Should show: exitcode=EX_OK

# Enable in config.conf
ALERT_EMAIL="YOUR@gmail.com"
MAIL_CMD="msmtp"
```

### Email Behaviour (Updated v2)

- Sent automatically when a scan finds at least **1 CRITICAL or WARN** alert **(updated in v2)**
- Subject format: `[HIDS ALERT] N critical / N warning(s) on hostname`
- Content includes: host, timestamp, CRITICAL count, WARN count, full details of every finding
- Check delivery: `sudo cat /var/log/msmtp.log`

---

## 12. Network Monitoring (lab-net)

### Lab Architecture

| Machine | IP | Role |
|---|---|---|
| Ubuntu HIDS | 192.168.0.41 | Monitoring machine — runs our HIDS |
| Metasploitable 2 | 192.168.0.21 | Intentionally vulnerable Linux VM |
| Colleague VM | 192.168.0.31 | FTP server (vsftpd 3.0.5) |

### v2 Fix: Auto-Discovery of All Hosts

The network scan now discovers ALL hosts on the /24 subnet automatically.
A separate port baseline is maintained per host. Any new host on the network
or any new port on a known host triggers an alert.

### Dangerous Metasploitable Ports

| Port | Service | Vulnerability |
|---|---|---|
| 21/tcp | vsftpd 2.3.4 | Backdoor — send `USER :)` to trigger shell on port 6200 |
| 23/tcp | Telnet | Cleartext credentials — captures all keystrokes |
| 1524/tcp | Bindshell | Root shell — **zero authentication required** |
| 6667/tcp | UnrealIRCd | Backdoor — triggers remote command execution as root |
| 512-514/tcp | rsh/rlogin | Trusts hostname-based auth — easily bypassed |
| 2121/tcp | ProFTPD 1.3.1 | Multiple known overflow vulnerabilities |
| 3632/tcp | distccd | Remote compilation — executes arbitrary commands |

> **Demo tip:** Try `nc 192.168.0.21 1524` — you get an immediate root shell
> with no password required. This is the bindshell backdoor.

### Network Commands

```bash
# Discover all hosts on lab-net
sudo nmap -sn 192.168.0.0/24

# Full scan of Metasploitable with service detection
sudo nmap -sV -O 192.168.0.21

# Fast full port scan
sudo nmap -sT --open -p- --min-rate 1000 -T4 192.168.0.21

# Active connections to lab-net
ss -tnp | grep '192.168.0'

# View per-host port baselines
ls /var/lib/hids/network_baseline/
cat /var/lib/hids/network_baseline/192_168_0_21_ports.list

# Reset baseline for a specific host (forces full re-scan next time)
rm /var/lib/hids/network_baseline/192_168_0_21_ports.list
```

---

## 13. Interpreting the Output

### Severity Levels

| Level | Meaning | Required Action |
|---|---|---|
| 🚨 `CRITICAL` | Active compromise indicator or dangerous misconfiguration | Investigate **immediately** |
| ⚠️ `WARN` | Anomaly worth investigating — may be legitimate | Review within hours |
| ℹ️ `INFO` | Informational — recorded but not surfaced by default | Audit log only |

### Common CRITICAL Alerts Explained

| Alert | What It Means | What To Do |
|---|---|---|
| `hash_mismatch /etc/passwd` | User accounts file was modified | Check for new or modified accounts — look for UID 0 |
| `uid0_duplicate` | Multiple accounts with UID 0 | Remove illegitimate root account immediately |
| `new_suid_binary` | New SUID binary appeared since baseline | Identify — remove if not from a known package |
| `executable_in_tmp` | Executable found in `/tmp` or `/dev/shm` | Identify — almost always malicious |
| `suspicious_path_process` | Process running from `/tmp`, `/dev/shm`... | Identify and terminate |
| `brute_force` | > `THRESHOLD_FAILED_LOGINS` from one IP | Block IP with `ufw` or `fail2ban` |
| `authorized_keys_modified` | SSH key added unexpectedly | Remove suspicious key from `authorized_keys` |
| `ld_preload_env` | Library injection detected in process environ | Kill process if unrecognized |
| `new_port_detected` (network) | New port on Metasploitable or colleague VM | Verify if a legitimate service was started |
| `dangerous_port` (process) | Known backdoor port open locally | Immediate investigation — should not exist |
| `crontab_modified` | Crontab hash changed since baseline | Review crontab for unauthorized entries |
| `world_writable_file` | File in /etc is world-writable | Fix permissions: `chmod go-w <file>` |
| `cpu_trend_critical` (history) | CPU steadily rising toward limit | Check for cryptominer (`top`, `ps aux`) |
| `ram_trend_critical` (history) | RAM steadily filling | Check for memory-leaking process |
| `disk_trend_critical` (history) | Disk filling fast | Free space immediately, check ETA projection |

### Reading the JSON Alert Log

```bash
# Query by severity
sudo /opt/hids/hids.sh --query --severity CRITICAL
sudo /opt/hids/hids.sh --query --severity WARN

# Query by module
sudo /opt/hids/hids.sh --query --module mod_integrity
sudo /opt/hids/hids.sh --query --module mod_network_scan
sudo /opt/hids/hids.sh --query --module mod_history

# Combined
sudo /opt/hids/hids.sh --query --severity CRITICAL --last 10

# Manual analysis with jq
sudo cat /var/log/hids/alerts.json | jq 'select(.severity=="CRITICAL")'
sudo cat /var/log/hids/alerts.json | jq 'select(.event=="brute_force")'
sudo cat /var/log/hids/alerts.json | jq '[.module] | unique'  # All modules that fired
```

---

## 14. Reducing False Positives

### Common False Positives and Solutions

| False Positive | Root Cause | Solution |
|---|---|---|
| `snap-*.mount` detected as modified | snap dynamically manages `/etc/systemd/system/` | Remove from `INTEGRITY_WATCH_DIRS` |
| `LD_PRELOAD snapd-desktop-i` | snap uses LD_PRELOAD legitimately | Whitelist regex in `mod_integrity.sh` |
| `ps` at 100% CPU | HIDS itself uses `ps` to scan | Add `ps` to `WHITELIST_SUSPICIOUS_PROCS` |
| avahi-daemon dynamic UDP ports | mDNS uses random UDP ports on each boot | Show as REVIEW — visible, not alarming |
| ISO mounted at 100% disk | Read-only CD/ISO always appears full | `DISK_EXCLUDE_MOUNTPOINTS="/media"` |
| `cups/subscriptions.conf` modified | CUPS auto-updates this runtime file | `INTEGRITY_RECENT_EXCLUDE="/etc/cups"` |
| `/root/.lesshst` modified | `less` command updates history file | `INTEGRITY_RECENT_EXCLUDE="...,/root/.lesshst"` |
| Hashed 0 files | `IFS=$'\n\t'` breaks space-separated paths | One path per line in `INTEGRITY_WATCH` |
| `mawk` syntax error | Ubuntu 24.04 uses mawk (insufficient) | `sudo apt install gawk -y` |
| Network scan integer error | `grep -c` returns multi-line on empty input | Fixed in v2 — update `mod_network_scan.sh` |
| `denis@login` untrusted session | Physical session misclassified as remote | Fixed in v2 — update `mod_users.sh` |
| Email only on CRITICAL | WARN alerts not emailed | Fixed in v2 — update `mod_alert.sh` |

### False Positive Workflow

```
False positive identified
        ↓
Is it REALLY legitimate?
├── YES → Whitelist it (method depends on type)
└── NO  → Investigate as a real alert!
        ↓
Whitelist methods:
├── Port          → WHITELIST_PORTS in config.conf or whitelist_ports.conf
├── Process       → WHITELIST_SUSPICIOUS_PROCS in config.conf
├── SUID binary   → whitelist_suid.conf
├── Mountpoint    → DISK_EXCLUDE_MOUNTPOINTS in config.conf
├── Recent file   → INTEGRITY_RECENT_EXCLUDE in config.conf
└── System change → Re-baseline after accepting the new state
        ↓
Re-run scan and verify: CRITICAL: 0, WARN: 0
sudo /opt/hids/hids.sh
```

### Whitelisting Commands

```bash
# Whitelist a SUID binary
echo '/usr/bin/newbinary' | sudo tee -a /var/lib/hids/whitelist_suid.conf

# Whitelist a port (shows as OK, NOT hidden from the inventory)
echo '8080' | sudo tee -a /var/lib/hids/whitelist_ports.conf
# Or in config.conf: WHITELIST_PORTS="22,53,80,443,631,8080"

# Whitelist a process from suspicious path check
# In config.conf: WHITELIST_SUSPICIOUS_PROCS="snapd-desktop-i,ps"

# Exclude auto-updated files from recent modification detection (NEW v2)
# In config.conf: INTEGRITY_RECENT_EXCLUDE="/etc/cups,/root/.lesshst"

# Exclude a disk mountpoint from disk usage alerts (NEW v2)
# In config.conf: DISK_EXCLUDE_MOUNTPOINTS="/media"

# Always re-baseline after whitelisting
sudo /opt/hids/hids.sh --baseline
```

---

## 15. Test Scenarios

> ⚠️ **Run these tests ONLY on your own lab VM. Never on a production system.**

### Pre-Test Setup

```bash
# Start from a clean baseline
sudo truncate -s 0 /var/log/hids/alerts.json
sudo /opt/hids/hids.sh --baseline
sudo /opt/hids/hids.sh 2>&1 | tail -10
# Expected: CRITICAL: 0, WARN: 0 — System is clean
```

### Test 1 — Modified Critical File

```bash
# Simulate a backdoor account
sudo echo "backdoor:x:0:0::/root:/bin/bash" >> /etc/passwd

sudo /opt/hids/hids.sh
# Expected: CRITICAL — hash_mismatch on /etc/passwd + uid0_duplicate
#           Gmail email received with both findings

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

sudo /opt/hids/hids.sh
# Expected: CRITICAL — executable_in_tmp + suspicious_path_process

# Cleanup
kill %1
rm /tmp/malware
```

### Test 3 — Hidden Process in /dev/shm (RAM filesystem)

```bash
# More sophisticated malware hides in RAM — no disk trace
cp /usr/bin/bash /dev/shm/hidden_shell
chmod +x /dev/shm/hidden_shell
/dev/shm/hidden_shell -c "sleep 300" &

sudo /opt/hids/hids.sh
# Expected: CRITICAL — executable_in_tmp + suspicious_path_process

# Cleanup
kill %1
rm /dev/shm/hidden_shell
```

### Test 4 — Unexpected Port (REVIEW Classification)

```bash
# Simulate an unwhitelisted service
python3 -m http.server 9999 &

sudo /opt/hids/hids.sh
# Expected: REVIEW — port 9999/tcp visible in port inventory
#           WARN — unexpected_port

# Cleanup
kill %1
```

### Test 5 — Dangerous Port (ALERT Classification)

```bash
# Simulate a Metasploit-style listener
nc -lvp 4444 &

sudo bash /opt/hids/modules/mod_process.sh
# Expected: port 4444 shown as ALERT — Metasploit default listener

# Cleanup
kill %1
```

### Test 6 — SSH Brute Force (from another machine)

```bash
# From Metasploitable or another machine:
for i in {1..10}; do
    ssh wrong_user@192.168.0.41 2>/dev/null || true
done

sudo /opt/hids/hids.sh
# Expected: CRITICAL — brute_force from source IP
```

### Test 7 — New User Account Created

```bash
sudo useradd -m testuser123

sudo /opt/hids/hids.sh
# Expected: CRITICAL — new_user_account: testuser123

# Cleanup
sudo userdel -r testuser123
sudo /opt/hids/hids.sh --baseline
```

### Test 8 — Crontab Modification (Persistence)

```bash
echo "* * * * * root /tmp/backdoor.sh" | sudo tee -a /etc/crontab

sudo /opt/hids/hids.sh
# Expected: CRITICAL — crontab_modified: /etc/crontab

# Cleanup
sudo sed -i '/backdoor/d' /etc/crontab
sudo /opt/hids/hids.sh --baseline
```

### Test 9 — New Port on Metasploitable

```bash
# Step 1: Connect to Metasploitable root shell (no password!)
nc 192.168.0.21 1524

# Step 2: From Metasploitable shell, open a new port
nc -lvp 9999 &

# Step 3: Run network scan from Ubuntu
sudo bash /opt/hids/modules/mod_network_scan.sh
# Expected: CRITICAL — new_port_detected: 9999/tcp on 192.168.0.21
```

### Test 10 — World-Writable File in /etc

```bash
sudo touch /etc/hids_test_file
sudo chmod 777 /etc/hids_test_file

sudo /opt/hids/hids.sh
# Expected: CRITICAL — world_writable_file: /etc/hids_test_file

# Cleanup
sudo rm /etc/hids_test_file
```

### Test 11 — Historical Trends (mod_history)

```bash
# After several automatic scans have run (wait 10-15 minutes):
sudo bash /opt/hids/modules/mod_history.sh
# Expected: sparkline charts ▁▂▃▄▅▆▇█ + trend classification + current/peak/delta

# View raw data
sudo bash /opt/hids/modules/mod_history.sh --show cpu --last 10
```

### Test 12 — Full Demo Showcase

Recommended sequence for a 5-minute live demonstration:

```bash
# 1. Show clean system
sudo truncate -s 0 /var/log/hids/alerts.json && sudo /opt/hids/hids.sh --baseline
sudo /opt/hids/hids.sh 2>&1 | tail -10   # Show: CRITICAL: 0, WARN: 0

# 2. File integrity attack
sudo echo "backdoor:x:0:0::/root:/bin/bash" >> /etc/passwd
sudo /opt/hids/hids.sh   # Show: CRITICAL hash_mismatch + uid0_duplicate
sudo sed -i '/backdoor/d' /etc/passwd && sudo /opt/hids/hids.sh --baseline

# 3. Malware in /tmp
cp /usr/bin/python3 /tmp/malware && chmod +x /tmp/malware
/tmp/malware -c "import time; time.sleep(300)" &
sudo /opt/hids/hids.sh   # Show: CRITICAL executable_in_tmp
kill %1 && rm /tmp/malware

# 4. Network scan (Metasploitable must be running)
# (on Metasploitable) nc -lvp 9999 &
sudo bash /opt/hids/modules/mod_network_scan.sh   # Show: new_port_detected

# 5. Historical trends
sudo bash /opt/hids/modules/mod_history.sh   # Show: sparklines + trend analysis

# 6. Show Gmail inbox with received alert email
```

---

## 16. Troubleshooting

| Problem | Solution |
|---|---|
| `Hashed 0 files` | Put INTEGRITY_WATCH paths one per line — IFS=$'\n\t' issue |
| `awk: syntax error at or near ,` | `sudo apt install gawk -y` — mawk limitation on Ubuntu 24.04 |
| `gum: command not found` | Install from charm.sh repo — see Section 3 |
| Email not received | `echo 'test' \| sudo msmtp your@gmail.com` — check App Password |
| `Permission denied on alerts.json` | `sudo chmod 666 /var/log/hids/alerts.json` |
| `msmtp: cannot log` | `sudo touch /var/log/msmtp.log && sudo chmod 666 /var/log/msmtp.log` |
| Baseline incomplete — no meta.conf | `sudo rm -rf /var/lib/hids/baseline && sudo /opt/hids/hids.sh --baseline` |
| `mod_history: not enough data` | Normal — needs at least 2 scan runs to display trend |
| ISO at 100% disk CRITICAL | Set `DISK_EXCLUDE_MOUNTPOINTS=/media` in config.conf |
| `cups/subscriptions.conf` WARN every scan | Set `INTEGRITY_RECENT_EXCLUDE=/etc/cups` in config.conf |
| Network scan misses hosts | Verify the v2 fix in `mod_network_scan.sh` is applied |
| Network scan integer error | Update to v2 — the `tr` + arithmetic fix |
| HIDS scan very slow | Normal — `nmap -p-` on multiple hosts takes 3-5 minutes |
| Email digest not sent for WARN | Update `mod_alert.sh` to v2 version |

### Diagnostic Commands

```bash
# Check baseline integrity
sudo ls -la /var/lib/hids/baseline/
sudo cat /var/lib/hids/baseline/meta.conf
sudo wc -l /var/lib/hids/baseline/file_hashes.db

# Debug a specific module in verbose mode
sudo bash -x /opt/hids/modules/mod_health.sh 2>&1 | head -50

# Test configuration loading
sudo bash -c 'source /opt/hids/lib/lib_utils.sh && load_config /opt/hids/config.conf && echo "[$INTEGRITY_WATCH]"'

# Test email with debug
echo 'test' | sudo msmtp --debug your@gmail.com
```

---

## 17. Maintenance & Best Practices

### Recommended Daily Routine

```bash
# 1. Check timer is running
sudo systemctl status hids.timer

# 2. Check today's alerts
sudo journalctl -u hids.service --since "today" | grep -E "CRITICAL|WARN"
sudo /opt/hids/hids.sh --query --severity CRITICAL

# 3. Read last run report
sudo cat /var/log/hids/report.txt

# 4. Check trends
sudo bash /opt/hids/modules/mod_history.sh
```

### Recommended Weekly Routine

```bash
# Check log sizes
du -sh /var/log/hids/
du -sh /var/log/msmtp.log
ls -lh /var/lib/hids/history/
wc -l /var/lib/hids/history/cpu.csv    # Should approach 288 (24h max)

# Check baseline age
sudo cat /var/lib/hids/baseline/meta.conf

# Review all CRITICAL alerts from the week
sudo /opt/hids/hids.sh --query --severity CRITICAL --last 100
```

### Log Rotation

```bash
# Keep last 1000 alert lines (rolling archive)
sudo tail -1000 /var/log/hids/alerts.json > /tmp/alerts_trim.json
sudo mv /tmp/alerts_trim.json /var/log/hids/alerts.json

# Clear msmtp log
sudo truncate -s 0 /var/log/msmtp.log

# Reset trend history (optional — auto-rotates at 288 points)
rm /var/lib/hids/history/*.csv
```

### After a System Update

```bash
# Always in this exact order:
sudo apt update && sudo apt upgrade -y
sudo /opt/hids/hids.sh --baseline
sudo /opt/hids/hids.sh
# Verify: CRITICAL: 0, WARN: 0
```

### Configuration Backup

```bash
# Backup config, baseline, whitelists, and email config
sudo tar czf /home/denis/hids_backup_$(date +%Y%m%d).tar.gz \
    /opt/hids/config.conf \
    /var/lib/hids/baseline/ \
    /var/lib/hids/whitelist_suid.conf \
    /var/lib/hids/whitelist_ports.conf \
    /etc/msmtprc

echo "Backup created: hids_backup_$(date +%Y%m%d).tar.gz"

# Restore
sudo tar xzf /home/denis/hids_backup_20260416.tar.gz -C /
```

---

## 18. Complete Command Reference

```bash
# ── SCANNING ────────────────────────────────────────────────────
sudo /opt/hids/hids.sh
sudo /opt/hids/hids.sh --live
sudo /opt/hids/hids.sh --baseline
sudo /opt/hids/hids.sh --status
sudo /opt/hids/hids.sh --query --severity CRITICAL
sudo /opt/hids/hids.sh --query --severity WARN
sudo /opt/hids/hids.sh --query --module mod_integrity
sudo /opt/hids/hids.sh --query --module mod_process
sudo /opt/hids/hids.sh --query --module mod_network_scan
sudo /opt/hids/hids.sh --query --last 20
sudo /opt/hids/hids.sh --query --severity CRITICAL --last 5

# ── MODULES ──────────────────────────────────────────────────────
sudo bash /opt/hids/modules/mod_health.sh
sudo bash /opt/hids/modules/mod_history.sh
sudo bash /opt/hids/modules/mod_history.sh --show cpu  --last 20
sudo bash /opt/hids/modules/mod_history.sh --show ram  --last 20
sudo bash /opt/hids/modules/mod_history.sh --show disk --last 20
sudo bash /opt/hids/modules/mod_users.sh
sudo bash /opt/hids/modules/mod_process.sh
sudo bash /opt/hids/modules/mod_integrity.sh
sudo bash /opt/hids/modules/mod_network_scan.sh

# ── SYSTEMD ──────────────────────────────────────────────────────
sudo systemctl enable --now hids.timer
sudo systemctl status hids.timer
sudo systemctl status hids.service
sudo journalctl -u hids.service -n 50
sudo journalctl -u hids.service -f
sudo journalctl -u hids.service --since today
sudo systemctl start hids.service         # Manual trigger
sudo systemctl stop hids.timer
sudo systemctl disable hids.timer

# ── MAINTENANCE ───────────────────────────────────────────────────
sudo cat /var/log/hids/report.txt
sudo truncate -s 0 /var/log/hids/alerts.json
sudo tail -f /var/log/hids/alerts.json
sudo ls -la /var/lib/hids/baseline/
sudo cat /var/lib/hids/baseline/meta.conf
sudo wc -l /var/lib/hids/baseline/file_hashes.db
sudo rm -rf /var/lib/hids/baseline              # Reset baseline
ls /var/lib/hids/history/
tail -20 /var/lib/hids/history/cpu.csv
rm /var/lib/hids/history/*.csv                  # Reset trend history

# ── EMAIL ──────────────────────────────────────────────────────────
echo 'Test' | sudo msmtp your@gmail.com
sudo cat /var/log/msmtp.log
sudo truncate -s 0 /var/log/msmtp.log

# ── NETWORK ────────────────────────────────────────────────────────
sudo nmap -sn 192.168.0.0/24
sudo nmap -sV -O 192.168.0.21
sudo nmap -sT --open -p- --min-rate 1000 -T4 192.168.0.21
ss -tnp | grep '192.168.0'
ls /var/lib/hids/network_baseline/
rm /var/lib/hids/network_baseline/*_ports.list  # Reset all network baselines
```

---

## 19. Known Bug Fixes (v2)

| Bug | Root Cause | Fix Applied |
|---|---|---|
| `mawk syntax error` | Ubuntu 24.04 uses mawk — lacks `match()` with arrays | `sudo apt install gawk -y` |
| `Hashed 0 files` | `IFS=$'\n\t'` breaks space-separated paths | One path per line in `INTEGRITY_WATCH` |
| Network scan misses hosts | `discover_hosts` stdout mixed with IP list | Separated display from IP collection in `main()` |
| Network scan integer error | `grep -c` returns multi-line on empty input | Added `\| tr -d '[:space:]'` + `$(( n + 0 ))` |
| ISO disk 100% CRITICAL | Mounted read-only ISO appears full | `DISK_EXCLUDE_MOUNTPOINTS="/media"` |
| `denis@login` untrusted session | Physical local session misclassified as remote | Fixed local/remote session detection logic |
| `cups/subscriptions.conf` WARN every scan | CUPS auto-updates this runtime file | `INTEGRITY_RECENT_EXCLUDE="/etc/cups"` |
| Email only on CRITICAL | WARN alerts not emailed | `send_email_digest()` updated to send WARN too |
| Process table missing details | Only CPU/MEM/user shown | Added STAT, START, TIME, ↳ exe path |
| Network scans only `.21` | Only Metasploitable was scanned | Auto-discovery of all hosts on /24 subnet |

---

## 20. Glossary

| Term | Definition |
|---|---|
| **HIDS** | Host Intrusion Detection System — monitors the machine from within |
| **NIDS** | Network IDS — monitors network traffic between machines |
| **Baseline** | Snapshot of known-good system state used as comparison reference |
| **SHA256** | Cryptographic hash — unique fingerprint of a file's exact content |
| **SUID** | Set User ID — runs a file with its owner's privileges (escalation risk) |
| **SGID** | Set Group ID — similar to SUID but for the group |
| **World-writable** | File/directory modifiable by any system user — dangerous |
| **LD_PRELOAD** | Env variable to preload libraries — exploited by rootkits for hooking |
| **C2** | Command and Control — attacker's remote instruction server |
| **Brute force** | Attack trying many passwords until finding the correct one |
| **Privilege escalation** | Gaining higher permissions than originally granted |
| **Persistence** | Technique allowing malware to survive reboots (cron, SUID, etc.) |
| **Whitelist** | List of known-legitimate items explicitly excluded from alerts |
| **False positive** | Alert triggered by legitimate activity — requires tuning |
| **Alert fatigue** | Ignoring real alerts because of too many false positives |
| **Deduplication** | Alert only once on persistent conditions to prevent alert fatigue |
| **IFS** | Internal Field Separator — bash field split character (default: space/tab/newline) |
| **systemd** | Linux service manager and init system |
| **Timer** | Systemd unit that triggers a service on a schedule |
| **msmtp** | Lightweight SMTP client for Linux terminal email sending |
| **gum** | Charm.sh CLI tool for professional terminal UIs (borders, colors, badges) |
| **gawk** | GNU Awk — required (mawk lacks advanced regex features we use) |
| **mawk** | Default awk on Ubuntu 24.04 — insufficient, replace with gawk |
| **journalctl** | Systemd journal log viewer — reads binary journal files |
| **ss** | Socket statistics — replaces netstat, faster and shows cgroup info |
| **cgroup** | Linux control group — systemd uses these to track which service owns a port |
| **Sparkline** | Compact ASCII trend chart in one line: `▁▂▃▄▅▆▇█` |
| **Linear regression** | Math method to calculate slope/trend direction of a data series |
| **ETA** | Estimated Time to Arrival — projected disk-full time at current growth rate |
| **nmap** | Network scanner — host discovery and port scanning |
| **lab-net** | Isolated virtual network (192.168.0.0/24) used for testing |
| **Metasploitable** | Intentionally vulnerable Linux VM for pentesting practice |
| **IOC** | Indicator of Compromise — sign that a system has been breached |
| **NDJSON** | Newline Delimited JSON — one JSON object per line in a log file |
| **Timestomping** | Attacker technique: fake file timestamps to hide modifications |
| **mDNS** | Multicast DNS — Avahi/Bonjour local discovery, uses dynamic UDP ports |
| **RCE** | Remote Code Execution — running arbitrary commands on a remote system |
| **APT** | Advanced Persistent Threat — sophisticated slow-and-low attackers |
| **STAT** | Process state code shown by ps (S=sleep, R=run, Z=zombie, D=uninterruptible) |
| **Zombie process** | Process that has finished but whose parent has not called wait() — investigate! |

---

## 21. Quick Reference & Checklists

### Installation Checklist

| Step | Command | Done? |
|---|---|---|
| 1. Install gawk + nmap | `sudo apt install gawk nmap -y` | ☐ |
| 2. Install gum | `sudo apt install gum -y` (charm.sh repo) | ☐ |
| 3. Create main directories | `sudo mkdir -p /opt/hids/lib /opt/hids/modules /var/lib/hids /var/log/hids` | ☐ |
| 4. Create v2 directories | `sudo mkdir -p /var/lib/hids/history /var/lib/hids/network_baseline` | ☐ |
| 5. Copy all scripts | `sudo cp *.sh /opt/hids/ && sudo cp modules/*.sh /opt/hids/modules/` | ☐ |
| 6. Set permissions | `sudo chmod +x /opt/hids/*.sh /opt/hids/modules/*.sh` | ☐ |
| 7. Configure config.conf | `sudo nano /opt/hids/config.conf` | ☐ |
| 8. Initial baseline | `sudo /opt/hids/hids.sh --baseline` | ☐ |
| 9. First scan | `sudo /opt/hids/hids.sh` — verify CRITICAL: 0, WARN: 0 | ☐ |
| 10. Install msmtp | `sudo apt install msmtp msmtp-mta -y` | ☐ |
| 11. Configure /etc/msmtprc | `sudo nano /etc/msmtprc && sudo chmod 600 /etc/msmtprc` | ☐ |
| 12. Test email | `echo 'test' \| sudo msmtp your@gmail.com` | ☐ |
| 13. Enable systemd timer | `sudo systemctl enable --now hids.timer` | ☐ |
| 14. Verify automation | `sudo systemctl status hids.timer` — should show active (waiting) | ☐ |

### Daily Workflow

```bash
# ── STARTUP ────────────────────────────────────────────────────
sudo systemctl status hids.timer         # Verify automation is running
sudo /opt/hids/hids.sh --status          # Check baseline + recent alerts
sudo bash /opt/hids/modules/mod_history.sh   # Check trends

# ── INVESTIGATING AN ALERT ───────────────────────────────────────
sudo /opt/hids/hids.sh --query --severity CRITICAL
sudo cat /var/log/hids/report.txt
# → Identify the finding
# → If false positive: whitelist it + re-baseline
# → If confirmed intrusion: isolate the machine immediately

# ── AFTER A SYSTEM UPDATE ───────────────────────────────────────
sudo apt upgrade -y && sudo /opt/hids/hids.sh --baseline
sudo /opt/hids/hids.sh   # Verify: CRITICAL: 0, WARN: 0
```

### Important Files Summary

| File / Directory | Role |
|---|---|
| `/opt/hids/hids.sh` | Main entry point |
| `/opt/hids/config.conf` | **ALL** configuration — the only file to edit |
| `/opt/hids/modules/mod_history.sh` | Trend analysis (NEW v2) |
| `/opt/hids/modules/mod_process.sh` | Port inventory + process audit (ENHANCED v2) |
| `/var/lib/hids/baseline/` | Reference snapshots — forensic evidence |
| `/var/lib/hids/history/` | Trend CSV data (NEW v2) |
| `/var/lib/hids/network_baseline/` | Per-host port baselines (FIXED v2) |
| `/var/log/hids/alerts.json` | NDJSON alert log — full history |
| `/var/log/hids/report.txt` | Human-readable last scan report |
| `/etc/msmtprc` | Gmail config — **PROTECT THIS (chmod 600)!** |
| `/etc/systemd/system/hids.timer` | Automatic scheduling (every 5 minutes) |
| `/var/lib/hids/whitelist_suid.conf` | Allowed SUID binaries |
| `/var/lib/hids/whitelist_ports.conf` | Allowed ports (OK classification) |

---

*Guide written April 15, 2026 — Ubuntu 24.04.4 LTS*
*HIDS Version 2.0 — BeCode Security Lab Project*
*Last updated: April 16, 2026 — v2 changes: mod_history (trend analysis), enhanced mod_process*
*(STAT/START/TIME/exe), DISK_EXCLUDE_MOUNTPOINTS, INTEGRITY_RECENT_EXCLUDE,*
*email WARN+CRITICAL, network scan all hosts auto-discovered, 10 bug fixes applied*
