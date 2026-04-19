# HIDS — Host Intrusion Detection System

A modular, Bash-native HIDS for Linux. No third-party software required beyond
standard system tools, `gawk`, and `gum` for the visual interface.

---

## What It Does

HIDS continuously monitors **seven areas** of your system and alerts you when
something looks wrong:

| Module | What it monitors |
|---|---|
| `mod_health.sh` | CPU load, RAM, disk, swap, I/O wait, file descriptors, uptime |
| `mod_history.sh` | Historical trends for CPU/RAM/disk — sparkline charts, drift detection |
| `mod_users.sh` | Logins, failed auth, sudo usage, new accounts, group changes, SSH keys |
| `mod_process.sh` | Full port inventory (OK/REVIEW/ALERT), process details (STAT/START/TIME/exe), suspicious paths |
| `mod_integrity.sh` | Hash verification, SUID binaries, world-writable files, crontabs, LD_PRELOAD |
| `mod_network_scan.sh` | Full lab-net scan (all active hosts), per-host port baseline, connection tracking |
| `mod_alert.sh` | JSON alert log, severity engine, deduplication, email (CRITICAL + WARN) |

---

## Requirements

- Linux (Ubuntu 20.04+ or Debian 11+)
- Bash 4.3+
- Must run as root
- Standard tools: `ss`, `sha256sum`, `find`, `stat`, `who`, `last`
- `gawk` — required (mawk does not support advanced regex used by alert modules)
- `gum` — required for the visual terminal interface
- `nmap` — required for network scanning module
- `msmtp` — optional, for Gmail alert notifications

```bash
# Install required dependencies
sudo apt install gawk nmap -y

# Install gum (visual interface)
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://repo.charm.sh/apt/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/charm.gpg
echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" | sudo tee /etc/apt/sources.list.d/charm.list
sudo apt update && sudo apt install gum -y
```

> ⚠️ **Important**: Ubuntu 24.04 uses `mawk` by default. Always install `gawk`
> explicitly — `awk --version` should show `GNU Awk`, not `mawk`.

---

## Installation

```bash
# Create installation directories
sudo mkdir -p /opt/hids/lib /opt/hids/modules
sudo mkdir -p /var/lib/hids /var/log/hids
sudo mkdir -p /var/lib/hids/network_baseline /var/lib/hids/history

# Copy all scripts
sudo cp hids.sh config.conf baseline.sh live_monitor.sh /opt/hids/
sudo cp lib/lib_utils.sh /opt/hids/lib/
sudo cp modules/*.sh /opt/hids/modules/

# Apply permissions
sudo chmod +x /opt/hids/hids.sh /opt/hids/baseline.sh /opt/hids/live_monitor.sh
sudo chmod +x /opt/hids/modules/*.sh
sudo chown -R root:root /opt/hids /var/lib/hids /var/log/hids
sudo chmod 750 /opt/hids /var/lib/hids /var/log/hids
sudo chmod 640 /opt/hids/config.conf

# Take the initial baseline (run on a known-clean system)
sudo /opt/hids/hids.sh --baseline
```

---

## Running HIDS

```bash
# Full one-shot monitoring run
sudo /opt/hids/hids.sh

# Live continuous dashboard (Ctrl+C to exit)
sudo /opt/hids/hids.sh --live

# Re-take the baseline (after planned system changes)
sudo /opt/hids/hids.sh --baseline

# Show baseline status and recent alerts
sudo /opt/hids/hids.sh --status

# Query the alert log
sudo /opt/hids/hids.sh --query --severity CRITICAL
sudo /opt/hids/hids.sh --query --severity WARN
sudo /opt/hids/hids.sh --query --module mod_integrity --last 20

# Run individual modules
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

---

## Health History & Trend Analysis (mod_history)

`mod_history.sh` records CPU load, RAM usage, and disk usage at every scan.
It detects dangerous trends — a cryptominer slowly consuming CPU, a memory
leak filling RAM, or a growing log file eating disk space.

**How it works:**
- Records one data point per scan → stored in `/var/lib/hids/history/*.csv`
- Keeps last **288 points = 24 hours** of rolling history (at 5-min intervals)
- Calculates **linear regression** over the last 12 points (1-hour window)
- Classifies trend as: `rising` / `falling` / `stable`
- Draws **ASCII sparkline charts**: `▁▂▃▄▅▆▇█`
- Alerts `WARN` or `CRITICAL` if trend reaches dangerous thresholds

| Metric | WARN | CRITICAL |
|---|---|---|
| CPU Load | Trending up toward 80% of threshold | Trending up > 80% of threshold |
| RAM Usage | Trending up > 70% | Trending up > 85% |
| Disk (/) | Trending up > 70% of threshold | Trending up > threshold |

---

## Port Classification (mod_process)

`mod_process.sh` displays **every** listening port with full enriched details.
Nothing is hidden. Ports are classified automatically:

| Status | Meaning |
|---|---|
| `OK` | Whitelisted / known-good service (SSH, DNS, HTTPS...) |
| `REVIEW` | Not in whitelist — unusual port, requires investigation |
| `ALERT` | Known dangerous port (Telnet, bindshell, Metasploit, C2...) |

For each port: protocol, local address, port, service/cgroup, UID, username, description.
For each process: PID, name, CPU%, MEM%, user, **STAT, START, TIME**, ↳ exe path.

Known `ALERT` ports: `23` (Telnet), `1524` (bindshell), `4444` (Metasploit),
`6667` (IRC botnet), `1337`, `31337`, `9090`, and more.

---

## Automated Scheduling

```bash
# Copy the unit files
sudo cp etc_systemd_system/hids.service /etc/systemd/system/
sudo cp etc_systemd_system/hids.timer   /etc/systemd/system/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now hids.timer

# Check status
sudo systemctl status hids.timer
sudo journalctl -u hids.service -n 50
sudo journalctl -u hids.service -f
```

---

## Configuration

All settings live in `/opt/hids/config.conf`.
**Never edit the module scripts directly.**

```bash
# --- System Health ---
LOAD_MULTIPLIER=2.0
THRESHOLD_RAM_MB=512
THRESHOLD_DISK_PCT=85
THRESHOLD_SWAP_PCT=70
THRESHOLD_IOWAIT_PCT=30
DISK_EXCLUDE_MOUNTPOINTS="/media"      # Exclude mounted ISOs — NEW v2

# --- User Activity ---
THRESHOLD_FAILED_LOGINS=5
TRUSTED_SSH_SOURCES=""
SENSITIVE_GROUPS="sudo,wheel,docker,adm,shadow,disk"

# --- Process & Network ---
SUSPICIOUS_PATHS="/tmp,/var/tmp,/dev/shm,/run/shm"
WHITELIST_PORTS="22,53,80,443,631,5353"
WHITELIST_SUSPICIOUS_PROCS="snapd-desktop-i,ps"
ALERT_OUTBOUND_PORTS="4444,1337,31337,8080,9090,6666,6667"
THRESHOLD_PROC_CPU=90
THRESHOLD_PROC_MEM=50

# --- File Integrity ---
# ⚠️ One path per line (IFS=$'\n\t' bug)
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
INTEGRITY_RECENT_MINUTES=15
INTEGRITY_RECENT_EXCLUDE="/etc/cups,/root/.lesshst"  # Exclude auto-updated files — NEW v2

# --- Alerting ---
ALERT_EMAIL="your@gmail.com"
MAIL_CMD="msmtp"
# Emails sent for both CRITICAL and WARN — NEW v2
```

---

## Email Alerts (Gmail via msmtp)

```bash
sudo apt install msmtp msmtp-mta -y
sudo touch /var/log/msmtp.log && sudo chmod 666 /var/log/msmtp.log
sudo nano /etc/msmtprc
sudo chmod 600 /etc/msmtprc
echo "HIDS test" | sudo msmtp your@gmail.com
```

Email digests are sent for **both CRITICAL and WARN** alerts (updated in v2).

---

## Interpreting the Output

| Level | Meaning | Action |
|---|---|---|
| `CRITICAL` | Active compromise or dangerous misconfiguration | Investigate immediately |
| `WARN` | Anomaly — may be legitimate | Review within hours |
| `INFO` | Informational only | Audit log only |

---

## Whitelists

```bash
# SUID binary
echo "/usr/bin/newbinary" | sudo tee -a /var/lib/hids/whitelist_suid.conf

# Port (shown as OK — never hidden)
WHITELIST_PORTS="22,80,443,53,8080"
echo "8080" | sudo tee -a /var/lib/hids/whitelist_ports.conf

# Process
WHITELIST_SUSPICIOUS_PROCS="snapd-desktop-i,ps"

# File exclusion from recent modifications
INTEGRITY_RECENT_EXCLUDE="/etc/cups,/root/.lesshst"
```

---

## Known Bug Fixes (v2)

| Bug | Cause | Fix |
|---|---|---|
| `mawk syntax error` | Ubuntu 24.04 uses mawk | `sudo apt install gawk -y` |
| `Hashed 0 files` | IFS breaks space-split paths | One path per line in INTEGRITY_WATCH |
| Network scan misses hosts | stdout mixed with IP list | Separated display from IP collection |
| ISO disk 100% CRITICAL | Mounted read-only ISO | `DISK_EXCLUDE_MOUNTPOINTS="/media"` |
| Network scan integer error | `grep -c` multi-line on empty | Added `tr -d '[:space:]'` + `$(( n + 0 ))` |
| `denis@login` untrusted | Physical session misclassified | Fixed local/remote session logic |
| cups WARN every scan | CUPS auto-updates runtime file | `INTEGRITY_RECENT_EXCLUDE="/etc/cups"` |
| Email only on CRITICAL | WARN not emailed | `send_email_digest` updated |
| Process table missing info | Only CPU/MEM/user | Added STAT, START, TIME, exe path |

---

## Architecture

```
/opt/hids/
├── hids.sh                    # Orchestrator
├── config.conf                # ALL configuration
├── baseline.sh                # Snapshot engine
├── live_monitor.sh            # Real-time dashboard
├── lib/lib_utils.sh           # Shared library
└── modules/
    ├── mod_health.sh          # System Health
    ├── mod_history.sh         # Trend Analysis (NEW v2)
    ├── mod_users.sh           # User Activity
    ├── mod_process.sh         # Process & Network (ENHANCED v2)
    ├── mod_integrity.sh       # File Integrity
    ├── mod_network_scan.sh    # Network Scan (FIXED v2)
    └── mod_alert.sh           # Alerts & Reporting

/var/lib/hids/
├── baseline/                  # Reference snapshots
├── history/                   # Trend CSVs (NEW v2)
├── network_baseline/          # Per-host port baselines
├── whitelist_suid.conf
└── whitelist_ports.conf

/var/log/hids/
├── alerts.json                # NDJSON alert log
└── report.txt                 # Human-readable report
```

---

## Demo Questions

**Where does the data come from?**
`/proc/loadavg` (CPU), `/proc/meminfo` (RAM), `ss -tulnpe` (ports + UID + cgroup),
`/proc/[pid]/exe` (processes), `sha256sum` (integrity), `nmap` (network scan).

**HIDS vs NIDS?**
NIDS sees packets; HIDS sees what those packets triggered. Stolen credentials
bypass NIDS entirely — only HIDS catches post-exploitation activity.

**Evasion techniques?**
Modify baseline files, kill the process, timestomping, rename malware, LD_PRELOAD hooking.
Mitigations: SHA256 hashing, systemd restart, `/proc/[pid]/exe` verification, LD_PRELOAD detection.

**Hardest design decision?**
The deduplication engine — alerting once on persistent conditions without missing new ones.

**Distinguishing real alerts from false positives?**
Tuned thresholds, dynamic baseline, three-tier whitelist, severity discipline.
Every unwhitelisted port shows as `REVIEW` — nothing silently hidden.

**If you had two more weeks?**
Web dashboard for `alerts.json`, MISP threat intelligence, snapshot diff mode.
