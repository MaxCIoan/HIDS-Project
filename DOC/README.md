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
| `mod_process.sh` | Suspicious processes, full port inventory with classification, outbound connections |
| `mod_integrity.sh` | Hash verification, SUID binaries, world-writable files, crontabs, LD_PRELOAD |
| `mod_network_scan.sh` | lab-net host discovery, Metasploitable port monitoring, connection tracking |
| `mod_alert.sh` | JSON alert log, severity engine, deduplication, email notification |

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
sudo bash /opt/hids/modules/mod_users.sh
sudo bash /opt/hids/modules/mod_process.sh
sudo bash /opt/hids/modules/mod_integrity.sh
sudo bash /opt/hids/modules/mod_network_scan.sh
```

---

## Health History & Trend Analysis (mod_history)

`mod_history.sh` records CPU load, RAM usage, and disk usage at every scan run.
It detects dangerous trends over time — a cryptominer slowly consuming CPU, a
memory leak filling RAM, or a growing log file eating disk space.

```bash
# Run trend analysis
sudo bash /opt/hids/modules/mod_history.sh

# View raw historical data
sudo bash /opt/hids/modules/mod_history.sh --show cpu  --last 20
sudo bash /opt/hids/modules/mod_history.sh --show ram  --last 20
sudo bash /opt/hids/modules/mod_history.sh --show disk --last 20
```

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

## Automated Scheduling

### systemd timer (recommended)

```bash
# Copy the unit files
sudo cp systemd/hids.service /etc/systemd/system/
sudo cp systemd/hids.timer   /etc/systemd/system/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now hids.timer

# Check status
sudo systemctl status hids.timer
sudo systemctl status hids.service

# View logs
sudo journalctl -u hids.service -n 50
sudo journalctl -u hids.service -f
```

### cron (alternative)

```bash
sudo crontab -e
# Add:
*/5 * * * * /opt/hids/hids.sh --once >> /var/log/hids/cron.log 2>&1
```

---

## Configuration

All settings live in `/opt/hids/config.conf`.
**Never edit the module scripts directly** — all tuning is done here.

```bash
# --- System Health ---
LOAD_MULTIPLIER=2.0          # Alert if load > N × CPU cores
THRESHOLD_RAM_MB=512         # Alert if available RAM < N MB
THRESHOLD_DISK_PCT=85        # Alert if any filesystem exceeds N%
THRESHOLD_SWAP_PCT=70        # Alert if swap used > N%
THRESHOLD_IOWAIT_PCT=30      # Alert if I/O wait > N%
DISK_EXCLUDE_MOUNTPOINTS="/media"  # Exclude mounted ISOs from disk alerts

# --- User Activity ---
THRESHOLD_FAILED_LOGINS=5    # Brute force threshold per source IP
TRUSTED_SSH_SOURCES=""       # Trusted SSH subnets (empty = alert all remote)
SENSITIVE_GROUPS="sudo,wheel,docker,adm,shadow,disk"

# --- Process & Network ---
SUSPICIOUS_PATHS="/tmp,/var/tmp,/dev/shm,/run/shm"
WHITELIST_PORTS="22,53,80,443,631,5353"   # Known-good ports
WHITELIST_SUSPICIOUS_PROCS="snapd-desktop-i,ps"
ALERT_OUTBOUND_PORTS="4444,1337,31337,8080,9090,6666,6667"
THRESHOLD_PROC_CPU=90        # Alert if process exceeds N% CPU
THRESHOLD_PROC_MEM=50        # Alert if process exceeds N% RAM

# --- File Integrity ---
# ⚠️  One path per line — spaces in IFS=$'\n\t' break space-splitting
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
INTEGRITY_RECENT_MINUTES=15  # Recent modification detection window
SUID_SCAN_EXCLUDE="/proc /sys /dev /run /snap"

# --- Alerting ---
ALERT_EMAIL="your@gmail.com"
MAIL_CMD="msmtp"
```

---

## Port Classification (mod_process)

`mod_process.sh` displays **every** listening port with full details — nothing
is hidden. Ports are classified automatically:

| Status | Meaning |
|---|---|
| `OK` | Whitelisted / known-good service (SSH, DNS, HTTPS...) |
| `REVIEW` | Not in whitelist — unusual port, requires investigation |
| `ALERT` | Known dangerous port (Telnet, bindshell, Metasploit, C2...) |

For each port the module shows: protocol, local address, port number,
service/cgroup name, UID, username, and a plain-English description.

Known dangerous ports flagged as `ALERT`: `23` (Telnet), `1524` (bindshell),
`4444` (Metasploit), `6667` (IRC botnet), `1337`, `31337`, `9090`, and more.

---

## Email Alerts (Gmail via msmtp)

```bash
# Install msmtp
sudo apt install msmtp msmtp-mta -y
sudo touch /var/log/msmtp.log && sudo chmod 666 /var/log/msmtp.log

# Configure /etc/msmtprc
# (requires a Gmail App Password — see myaccount.google.com/apppasswords)
sudo nano /etc/msmtprc
sudo chmod 600 /etc/msmtprc

# Test
echo "HIDS test" | sudo msmtp your@gmail.com
```

An email digest is sent automatically when a scan detects at least one
`CRITICAL` alert. The digest includes host, timestamp, count, and full details
of every critical finding.

---

## Interpreting the Output

### Severity Levels

| Level | Meaning | Action |
|---|---|---|
| `CRITICAL` | Active compromise indicator or dangerous misconfiguration | Investigate immediately |
| `WARN` | Anomaly worth investigating — may be legitimate | Review within hours |
| `INFO` | Informational — recorded but not surfaced by default | Audit log only |

### Alert Log

Alerts are written to `/var/log/hids/alerts.json` in NDJSON format
(one JSON object per line):

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

```bash
# Query the alert log
sudo /opt/hids/hids.sh --query --severity CRITICAL
sudo /opt/hids/hids.sh --query --module mod_integrity
sudo /opt/hids/hids.sh --query --last 20

# Clear the alert log
sudo truncate -s 0 /var/log/hids/alerts.json

# Read the last run report
sudo cat /var/log/hids/report.txt
```

---

## Whitelists

### SUID Binaries

```bash
# View current whitelist
cat /var/lib/hids/whitelist_suid.conf

# Add a known-good binary
echo "/usr/bin/newbinary" | sudo tee -a /var/lib/hids/whitelist_suid.conf
```

### Listening Ports

```bash
# In config.conf:
WHITELIST_PORTS="22,80,443,53,8080"

# Or one port per line in:
/var/lib/hids/whitelist_ports.conf
```

### Processes

```bash
# In config.conf:
WHITELIST_SUSPICIOUS_PROCS="snapd-desktop-i,ps,my-process"
```

---

## Reducing False Positives

1. **Re-baseline after planned changes** — after package updates, config
   changes, or adding new services:
   ```bash
   sudo apt upgrade -y && sudo /opt/hids/hids.sh --baseline
   ```
2. **Tune thresholds** in `config.conf` to match your machine's normal profile.
3. **Whitelist known-good SUID binaries** in `whitelist_suid.conf`.
4. **Classify ports** via `WHITELIST_PORTS` — unwhitelisted ports show as
   `REVIEW`, not hidden.
5. **Exclude dynamic mountpoints** via `DISK_EXCLUDE_MOUNTPOINTS` (e.g. ISOs).

> ⚠️ **Never re-baseline if an intrusion is suspected.** The baseline must
> always represent a known-good state.

---

## Architecture

```
/opt/hids/
├── hids.sh                    # Orchestrator — entry point
├── config.conf                # ALL configuration lives here
├── baseline.sh                # Snapshot and diff engine
├── live_monitor.sh            # Continuous real-time dashboard
├── lib/
│   └── lib_utils.sh           # Shared library (alerts, colors, dedup)
└── modules/
    ├── mod_health.sh          # Module 1: System Health
    ├── mod_history.sh         # Module 2: Health History & Trend Analysis
    ├── mod_users.sh           # Module 3: User Activity
    ├── mod_process.sh         # Module 4: Process & Network Audit
    ├── mod_integrity.sh       # Module 5: File Integrity
    ├── mod_network_scan.sh    # Module 6: Network Scan (lab-net)
    └── mod_alert.sh           # Module 7: Alert Aggregation & Reporting

/var/lib/hids/
├── baseline/                  # Reference snapshots
│   ├── file_hashes.db         # SHA256 hashes of watched files
│   ├── suid_binaries.list     # Known SUID binaries
│   ├── listening_ports.list   # Open ports at baseline time
│   └── meta.conf              # Baseline metadata (date, host)
├── history/                   # Trend data (mod_history)
│   ├── cpu.csv                # CPU load time series
│   ├── ram.csv                # RAM usage time series
│   └── disk.csv               # Disk usage time series
├── network_baseline/          # Per-host port baselines
├── whitelist_suid.conf        # Whitelisted SUID binaries
└── whitelist_ports.conf       # Whitelisted ports

/var/log/hids/
├── alerts.json                # NDJSON alert log
└── report.txt                 # Human-readable run report
```

---

## Demo Scenarios

### Scenario 1 — File integrity alert

```bash
# Simulate a backdoor account (as root — simulating attacker)
sudo echo "backdoor:x:0:0::/root:/bin/bash" >> /etc/passwd

# Run HIDS
sudo /opt/hids/hids.sh
# Expected: CRITICAL — hash_mismatch on /etc/passwd + uid0_duplicate

# Cleanup
sudo sed -i '/backdoor/d' /etc/passwd
sudo /opt/hids/hids.sh --baseline
```

### Scenario 2 — Suspicious process in /tmp

```bash
cp /usr/bin/python3 /tmp/python3
chmod +x /tmp/python3
/tmp/python3 -c "import time; time.sleep(300)" &

sudo /opt/hids/hids.sh
# Expected: CRITICAL — executable_in_tmp + suspicious_path_process

# Cleanup
kill %1 && rm /tmp/python3
```

### Scenario 3 — New port on Metasploitable

```bash
# Connect to Metasploitable root shell
nc 192.168.0.21 1524

# From Metasploitable shell, open a new port
nc -lvp 9999 &

# From Ubuntu HIDS
sudo bash /opt/hids/modules/mod_network_scan.sh
# Expected: CRITICAL — new_port_detected: 9999/tcp on 192.168.0.21
```

### Scenario 4 — Historical trends

```bash
# After several scans, view sparkline trend charts
sudo bash /opt/hids/modules/mod_history.sh

# View raw data
sudo bash /opt/hids/modules/mod_history.sh --show cpu --last 10
sudo bash /opt/hids/modules/mod_history.sh --show ram --last 10
```

---

## Demo Questions

**Where does the data come from?**
Each module reads directly from Linux kernel interfaces. Key sources:
`/proc/loadavg` (CPU), `/proc/meminfo` (RAM), `/proc/[pid]/exe` (processes),
`ss -tulnpe` (ports + PID + UID + cgroup), `/var/log/auth.log` (logins),
`sha256sum` against baseline (file integrity), `nmap` (network).

**HIDS vs NIDS?**
A HIDS runs on the monitored machine and sees everything at the OS level —
processes, files, users, local logs. A NIDS sits on the network and inspects
traffic. NIDS sees packets; HIDS sees what those packets triggered. An attacker
using stolen credentials bypasses NIDS entirely — only HIDS catches them
modifying `/etc/passwd` once inside.

**Evasion techniques?**
Modify the baseline files, kill the monitoring process, use timestomping to
hide file modifications, rename malicious processes, or replace the HIDS binary
itself. Our mitigations: SHA256 hashing (timestamps are irrelevant), systemd
auto-restart, `/proc/[pid]/exe` path verification (not just process name),
and LD_PRELOAD detection.

**Hardest design decision?**
The deduplication engine. Alerting once on a persistent condition (rather than
once per run) dramatically reduces noise but requires careful state management
around what constitutes "the same alert" and when it should re-fire.

**Distinguishing real alerts from false positives?**
Tuned thresholds via `config.conf`, dynamic baseline (not hardcoded values),
three-tier whitelist system (ports, SUID, processes), and severity discipline.
Every unwhitelisted port is shown as `REVIEW` — nothing is silently hidden.

**If you had two more weeks?**
A web dashboard reading `alerts.json` in real time, MISP integration for threat
intelligence enrichment, and a snapshot diff mode to detect slow drift between
two baselines taken weeks apart.
