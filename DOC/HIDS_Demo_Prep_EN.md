# HIDS — Demo Preparation Guide
## 6 Key Questions & Answers
### BeCode Security Lab — Ubuntu 24.04.4 LTS

---

## Question 1 — Where Does the Data Come From?

**The HIDS reads directly from Linux kernel interfaces — no agents, no databases.**

Each module has its own data source:

| Module | Source | What it reads |
|---|---|---|
| mod_health | `/proc/loadavg` | CPU load average (1/5/15 min) |
| mod_health | `/proc/meminfo` | Available/total RAM |
| mod_health | `df --output=pcent,target` | Disk usage per mountpoint |
| mod_health | `/proc/stat` (2 samples, delta) | I/O wait percentage |
| mod_history | Same as health + CSV files | Time series for trend analysis |
| mod_users | `who(1)` → `/var/run/utmp` | Active sessions |
| mod_users | `journalctl -u sshd` | Failed SSH login attempts |
| mod_users | `journalctl` / `/var/log/auth.log` | Sudo activity |
| mod_process | `/proc/[pid]/exe` | Process binary path |
| mod_process | `ss -tulnpe` | Ports + UID + cgroup (which service owns each port) |
| mod_integrity | `sha256sum` on INTEGRITY_WATCH | File fingerprints |
| mod_integrity | `find / -perm /6000` | SUID/SGID binaries |
| mod_integrity | `/proc/[pid]/environ` | LD_PRELOAD injection |
| mod_network_scan | `nmap -sn 192.168.0.0/24` | Active hosts on lab-net |
| mod_network_scan | `nmap -sT --open -p-` | All open ports per host |

**Key insight:** `ss -tulnpe` is particularly powerful — it shows not just the port
but the exact process owning it, its UID, and the systemd cgroup responsible.
This makes port ownership unambiguous.

---

## Question 2 — HIDS vs NIDS: What's the Difference?

| | HIDS | NIDS |
|---|---|---|
| **Location** | On the monitored machine | On the network (dedicated device) |
| **What it sees** | Files, processes, users, local logs, OS state | Network packets in transit |
| **Examples** | Our HIDS, OSSEC, Wazuh, Tripwire | Suricata, Snort, Zeek |
| **Strength** | Full OS-level visibility | Global network traffic view |
| **Weakness** | Blind to encrypted network content | Blind to what happens inside the OS |

**The key insight:** NIDS sees the packets. HIDS sees what those packets triggered.

**Concrete example:** An attacker uses stolen SSH credentials to log in. The SSH
connection is encrypted — NIDS sees nothing suspicious. But once inside, the attacker
runs `echo "backdoor:x:0:0::/root:/bin/bash" >> /etc/passwd`. NIDS still sees nothing.
Our HIDS detects the SHA256 hash change on `/etc/passwd` within 5 minutes and fires CRITICAL.

**Complementarity:** In a real environment, HIDS and NIDS work together:
- NIDS catches network-level attacks (port scans, exploit attempts)
- HIDS catches post-exploitation (file changes, new processes, persistence mechanisms)

---

## Question 3 — How Could an Attacker Evade This HIDS?

**Honest answer — a sophisticated attacker has several options:**

| Evasion Technique | How It Works | Our Mitigation |
|---|---|---|
| Modify the baseline | Overwrite `/var/lib/hids/baseline/` to accept malicious state | Baseline directory owned by root, 750 permissions |
| Kill the HIDS process | `kill $(pgrep -f hids.sh)` | Systemd restarts the service automatically |
| Timestomping | `touch -t` to fake file modification times | We use SHA256 hashes — timestamps are irrelevant |
| Rename malware | Name process `sshd` or `systemd` | We verify `/proc/[pid]/exe` path, not just the name |
| LD_PRELOAD hooking | Inject library to intercept syscalls | We scan `/proc/[pid]/environ` for LD_PRELOAD |
| Replace HIDS binary | Swap `/opt/hids/hids.sh` with a fake | Could add hash verification of HIDS itself |
| Act within thresholds | Stay below alert thresholds | Historical trend analysis (mod_history) detects slow drift |

**Most important limitation:** This is a detection tool, not a prevention tool.
It tells you *that* something happened, not *before* it happens.

---

## Question 4 — What Was the Hardest Design Decision?

**The deduplication engine.**

The core problem: if a condition persists (e.g. an ISO always mounted at 100% disk),
the HIDS would fire `CRITICAL` on every scan — every 5 minutes. After a day,
that's 288 identical alerts. This is called **alert fatigue** and it causes administrators
to ignore real alerts because they're buried in noise.

**Our solution — `alert_state.db`:**
- At the first detection, emit the alert AND record it in `alert_state.db`
- On subsequent scans, check: has this exact condition already been reported?
- If yes — skip (the admin already knows). If no — emit.
- When the condition disappears, clear the state so it re-fires if it returns.

**The design tension:** Alert too eagerly → fatigue. Alert too conservatively → miss real incidents.

**What we learned:** The deduplication key must include enough context to distinguish
"same condition still present" from "new occurrence of similar condition."

---

## Question 5 — How Do You Tell a Real Alert From a False Positive?

**Our four-layer approach:**

**Layer 1 — Thresholds in config.conf**
Every numeric threshold is configurable. Example: `THRESHOLD_FAILED_LOGINS=5`
means 4 failed logins = nothing, 5 = alert. We tuned each to match our lab environment.

**Layer 2 — Dynamic baseline**
We don't hardcode "normal" values. We take a snapshot of the actual system at a
known-good moment. This means the baseline adapts to each machine's normal profile.

**Layer 3 — Three-tier whitelist system**
- `WHITELIST_PORTS` — ports classified as OK (still visible, not hidden)
- `whitelist_suid.conf` — known-good SUID binaries
- `WHITELIST_SUSPICIOUS_PROCS` — processes excluded from suspicious path check
- `INTEGRITY_RECENT_EXCLUDE` — files excluded from recent modification detection

**Layer 4 — Severity discipline**
Not everything is CRITICAL. Unknown ports → REVIEW (visible, not alarming).
Dangerous ports → ALERT. Hash mismatches → CRITICAL. This gradation prevents
treating every anomaly as an emergency.

**Key principle:** Nothing is silently hidden. An unwhitelisted port doesn't
disappear — it shows as REVIEW and requires a human decision.

---

## Question 6 — What Would You Add With Two More Weeks?

**Three concrete improvements, prioritized:**

**Priority 1 — Web Dashboard**
A lightweight web interface reading `alerts.json` in real time. The NDJSON format
makes this trivial — one JSON object per line, easy to parse and display.
Features: live alert feed, severity filters, trend charts, baseline status.
Tech stack: simple Python Flask + Chart.js, reading directly from `alerts.json`.

**Priority 2 — MISP Threat Intelligence Integration**
MISP (Malware Information Sharing Platform) provides community-maintained IOC
(Indicator of Compromise) feeds. Integration would automatically enrich our alerts:
if a detected IP, file hash, or domain matches a known threat actor's infrastructure,
the alert severity would automatically escalate.

**Priority 3 — Snapshot Diff Mode**
Compare two baselines taken weeks apart to detect slow drift:
`hids.sh --diff baseline_2026-04-01 baseline_2026-04-15`
This would catch attacks that operate below single-scan detection thresholds
but accumulate detectable changes over time — a technique called slow-and-low or APT-style infiltration.

**Bonus — Active Response**
Automatically block a brute-force source IP with `ufw` when `brute_force` is detected.
This crosses from detection into prevention — a different category, but a natural next step.

---

## Quick Demo Script (5 minutes)

```bash
# 1. Show clean baseline
sudo /opt/hids/hids.sh 2>&1 | tail -5
# → CRITICAL: 0, WARN: 0

# 2. Simulate backdoor account
sudo echo "backdoor:x:0:0::/root:/bin/bash" >> /etc/passwd
sudo /opt/hids/hids.sh 2>&1 | grep -E "CRITICAL|hash_mismatch|uid0"

# 3. Clean up + malware in /tmp
sudo sed -i '/backdoor/d' /etc/passwd && sudo /opt/hids/hids.sh --baseline
cp /usr/bin/python3 /tmp/malware && chmod +x /tmp/malware
/tmp/malware -c "import time; time.sleep(300)" &
sudo /opt/hids/hids.sh 2>&1 | grep -E "CRITICAL|tmp"
kill %1 && rm /tmp/malware

# 4. Show trends
sudo bash /opt/hids/modules/mod_history.sh | grep -A5 "CPU Load"

# 5. Show Gmail received
```

---

*HIDS Demo Prep — v2 — English — BeCode Security Lab — April 2026*
