# 🛡️ HIDS — Test Scenarios & Validation Guide
## Ubuntu 24.04.4 LTS — BeCode Security Lab

> ⚠️ **Run ALL tests ONLY on your own lab VM. Never on production systems.**
> Always clean up after each test and re-baseline when needed.

---

## Pre-Test Checklist

```bash
# Ensure system is clean before starting
sudo truncate -s 0 /var/log/hids/alerts.json
sudo /opt/hids/hids.sh --baseline
sudo /opt/hids/hids.sh 2>&1 | tail -10
# Expected: CRITICAL: 0, WARN: 0 — System is clean
```

---

## TEST 1 — File Integrity: Modified /etc/passwd

**Module tested:** `mod_integrity.sh`
**What it proves:** SHA256 hash comparison detects account tampering

```bash
# SIMULATE: attacker adds backdoor root account
sudo echo "backdoor:x:0:0::/root:/bin/bash" >> /etc/passwd

# RUN HIDS
sudo /opt/hids/hids.sh
```

**Expected alerts:**
- 🚨 CRITICAL — `hash_mismatch` on `/etc/passwd`
- 🚨 CRITICAL — `uid0_duplicate` (two UID 0 accounts)
- Gmail email received

```bash
# CLEANUP
sudo sed -i '/backdoor/d' /etc/passwd
sudo /opt/hids/hids.sh --baseline
```

---

## TEST 2 — File Integrity: New SUID Binary

**Module tested:** `mod_integrity.sh`
**What it proves:** SUID/SGID binary inventory detects privilege escalation tools

```bash
# SIMULATE: attacker creates SUID binary
sudo cp /usr/bin/find /tmp/find_suid
sudo chmod u+s /tmp/find_suid

# RUN HIDS
sudo /opt/hids/hids.sh
```

**Expected alerts:**
- 🚨 CRITICAL — `new_suid_binary`: `/tmp/find_suid`
- 🚨 CRITICAL — `executable_in_tmp`

```bash
# CLEANUP
sudo rm /tmp/find_suid
```

---

## TEST 3 — Process: Malware in /tmp

**Module tested:** `mod_process.sh`
**What it proves:** Executables running from suspicious paths are detected

```bash
# SIMULATE: malware launched from /tmp
cp /usr/bin/python3 /tmp/malware
chmod +x /tmp/malware
/tmp/malware -c "import time; time.sleep(300)" &

# RUN HIDS
sudo /opt/hids/hids.sh
```

**Expected alerts:**
- 🚨 CRITICAL — `executable_in_tmp`
- 🚨 CRITICAL — `suspicious_path_process`

```bash
# CLEANUP
kill %1
rm /tmp/malware
```

---

## TEST 4 — Process: Hidden Process in /dev/shm (RAM)

**Module tested:** `mod_process.sh`
**What it proves:** RAM filesystem used as malware hiding spot is detected

```bash
# SIMULATE: malware hidden in RAM disk
cp /usr/bin/bash /dev/shm/hidden_shell
chmod +x /dev/shm/hidden_shell
/dev/shm/hidden_shell -c "sleep 300" &

# RUN HIDS
sudo /opt/hids/hids.sh
```

**Expected alerts:**
- 🚨 CRITICAL — `executable_in_tmp` (covers /dev/shm)
- 🚨 CRITICAL — `suspicious_path_process`

```bash
# CLEANUP
kill %1
rm /dev/shm/hidden_shell
```

---

## TEST 5 — Users: SSH Brute Force

**Module tested:** `mod_users.sh`
**What it proves:** Failed login threshold detects brute force attacks

```bash
# SIMULATE: from Metasploitable or another machine
for i in {1..10}; do
    ssh wrong_user@192.168.0.41 2>/dev/null || true
done

# RUN HIDS (from Ubuntu)
sudo /opt/hids/hids.sh
```

**Expected alerts:**
- 🚨 CRITICAL — `brute_force` from source IP (>5 failed attempts)

---

## TEST 6 — Users: New Account Created

**Module tested:** `mod_users.sh`
**What it proves:** Unauthorized new accounts are detected vs baseline

```bash
# SIMULATE: attacker creates backdoor account
sudo useradd -m testuser123

# RUN HIDS
sudo /opt/hids/hids.sh
```

**Expected alerts:**
- 🚨 CRITICAL — `new_user_account`: `testuser123`

```bash
# CLEANUP
sudo userdel -r testuser123
sudo /opt/hids/hids.sh --baseline
```

---

## TEST 7 — Users: Unauthorized SSH Key

**Module tested:** `mod_users.sh`
**What it proves:** SSH key backdoors are detected

```bash
# SIMULATE: attacker adds SSH key
ssh-keygen -t rsa -N "" -f /tmp/test_key 2>/dev/null
cat /tmp/test_key.pub >> ~/.ssh/authorized_keys

# RUN HIDS
sudo /opt/hids/hids.sh
```

**Expected alerts:**
- 🚨 CRITICAL — `authorized_keys_modified`

```bash
# CLEANUP
head -n -1 ~/.ssh/authorized_keys > /tmp/ak_tmp
mv /tmp/ak_tmp ~/.ssh/authorized_keys
rm /tmp/test_key /tmp/test_key.pub
sudo /opt/hids/hids.sh --baseline
```

---

## TEST 8 — Network: New Port on Metasploitable

**Module tested:** `mod_network_scan.sh`
**What it proves:** New services on monitored hosts are detected

```bash
# Step 1: Connect to Metasploitable root shell (no password required)
nc 192.168.0.21 1524

# Step 2: From Metasploitable shell, open a new port
nc -lvp 9999 &

# Step 3: Back on Ubuntu — run network scan
sudo bash /opt/hids/modules/mod_network_scan.sh
```

**Expected alerts:**
- 🚨 CRITICAL — `new_port_detected`: `9999/tcp` on `192.168.0.21`

```bash
# CLEANUP (on Metasploitable)
kill %1
```

---

## TEST 9 — Network: Dangerous Port Open Locally

**Module tested:** `mod_process.sh`
**What it proves:** Known backdoor ports are classified as ALERT

```bash
# SIMULATE: Metasploit-style listener
nc -lvp 4444 &

# RUN HIDS
sudo bash /opt/hids/modules/mod_process.sh
```

**Expected result:**
- Port `4444` shown as 🔴 `ALERT` — Metasploit default listener
- Visible in full port inventory table

```bash
# CLEANUP
kill %1
```

---

## TEST 10 — Network: Telnet Port Detected

**Module tested:** `mod_process.sh`
**What it proves:** Legacy/dangerous protocols are flagged

```bash
# SIMULATE: Telnet listener
sudo nc -lvp 23 &

# RUN HIDS
sudo bash /opt/hids/modules/mod_process.sh
```

**Expected result:**
- Port `23` shown as 🔴 `ALERT` — Telnet (cleartext credentials)

```bash
# CLEANUP
sudo kill %1
```

---

## TEST 11 — Integrity: Crontab Modification

**Module tested:** `mod_integrity.sh`
**What it proves:** Persistence via cron is detected

```bash
# SIMULATE: attacker adds cron job for persistence
echo "* * * * * root /tmp/backdoor.sh" | sudo tee -a /etc/crontab

# RUN HIDS
sudo /opt/hids/hids.sh
```

**Expected alerts:**
- 🚨 CRITICAL — `crontab_modified`: `/etc/crontab`

```bash
# CLEANUP
sudo sed -i '/backdoor/d' /etc/crontab
sudo /opt/hids/hids.sh --baseline
```

---

## TEST 12 — Integrity: World-Writable File in /etc

**Module tested:** `mod_integrity.sh`
**What it proves:** Dangerous file permissions are detected

```bash
# SIMULATE: misconfigured permissions
sudo touch /etc/hids_test_file
sudo chmod 777 /etc/hids_test_file

# RUN HIDS
sudo /opt/hids/hids.sh
```

**Expected alerts:**
- 🚨 CRITICAL — `world_writable_file`: `/etc/hids_test_file`

```bash
# CLEANUP
sudo rm /etc/hids_test_file
```

---

## TEST 13 — History: CPU Trend Spike

**Module tested:** `mod_history.sh`
**What it proves:** Trend analysis detects gradual CPU abuse (cryptominer simulation)

```bash
# SIMULATE: sustained CPU load
for i in {1..4}; do yes > /dev/null & done

# Wait 2-3 scans (10-15 min) then check trends
sudo bash /opt/hids/modules/mod_history.sh
```

**Expected result:**
- Sparkline shows rising trend: `▁▁▁▃▅▇█`
- ⚠️ WARN or 🚨 CRITICAL — `cpu_trend_*`

```bash
# CLEANUP
kill $(jobs -p)
```

---

## TEST 14 — Unexpected Port (REVIEW Classification)

**Module tested:** `mod_process.sh`
**What it proves:** Unwhitelisted ports are visible and classified for investigation

```bash
# SIMULATE: developer starts a local web server
python3 -m http.server 9999 &

# RUN HIDS
sudo bash /opt/hids/modules/mod_process.sh
```

**Expected result:**
- Port `9999` shown as 🟡 `REVIEW` — not whitelisted, visible in inventory
- ⚠️ WARN — `unexpected_port`

```bash
# CLEANUP
kill %1
```

---

## TEST 15 — Alert Query System

**Module tested:** `mod_alert.sh`
**What it proves:** Alert querying and filtering works correctly

```bash
# After running several tests above:
sudo /opt/hids/hids.sh --query --severity CRITICAL
sudo /opt/hids/hids.sh --query --severity WARN
sudo /opt/hids/hids.sh --query --module mod_integrity
sudo /opt/hids/hids.sh --query --module mod_process
sudo /opt/hids/hids.sh --query --last 20
sudo /opt/hids/hids.sh --query --severity CRITICAL --last 5
```

**Expected result:** Filtered, formatted output from `alerts.json`

---

## TEST 16 — Email Alert (CRITICAL + WARN)

**Module tested:** `mod_alert.sh`
**What it proves:** Gmail digest includes both CRITICAL and WARN findings

```bash
# Trigger any alert (Test 3 is quick and clean)
cp /usr/bin/python3 /tmp/malware && chmod +x /tmp/malware
/tmp/malware -c "import time; time.sleep(60)" &
sudo /opt/hids/hids.sh

# Verify email was sent
sudo cat /var/log/msmtp.log | tail -5
# Expected: exitcode=EX_OK
```

**Expected result:**
- Email subject: `[HIDS ALERT] N critical / N warning(s) on ubuntu1`
- Body contains full finding details

```bash
# CLEANUP
kill %1 && rm /tmp/malware
```

---

## TEST 17 — Systemd Automation

**Module tested:** Systemd timer
**What it proves:** Automated scans run every 5 minutes without intervention

```bash
# Verify timer is active
sudo systemctl status hids.timer

# Check last automatic scan result
sudo systemctl status hids.service

# Follow live logs
sudo journalctl -u hids.service -f

# Trigger manual scan via systemd
sudo systemctl start hids.service
sudo journalctl -u hids.service -n 15
```

**Expected result:**
- Timer shows `Active: active (waiting)`
- Logs show successful scan with clean result

---

## TEST 18 — Full Demo Showcase

**Recommended order for a live presentation:**

```bash
# === STEP 1: Show clean system ===
sudo truncate -s 0 /var/log/hids/alerts.json
sudo /opt/hids/hids.sh --baseline
sudo /opt/hids/hids.sh 2>&1 | tail -10
# Show: CRITICAL: 0, WARN: 0

# === STEP 2: File integrity (most impactful) ===
sudo echo "backdoor:x:0:0::/root:/bin/bash" >> /etc/passwd
sudo /opt/hids/hids.sh
# Show: CRITICAL — hash_mismatch + uid0_duplicate

# Cleanup
sudo sed -i '/backdoor/d' /etc/passwd
sudo /opt/hids/hids.sh --baseline

# === STEP 3: Malware in /tmp ===
cp /usr/bin/python3 /tmp/malware && chmod +x /tmp/malware
/tmp/malware -c "import time; time.sleep(300)" &
sudo /opt/hids/hids.sh
# Show: CRITICAL — executable_in_tmp + suspicious_path_process
kill %1 && rm /tmp/malware

# === STEP 4: Network scan ===
# (on Metasploitable) nc -lvp 9999 &
sudo bash /opt/hids/modules/mod_network_scan.sh
# Show: CRITICAL — new_port_detected on 192.168.0.21

# === STEP 5: Historical trends ===
sudo bash /opt/hids/modules/mod_history.sh
# Show: sparklines ▁▂▃▄▅▆▇█ + trend analysis

# === STEP 6: Show Gmail received ===
```

---

## Quick Reference Table

| # | Test | Module | Expected Alert | Severity |
|---|---|---|---|---|
| 1 | Modified /etc/passwd | mod_integrity | hash_mismatch + uid0_duplicate | 🚨 CRITICAL |
| 2 | New SUID binary | mod_integrity | new_suid_binary | 🚨 CRITICAL |
| 3 | Executable in /tmp | mod_process | executable_in_tmp + suspicious_path | 🚨 CRITICAL |
| 4 | Hidden in /dev/shm | mod_process | executable_in_tmp | 🚨 CRITICAL |
| 5 | SSH brute force | mod_users | brute_force | 🚨 CRITICAL |
| 6 | New user account | mod_users | new_user_account | 🚨 CRITICAL |
| 7 | Unauthorized SSH key | mod_users | authorized_keys_modified | 🚨 CRITICAL |
| 8 | New port Metasploitable | mod_network_scan | new_port_detected | 🚨 CRITICAL |
| 9 | Port 4444 open | mod_process | dangerous_port ALERT | ⚠️ WARN |
| 10 | Telnet port 23 | mod_process | dangerous_port ALERT | ⚠️ WARN |
| 11 | Crontab modified | mod_integrity | crontab_modified | 🚨 CRITICAL |
| 12 | World-writable /etc | mod_integrity | world_writable_file | 🚨 CRITICAL |
| 13 | CPU trend spike | mod_history | cpu_trend_critical | ⚠️/🚨 |
| 14 | Unexpected port 9999 | mod_process | unexpected_port REVIEW | ⚠️ WARN |
| 15 | Alert query system | mod_alert | — (CLI test) | — |
| 16 | Gmail email digest | mod_alert | Email received | — |
| 17 | Systemd automation | systemd | Timer running | — |
| 18 | Full demo showcase | ALL | Combined demo | — |

---

*HIDS Test Scenarios v2 — Ubuntu 24.04.4 LTS — BeCode Security Lab — April 2026*
