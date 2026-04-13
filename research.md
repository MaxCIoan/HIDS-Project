# Bash HIDS Research -- Phase 1

------------------------------------------------------------------------

# System Health Monitoring

## What aspects of a running Linux system tell you whether it is healthy or under stress?

A healthy Linux system shows balanced resource usage across CPU, memory,
disk, network, and processes. Signs of stress include high or sustained
CPU load, especially if the load average exceeds the number of cores;
low free memory or excessive swap usage; disk space nearing capacity or
high I/O wait times; network saturation or errors; and the presence of
zombie or stuck processes. System logs with repeated errors or warnings
also indicate potential issues.

------------------------------------------------------------------------

## Where does Linux expose this information?

Linux provides real-time system information through both commands and
the /proc filesystem. For CPU, use tools like top, htop, or mpstat, or
check /proc/stat and /proc/loadavg. Memory status is available via free
or /proc/meminfo. Disk usage and I/O can be monitored with df, iostat,
or /proc/diskstats. Network activity is visible through netstat, iftop,
or files like /proc/net/dev. Process health is tracked with ps, top, or
by inspecting /proc/\[pid\]/status. System logs are found in /var/log/
and can be viewed with dmesg or journalctl.

------------------------------------------------------------------------

## What values or thresholds would indicate a problem worth alerting on?

Alerts should be triggered when the load average exceeds the number of
CPU cores over 1, 5, or 15 minutes, or if CPU usage stays above 90% for
extended periods. Memory issues arise when free memory drops below 10%
or swap usage exceeds 10% of total RAM. For disks, alert if usage
surpasses 90% or if I/O wait is consistently above 20%. Network alerts
should fire for saturation above 90% or any sustained error or drop
rates. Any zombie processes or processes stuck in an uninterruptible
sleep state (D) are cause for concern. Finally, repeated or critical
errors in system logs should never be ignored.


------------------------------------------------------------------------

# Users and Activity

## How does Linux record logins, when, and from where?

Linux commonly stores login/session records in utmp, wtmp, and failed
login records in btmp. The utmp(5) man page states that wtmp records
logins and logouts, and commands such as last and lslogins can read this
information.

### Test commands

``` bash
last -a | head
lastb | head
who
w
lslogins | head
```

------------------------------------------------------------------------

## Where are these records stored?

Typical locations:

/var/run/utmp or runtime-managed equivalent\
/var/log/wtmp\
/var/log/btmp

Also, auth-related logs may be stored in:

Debian/Ubuntu/Kali: /var/log/auth.log\
RHEL/CentOS: /var/log/secure\
systemd journal: view with journalctl

Linux systems using systemd-journald store structured journal entries
and journalctl reads them. systemd-journald collects logs from kernel
messages, syslog calls, services, and more.

### Test commands

``` bash
sudo ls -l /var/log/wtmp /var/log/btmp 2>/dev/null
sudo grep -i 'failed|invalid|session opened|session closed' /var/log/auth.log | tail
journalctl -u ssh
journalctl -p warning -b
```

------------------------------------------------------------------------

## What user activity looks suspicious on a production server?

Examples:

- Repeated failed logins\
- Successful login at an unusual hour\
- Login from an unusual IP or country\
- A new sudo session for a user who rarely uses sudo\
- Direct root login\
- A dormant account becoming active\
- Many SSH connections in a short period\
- Account creation or privilege change

A good HIDS should not only say "someone logged in." It should answer:
who, when, from where, and is it unusual for this host?

### Test commands

``` bash
last -a | head -20
sudo grep 'Failed password' /var/log/auth.log | tail -20
sudo grep 'sudo:' /var/log/auth.log | tail -20
journalctl _COMM=sshd --since "1 hour ago"
```

------------------------------------------------------------------------

## What is possible or not in Linux?

### Possible

Detect logins, failed logins, sudo use, SSH events\
Correlate users with terminals and remote IPs\
Flag anomalies based on simple Bash rules

### Not fully possible with Bash alone

Strong behavioral analytics\
geolocation or reputation checks without outside data\
perfect attribution if logs are missing or rotated

------------------------------------------------------------------------

# Processes

## How do you get a full picture of what is running on a system?

To obtain a comprehensive overview of active processes using only native
tools, we rely on the ps (process status) utility. The standard
professional command is:

``` bash
ps aux
```

a: Shows processes for all users.\
u: Displays the user/owner of the process and resource usage (CPU/RAM).\
x: Shows processes not attached to a terminal (daemons, background
services).

For a structural view, ps -ef or ps fax (forest view) is used to
visualize parent-child relationships. This is crucial for identifying
process tree injection, where a suspicious process is spawned by a
legitimate parent (like www-data spawning a bash shell).

------------------------------------------------------------------------

## What makes a process look suspicious?

Detection goes beyond the process name, as attackers often rename
malicious binaries to look like system tasks (e.g., kworker or systemd).
We evaluate suspicion based on four pillars:

  -----------------------------------------------------------------------
  Indicator              Suspicious Attribute
  ---------------------- ------------------------------------------------
  Path (Binary Location) Processes running from "world-writable" or
                         temporary directories like /tmp, /dev/shm, or
                         /var/tmp. Legitimate binaries should reside in
                         /usr/bin, /usr/sbin, etc.

  Ownership (User)       A web server user (www-data or apache) owning an
                         interactive shell (sh, bash) or a high-privilege
                         process running under a low-privilege user
                         account.

  Resource Usage         Sudden, sustained spikes in CPU or RAM without a
                         known business reason, which could indicate
                         cryptominers or data exfiltration compression.

  Hidden Processes       A process that appears in /proc but is hidden
                         from the ps command (often an indicator of a
                         rootkit).

  Orphan Processes       A process whose parent has died (PPID 1)
                         unexpectedly, which may be a technique to bypass
                         session monitoring.
  -----------------------------------------------------------------------



## Where does Linux store live process information?

The source of truth for all process information in Linux is the /proc
file system.

Definition: It is a "pseudo-filesystem" (Virtual File System) that acts
as an interface to the kernel's internal data structures. It does not
exist on the disk; it exists in memory.

Structure: Every running process has a directory named after its Process
ID (PID). For example:

/proc/1234/

### Key Files inside /proc/\[PID\]/

/proc/\[PID\]/exe\
/proc/\[PID\]/cmdline\
/proc/\[PID\]/status\
/proc/\[PID\]/environ\
/proc/\[PID\]/fd/

-   /proc/\[PID\]/exe: A symbolic link to the actual executable file on
    the disk.\
-   /proc/\[PID\]/cmdline: The full command line used to start the
    process (including arguments).\
-   /proc/\[PID\]/status: A human-readable file containing the process
    state, UID/GID, and memory usage.\
-   /proc/\[PID\]/environ: The environment variables set for that
    process.\
-   /proc/\[PID\]/fd/: A directory containing links to every file or
    network socket the process has open.

------------------------------------------------------------------------

# Network Monitoring

## How do you see what ports a machine is listening on?

To check which ports are open and listening on a machine, use the
command ss -tulnp or netstat -tulnp on Linux. These commands display all
listening TCP and UDP ports, along with the process using each port. On
Windows, you can use netstat -ano or the PowerShell command
Get-NetTCPConnection -State Listen. These tools are essential for
identifying exposed services and potential attack surfaces.

------------------------------------------------------------------------

## How do you see active connections and which process is responsible for each?

You can view active network connections and the processes behind them
using ss -tupn or netstat -tupn on Linux. These commands show all active
TCP and UDP connections, including the process ID and name. On Windows,
netstat -ano provides the process ID, which you can then look up in Task
Manager. This helps you spot unauthorized or suspicious network
activity.

------------------------------------------------------------------------

## What kind of network activity would be a red flag?

Several types of network activity should raise immediate concern.
Unexpected open ports, especially on non-standard or high-numbered
ports, may indicate unauthorized services. Unusual outbound connections
to unknown external IPs, particularly in unexpected geographic
locations, could signal data exfiltration or command-and-control
traffic. High traffic volumes to or from a single IP might indicate a
DDoS attack or data theft. Repeated connection attempts, such as failed
logins or port scans, often precede an attack. Finally, the use of
unusual protocols like IRC, Tor, or uncommon VPNs without a clear
business purpose should always be investigated.

------------------------------------------------------------------------

# File Integrity

## Which files on a Linux system are critical enough that any unexpected change should trigger an alert?

On a Linux system, several files are so critical that any unexpected
change should immediately trigger an alert. These include system
binaries in /bin, /sbin, /usr/bin, and /usr/sbin, as well as
configuration files like /etc/passwd, /etc/shadow, /etc/sudoers, and
/etc/ssh/sshd_config. Cron job files in /etc/crontab and
/var/spool/cron/, kernel and boot files in /boot/ and /lib/modules/, and
log files in /var/log/ are also high-value targets. For web servers,
files in /var/www/, /etc/apache2/, and /etc/nginx/ are especially
sensitive.

------------------------------------------------------------------------

## What file attributes or permissions settings are known to be dangerous if misconfigured?

Certain file attributes and permission settings are particularly
dangerous if misconfigured. World-writable files, set with chmod 777 or
o+w, allow anyone to modify the file, creating a major security risk.
SUID or SGID bits, when set on binaries, can allow privilege escalation
attacks. Improper ownership, such as files owned by root but writable by
others, can lead to unauthorized access. The sticky bit, when misused,
can cause security issues, especially on directories like /tmp.
Unrestricted home directories, with permissions like chmod 777 \~,
expose user files to everyone on the system.

------------------------------------------------------------------------

## How do you detect whether a file was modified recently?

To detect if a file was modified recently, use the ls -lt command, which
lists files sorted by modification time, with the newest first. For a
specific file, stat filename provides detailed timestamps. For ongoing
monitoring, tools like AIDE (Advanced Intrusion Detection Environment)
or Tripwire are designed to detect and alert on changes to critical
files, helping you maintain file integrity and spot potential breaches.

------------------------------------------------------------------------

# Logging and Alerting

## Where do Linux systems store their logs by default? What does each log file record?

Linux systems store their logs in the /var/log/ directory by default.
Each log file records different types of events: /var/log/syslog or
/var/log/messages contain general system messages, /var/log/auth.log
tracks authentication events like login attempts and sudo usage, and
/var/log/kern.log holds kernel messages. /var/log/cron.log records cron
job activity, /var/log/secure (on some distributions) contains
security-related messages, and /var/log/boot.log logs system boot
events. Web server logs are typically found in /var/log/httpd/ or
/var/log/nginx/.

------------------------------------------------------------------------

## What format do professional security tools use for structured alerts? Why does format matter?

Professional security tools use structured formats for alerts, such as
JSON, XML, CEF (Common Event Format), Syslog, and STIX/TAXII. The format
matters because it makes alerts machine-readable, enabling automated
parsing and correlation between different security tools.
Standardization ensures that various tools can communicate effectively,
and structured formats improve efficiency by reducing false positives
and speeding up incident response.

------------------------------------------------------------------------

## What is the difference between a tool that floods you with alerts and one you can actually trust?

The difference between a tool that floods you with alerts and one you
can trust is significant. A flooding tool generates too many alerts,
often including false positives, which can lead to alert fatigue and
cause you to miss real threats. A trustworthy tool, on the other hand,
uses context---such as user behavior, time of day, and location---to
filter and prioritize alerts. It applies threat intelligence to block
known malicious IPs and domains, allows for tuning with custom rules and
thresholds, and provides severity scoring to help you focus on the most
critical issues first.
