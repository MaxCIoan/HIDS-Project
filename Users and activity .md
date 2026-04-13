2) On users and activity
How does Linux record logins, when, and from where?

Linux commonly stores login/session records in utmp, wtmp, and failed login records in btmp. The utmp(5) man page states that wtmp records logins and logouts, and commands such as last and lslogins can read this information.

Test commands

last -a | head
lastb | head
who
w
lslogins | head
Where are these records stored?

Typical locations:

/var/run/utmp or runtime-managed equivalent
/var/log/wtmp
/var/log/btmp

Also, auth-related logs may be stored in:

Debian/Ubuntu/Kali: /var/log/auth.log
RHEL/CentOS: /var/log/secure
systemd journal: view with journalctl

Linux systems using systemd-journald store structured journal entries and journalctl reads them. systemd-journald collects logs from kernel messages, syslog calls, services, and more.

Test commands

sudo ls -l /var/log/wtmp /var/log/btmp 2>/dev/null
sudo grep -i 'failed\|invalid\|session opened\|session closed' /var/log/auth.log | tail
journalctl -u ssh
journalctl -p warning -b
What user activity looks suspicious on a production server?

Examples:

repeated failed logins
successful login at an unusual hour
login from an unusual IP or country
a new sudo session for a user who rarely uses sudo
direct root login
a dormant account becoming active
many SSH connections in a short period
account creation or privilege change

A good HIDS should not only say “someone logged in.” It should answer: who, when, from where, and is it unusual for this host?

Test commands

last -a | head -20
sudo grep 'Failed password' /var/log/auth.log | tail -20
sudo grep 'sudo:' /var/log/auth.log | tail -20
journalctl _COMM=sshd --since "1 hour ago"
What is possible or not in Linux?

Possible

Detect logins, failed logins, sudo use, SSH events
Correlate users with terminals and remote IPs
Flag anomalies based on simple Bash rules

Not fully possible with Bash alone

Strong behavioral analytics
geolocation or reputation checks without outside data
perfect attribution if logs are missing or rotated