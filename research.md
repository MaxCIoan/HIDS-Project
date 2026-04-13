
# What aspects of a running Linux system tell you whether it is healthy or under stress?

A healthy Linux system shows balanced resource usage across CPU, memory, disk, network, and processes. 
Signs of stress include high or sustained CPU load, especially if the load average exceeds the number of cores; low free memory or excessive swap usage; disk space nearing capacity or high I/O wait times; network saturation or errors; and the presence of zombie or stuck processes. System logs with repeated errors or warnings also indicate potential issues.

# Where does Linux expose this information?

Linux provides real-time system information through both commands and the /proc filesystem. For CPU, use tools like top, htop, or mpstat, or check /proc/stat and /proc/loadavg. Memory status is available via free or /proc/meminfo. Disk usage and I/O can be monitored with df, iostat, or /proc/diskstats. Network activity is visible through netstat, iftop, or files like /proc/net/dev. Process health is tracked with ps, top, or by inspecting /proc/[pid]/status. System logs are found in /var/log/ and can be viewed with dmesg or journalctl.


# What values or thresholds would indicate a problem worth alerting on?

Alerts should be triggered when the load average exceeds the number of CPU cores over 1, 5, or 15 minutes, or if CPU usage stays above 90% for extended periods. Memory issues arise when free memory drops below 10% or swap usage exceeds 10% of total RAM. For disks, alert if usage surpasses 90% or if I/O wait is consistently above 20%. Network alerts should fire for saturation above 90% or any sustained error or drop rates. Any zombie processes or processes stuck in an uninterruptible sleep state (D) are cause for concern. Finally, repeated or critical errors in system logs should never be ignored.

Summary:

Aspects cover CPU, memory, disk, network, processes, and logs.
Information sources are exposed via commands, /proc files, and log files.
Alert thresholds are provided for each aspect to help you identify when the system is under stress.



