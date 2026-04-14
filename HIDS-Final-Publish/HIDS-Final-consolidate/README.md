# HIDS-Final-consolidate

A Bash-based Host Intrusion Detection System packaged so your team can clone the repo and run it directly. No `/opt/hids` install step is required.

## Quick Start

```bash
git clone https://github.com/MaxCIoan/HIDS-Project.git
cd HIDS-Project/HIDS-Final-Publish/HIDS-Final-consolidate

# Only needed if your clone loses executable bits
chmod +x hids.sh baseline.sh live_monitor.sh modules/*.sh

# Recommended on a known-clean system - It tells the security software to record the current state of your system so it can detect unauthorized changes later.
sudo ./hids.sh --baseline

# One-shot monitoring run
sudo ./hids.sh
```

## What Happens On First Run

- `hids.sh` resolves its own path, so it can run from the cloned repo directory.
- The scripts create `/var/lib/hids` and `/var/log/hids` automatically when run as root.
- If no baseline exists yet, `hids.sh` initializes one automatically before the first monitoring run.
- This package also includes a local `.tmp_hids/` tree so the standalone fallback paths already exist inside the cloned project.

## Common Commands

```bash
sudo ./hids.sh
sudo ./hids.sh --live
sudo ./hids.sh --baseline
sudo ./hids.sh --status
sudo ./hids.sh --query --severity CRITICAL
sudo ./hids.sh --query --module mod_integrity --last 20
```

## Configuration

Edit `config.conf` in this folder to tune thresholds, ports, watch paths, and alert settings for the target machine.

Default runtime paths are still:

```bash
/var/lib/hids
/var/log/hids
```

## Project Layout

```text
HIDS-Final-Publish/
└── HIDS-Final-consolidate/
    ├── hids.sh
    ├── baseline.sh
    ├── live_monitor.sh
    ├── config.conf
    ├── .tmp_hids/
    │   ├── data/
    │   │   ├── alert_state.db
    │   │   └── baseline/
    │   └── output/
    │       └── alerts.json
    ├── lib/
    │   └── lib_utils.sh
    └── modules/
        ├── mod_health.sh
        ├── mod_users.sh
        ├── mod_process.sh
        ├── mod_integrity.sh
        └── mod_alert.sh
```

## Notes

- Run as `root` or with `sudo`.
- Linux executable bits should be preserved when committed from WSL/Linux.
- `.tmp_hids/data/` and `.tmp_hids/output/` are included in this package for local standalone runs.