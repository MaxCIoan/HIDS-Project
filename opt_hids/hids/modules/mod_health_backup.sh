#!/usr/bin/env bash
# =============================================================================
# mod_health.sh — Module 1: System Health Monitor
# =============================================================================
# Checks CPU load, memory pressure, disk usage, swap, I/O wait, and file
# descriptor exhaustion. Compares against dynamic baselines stored in the
# health reference file (BL_HEALTH) and against config thresholds.
#
# Returns:
#   0 = all checks clean
#   1 = at least one WARN finding
#   2 = at least one CRITICAL finding
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lib_utils.sh"
load_config

# Module identifier used in all alert records
MOD="mod_health"

# Health baseline file written by baseline.sh
BL_HEALTH="${HIDS_DATA_DIR}/baseline/health_averages.conf"

# Track worst finding for return code
_worst=0   # 0=ok, 1=warn, 2=critical
_flag() { [[ "$1" -gt "${_worst}" ]] && _worst="$1" || true; }

# =============================================================================
# CPU LOAD AVERAGE
# =============================================================================

check_load() {
    # Reads /proc/loadavg and compares the 1-min load against LOAD_MULTIPLIER × nproc.
    # A load of 2× nproc sustained for 1 minute indicates a heavily saturated system.
    local load_1 load_5 load_15 nproc threshold
    read -r load_1 load_5 load_15 _ _ < /proc/loadavg
    nproc=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)
    threshold=$(bc_calc "${LOAD_MULTIPLIER} * ${nproc}")

    report_line "CPU Load:  1m=${load_1}  5m=${load_5}  15m=${load_15}  (nproc=${nproc}, threshold=${threshold})"

    if float_gt "${load_1}" "${threshold}"; then
        print_critical "CPU load ${load_1} exceeds threshold ${threshold} (${LOAD_MULTIPLIER}× ${nproc} cores)"
        emit_alert --severity CRITICAL --module "${MOD}" --event high_load \
            --detail "1-min load ${load_1} > threshold ${threshold} (${LOAD_MULTIPLIER}×${nproc} cores)" \
            --target "cpu"
        _flag 2
    elif float_gt "${load_5}" "${threshold}"; then
        # 5-min sustained load above threshold is a WARN — not yet critical but trending
        print_warn "5-min load ${load_5} above threshold ${threshold}"
        emit_alert --severity WARN --module "${MOD}" --event elevated_load \
            --detail "5-min load ${load_5} > threshold ${threshold}" --target "cpu"
        _flag 1
    else
        print_ok "Load: ${load_1} / ${load_5} / ${load_15} (threshold: ${threshold})"
    fi
}

# =============================================================================
# MEMORY
# =============================================================================

check_memory() {
    # Reads /proc/meminfo for MemAvailable (not MemFree — MemAvailable accounts
    # for reclaimable page cache and is the correct production metric).
    local mem_total_kb mem_avail_kb mem_avail_mb mem_used_pct
    mem_total_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
    mem_avail_kb=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
    mem_avail_mb=$(( mem_avail_kb / 1024 ))
    mem_used_pct=$(awk "BEGIN { printf \"%d\", (1 - ${mem_avail_kb}/${mem_total_kb}) * 100 }")

    report_line "Memory:    Total=$(( mem_total_kb / 1024 ))MB  Available=${mem_avail_mb}MB  Used=${mem_used_pct}%"

    if [[ "${mem_avail_mb}" -lt "${THRESHOLD_RAM_MB}" ]]; then
        print_critical "Available RAM ${mem_avail_mb}MB below threshold ${THRESHOLD_RAM_MB}MB"
        emit_alert --severity CRITICAL --module "${MOD}" --event low_memory \
            --detail "Available RAM ${mem_avail_mb}MB < threshold ${THRESHOLD_RAM_MB}MB (${mem_used_pct}% used)" \
            --target "memory"
        _flag 2
    elif [[ "${mem_avail_mb}" -lt $(( THRESHOLD_RAM_MB * 2 )) ]]; then
        print_warn "Available RAM ${mem_avail_mb}MB approaching threshold ${THRESHOLD_RAM_MB}MB"
        emit_alert --severity WARN --module "${MOD}" --event low_memory_warn \
            --detail "Available RAM ${mem_avail_mb}MB approaching threshold ${THRESHOLD_RAM_MB}MB" \
            --target "memory"
        _flag 1
    else
        print_ok "RAM: ${mem_avail_mb}MB available / $(( mem_total_kb / 1024 ))MB total"
    fi
}

# =============================================================================
# SWAP
# =============================================================================

check_swap() {
    # Checks swap usage percentage. High swap indicates memory pressure.
    local swap_total_kb swap_free_kb swap_used_pct
    swap_total_kb=$(awk '/^SwapTotal:/{print $2}' /proc/meminfo)
    swap_free_kb=$(awk '/^SwapFree:/{print $2}' /proc/meminfo)

    # No swap configured — skip check
    if [[ "${swap_total_kb}" -eq 0 ]]; then
        print_info "Swap: not configured"
        report_line "Swap:      not configured"
        return
    fi

    swap_used_pct=$(awk "BEGIN { printf \"%d\", (1 - ${swap_free_kb}/${swap_total_kb}) * 100 }")
    report_line "Swap:      Total=$(( swap_total_kb / 1024 ))MB  Used=${swap_used_pct}%"

    if [[ "${swap_used_pct}" -gt "${THRESHOLD_SWAP_PCT}" ]]; then
        print_critical "Swap usage ${swap_used_pct}% exceeds threshold ${THRESHOLD_SWAP_PCT}%"
        emit_alert --severity CRITICAL --module "${MOD}" --event high_swap \
            --detail "Swap usage ${swap_used_pct}% > threshold ${THRESHOLD_SWAP_PCT}%" \
            --target "swap"
        _flag 2
    else
        print_ok "Swap: ${swap_used_pct}% used (threshold: ${THRESHOLD_SWAP_PCT}%)"
    fi
}

# =============================================================================
# DISK USAGE
# =============================================================================

check_disk() {
    # Iterates all mounted filesystems (excluding pseudo-filesystems) and checks
    # usage percentage against THRESHOLD_DISK_PCT.
    report_line ""
    report_line "Disk Usage:"
    local found_critical=0

    # -P = POSIX output (consistent across locales), exclude tmpfs/devtmpfs/overlay
    df -P --exclude-type=tmpfs --exclude-type=devtmpfs --exclude-type=overlay \
          --exclude-type=squashfs --exclude-type=fuse.portal 2>/dev/null | \
    tail -n +2 | while read -r device blocks used avail pct mount; do
        # Strip the trailing % from the usage column
        local usage_num="${pct//%/}"
        report_line "  ${mount}  ${pct} used  (${avail} blocks free)"

        if [[ "${usage_num}" -ge "${THRESHOLD_DISK_PCT}" ]]; then
            print_critical "Disk ${mount}: ${pct} used (threshold: ${THRESHOLD_DISK_PCT}%)"
            emit_alert --severity CRITICAL --module "${MOD}" --event disk_usage_critical \
                --detail "Filesystem ${mount} at ${pct} — threshold ${THRESHOLD_DISK_PCT}% (device: ${device})" \
                --target "${mount}"
            found_critical=1
        elif [[ "${usage_num}" -ge $(( THRESHOLD_DISK_PCT - 10 )) ]]; then
            print_warn "Disk ${mount}: ${pct} used (approaching threshold ${THRESHOLD_DISK_PCT}%)"
            emit_alert --severity WARN --module "${MOD}" --event disk_usage_warn \
                --detail "Filesystem ${mount} at ${pct} — approaching threshold ${THRESHOLD_DISK_PCT}%" \
                --target "${mount}"
        else
            print_ok "Disk ${mount}: ${pct} used"
        fi
    done

    [[ "${found_critical}" -eq 1 ]] && _flag 2 || true
}

# =============================================================================
# I/O WAIT
# =============================================================================

check_iowait() {
    # Measures iowait percentage by reading /proc/stat twice with a 1-second
    # interval and computing the delta. iowait is the 5th field of the cpu line.
    # High iowait indicates disk bottleneck, which can mask other performance issues.

    local sample1 sample2
    sample1=$(grep '^cpu ' /proc/stat)
    sleep 1
    sample2=$(grep '^cpu ' /proc/stat)

    local iowait_pct
    iowait_pct=$(awk -v s1="${sample1}" -v s2="${sample2}" '
    BEGIN {
        n1 = split(s1, a1); n2 = split(s2, a2)
        # Fields: user nice system idle iowait irq softirq steal
        total1=0; total2=0
        for(i=2;i<=n1;i++) { total1+=a1[i]; total2+=a2[i] }
        delta_total = total2 - total1
        delta_iowait = a2[6] - a1[6]
        if (delta_total > 0)
            printf "%.1f", (delta_iowait / delta_total) * 100
        else
            print "0.0"
    }')

    report_line "I/O Wait:  ${iowait_pct}% (threshold: ${THRESHOLD_IOWAIT_PCT}%)"

    if float_gt "${iowait_pct}" "${THRESHOLD_IOWAIT_PCT}"; then
        print_critical "I/O wait ${iowait_pct}% exceeds threshold ${THRESHOLD_IOWAIT_PCT}%"
        emit_alert --severity WARN --module "${MOD}" --event high_iowait \
            --detail "I/O wait ${iowait_pct}% > threshold ${THRESHOLD_IOWAIT_PCT}% — possible disk bottleneck" \
            --target "iowait"
        _flag 1
    else
        print_ok "I/O wait: ${iowait_pct}%"
    fi
}

# =============================================================================
# FILE DESCRIPTORS
# =============================================================================

check_file_descriptors() {
    # Reads /proc/sys/fs/file-nr: allocated FDs, 0 (legacy), max FDs.
    # Near-exhaustion of the system-wide FD limit causes service failures.
    if [[ ! -r /proc/sys/fs/file-nr ]]; then
        print_info "File descriptor check skipped (no /proc/sys/fs/file-nr — container?)"
        return
    fi
    local fd_allocated fd_max fd_pct
    read -r fd_allocated _ fd_max < /proc/sys/fs/file-nr
    fd_pct=$(awk "BEGIN { printf \"%d\", (${fd_allocated}/${fd_max}) * 100 }")

    report_line "File Descriptors: ${fd_allocated}/${fd_max} (${fd_pct}% used)"

    if [[ "${fd_allocated}" -gt "${THRESHOLD_FD_COUNT}" ]]; then
        print_critical "Open FDs ${fd_allocated} exceeds threshold ${THRESHOLD_FD_COUNT}"
        emit_alert --severity CRITICAL --module "${MOD}" --event fd_exhaustion \
            --detail "Open file descriptors ${fd_allocated}/${fd_max} — threshold ${THRESHOLD_FD_COUNT}" \
            --target "fd"
        _flag 2
    else
        print_ok "File descriptors: ${fd_allocated}/${fd_max}"
    fi
}

# =============================================================================
# UNEXPECTED REBOOT DETECTION
# =============================================================================

check_uptime() {
    # Compares current uptime against the baseline epoch to detect unexpected reboots.
    # A reboot since the baseline was taken may indicate a kernel panic, power loss,
    # or — more seriously — a forced reboot by an attacker to apply changes.
    local uptime_seconds
    read -r uptime_seconds _ < /proc/uptime
    uptime_seconds=${uptime_seconds%%.*}
    local boot_epoch=$(( $(epoch_now) - uptime_seconds ))

    report_line "Uptime:    ${uptime_seconds}s since boot (boot epoch: ${boot_epoch})"

    # Load baseline epoch if available
    if [[ -f "${HIDS_DATA_DIR}/baseline/meta.conf" ]]; then
        local bl_epoch
        bl_epoch=$(awk -F= '/BASELINE_EPOCH/{print $2}' "${HIDS_DATA_DIR}/baseline/meta.conf" 2>/dev/null || echo 0)
        if [[ "${boot_epoch}" -gt "${bl_epoch}" ]]; then
            local reboot_time
            reboot_time=$(date -d "@${boot_epoch}" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || date -r "${boot_epoch}" 2>/dev/null || echo "unknown")
            print_warn "System rebooted since baseline was taken (boot at ${reboot_time})"
            emit_alert --severity WARN --module "${MOD}" --event reboot_detected \
                --detail "System boot at ${reboot_time} occurred after baseline epoch ${bl_epoch}" \
                --target "uptime"
            _flag 1
        else
            print_ok "No reboot since baseline"
        fi
    else
        local human_uptime
        human_uptime=$(awk "BEGIN { s=${uptime_seconds}; printf \"%dd %02dh %02dm\", s/86400, (s%86400)/3600, (s%3600)/60 }")
        print_info "Uptime: ${human_uptime} (no baseline for reboot comparison)"
    fi
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    print_section_header "System Health" "♥"

    check_load
    check_memory
    check_swap
    check_disk
    check_iowait
    check_file_descriptors
    check_uptime

    return "${_worst}"
}

# Allow sourcing for testing; run main only when executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    load_config
    main
    exit "${_worst}"
fi
