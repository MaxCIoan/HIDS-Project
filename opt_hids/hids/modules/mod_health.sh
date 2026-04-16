#!/usr/bin/env bash
# =============================================================================
# mod_health.sh — Module 1: System Health Monitor (GUM Edition)
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lib_utils.sh"
load_config

MOD="mod_health"
BL_HEALTH="${HIDS_DATA_DIR}/baseline/health_averages.conf"
_worst=0
_flag() { [[ "$1" -gt "${_worst}" ]] && _worst="$1" || true; }

GUM=$(command -v gum 2>/dev/null || echo "")

# =============================================================================
# HELPERS VISUELS
# =============================================================================
badge_ok()     { gum style --background 82  --foreground 0   --bold --padding "0 1" " OK     "; }
badge_review() { gum style --background 214 --foreground 0   --bold --padding "0 1" " REVIEW "; }
badge_alert()  { gum style --background 196 --foreground 255 --bold --padding "0 1" " ALERT  "; }

badge() {
    case "$1" in
        OK)     badge_ok ;;
        REVIEW) badge_review ;;
        ALERT)  badge_alert ;;
    esac
}

progress_bar() {
    # Usage: progress_bar VALUE MAX WIDTH
    local val=$1 max=$2 width=${3:-20}
    local filled=$(( val * width / max ))
    local empty=$(( width - filled ))
    local color=82
    [[ $val -gt 70 ]] && color=214
    [[ $val -gt 85 ]] && color=196
    local bar=""
    for (( i=0; i<filled; i++ )); do bar+="█"; done
    for (( i=0; i<empty; i++ )); do bar+="░"; done
    gum style --foreground "${color}" "${bar} ${val}%"
}

section_header() {
    gum style \
        --foreground 212 --border-foreground 212 --border normal \
        --width 70 --padding "0 2" \
        "$1"
}

metric_box() {
    # Usage: metric_box "TITLE" "STATUS" "VALUE" "THRESHOLD" "WHY"
    local title="$1" status="$2" value="$3" threshold="$4" why="$5"
    local color=82
    [[ "$status" == "REVIEW" ]] && color=214
    [[ "$status" == "ALERT"  ]] && color=196
    gum style \
        --border rounded --border-foreground "${color}" \
        --width 33 --padding "0 1" \
        "$(gum style --foreground "${color}" --bold "${title}")" \
        "$(badge "${status}") ${value}" \
        "$(gum style --foreground 245 "Threshold: ${threshold}")" \
        "$(gum style --foreground 245 "${why}")"
}

# =============================================================================
# CPU LOAD
# =============================================================================
check_load() {
    local load_1 load_5 load_15 nproc threshold status why
    load_1=$(awk '{print $1}' /proc/loadavg)
    load_5=$(awk '{print $2}' /proc/loadavg)
    load_15=$(awk '{print $3}' /proc/loadavg)
    nproc=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)
    threshold=$(bc_calc "${LOAD_MULTIPLIER} * ${nproc}")

    if float_gt "${load_1}" "${threshold}"; then
        status="ALERT"; why="exceeds threshold!!"
        emit_alert --severity CRITICAL --module "${MOD}" --event high_load \
            --detail "1-min load ${load_1} > threshold ${threshold}" --target "cpu"
        _flag 2
    elif float_gt "${load_5}" "${threshold}"; then
        status="REVIEW"; why="5m elevated — monitor"
        emit_alert --severity WARN --module "${MOD}" --event elevated_load \
            --detail "5-min load ${load_5} > threshold ${threshold}" --target "cpu"
        _flag 1
    else
        status="OK"; why="within threshold"
    fi

    echo "${status}|CPU Load ⚡|${load_1}/${load_5}/${load_15}|${threshold}|${why}"
}

# =============================================================================
# MEMORY
# =============================================================================
check_memory() {
    local mem_total_kb mem_avail_kb mem_avail_mb mem_total_mb mem_used_pct status why
    mem_total_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
    mem_avail_kb=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
    mem_avail_mb=$(( mem_avail_kb / 1024 ))
    mem_total_mb=$(( mem_total_kb / 1024 ))
    mem_used_pct=$(awk "BEGIN { printf \"%d\", (1 - ${mem_avail_kb}/${mem_total_kb}) * 100 }")

    if [[ "${mem_avail_mb}" -lt "${THRESHOLD_RAM_MB}" ]]; then
        status="ALERT"; why="below threshold!"
        emit_alert --severity CRITICAL --module "${MOD}" --event low_memory \
            --detail "Available RAM ${mem_avail_mb}MB < threshold ${THRESHOLD_RAM_MB}MB" --target "memory"
        _flag 2
    elif [[ "${mem_used_pct}" -gt 80 ]]; then
        status="REVIEW"; why="${mem_used_pct}% used — monitor"
        _flag 1
    else
        status="OK"; why="${mem_used_pct}% used"
    fi

    echo "${status}|RAM 💾|${mem_avail_mb}MB / ${mem_total_mb}MB|${THRESHOLD_RAM_MB}MB|${why}|${mem_used_pct}"
}

# =============================================================================
# SWAP
# =============================================================================
check_swap() {
    local swap_total_kb swap_free_kb swap_used_pct status why
    swap_total_kb=$(awk '/^SwapTotal:/{print $2}' /proc/meminfo)
    swap_free_kb=$(awk '/^SwapFree:/{print $2}' /proc/meminfo)

    if [[ "${swap_total_kb}" -eq 0 ]]; then
        echo "OK|Swap 🔄|none|none|no swap configured|0"
        return
    fi

    swap_used_pct=$(awk "BEGIN { printf \"%d\", (1 - ${swap_free_kb}/${swap_total_kb}) * 100 }")

    if [[ "${swap_used_pct}" -gt "${THRESHOLD_SWAP_PCT}" ]]; then
        status="ALERT"; why="exceeds threshold!"
        emit_alert --severity WARN --module "${MOD}" --event high_swap \
            --detail "Swap ${swap_used_pct}% > threshold ${THRESHOLD_SWAP_PCT}%" --target "swap"
        _flag 1
    else
        status="OK"; why="within threshold"
    fi

    echo "${status}|Swap 🔄|${swap_used_pct}%|${THRESHOLD_SWAP_PCT}%|${why}|${swap_used_pct}"
}

# =============================================================================
# I/O WAIT
# =============================================================================
check_iowait() {
    local sample1 sample2 iowait_pct status why
    sample1=$(grep '^cpu ' /proc/stat)
    sleep 1
    sample2=$(grep '^cpu ' /proc/stat)
    iowait_pct=$(awk -v s1="${sample1}" -v s2="${sample2}" '
    BEGIN {
        n1=split(s1,a1); n2=split(s2,a2)
        total1=0; total2=0
        for(i=2;i<=n1;i++) { total1+=a1[i]; total2+=a2[i] }
        delta_total=total2-total1; delta_iowait=a2[6]-a1[6]
        if (delta_total > 0) printf "%.1f", (delta_iowait/delta_total)*100
        else print "0.0"
    }')
    local iowait_int=${iowait_pct%.*}

    if float_gt "${iowait_pct}" "${THRESHOLD_IOWAIT_PCT}"; then
        status="ALERT"; why="disk bottleneck!"
        emit_alert --severity WARN --module "${MOD}" --event high_iowait \
            --detail "I/O wait ${iowait_pct}% > threshold ${THRESHOLD_IOWAIT_PCT}%" --target "iowait"
        _flag 1
    else
        status="OK"; why="within threshold"
    fi

    echo "${status}|I/O Wait 💿|${iowait_pct}%|${THRESHOLD_IOWAIT_PCT}%|${why}|${iowait_int}"
}

# =============================================================================
# FILE DESCRIPTORS
# =============================================================================
check_file_descriptors() {
    if [[ ! -r /proc/sys/fs/file-nr ]]; then
        echo "OK|File Descriptors 📂|N/A|-|skipped|0"
        return
    fi
    local fd_allocated fd_max fd_pct status why
    read -r fd_allocated _ fd_max < /proc/sys/fs/file-nr
    fd_pct=$(awk "BEGIN { printf \"%d\", (${fd_allocated}/${fd_max}) * 100 }")

    if [[ "${fd_allocated}" -gt "${THRESHOLD_FD_COUNT}" ]]; then
        status="ALERT"; why="exceeds threshold!"
        emit_alert --severity CRITICAL --module "${MOD}" --event fd_exhaustion \
            --detail "Open FDs ${fd_allocated}/${fd_max} > threshold ${THRESHOLD_FD_COUNT}" --target "fd"
        _flag 2
    elif [[ "${fd_pct}" -gt 70 ]]; then
        status="REVIEW"; why="${fd_pct}% used — monitor"
    else
        status="OK"; why="${fd_pct}% used"
    fi

    echo "${status}|File Descriptors 📂|${fd_allocated}/${fd_max}|${THRESHOLD_FD_COUNT}|${why}|${fd_pct}"
}

# =============================================================================
# UPTIME
# =============================================================================
check_uptime() {
    local uptime_seconds
    read -r uptime_seconds _ < /proc/uptime
    uptime_seconds=${uptime_seconds%%.*}
    local boot_epoch=$(( $(epoch_now) - uptime_seconds ))
    local human_uptime
    human_uptime=$(awk "BEGIN { s=${uptime_seconds}; printf \"%dd %02dh %02dm\", s/86400, (s%86400)/3600, (s%3600)/60 }")

    if [[ -f "${HIDS_DATA_DIR}/baseline/meta.conf" ]]; then
        local bl_epoch
        bl_epoch=$(awk -F= '/BASELINE_EPOCH/{print $2}' "${HIDS_DATA_DIR}/baseline/meta.conf" 2>/dev/null || echo 0)
        if [[ "${boot_epoch}" -gt "${bl_epoch}" ]]; then
            local reboot_time
            reboot_time=$(date -d "@${boot_epoch}" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "unknown")
            emit_alert --severity WARN --module "${MOD}" --event reboot_detected \
                --detail "System rebooted at ${reboot_time} after baseline" --target "uptime"
            _flag 1
            echo "ALERT|Uptime ⏱️|${human_uptime}|-|reboot since baseline!|0"
            return
        fi
    fi
    echo "OK|Uptime ⏱️|${human_uptime}|-|no reboot since baseline|0"
}

# =============================================================================
# DISK
# =============================================================================
check_disk() {
    local results=()
    while IFS= read -r line; do
        local usage_pct mount status
        usage_pct=$(echo "${line}" | grep -oP '^\s*\K\d+(?=%)')
        mount=$(echo "${line}" | grep -oP '%\s+\K.*')
        [[ -z "${usage_pct}" ]] && continue

        if [[ "${usage_pct}" -gt "${THRESHOLD_DISK_PCT}" ]]; then
            status="ALERT"
            emit_alert --severity CRITICAL --module "${MOD}" --event disk_full \
                --detail "Filesystem ${mount} at ${usage_pct}%" --target "${mount}"
            _flag 2
        elif [[ "${usage_pct}" -gt $(( THRESHOLD_DISK_PCT - 10 )) ]]; then
            status="REVIEW"
            _flag 1
        else
            status="OK"
        fi
        results+=("${status}|Disk 💽 ${mount}|${usage_pct}%|${THRESHOLD_DISK_PCT}%|$([ "$status" = "OK" ] && echo "within threshold" || echo "check required")|${usage_pct}")
    done < <(df --output=pcent,target -x tmpfs -x devtmpfs \
        --exclude-type=squashfs --exclude-type=fuse.portal 2>/dev/null | tail -n +2 | \
        grep -vE "^[[:space:]]*[0-9]+%[[:space:]]+$(echo "${DISK_EXCLUDE_MOUNTPOINTS:-}" | tr ',' '|')" 2>/dev/null || \
        df --output=pcent,target -x tmpfs -x devtmpfs \
        --exclude-type=squashfs --exclude-type=fuse.portal 2>/dev/null | tail -n +2)

    for r in "${results[@]}"; do echo "${r}"; done
}

# =============================================================================
# MAIN — Affichage GUM
# =============================================================================
main() {
    # Header principal
    echo ""
    gum style \
        --foreground 212 --border-foreground 212 --border double \
        --align center --width 72 --padding "1 2" \
        "🛡️  HIDS — SYSTEM HEALTH MONITOR" \
        "Host: $(hostname) | $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""

    section_header "📊 Collecting metrics..."

    # Collecter toutes les métriques
    local load_data mem_data swap_data io_data fd_data up_data
    load_data=$(check_load)
    mem_data=$(check_memory)
    swap_data=$(check_swap)
    io_data=$(check_iowait)
    fd_data=$(check_file_descriptors)
    up_data=$(check_uptime)

    # Parser les données
    IFS='|' read -r l_status l_title l_val l_thr l_why _ <<< "${load_data}"
    IFS='|' read -r m_status m_title m_val m_thr m_why m_pct <<< "${mem_data}"
    IFS='|' read -r s_status s_title s_val s_thr s_why s_pct <<< "${swap_data}"
    IFS='|' read -r i_status i_title i_val i_thr i_why i_pct <<< "${io_data}"
    IFS='|' read -r f_status f_title f_val f_thr f_why f_pct <<< "${fd_data}"
    IFS='|' read -r u_status u_title u_val u_thr u_why _ <<< "${up_data}"

    echo ""
    section_header "⚡ CPU & Memory"

    # Ligne 1 : CPU + RAM côte à côte
    paste \
        <(metric_box "${l_title}" "${l_status}" "${l_val}" "${l_thr}" "${l_why}") \
        <(metric_box "${m_title}" "${m_status}" "${m_val}" "${m_thr}" "${m_why}")

    # Barre RAM
    printf "  RAM usage:  "
    progress_bar "${m_pct}" 100 30
    echo ""

    section_header "💾 Swap & I/O"

    paste \
        <(metric_box "${s_title}" "${s_status}" "${s_val}" "${s_thr}" "${s_why}") \
        <(metric_box "${i_title}" "${i_status}" "${i_val}" "${i_thr}" "${i_why}")

    echo ""
    section_header "📂 File Descriptors & Uptime"

    paste \
        <(metric_box "${f_title}" "${f_status}" "${f_val}" "${f_thr}" "${f_why}") \
        <(metric_box "${u_title}" "${u_status}" "${u_val}" "${u_thr}" "${u_why}")

    echo ""
    section_header "💽 Disk Usage"

    while IFS='|' read -r d_status d_title d_val d_thr d_why d_pct; do
        printf "  "
        badge "${d_status}"
        printf " %-35s " "${d_title}"
        progress_bar "${d_pct}" 100 20
    done < <(check_disk)

    echo ""
    # Assessment final
    local assess_color=82
    local assess_icon="✅"
    local assess_msg="All system health checks passed"
    case "${_worst}" in
        1) assess_color=214; assess_icon="⚠️ "; assess_msg="Some metrics require attention" ;;
        2) assess_color=196; assess_icon="🚨"; assess_msg="Critical health issues detected!" ;;
    esac

    gum style \
        --border double --border-foreground "${assess_color}" \
        --align center --width 72 --padding "0 2" \
        "$(gum style --foreground "${assess_color}" --bold "${assess_icon}  ASSESSMENT: ${assess_msg}")"
    echo ""

    return "${_worst}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    load_config
    main
    exit "${_worst}"
fi
