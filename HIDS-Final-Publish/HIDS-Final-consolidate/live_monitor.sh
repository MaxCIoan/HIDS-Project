#!/usr/bin/env bash
# =============================================================================
# live_monitor.sh — Continuous Live Monitoring Mode
# =============================================================================
# Provides a continuously-refreshing dashboard of key system metrics and
# recent alerts. Uses tput for screen control — no external TUI dependencies.
#
# Architecture:
#   - Main loop redraws the screen every LIVE_REFRESH_SECONDS using tput
#   - Slow checks (integrity, SUID scan) run in background subshells on
#     their own timer (LIVE_SLOW_REFRESH_SECONDS) to avoid blocking the UI
#   - Each module writes its output to a shared tmpfile; the main loop reads
#     and renders it without waiting for module completion
#   - Alerts surface in a dedicated panel at the bottom of the screen
#
# Launched by: hids.sh --live
# Exit: Ctrl+C
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "${SCRIPT_DIR}/lib/lib_utils.sh"
load_config

export RUN_EPOCH
RUN_EPOCH=$(epoch_now)

# =============================================================================
# TMPFILE REGISTRY
# =============================================================================
# Each module writes its latest output to a dedicated tmpfile.
# The render loop reads these files; they are never locked — a partial read
# shows slightly stale data for one cycle, which is acceptable.

TMPDIR_LIVE=$(mktemp -d)
TMP_HEALTH="${TMPDIR_LIVE}/health"
TMP_USERS="${TMPDIR_LIVE}/users"
TMP_PROCESS="${TMPDIR_LIVE}/process"
TMP_INTEGRITY="${TMPDIR_LIVE}/integrity"
TMP_ALERTS="${TMPDIR_LIVE}/alerts"

# Timestamps of last slow-check completion
LAST_INTEGRITY_RUN=0

# Cleanup on exit
trap 'tput cnorm; tput rmcup; rm -rf "${TMPDIR_LIVE}"; echo "Live monitor stopped."; exit 0' \
    INT TERM EXIT

# =============================================================================
# BACKGROUND MODULE RUNNERS
# =============================================================================

_run_health_bg() {
    # Runs mod_health in a loop and writes output to TMP_HEALTH.
    # Captures terminal output without color (plain text for the TUI to render).
    while true; do
        {
            # Inline the key health metrics for speed — avoids forking the full module
            local load_1 nproc threshold
            read -r load_1 _ < /proc/loadavg
            nproc=$(nproc 2>/dev/null || echo 1)
            threshold=$(awk "BEGIN { printf \"%.1f\", ${LOAD_MULTIPLIER} * ${nproc} }")

            local mem_avail_kb mem_total_kb mem_avail_mb
            mem_total_kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
            mem_avail_kb=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
            mem_avail_mb=$(( mem_avail_kb / 1024 ))
            local mem_pct=$(( 100 - (mem_avail_kb * 100 / mem_total_kb) ))

            local swap_total_kb swap_free_kb swap_pct=0
            swap_total_kb=$(awk '/^SwapTotal:/{print $2}' /proc/meminfo)
            swap_free_kb=$(awk '/^SwapFree:/{print $2}' /proc/meminfo)
            [[ "${swap_total_kb}" -gt 0 ]] && \
                swap_pct=$(( (swap_total_kb - swap_free_kb) * 100 / swap_total_kb ))

            printf "LOAD     %-8s / %-8s  (threshold: %s)\n" "${load_1}" "${nproc} cores" "${threshold}"
            printf "RAM      %sMB avail / %sMB total  (%s%% used)\n" \
                "${mem_avail_mb}" "$(( mem_total_kb / 1024 ))" "${mem_pct}"
            printf "SWAP     %s%% used\n" "${swap_pct}"

            # Disk
            df -P --exclude-type=tmpfs --exclude-type=devtmpfs --exclude-type=squashfs \
               --exclude-type=overlay 2>/dev/null | awk 'NR>1 {
                gsub(/%/,"",$5)
                warn = ($5 >= '"${THRESHOLD_DISK_PCT}"') ? " !" : ""
                printf "DISK     %-20s %s%%%s\n", $6, $5, warn
            }'
        } > "${TMP_HEALTH}" 2>/dev/null
        sleep "${LIVE_REFRESH_SECONDS}"
    done
}

_run_users_bg() {
    # Runs user session checks in a loop.
    while true; do
        {
            who 2>/dev/null | awk '{printf "SESSION  %-12s %-8s %s\n", $1, $2, $NF}' || \
                echo "SESSION  (none)"
            # Recent failed logins (last 5 minutes)
            local auth_log=""
            for f in /var/log/auth.log /var/log/secure; do
                [[ -r "${f}" ]] && auth_log="${f}" && break
            done
            if [[ -n "${auth_log}" ]]; then
                local fail_count
                fail_count=$(tail -200 "${auth_log}" 2>/dev/null | \
                    grep -c "Failed password\|Invalid user" 2>/dev/null || echo 0)
                printf "AUTHFAIL %-8s (last 200 auth log lines)\n" "${fail_count}"
            fi
        } > "${TMP_USERS}" 2>/dev/null
        sleep $(( LIVE_REFRESH_SECONDS * 2 ))
    done
}

_run_process_bg() {
    # Checks for suspicious processes and listening ports.
    while true; do
        {
            # Top 5 processes by CPU
            printf "TOP-CPU:\n"
            ps aux --no-headers --sort=-%cpu 2>/dev/null | head -5 | \
                awk '{printf "  %-20s pid=%-7s cpu=%s%% mem=%s%%\n", $11, $2, $3, $4}'

            # Listening ports
            printf "PORTS:\n"
            ss -tulnp 2>/dev/null | awk 'NR>1 {
                n=split($5,a,":"); port=a[n]
                match($NF, /"([^"]+)"/, proc)
                printf "  %-8s %s\n", port, proc[1]
            }' | head -15

            # Suspicious path processes (fast check)
            local susp=0
            for pid_dir in /proc/[0-9]*/; do
                local exe
                exe=$(readlink "${pid_dir}exe" 2>/dev/null || continue)
                if echo "${exe}" | grep -qE "^(/tmp|/var/tmp|/dev/shm)"; then
                    (( susp++ )) || true
                fi
            done
            printf "SUSP-PROC %s\n" "${susp}"
        } > "${TMP_PROCESS}" 2>/dev/null
        sleep "${LIVE_REFRESH_SECONDS}"
    done
}

_run_integrity_bg() {
    # Integrity checks are slow; run on the slow timer.
    while true; do
        {
            # Quick check: recently modified files in critical dirs
            local recent_count
            recent_count=$(find /etc /bin /usr/bin -mmin -"${LIVE_SLOW_REFRESH_SECONDS}" \
                -type f 2>/dev/null | wc -l)
            printf "RECENT-MOD  %s files (last %ss)\n" \
                "${recent_count}" "${LIVE_SLOW_REFRESH_SECONDS}"

            # Count SUID binaries
            local suid_count
            suid_count=$(find / -perm /6000 -type f \
                -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" \
                2>/dev/null | wc -l)
            printf "SUID-COUNT  %s\n" "${suid_count}"

            # ld.so.preload presence
            if [[ -s /etc/ld.so.preload ]]; then
                printf "LD-PRELOAD  WARNING: non-empty\n"
            else
                printf "LD-PRELOAD  clean\n"
            fi
        } > "${TMP_INTEGRITY}" 2>/dev/null
        sleep "${LIVE_SLOW_REFRESH_SECONDS}"
    done
}

_refresh_alerts() {
    # Reads the last LIVE_ALERT_LINES from the alert log into the alert panel tmpfile.
    [[ ! -f "${ALERT_LOG}" ]] && echo "(no alerts yet)" > "${TMP_ALERTS}" && return
    tail -"${LIVE_ALERT_LINES}" "${ALERT_LOG}" 2>/dev/null | awk '
        match($0, /"timestamp":"([^"]+)"/, t)
        match($0, /"severity":"([^"]+)"/, s)
        match($0, /"detail":"([^"]+)"/, d)
        { printf "[%s] [%-8s] %s\n", substr(t[1],1,19), s[1], substr(d[1],1,60) }
    ' > "${TMP_ALERTS}" 2>/dev/null || echo "(no alerts)" > "${TMP_ALERTS}"
}

# =============================================================================
# RENDER — DRAWS THE ENTIRE SCREEN IN ONE PASS
# =============================================================================

_render() {
    # Moves cursor to top-left and redraws the full dashboard.
    # We build the full screen buffer as a string first, then print it in one
    # write — this minimises flicker compared to many small printf calls.
    local cols rows
    cols=$(tput cols 2>/dev/null || echo 80)
    rows=$(tput lines 2>/dev/null || echo 24)
    local ts
    ts=$(now_human)

    # ── Header ────────────────────────────────────────────────────────────────
    tput cup 0 0
    printf '%s%-*s%s\n' "${C_BOLD}${C_BLUE}" "${cols}" \
        " HIDS Live Monitor | ${_HIDS_HOST} | ${ts} | Ctrl+C to exit" "${C_RESET}"
    printf '%s\n' "$(printf '─%.0s' $(seq 1 "${cols}"))"

    local row=2

    # ── System Health ─────────────────────────────────────────────────────────
    tput cup "${row}" 0
    printf '%s System Health %s\n' "${C_BOLD}${C_CYAN}" "${C_RESET}"
    (( row++ )) || true
    if [[ -f "${TMP_HEALTH}" ]]; then
        while IFS= read -r line; do
            tput cup "${row}" 0
            # Color critical lines red
            if echo "${line}" | grep -q ' !'; then
                printf '%s%-*s%s\n' "${C_RED}" "${cols}" "${line}" "${C_RESET}"
            else
                printf '%-*s\n' "${cols}" "${line}"
            fi
            (( row++ )) || true
            [[ "${row}" -ge $(( rows - 12 )) ]] && break
        done < "${TMP_HEALTH}"
    fi

    tput cup "${row}" 0; printf '%s\n' "$(printf '─%.0s' $(seq 1 "${cols}"))"; (( row++ )) || true

    # ── Active Sessions ───────────────────────────────────────────────────────
    tput cup "${row}" 0
    printf '%s Sessions & Auth %s\n' "${C_BOLD}${C_CYAN}" "${C_RESET}"
    (( row++ )) || true
    if [[ -f "${TMP_USERS}" ]]; then
        head -5 "${TMP_USERS}" | while IFS= read -r line; do
            tput cup "${row}" 0; printf '%-*s\n' "${cols}" "${line}"
            (( row++ )) || true
        done
    fi

    tput cup "${row}" 0; printf '%s\n' "$(printf '─%.0s' $(seq 1 "${cols}"))"; (( row++ )) || true

    # ── Process & Network ─────────────────────────────────────────────────────
    tput cup "${row}" 0
    printf '%s Process & Network %s\n' "${C_BOLD}${C_CYAN}" "${C_RESET}"
    (( row++ )) || true
    if [[ -f "${TMP_PROCESS}" ]]; then
        head -10 "${TMP_PROCESS}" | while IFS= read -r line; do
            tput cup "${row}" 0; printf '%-*s\n' "${cols}" "${line}"
            (( row++ )) || true
        done
    fi

    tput cup "${row}" 0; printf '%s\n' "$(printf '─%.0s' $(seq 1 "${cols}"))"; (( row++ )) || true

    # ── File Integrity ────────────────────────────────────────────────────────
    tput cup "${row}" 0
    printf '%s Integrity (slow refresh: %ss) %s\n' "${C_BOLD}${C_CYAN}" \
        "${LIVE_SLOW_REFRESH_SECONDS}" "${C_RESET}"
    (( row++ )) || true
    if [[ -f "${TMP_INTEGRITY}" ]]; then
        while IFS= read -r line; do
            tput cup "${row}" 0
            echo "${line}" | grep -q "WARNING" && \
                printf '%s%-*s%s\n' "${C_RED}" "${cols}" "${line}" "${C_RESET}" || \
                printf '%-*s\n' "${cols}" "${line}"
            (( row++ )) || true
        done < "${TMP_INTEGRITY}"
    fi

    tput cup "${row}" 0; printf '%s\n' "$(printf '─%.0s' $(seq 1 "${cols}"))"; (( row++ )) || true

    # ── Alert Panel ───────────────────────────────────────────────────────────
    tput cup "${row}" 0
    printf '%s Recent Alerts (last %s) %s\n' \
        "${C_BOLD}${C_YELLOW}" "${LIVE_ALERT_LINES}" "${C_RESET}"
    (( row++ )) || true
    _refresh_alerts
    if [[ -f "${TMP_ALERTS}" ]]; then
        while IFS= read -r line; do
            [[ "${row}" -ge $(( rows - 1 )) ]] && break
            tput cup "${row}" 0
            if echo "${line}" | grep -q 'CRITICAL'; then
                printf '%s%-*s%s\n' "${C_RED}" "${cols}" "${line}" "${C_RESET}"
            elif echo "${line}" | grep -q 'WARN'; then
                printf '%s%-*s%s\n' "${C_YELLOW}" "${cols}" "${line}" "${C_RESET}"
            else
                printf '%-*s\n' "${cols}" "${line}"
            fi
            (( row++ )) || true
        done < "${TMP_ALERTS}"
    fi

    # Clear any remaining lines from previous render (prevents ghost text)
    while [[ "${row}" -lt "${rows}" ]]; do
        tput cup "${row}" 0; tput el
        (( row++ )) || true
    done
}

# =============================================================================
# MAIN LIVE LOOP
# =============================================================================

main() {
    require_root

    # Enter alternate screen buffer (preserves original terminal content)
    tput smcup
    # Hide cursor during rendering
    tput civis
    # Clear the alternate screen
    clear

    printf '%sStarting background monitors...%s\n' "${C_CYAN}" "${C_RESET}"

    # Launch background module runners as subshells
    _run_health_bg    &
    _run_users_bg     &
    _run_process_bg   &
    _run_integrity_bg &

    # Give modules a moment to populate their tmpfiles before first render
    sleep 2

    # Main render loop
    while true; do
        _render
        sleep "${LIVE_REFRESH_SECONDS}"
    done
}

main
