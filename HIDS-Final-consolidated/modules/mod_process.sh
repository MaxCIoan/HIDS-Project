#!/usr/bin/env bash
# =============================================================================
# mod_process.sh — Module 3: Process and Network Audit
# =============================================================================
# Answers one question:
# is anything running or listening on this system that should not be?
#   
# Terminal dashboard layout:
#   - Large count cards with plain numeric values
#   - Left/right column panels
#   - Donut-style risk charts and horizontal bars
#   - Expanded lists for processes and listeners
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

export TERM="${TERM:-xterm-256color}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lib_utils.sh"
load_config

MOD="mod_process"
_worst=0

DASHBOARD_PROC_LIMIT="${DASHBOARD_PROC_LIMIT:-12}"
DASHBOARD_PORT_LIMIT="${DASHBOARD_PORT_LIMIT:-0}"
PANEL_WIDTH=58
CHART_BAR_WIDTH=24

TOTAL_PROCESSES=0
TOTAL_LISTENERS=0
VISIBLE_PROCESS_ROWS=0
VISIBLE_LISTENER_ROWS=0
PROCESS_FINDING_COUNT=0
LISTENER_FINDING_COUNT=0
TOP_PROCESS_GREEN=0
TOP_PROCESS_YELLOW=0
TOP_PROCESS_RED=0
LISTENER_GREEN_COUNT=0
LISTENER_YELLOW_COUNT=0
LISTENER_RED_COUNT=0
LAST_SUSPICIOUS_PROCESSES=0
LAST_SUSPICIOUS_PORTS=0
LAST_REVIEW_PORTS=0

P_RESET='\033[0m'
P_BOLD='\033[1m'
P_DIM='\033[2m'
P_RED='\033[38;5;203m'
P_GREEN='\033[38;5;84m'
P_YELLOW='\033[38;5;220m'
P_BLUE='\033[38;5;117m'
P_WHITE='\033[1;37m'
P_GREY='\033[38;5;245m'
P_BG_BLUE='\033[48;5;24m'
P_BG_RED='\033[48;5;160m'
P_BG_GREEN='\033[48;5;28m'
P_BG_YELLOW='\033[48;5;136m'
P_BG_BLACK='\033[48;5;234m'

declare -a TOP_PROCESS_ROWS=()
declare -a LISTENER_ROWS=()
declare -a PROCESS_FINDINGS=()
declare -a LISTENER_FINDINGS=()

_flag() {
    [[ "$1" -gt "${_worst}" ]] && _worst="$1" || true
}

init_runtime_dirs() {
    if ensure_dirs >/dev/null 2>&1; then
        return 0
    fi

    local fallback_root
    fallback_root="${SCRIPT_DIR}/../.tmp_hids"

    HIDS_DATA_DIR="${fallback_root}/data"
    HIDS_OUTPUT_DIR="${fallback_root}/output"
    ALERT_LOG="${HIDS_OUTPUT_DIR}/alerts.json"
    ALERT_STATE_FILE="${HIDS_DATA_DIR}/alert_state.db"
    REPORT_FILE="${HIDS_OUTPUT_DIR}/report.txt"

    mkdir -p "${HIDS_DATA_DIR}" "${HIDS_OUTPUT_DIR}" "${HIDS_DATA_DIR}/baseline"
}

_status_block() {
    case "$1" in
        green) printf '%b' "${P_BG_GREEN}${P_WHITE}   OK   ${P_RESET}" ;;
        yellow) printf '%b' "${P_BG_YELLOW}${P_WHITE} REVIEW ${P_RESET}" ;;
        red) printf '%b' "${P_BG_RED}${P_WHITE} ALERT  ${P_RESET}" ;;
        blue) printf '%b' "${P_BG_BLUE}${P_WHITE} INFO   ${P_RESET}" ;;
        *) printf '%b' "${P_BG_BLUE}${P_WHITE} INFO   ${P_RESET}" ;;
    esac
}

_risk_text_color() {
    case "$1" in
        green) printf '%b' "${P_GREEN}" ;;
        yellow) printf '%b' "${P_YELLOW}" ;;
        red) printf '%b' "${P_RED}" ;;
        *) printf '%b' "${P_WHITE}" ;;
    esac
}

_strip_ansi() {
    printf '%b' "$1" | awk '{
        gsub(/\033\[[0-9;]*[A-Za-z]/, "")
        printf "%s", $0
    }'
}

_visible_len() {
    local plain
    plain=$(_strip_ansi "$1")
    echo "${#plain}"
}

_pad_ansi() {
    local width="$1"
    local text="${2:-}"
    local len
    len=$(_visible_len "${text}")

    if (( len < width )); then
        printf '%b%*s' "${text}" $(( width - len )) ''
    else
        printf '%b' "${text}"
    fi
}

_center_ansi() {
    local width="$1"
    local text="${2:-}"
    local len left right
    len=$(_visible_len "${text}")

    if (( len >= width )); then
        printf '%b' "${text}"
        return
    fi

    left=$(( (width - len) / 2 ))
    right=$(( width - len - left ))
    printf '%*s%b%*s' "${left}" '' "${text}" "${right}" ''
}

_repeat_char() {
    local count="$1"
    local char="$2"
    (( count <= 0 )) && return 0
    printf '%*s' "${count}" '' | tr ' ' "${char}"
}

_trim_text() {
    local max="$1"
    local text="${2:-}"
    if (( ${#text} > max )); then
        printf '%s' "${text:0:max-3}..."
    else
        printf '%s' "${text}"
    fi
}

_panel_title() {
    local title=" $1 "
    printf '%b' "$(_pad_ansi "${PANEL_WIDTH}" "${P_BG_BLUE}${P_WHITE}${title}${P_RESET}")"
}

_bar_line() {
    local label="$1"
    local count="$2"
    local total="$3"
    local level="$4"
    local fill=0 empty color
    color=$(_risk_text_color "${level}")

    if (( total > 0 )); then
        fill=$(( count * CHART_BAR_WIDTH / total ))
    fi
    empty=$(( CHART_BAR_WIDTH - fill ))

    printf '  %-8s %b%s%b%b%s%b %3s' \
        "${label}" \
        "${color}" "$(_repeat_char "${fill}" '#')" "${P_RESET}" \
        "${P_GREY}" "$(_repeat_char "${empty}" '.')" "${P_RESET}" \
        "${count}"
}

_donut_lines() {
    local label="$1"
    local total="$2"
    local green="$3"
    local yellow="$4"
    local red="$5"
    local center="$6"
    local green_segs=0 yellow_segs=0 red_segs=0 pos
    local -a ring=()

    if (( total > 0 )); then
        green_segs=$(( green * 12 / total ))
        yellow_segs=$(( yellow * 12 / total ))
        red_segs=$(( 12 - green_segs - yellow_segs ))
        (( green > 0 && green_segs == 0 )) && green_segs=1
        (( yellow > 0 && yellow_segs == 0 && green_segs < 12 )) && yellow_segs=1
        red_segs=$(( 12 - green_segs - yellow_segs ))
        (( red_segs < 0 )) && red_segs=0
    fi

    for pos in {1..12}; do
        if (( total == 0 )); then
            ring[pos]="${P_GREY}o${P_RESET}"
        elif (( pos <= green_segs )); then
            ring[pos]="${P_GREEN}o${P_RESET}"
        elif (( pos <= green_segs + yellow_segs )); then
            ring[pos]="${P_YELLOW}o${P_RESET}"
        else
            ring[pos]="${P_RED}o${P_RESET}"
        fi
    done

    printf '      %b %b %b\n' "${ring[1]}" "${ring[2]}" "${ring[3]}"
    printf '    %b       %b\n' "${ring[12]}" "${ring[4]}"
    printf '    %b  %b  %b\n' "${ring[11]}" "$(_center_ansi 4 "${P_WHITE}${center}${P_RESET}")" "${ring[5]}"
    printf '    %b       %b\n' "${ring[10]}" "${ring[6]}"
    printf '      %b %b %b\n' "${ring[9]}" "${ring[8]}" "${ring[7]}"
    printf '%s\n' "$(_center_ansi "${PANEL_WIDTH}" "${P_DIM}${label}${P_RESET}")"
}

_render_two_columns() {
    local left_fn="$1"
    local right_fn="$2"
    local left_file right_file max i left_line right_line left_count right_count
    local -a left_lines=()
    local -a right_lines=()
    left_file=$(mktemp)
    right_file=$(mktemp)

    "${left_fn}" > "${left_file}"
    "${right_fn}" > "${right_file}"

    left_count=0
    while IFS= read -r left_line || [[ -n "${left_line}" ]]; do
        left_lines+=("${left_line}")
        (( left_count++ )) || true
    done < "${left_file}"

    right_count=0
    while IFS= read -r right_line || [[ -n "${right_line}" ]]; do
        right_lines+=("${right_line}")
        (( right_count++ )) || true
    done < "${right_file}"

    max=${left_count}
    (( right_count > max )) && max=${right_count}

    for (( i=0; i<max; i++ )); do
        left_line="${left_lines[i]:-}"
        right_line="${right_lines[i]:-}"
        printf '%b  %b\n' "$(_pad_ansi "${PANEL_WIDTH}" "${left_line}")" "${right_line}"
    done

    rm -f "${left_file}" "${right_file}"
}

_build_suspicious_path_regex() {
    printf '%s' "${SUSPICIOUS_PATHS:-/tmp,/var/tmp,/dev/shm,/run/shm}" | tr ',' '|'
}

_build_whitelist_port_regex() {
    local wl_ports="${WHITELIST_PORTS:-}"

    if [[ -n "${WHITELIST_PORTS_FILE:-}" && -f "${WHITELIST_PORTS_FILE}" ]]; then
        local file_ports
        file_ports=$(grep -v '^[[:space:]]*#' "${WHITELIST_PORTS_FILE}" 2>/dev/null | \
            grep -oE '^[0-9]+' | paste -sd, - || true)
        [[ -n "${file_ports}" ]] && wl_ports="${wl_ports:+${wl_ports},}${file_ports}"
    fi

    printf '%s' "${wl_ports}" | tr ',' '\n' | sed '/^[[:space:]]*$/d' | sort -u | paste -sd'|' -
}

_port_is_whitelisted() {
    local port="$1"
    local wl_regex
    wl_regex=$(_build_whitelist_port_regex)
    [[ -n "${wl_regex}" ]] && printf '%s\n' "${port}" | grep -qE "^(${wl_regex})$"
}

_is_loopback_listener() {
    [[ "$1" =~ ^127\. ]] || [[ "$1" =~ ^\[::1\] ]] || [[ "$1" =~ ^localhost: ]]
}

_is_wildcard_listener() {
    [[ "$1" == *"*:"* ]] || [[ "$1" =~ ^0\.0\.0\.0: ]] || [[ "$1" =~ ^\[::\]: ]]
}

_is_private_listener() {
    [[ "$1" =~ ^10\. ]] || [[ "$1" =~ ^192\.168\. ]] || \
    [[ "$1" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || [[ "$1" =~ ^169\.254\. ]] || \
    [[ "$1" =~ ^\[fe80: ]] || [[ "$1" =~ ^\[fc ]] || [[ "$1" =~ ^\[fd ]]
}

_classify_process() {
    local pid="$1"
    local user="$2"
    local pname="$3"
    local suspicious_regex exe uid cmdline

    suspicious_regex=$(_build_suspicious_path_regex)
    exe=$(readlink "/proc/${pid}/exe" 2>/dev/null || true)
    uid=$(awk '/^Uid:/{print $2; exit}' "/proc/${pid}/status" 2>/dev/null || echo "")
    cmdline=$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || true)

    if [[ -z "${exe}" ]]; then
        if [[ -z "${cmdline}" ]]; then
            printf 'green|kernel/system thread|%s\n' "-"
        else
            printf 'yellow|path unavailable|%s\n' "-"
        fi
    elif [[ "${exe}" == *" (deleted)" ]]; then
        printf 'red|deleted binary|%s\n' "${exe}"
    elif printf '%s\n' "${exe}" | grep -qE "^(${suspicious_regex})"; then
        printf 'red|running from temp path|%s\n' "${exe}"
    elif [[ "${uid}" == "0" ]] && printf '%s\n' "${exe}" | grep -qE '^/home/|^/root/'; then
        printf 'red|root binary in home dir|%s\n' "${exe}"
    elif printf '%s\n' "${exe}" | grep -qE '^/usr/|^/bin/|^/sbin/|^/lib|^/lib64'; then
        printf 'green|expected system binary|%s\n' "${exe}"
    elif printf '%s\n' "${exe}" | grep -qE '^/usr/local/|^/opt/|^/snap/|^/home/'; then
        printf 'yellow|optional app path|%s\n' "${exe}"
    elif [[ "${user}" != "root" ]]; then
        printf 'yellow|user-space process|%s\n' "${exe}"
    else
        printf 'yellow|non-standard process path|%s\n' "${exe}"
    fi
}

_classify_listener() {
    local local_addr="$1"
    local port="$2"
    local pid="$3"

    if _port_is_whitelisted "${port}"; then
        printf 'green|expected whitelisted service\n'
        return 0
    fi

    if [[ "${pid}" =~ ^[0-9]+$ ]]; then
        local proc_level proc_reason proc_path
        IFS='|' read -r proc_level proc_reason proc_path <<< "$(_classify_process "${pid}" "" "")"
        if [[ "${proc_level}" == "red" ]]; then
            printf 'red|listener owned by suspicious process\n'
            return 0
        fi
    fi

    if _is_loopback_listener "${local_addr}"; then
        printf 'yellow|local-only service\n'
    elif _is_private_listener "${local_addr}"; then
        printf 'yellow|internal-only listener\n'
    elif _is_wildcard_listener "${local_addr}"; then
        printf 'red|exposed non-whitelist port\n'
    else
        printf 'red|unexpected network listener\n'
    fi
}

_listening_socket_rows() {
    ss -lntupH 2>/dev/null | awk '
    {
        proto = $1
        local_addr = $5
        proc_info = $NF
        n = split(local_addr, parts, ":")
        port = parts[n]

        proc = "-"
        pid = "-"
        if (match(proc_info, /"[^"]+"/)) {
            proc = substr(proc_info, RSTART + 1, RLENGTH - 2)
        }
        if (match(proc_info, /pid=[0-9]+/)) {
            pid = substr(proc_info, RSTART + 4, RLENGTH - 4)
        }

        if (port ~ /^[0-9]+$/) {
            printf "%s|%s|%s|%s|%s\n", proto, local_addr, port, pid, proc
        }
    }'
}

collect_top_process_rows() {
    TOP_PROCESS_ROWS=()
    VISIBLE_PROCESS_ROWS=0
    TOP_PROCESS_GREEN=0
    TOP_PROCESS_YELLOW=0
    TOP_PROCESS_RED=0
    TOTAL_PROCESSES=$(ps -e --no-headers 2>/dev/null | wc -l | tr -d ' ')

    if (( DASHBOARD_PROC_LIMIT > 0 )); then
        while IFS='|' read -r pid user cpu mem pname; do
            [[ -n "${pid}" ]] || continue
            local level reason exe
            IFS='|' read -r level reason exe <<< "$(_classify_process "${pid}" "${user}" "${pname}")"
            TOP_PROCESS_ROWS+=("${level}|${pid}|${user}|${cpu}|${mem}|${pname}|${reason}")
            (( VISIBLE_PROCESS_ROWS++ )) || true
            case "${level}" in
                green) (( TOP_PROCESS_GREEN++ )) || true ;;
                yellow) (( TOP_PROCESS_YELLOW++ )) || true ;;
                red) (( TOP_PROCESS_RED++ )) || true ;;
            esac
        done < <(ps -eo pid=,user=,%cpu=,%mem=,comm= --sort=-%cpu 2>/dev/null | head -n "${DASHBOARD_PROC_LIMIT}" | awk '{print $1 "|" $2 "|" $3 "|" $4 "|" $5}')
    else
        while IFS='|' read -r pid user cpu mem pname; do
            [[ -n "${pid}" ]] || continue
            local level reason exe
            IFS='|' read -r level reason exe <<< "$(_classify_process "${pid}" "${user}" "${pname}")"
            TOP_PROCESS_ROWS+=("${level}|${pid}|${user}|${cpu}|${mem}|${pname}|${reason}")
            (( VISIBLE_PROCESS_ROWS++ )) || true
            case "${level}" in
                green) (( TOP_PROCESS_GREEN++ )) || true ;;
                yellow) (( TOP_PROCESS_YELLOW++ )) || true ;;
                red) (( TOP_PROCESS_RED++ )) || true ;;
            esac
        done < <(ps -eo pid=,user=,%cpu=,%mem=,comm= --sort=-%cpu 2>/dev/null | awk '{print $1 "|" $2 "|" $3 "|" $4 "|" $5}')
    fi
}

collect_process_findings() {
    local suspicious_regex
    suspicious_regex=$(_build_suspicious_path_regex)
    LAST_SUSPICIOUS_PROCESSES=0
    PROCESS_FINDINGS=()
    PROCESS_FINDING_COUNT=0

    for pid_dir in /proc/[0-9]*/; do
        local pid pname uid exe cmdline
        pid=$(basename "${pid_dir}")
        [[ -d "${pid_dir}" ]] || continue

        exe=$(readlink "${pid_dir}exe" 2>/dev/null || true)
        [[ -n "${exe}" ]] || continue

        pname=$(awk '/^Name:/{print $2; exit}' "${pid_dir}status" 2>/dev/null || echo "unknown")
        uid=$(awk '/^Uid:/{print $2; exit}' "${pid_dir}status" 2>/dev/null || echo "?")
        cmdline=$(tr '\0' ' ' < "${pid_dir}cmdline" 2>/dev/null | sed 's/[[:space:]]\+/ /g' | cut -c1-120 || true)
        [[ -n "${cmdline}" ]] || cmdline="${pname}"

        if printf '%s\n' "${exe}" | grep -qE "^(${suspicious_regex})"; then
            PROCESS_FINDINGS+=("red|${pname} pid=${pid}|running from temp path")
            (( PROCESS_FINDING_COUNT++ )) || true
            emit_alert --severity CRITICAL --module "${MOD}" --event suspicious_path_process \
                --detail "Process launched from suspicious path: ${exe} (pid=${pid}, uid=${uid}, cmd=${cmdline})" \
                --target "${exe}" --pid "${pid}" >/dev/null
            _flag 2
            (( LAST_SUSPICIOUS_PROCESSES++ )) || true
            continue
        fi

        if [[ "${exe}" == *" (deleted)" ]]; then
            PROCESS_FINDINGS+=("red|${pname} pid=${pid}|deleted binary")
            (( PROCESS_FINDING_COUNT++ )) || true
            emit_alert --severity CRITICAL --module "${MOD}" --event deleted_binary \
                --detail "Process binary deleted after launch: ${exe} (pid=${pid}, uid=${uid})" \
                --target "${exe}" --pid "${pid}" >/dev/null
            _flag 2
            (( LAST_SUSPICIOUS_PROCESSES++ )) || true
            continue
        fi

        if [[ "${uid}" == "0" ]] && printf '%s\n' "${exe}" | grep -qE '^/home/|^/root/'; then
            PROCESS_FINDINGS+=("red|${pname} pid=${pid}|root binary in home dir")
            (( PROCESS_FINDING_COUNT++ )) || true
            emit_alert --severity CRITICAL --module "${MOD}" --event root_home_process \
                --detail "Root-owned process with binary in home directory: ${exe} (pid=${pid})" \
                --target "${exe}" --pid "${pid}" >/dev/null
            _flag 2
            (( LAST_SUSPICIOUS_PROCESSES++ )) || true
        fi
    done
}

collect_listener_data() {
    LISTENER_ROWS=()
    LISTENER_FINDINGS=()
    VISIBLE_LISTENER_ROWS=0
    LISTENER_FINDING_COUNT=0
    LISTENER_GREEN_COUNT=0
    LISTENER_YELLOW_COUNT=0
    LISTENER_RED_COUNT=0
    LAST_SUSPICIOUS_PORTS=0
    LAST_REVIEW_PORTS=0
    TOTAL_LISTENERS=0

    while IFS='|' read -r proto local_addr port pid proc; do
        [[ -n "${port}" ]] || continue

        local level reason
        IFS='|' read -r level reason <<< "$(_classify_listener "${local_addr}" "${port}" "${pid}")"

        (( TOTAL_LISTENERS++ )) || true
        if (( DASHBOARD_PORT_LIMIT == 0 || VISIBLE_LISTENER_ROWS < DASHBOARD_PORT_LIMIT )); then
            LISTENER_ROWS+=("${level}|${proto}|${local_addr}|${port}|${proc}|${reason}")
            (( VISIBLE_LISTENER_ROWS++ )) || true
        fi

        case "${level}" in
            green)
                (( LISTENER_GREEN_COUNT++ )) || true
                ;;
            yellow)
                (( LISTENER_YELLOW_COUNT++ )) || true
                (( LAST_REVIEW_PORTS++ )) || true
                LISTENER_FINDINGS+=("yellow|${port}/${proto}|${reason}")
                (( LISTENER_FINDING_COUNT++ )) || true
                _flag 1
                ;;
            red)
                (( LISTENER_RED_COUNT++ )) || true
                (( LAST_SUSPICIOUS_PORTS++ )) || true
                LISTENER_FINDINGS+=("red|${port}/${proto}|${reason}")
                (( LISTENER_FINDING_COUNT++ )) || true
                emit_alert --severity CRITICAL --module "${MOD}" --event suspicious_listener \
                    --detail "Suspicious listening port: ${port}/${proto} on ${local_addr} (${proc}, pid=${pid}) — ${reason}" \
                    --target "${port}" --pid "${pid}" >/dev/null
                _flag 2
                ;;
        esac
    done < <(_listening_socket_rows)
}

collect_dashboard_data() {
    collect_top_process_rows
    collect_process_findings
    collect_listener_data

    report_line "Running processes: ${TOTAL_PROCESSES}"
    report_line "Listening sockets: ${TOTAL_LISTENERS}"
    report_line "Suspicious processes: ${LAST_SUSPICIOUS_PROCESSES}"
    report_line "Suspicious listening ports: ${LAST_SUSPICIOUS_PORTS}"
    report_line "Review listening ports: ${LAST_REVIEW_PORTS}"
}

_emit_kpi_panel() {
    local title="$1"
    local value="$2"
    local subtitle="$3"
    local level="$4"
    local color

    color=$(_risk_text_color "${level}")
    echo "$(_panel_title "${title}")"
    echo "$(_center_ansi "${PANEL_WIDTH}" "${color}${P_BOLD}${value}${P_RESET}")"
    echo "$(_center_ansi "${PANEL_WIDTH}" "${P_WHITE}${subtitle}${P_RESET}")"
    echo "$(_center_ansi "${PANEL_WIDTH}" "$(_status_block "${level}")")"
    echo ""
}

panel_total_processes() {
    _emit_kpi_panel "RUNNING PROCESSES" "${TOTAL_PROCESSES}" "active processes right now" green
}

panel_total_listeners() {
    _emit_kpi_panel "LISTENING SOCKETS" "${TOTAL_LISTENERS}" "ports and sockets in listen state" green
}

panel_suspicious_total() {
    local total_red=$(( LAST_SUSPICIOUS_PROCESSES + LAST_SUSPICIOUS_PORTS ))
    local level="green"
    (( total_red > 0 )) && level="red"
    _emit_kpi_panel "RED FLAGS" "${total_red}" "things that should not be there" "${level}"
}

panel_review_total() {
    local level="green"
    (( LAST_REVIEW_PORTS > 0 )) && level="yellow"
    _emit_kpi_panel "REVIEW ITEMS" "${LAST_REVIEW_PORTS}" "listeners worth checking" "${level}"
}

panel_process_mix() {
    local total_top=$(( TOP_PROCESS_GREEN + TOP_PROCESS_YELLOW + TOP_PROCESS_RED ))
    echo "$(_panel_title "PROCESS RISK MIX")"
    while IFS= read -r line; do
        echo "$(_center_ansi "${PANEL_WIDTH}" "${line}")"
    done < <(_donut_lines "shown process rows" "${total_top}" "${TOP_PROCESS_GREEN}" "${TOP_PROCESS_YELLOW}" "${TOP_PROCESS_RED}" "${total_top}")
    echo "$(_pad_ansi "${PANEL_WIDTH}" "$(_bar_line OK "${TOP_PROCESS_GREEN}" "${total_top}" green)")"
    echo "$(_pad_ansi "${PANEL_WIDTH}" "$(_bar_line REVIEW "${TOP_PROCESS_YELLOW}" "${total_top}" yellow)")"
    echo "$(_pad_ansi "${PANEL_WIDTH}" "$(_bar_line ALERT "${TOP_PROCESS_RED}" "${total_top}" red)")"
}

panel_listener_mix() {
    local total_listen=$(( LISTENER_GREEN_COUNT + LISTENER_YELLOW_COUNT + LISTENER_RED_COUNT ))
    echo "$(_panel_title "LISTENER RISK MIX")"
    while IFS= read -r line; do
        echo "$(_center_ansi "${PANEL_WIDTH}" "${line}")"
    done < <(_donut_lines "all listening sockets" "${total_listen}" "${LISTENER_GREEN_COUNT}" "${LISTENER_YELLOW_COUNT}" "${LISTENER_RED_COUNT}" "${total_listen}")
    echo "$(_pad_ansi "${PANEL_WIDTH}" "$(_bar_line OK "${LISTENER_GREEN_COUNT}" "${total_listen}" green)")"
    echo "$(_pad_ansi "${PANEL_WIDTH}" "$(_bar_line REVIEW "${LISTENER_YELLOW_COUNT}" "${total_listen}" yellow)")"
    echo "$(_pad_ansi "${PANEL_WIDTH}" "$(_bar_line ALERT "${LISTENER_RED_COUNT}" "${total_listen}" red)")"
}

panel_top_processes() {
    local row level pid user cpu mem pname reason line placeholder
    echo "$(_panel_title "TOP PROCESSES")"
    echo "$(_pad_ansi "${PANEL_WIDTH}" "  ${P_WHITE}STATUS   PID    USER       CPU   MEM   NAME           WHY${P_RESET}")"

    if (( VISIBLE_PROCESS_ROWS == 0 )); then
        echo "$(_pad_ansi "${PANEL_WIDTH}" "  $(_status_block blue) no process rows collected")"
        return
    fi

    for row in "${TOP_PROCESS_ROWS[@]}"; do
        IFS='|' read -r level pid user cpu mem pname reason <<< "${row}"
        placeholder="STATUS__"
        line=$(printf '  %-8s %-6s %-10s %-5s %-5s %-14s %s' \
            "${placeholder}" \
            "$( _trim_text 6 "${pid}" )" \
            "$( _trim_text 10 "${user}" )" \
            "$( _trim_text 5 "${cpu}" )" \
            "$( _trim_text 5 "${mem}" )" \
            "$( _trim_text 14 "${pname}" )" \
            "$( _trim_text 16 "${reason}" )")
        line="${line/${placeholder}/$(_status_block "${level}")}"
        echo "$(_pad_ansi "${PANEL_WIDTH}" "${line}")"
    done
}

panel_top_listeners() {
    local row level proto local_addr port proc reason line placeholder
    echo "$(_panel_title "LISTENING PORTS")"
    echo "$(_pad_ansi "${PANEL_WIDTH}" "  ${P_WHITE}STATUS   CONN       LOCAL              PROCESS      WHY${P_RESET}")"

    if (( VISIBLE_LISTENER_ROWS == 0 )); then
        echo "$(_pad_ansi "${PANEL_WIDTH}" "  $(_status_block green) no listening sockets found")"
        return
    fi

    for row in "${LISTENER_ROWS[@]}"; do
        IFS='|' read -r level proto local_addr port proc reason <<< "${row}"
        placeholder="STATUS__"
        line=$(printf '  %-8s %-10s %-18s %-12s %s' \
            "${placeholder}" \
            "$( _trim_text 10 "${port}/${proto}" )" \
            "$( _trim_text 18 "${local_addr}" )" \
            "$( _trim_text 12 "${proc}" )" \
            "$( _trim_text 12 "${reason}" )")
        line="${line/${placeholder}/$(_status_block "${level}")}"
        echo "$(_pad_ansi "${PANEL_WIDTH}" "${line}")"
    done
}

panel_process_findings() {
    local row level item why count=0
    echo "$(_panel_title "PROCESS FINDINGS")"

    if (( PROCESS_FINDING_COUNT == 0 )); then
        echo "$(_pad_ansi "${PANEL_WIDTH}" "  $(_status_block green) no suspicious processes found")"
        return
    fi

    for row in "${PROCESS_FINDINGS[@]}"; do
        IFS='|' read -r level item why <<< "${row}"
        echo "$(_pad_ansi "${PANEL_WIDTH}" "  $(_status_block "${level}") $( _trim_text 20 "${item}" ) - $( _trim_text 22 "${why}" )")"
        (( count++ )) || true
        (( count >= 8 )) && break
    done
}

panel_listener_findings() {
    local row level item why count=0
    echo "$(_panel_title "PORT FINDINGS")"

    if (( LISTENER_FINDING_COUNT == 0 )); then
        echo "$(_pad_ansi "${PANEL_WIDTH}" "  $(_status_block green) all listeners look expected")"
        return
    fi

    for row in "${LISTENER_FINDINGS[@]}"; do
        IFS='|' read -r level item why <<< "${row}"
        echo "$(_pad_ansi "${PANEL_WIDTH}" "  $(_status_block "${level}") $( _trim_text 16 "${item}" ) - $( _trim_text 26 "${why}" )")"
        (( count++ )) || true
        (( count >= 10 )) && break
    done
}

show_header() {
    local title left right
    title="PROCESS AND NETWORK AUDIT"
    left="${P_BG_BLUE}${P_WHITE} HIDS ${P_RESET} ${P_WHITE}${P_BOLD}${title}${P_RESET}"
    right="${P_GREY}is anything running or listening that should not be?${P_RESET}"
    printf '%b\n' "$(_pad_ansi $(( PANEL_WIDTH * 2 + 2 )) "${left}")"
    printf '%b\n' "$(_pad_ansi $(( PANEL_WIDTH * 2 + 2 )) "${right}")"
    if [[ "${HIDS_DATA_DIR}" == *".tmp_hids/data" ]]; then
        printf '%b %s\n' "$(_status_block blue)" "Standalone mode using local dashboard output"
    fi
    printf '%b %s\n' "$(_status_block blue)" "Showing ${VISIBLE_PROCESS_ROWS} process row(s) and ${VISIBLE_LISTENER_ROWS} listener row(s)"
    printf '%b\n' "${P_GREY}$(_repeat_char $(( PANEL_WIDTH * 2 + 2 )) '-')${P_RESET}"
}

show_assessment() {
    local message level
    if (( LAST_SUSPICIOUS_PROCESSES > 0 || LAST_SUSPICIOUS_PORTS > 0 )); then
        level="red"
        message="${LAST_SUSPICIOUS_PROCESSES} suspicious process(es) and ${LAST_SUSPICIOUS_PORTS} suspicious listener(s) need attention now"
        report_line "Assessment: suspicious activity present"
    elif (( LAST_REVIEW_PORTS > 0 )); then
        level="yellow"
        message="Nothing clearly malicious, but ${LAST_REVIEW_PORTS} listener(s) should be reviewed"
        report_line "Assessment: review recommended"
    else
        level="green"
        message="Everything shown here looks expected"
        report_line "Assessment: expected process and network state"
    fi

    printf '%b\n' "${P_GREY}$(_repeat_char $(( PANEL_WIDTH * 2 + 2 )) '-')${P_RESET}"
    printf '%b %s\n' "$(_status_block "${level}")" "${message}"
}

main() {
    init_runtime_dirs
    collect_dashboard_data
    show_header
    _render_two_columns panel_total_processes panel_total_listeners
    _render_two_columns panel_suspicious_total panel_review_total
    _render_two_columns panel_process_mix panel_listener_mix
    _render_two_columns panel_top_processes panel_top_listeners
    _render_two_columns panel_process_findings panel_listener_findings
    show_assessment
    return "${_worst}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
    exit "${_worst}"
fi