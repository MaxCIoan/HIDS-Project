#!/usr/bin/env bash
# =============================================================================
# mod_network_scan.sh — Network Scanner Module for HIDS (GUM Edition)
# =============================================================================
# Scans target hosts on lab-net (192.168.0.0/24) and alerts on changes.
# Compares current open ports against a stored baseline.
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "${SCRIPT_DIR}/../lib/lib_utils.sh"
load_config "${SCRIPT_DIR}/../config.conf"

MOD="mod_network_scan"
_worst=0
_flag() { [[ $1 -gt $_worst ]] && _worst=$1; }

# --- Configuration ---
MY_IP="192.168.0.41"
SCAN_NETWORK="192.168.0.0/24"
BASELINE_DIR="${HIDS_DATA_DIR}/network_baseline"
mkdir -p "${BASELINE_DIR}"

# =============================================================================
# HELPERS VISUELS GUM
# =============================================================================
badge_ok()     { gum style --background 82  --foreground 0   --bold --padding "0 1" " OK     "; }
badge_review() { gum style --background 214 --foreground 0   --bold --padding "0 1" " REVIEW "; }
badge_alert()  { gum style --background 196 --foreground 255 --bold --padding "0 1" " ALERT  "; }
badge_info()   { gum style --background 33  --foreground 255 --bold --padding "0 1" " INFO   "; }

badge() {
    case "$1" in
        OK)     badge_ok ;;
        REVIEW) badge_review ;;
        ALERT)  badge_alert ;;
        INFO)   badge_info ;;
    esac
}

section_header() {
    echo ""
    gum style \
        --foreground 212 --border-foreground 212 --border normal \
        --width 70 --padding "0 2" "$1"
}

info_box()  { gum style --border rounded --border-foreground 33  --width 68 --padding "0 2" "$@"; }
alert_box() { gum style --border rounded --border-foreground 196 --width 68 --padding "0 2" "$@"; }
warn_box()  { gum style --border rounded --border-foreground 214 --width 68 --padding "0 2" "$@"; }
ok_box()    { gum style --border rounded --border-foreground 82  --width 68 --padding "0 2" "$@"; }

counter_box() {
    local title="$1" count="$2" status="$3" msg="$4"
    local color=82
    [[ "$status" == "REVIEW" ]] && color=214
    [[ "$status" == "ALERT"  ]] && color=196
    gum style --border rounded --border-foreground "${color}" --width 33 --padding "0 1" \
        "$(gum style --foreground "${color}" --bold "${title}")" \
        "$(gum style --foreground 255 --bold "    ${count}")" \
        "$(badge "${status}") ${msg}"
}

# =============================================================================
# DÉCOUVERTE DES HÔTES
# =============================================================================
discover_hosts() {
    section_header "🔍 Host Discovery — ${SCAN_NETWORK}"

    gum style --foreground 245 "  Scanning network... (this may take a moment)"

    local hosts
    hosts=$(nmap -sn "${SCAN_NETWORK}" 2>/dev/null | \
        awk '/Nmap scan report for/{print $NF}' | \
        grep -v "${MY_IP}" | \
        grep -v "ubuntu1" || true)

    local host_count
    host_count=$(echo "${hosts}" | grep -c '\.' 2>/dev/null | tr -d '[:space:]' || echo 0)
    host_count=$(( host_count + 0 ))

    echo ""
    paste \
        <(counter_box "Hosts Found 🖥️" "${host_count}" "$([ "$host_count" -gt 0 ] && echo REVIEW || echo OK)" "on lab-net") \
        <(counter_box "Our IP 🔵" "1" "OK" "${MY_IP}") 2>/dev/null || true
    echo ""

    if [[ "${host_count}" -eq 0 ]]; then
        ok_box "$(badge OK) No other hosts found on ${SCAN_NETWORK}"
    else
        local rows=()
        rows+=("$(gum style --bold --foreground 212 "$(printf '%-18s %-20s %s' 'IP ADDRESS' 'HOSTNAME' 'STATUS')")")
        rows+=("$(gum style --foreground 240 "$(printf '%-18s %-20s %s' '──────────────────' '────────────────────' '──────')")")

        while IFS= read -r host; do
            [[ -z "${host}" ]] && continue
            local hostname
            hostname=$(nmap -sn "${host}" 2>/dev/null | awk '/Nmap scan report/{print $5}' | head -1 || echo "unknown")
            rows+=("$(gum style --foreground 214 "$(printf '%-18s %-20s %s' "${host}" "${hostname:-unknown}" "ACTIVE")")")
        done <<< "${hosts}"

        gum style \
            --border rounded --border-foreground 214 \
            --width 70 --padding "0 1" \
            "${rows[@]}"
    fi

    echo "${hosts}"
}

# =============================================================================
# SCAN DES PORTS D'UN HÔTE
# =============================================================================
scan_host() {
    local target="$1"
    local safe_target="${target//./_}"
    local baseline_file="${BASELINE_DIR}/${safe_target}_ports.list"
    local current_file
    current_file=$(mktemp)

    section_header "🌐 Port Scan — ${target}"

    gum style --foreground 245 "  Scanning all ports... (please wait)"

    nmap -sT --open -p- --min-rate 1000 -T4 "${target}" 2>/dev/null | \
        awk '/^[0-9]+\/tcp.*open/{print $1}' | \
        sort > "${current_file}"

    local current_count
    current_count=$(wc -l < "${current_file}")

    # Première fois — créer la baseline
    if [[ ! -f "${baseline_file}" ]]; then
        cp "${current_file}" "${baseline_file}"
        echo ""
        ok_box \
            "$(badge OK) Baseline created for ${target}" \
            "   ${current_count} open ports recorded"
        rm -f "${current_file}"
        return
    fi

    # Comparer avec la baseline
    local new_ports closed_ports
    new_ports=$(comm -13 "${baseline_file}" "${current_file}" || true)
    closed_ports=$(comm -23 "${baseline_file}" "${current_file}" || true)
    local baseline_count
    baseline_count=$(wc -l < "${baseline_file}")

    echo ""
    paste \
        <(counter_box "Open Ports 🟢" "${current_count}"  "OK"    "currently open") \
        <(counter_box "Baseline 📋"   "${baseline_count}" "OK"    "at baseline") 2>/dev/null || true
    echo ""

    # Nouveaux ports — CRITICAL
    if [[ -n "${new_ports}" ]]; then
        local new_count
        new_count=$(echo "${new_ports}" | grep -c '\.' 2>/dev/null || echo $(echo "${new_ports}" | wc -l))
        local alert_rows=()
        alert_rows+=("$(gum style --foreground 196 --bold "🚨 New open ports on ${target}:")")
        alert_rows+=("")
        while IFS= read -r port; do
            [[ -z "${port}" ]] && continue
            alert_rows+=("  $(badge ALERT) ${port}")
            emit_alert --severity CRITICAL --module "${MOD}" \
                --event new_port_detected \
                --detail "New port opened on ${target}: ${port}" \
                --target "${target}"
            _flag 2
        done <<< "${new_ports}"
        alert_box "${alert_rows[@]}"
    else
        ok_box "$(badge OK) No new ports on ${target} since baseline"
    fi

    # Ports fermés — WARN
    if [[ -n "${closed_ports}" ]]; then
        local warn_rows=()
        warn_rows+=("$(gum style --foreground 214 --bold "⚠  Ports closed since baseline on ${target}:")")
        warn_rows+=("")
        while IFS= read -r port; do
            [[ -z "${port}" ]] && continue
            warn_rows+=("  $(badge REVIEW) ${port}")
            emit_alert --severity WARN --module "${MOD}" \
                --event port_closed \
                --detail "Port no longer open on ${target}: ${port}" \
                --target "${target}"
            _flag 1
        done <<< "${closed_ports}"
        warn_box "${warn_rows[@]}"
    fi

    rm -f "${current_file}"
}

# =============================================================================
# CONNEXIONS ÉTABLIES VERS LAB-NET
# =============================================================================
check_connections() {
    section_header "🔗 Established Connections to lab-net"

    local suspicious_conns
    suspicious_conns=$(ss -tnp 2>/dev/null | \
        awk '/ESTAB.*192\.168\.0\./{print $0}' || true)

    if [[ -n "${suspicious_conns}" ]]; then
        local conn_count
        conn_count=$(echo "${suspicious_conns}" | wc -l)
        local warn_rows=()
        warn_rows+=("$(gum style --foreground 214 --bold "⚠  ${conn_count} active connection(s) to lab-net:")")
        warn_rows+=("")

        while IFS= read -r conn; do
            [[ -z "${conn}" ]] && continue
            local dest
            dest=$(echo "${conn}" | awk '{print $5}')
            local proc
            proc=$(echo "${conn}" | awk '{print $NF}' | grep -oP '"[^"]+"' | tr -d '"' || echo "unknown")
            warn_rows+=("  $(badge REVIEW) ${dest} ← ${proc}")
            emit_alert --severity WARN --module "${MOD}" \
                --event active_lab_connection \
                --detail "Established connection to lab-net: ${conn}" \
                --target "lab-net"
            _flag 1
        done <<< "${suspicious_conns}"
        warn_box "${warn_rows[@]}"
    else
        ok_box "$(badge OK) No active connections to lab-net"
    fi
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    echo ""
    gum style \
        --foreground 212 --border-foreground 212 --border double \
        --align center --width 72 --padding "1 2" \
        "🌐  HIDS — NETWORK SCAN MONITOR" \
        "Network: ${SCAN_NETWORK} | $(date '+%Y-%m-%d %H:%M:%S')"

    # Découverte des hôtes
    local hosts
    hosts=$(discover_hosts)

    # Scanner chaque hôte découvert
    local scanned=0
    while IFS= read -r target; do
        [[ -z "${target}" ]] && continue
        [[ "${target}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
        scan_host "${target}"
        (( scanned++ )) || true
    done <<< "${hosts}"

    [[ "${scanned}" -eq 0 ]] && info_box "$(badge INFO) No hosts to scan on lab-net"

    # Connexions établies
    check_connections

    # Assessment
    echo ""
    local assess_color=82
    local assess_icon="✅"
    local assess_msg="All network checks passed"
    case "${_worst}" in
        1) assess_color=214; assess_icon="⚠️ "; assess_msg="Some network activity requires attention" ;;
        2) assess_color=196; assess_icon="🚨"; assess_msg="Critical network changes detected!" ;;
    esac

    gum style \
        --border double --border-foreground "${assess_color}" \
        --align center --width 72 --padding "0 2" \
        "$(gum style --foreground "${assess_color}" --bold "${assess_icon}  ASSESSMENT: ${assess_msg}")"
    echo ""

    return "${_worst}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
    exit "${_worst}"
fi
