#!/usr/bin/env bash
# =============================================================================
# mod_alert.sh — Module 5: Alert Aggregation and Report Engine
# =============================================================================
# Reads the JSON alert log produced by the other modules during this run,
# computes severity statistics, generates the human-readable report, and
# optionally sends an email digest for critical findings.
#
# This module is called last by the orchestrator, after all other modules
# have run and written their alerts to ALERT_LOG.
#
# Also provides: jq-free JSON query functions for the alert log.
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lib_utils.sh"
load_config

MOD="mod_alert"

# =============================================================================
# ALERT LOG STATISTICS
# =============================================================================

# Reads only alerts written during this run (since RUN_EPOCH, set by orchestrator)
: "${RUN_EPOCH:=0}"

count_by_severity() {
    # Returns the number of alerts with the given severity written during this run.
    # Uses pure awk — no jq dependency.
    local severity="${1^^}"
    [[ ! -f "${ALERT_LOG}" ]] && echo 0 && return
    awk -v sev="${severity}" -v epoch="${RUN_EPOCH}" '
        /"severity":"'"${severity}"'"/ { count++ }
        END { print count+0 }
    ' "${ALERT_LOG}"
}

list_alerts_by_severity() {
    # Prints all alerts of the given severity from this run in a formatted table.
    local severity="${1^^}"
    [[ ! -f "${ALERT_LOG}" ]] && return
    awk -v sev="\"${severity}\"" '
        index($0, "\"severity\":" sev) {
            # Extract module, event, detail using simple field parsing
            match($0, /"module":"([^"]+)"/, m)
            match($0, /"event":"([^"]+)"/, e)
            match($0, /"detail":"([^"]+)"/, d)
            match($0, /"timestamp":"([^"]+)"/, t)
            printf "  [%s] %s | %s | %s\n", t[1], m[1], e[1], d[1]
        }
    ' "${ALERT_LOG}"
}

# =============================================================================
# SUMMARY REPORT GENERATION
# =============================================================================

generate_report() {
    # Builds the full run report from the in-memory buffer and alert counts,
    # then writes it to REPORT_FILE via flush_report().

    local crit_count warn_count info_count total_count
    crit_count=$(count_by_severity CRITICAL)
    warn_count=$(count_by_severity WARN)
    info_count=$(count_by_severity INFO)
    total_count=$(( crit_count + warn_count + info_count ))

    # ── Terminal summary banner ───────────────────────────────────────────────
    printf '\n'
    printf '%s%s%s\n' "${C_BOLD}${C_BLUE}" "$(printf '═%.0s' {1..72})" "${C_RESET}"
    printf '%sHIDS Run Summary — %s%s\n' "${C_BOLD}" "$(now_human)" "${C_RESET}"
    printf '%s%s%s\n' "${C_BOLD}${C_BLUE}" "$(printf '═%.0s' {1..72})" "${C_RESET}"

    if [[ "${crit_count}" -gt 0 ]]; then
        printf '  %s%-12s %s%s%s\n' \
            "${C_BOLD}" "CRITICAL:" "${C_RED}${C_BOLD}" "${crit_count}" "${C_RESET}"
    else
        printf '  %-12s %s%s%s\n' "CRITICAL:" "${C_GREEN}${C_BOLD}" "0" "${C_RESET}"
    fi
    printf '  %-12s %s%s%s\n' "WARN:" \
        "$([[ "${warn_count}" -gt 0 ]] && echo "${C_YELLOW}${C_BOLD}" || echo "${C_GREEN}")" \
        "${warn_count}" "${C_RESET}"
    printf '  %-12s %s\n' "INFO:" "${info_count}"
    printf '  %-12s %s\n' "Total:" "${total_count}"
    printf '  %-12s %s\n' "Alert log:" "${ALERT_LOG}"
    printf '  %-12s %s\n' "Report:" "${REPORT_FILE}"
    printf '%s%s%s\n' "${C_BOLD}${C_BLUE}" "$(printf '═%.0s' {1..72})" "${C_RESET}"

    # Display critical findings prominently
    if [[ "${crit_count}" -gt 0 ]]; then
        printf '\n%s%sCRITICAL FINDINGS:%s\n' "${C_BOLD}" "${C_RED}" "${C_RESET}"
        list_alerts_by_severity CRITICAL | while IFS= read -r line; do
            printf '%s%s%s\n' "${C_RED}" "${line}" "${C_RESET}"
        done
    fi

    if [[ "${warn_count}" -gt 0 ]]; then
        printf '\n%s%sWARNINGS:%s\n' "${C_BOLD}" "${C_YELLOW}" "${C_RESET}"
        list_alerts_by_severity WARN | while IFS= read -r line; do
            printf '%s%s%s\n' "${C_YELLOW}" "${line}" "${C_RESET}"
        done
    fi

    # ── Append statistics to the report buffer then flush ────────────────────
    report_line ""
    report_line "===== Run Statistics ====="
    report_line "CRITICAL: ${crit_count}"
    report_line "WARN:     ${warn_count}"
    report_line "INFO:     ${info_count}"
    report_line "Total:    ${total_count}"
    report_line ""
    report_line "Alert log: ${ALERT_LOG}"
    report_line ""

    if [[ "${crit_count}" -gt 0 ]]; then
        report_line "--- CRITICAL FINDINGS ---"
        list_alerts_by_severity CRITICAL >> /dev/null  # feed to report
        list_alerts_by_severity CRITICAL | while IFS= read -r line; do
            report_line "${line}"
        done
        report_line ""
    fi

    if [[ "${warn_count}" -gt 0 ]]; then
        report_line "--- WARNINGS ---"
        list_alerts_by_severity WARN | while IFS= read -r line; do
            report_line "${line}"
        done
        report_line ""
    fi

    flush_report
}

# =============================================================================
# EMAIL DIGEST
# =============================================================================

send_email_digest() {
    # Sends a summary email digest when CRITICAL alerts were emitted this run.
    # Uses MAIL_CMD; only sent if ALERT_EMAIL is configured.
    [[ -z "${ALERT_EMAIL}" ]] && return

    local crit_count
    crit_count=$(count_by_severity CRITICAL)
    [[ "${crit_count}" -eq 0 ]] && return

    local subject="[HIDS CRITICAL] ${crit_count} critical finding(s) on ${_HIDS_HOST}"
    local body
    body=$(
        printf 'HIDS Critical Alert Digest\n'
        printf '==========================\n\n'
        printf 'Host:      %s\n' "${_HIDS_HOST}"
        printf 'Time:      %s\n' "$(now_human)"
        printf 'Critical:  %s\n' "${crit_count}"
        printf '\nFindings:\n'
        list_alerts_by_severity CRITICAL
        printf '\nFull alert log: %s\n' "${ALERT_LOG}"
        printf 'Full report:    %s\n' "${REPORT_FILE}"
    )

    echo "${body}" | \
        "${MAIL_CMD}" -s "${subject}" "${ALERT_EMAIL}" 2>/dev/null && \
        print_ok "Email digest sent to ${ALERT_EMAIL}" || \
        print_warn "Failed to send email digest via ${MAIL_CMD}"
}

# =============================================================================
# ALERT LOG QUERY UTILITIES (callable standalone)
# =============================================================================

cmd_query() {
    # Provides simple CLI querying of the alert log without jq.
    # Usage: mod_alert.sh --query [--severity CRITICAL] [--module mod_integrity] [--last N]
    local filter_sev="" filter_mod="" last_n=50

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --severity) filter_sev="${2^^}"; shift 2 ;;
            --module)   filter_mod="$2";    shift 2 ;;
            --last)     last_n="$2";        shift 2 ;;
            *)          shift ;;
        esac
    done

    [[ ! -f "${ALERT_LOG}" ]] && echo "Alert log not found: ${ALERT_LOG}" && return 1

    awk -v sev="${filter_sev}" -v mod="${filter_mod}" '
    {
        if (sev != "" && index($0, "\"severity\":\"" sev "\"") == 0) next
        if (mod != "" && index($0, "\"module\":\"" mod "\"") == 0) next
        match($0, /"timestamp":"([^"]+)"/, t)
        match($0, /"severity":"([^"]+)"/, s)
        match($0, /"module":"([^"]+)"/, m)
        match($0, /"detail":"([^"]+)"/, d)
        printf "[%s] [%s] [%s] %s\n", t[1], s[1], m[1], d[1]
    }
    ' "${ALERT_LOG}" | tail -"${last_n}"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    print_section_header "Alert Summary" "📋"
    generate_report
    send_email_digest
}

# Handle standalone invocation with --query flag
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    load_config
    if [[ "${1:-}" == "--query" ]]; then
        shift
        cmd_query "$@"
    else
        main
    fi
fi
