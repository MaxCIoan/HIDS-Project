#!/usr/bin/env bash
# =============================================================================
# mod_alert.sh — Module 5: Alert Aggregation and Report Engine (GUM Edition)
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lib_utils.sh"
load_config

MOD="mod_alert"
: "${RUN_EPOCH:=0}"

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

ok_box()    { gum style --border rounded --border-foreground 82  --width 68 --padding "0 2" "$@"; }
warn_box()  { gum style --border rounded --border-foreground 214 --width 68 --padding "0 2" "$@"; }
alert_box() { gum style --border rounded --border-foreground 196 --width 68 --padding "0 2" "$@"; }
info_box()  { gum style --border rounded --border-foreground 33  --width 68 --padding "0 2" "$@"; }

counter_box() {
    local title="$1" count="$2" status="$3" msg="$4"
    local color=82
    [[ "$status" == "REVIEW" ]] && color=214
    [[ "$status" == "ALERT"  ]] && color=196
    gum style --border rounded --border-foreground "${color}" --width 21 --padding "0 1" \
        "$(gum style --foreground "${color}" --bold "${title}")" \
        "$(gum style --foreground 255 --bold "  ${count}")" \
        "$(badge "${status}") ${msg}"
}

ok_box()    { gum style --border rounded --border-foreground 82  --width 68 --padding "0 2" "$@"; }
warn_box()  { gum style --border rounded --border-foreground 214 --width 68 --padding "0 2" "$@"; }
alert_box() { gum style --border rounded --border-foreground 196 --width 68 --padding "0 2" "$@"; }
info_box()  { gum style --border rounded --border-foreground 33  --width 68 --padding "0 2" "$@"; }

counter_box() {
    local title="$1" count="$2" status="$3" msg="$4"
    local color=82
    [[ "$status" == "REVIEW" ]] && color=214
    [[ "$status" == "ALERT"  ]] && color=196
    gum style --border rounded --border-foreground "${color}" --width 21 --padding "0 1" \
        "$(gum style --foreground "${color}" --bold "${title}")" \
        "$(gum style --foreground 255 --bold "  ${count}")" \
        "$(badge "${status}") ${msg}"
}

# =============================================================================
# ALERT LOG STATISTICS
# =============================================================================
count_by_severity() {
    local severity="${1^^}"
    [[ ! -f "${ALERT_LOG}" ]] && echo 0 && return
    awk -v sev="${severity}" -v epoch="${RUN_EPOCH}" '
        /"severity":"'"${severity}"'"/ { count++ }
        END { print count+0 }
    ' "${ALERT_LOG}"
}

list_alerts_by_severity() {
    local severity="${1^^}"
    [[ ! -f "${ALERT_LOG}" ]] && return
    awk -v sev="\"${severity}\"" '
        index($0, "\"severity\":" sev) {
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
    local crit_count warn_count info_count total_count
    crit_count=$(count_by_severity CRITICAL)
    warn_count=$(count_by_severity WARN)
    info_count=$(count_by_severity INFO)
    total_count=$(( crit_count + warn_count + info_count ))

    echo ""
    gum style \
        --foreground 212 --border-foreground 212 --border double \
        --align center --width 72 --padding "0 2" \
        "📋  HIDS RUN SUMMARY — $(now_human)"
    echo ""

    # Compteurs côte à côte
    paste \
        <(counter_box "CRITICAL 🚨" "${crit_count}" "$([ $crit_count -eq 0 ] && echo OK || echo ALERT)"  "findings") \
        <(counter_box "WARN ⚠️"     "${warn_count}" "$([ $warn_count  -eq 0 ] && echo OK || echo REVIEW)" "findings") \
        <(counter_box "TOTAL 📊"    "${total_count}" "$([ $total_count -eq 0 ] && echo OK || echo REVIEW)" "alerts") 2>/dev/null || true

    echo ""

    # Chemins des logs
    gum style --border rounded --border-foreground 33 --width 68 --padding "0 2" \
        "$(gum style --foreground 33 --bold "📁 Alert log:")  ${ALERT_LOG}" \
        "$(gum style --foreground 33 --bold "📄 Report:   ")  ${REPORT_FILE}"

    echo ""

    # CRITICAL findings
    if [[ "${crit_count}" -gt 0 ]]; then
        local crit_rows=()
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            crit_rows+=("$(gum style --foreground 196 "${line}")")
        done < <(list_alerts_by_severity CRITICAL)

        alert_box \
            "$(gum style --foreground 196 --bold "🚨 CRITICAL FINDINGS (${crit_count}):")" \
            "" \
            "${crit_rows[@]}"
        echo ""
    fi

    # WARN findings
    if [[ "${warn_count}" -gt 0 ]]; then
        local warn_rows=()
        while IFS= read -r line; do
            [[ -z "${line}" ]] && continue
            warn_rows+=("$(gum style --foreground 214 "${line}")")
        done < <(list_alerts_by_severity WARN)

        warn_box \
            "$(gum style --foreground 214 --bold "⚠  WARNINGS (${warn_count}):")" \
            "" \
            "${warn_rows[@]}"
        echo ""
    fi

    # Tout est propre
    if [[ "${total_count}" -eq 0 ]]; then
        ok_box \
            "$(badge OK) No alerts generated during this run" \
            "   System appears clean ✅"
        echo ""
    fi

    # Assessment final global
    local assess_color=82
    local assess_icon="✅"
    local assess_msg="System is clean — no threats detected"
    if [[ "${crit_count}" -gt 0 ]]; then
        assess_color=196; assess_icon="🚨"; assess_msg="CRITICAL threats require immediate attention!"
    elif [[ "${warn_count}" -gt 0 ]]; then
        assess_color=214; assess_icon="⚠️ "; assess_msg="Warnings detected — review recommended"
    fi

    gum style \
        --border double --border-foreground "${assess_color}" \
        --align center --width 72 --padding "1 2" \
        "$(gum style --foreground "${assess_color}" --bold "${assess_icon}  FINAL ASSESSMENT")" \
        "$(gum style --foreground "${assess_color}" "${assess_msg}")"
    echo ""

    # Écrire le rapport fichier
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
    local crit_count
    crit_count=$(count_by_severity CRITICAL)
    [[ "${crit_count}" -eq 0 ]] && return 0

    if ! _mail_config_ready; then
        return 1
    fi

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

    if _send_mail_message "${ALERT_EMAIL}" "${subject}" "${body}"; then
        ok_box "$(badge OK) Email digest sent to ${ALERT_EMAIL}"
        return 0
    fi

    if [[ -n "${_LAST_MAIL_ERROR:-}" ]]; then
        warn_box "$(badge REVIEW) Failed to send email digest via ${MAIL_CMD}" "   ${_LAST_MAIL_ERROR}"
    else
        warn_box "$(badge REVIEW) Failed to send email digest via ${MAIM_CMD}"
    fi
    return 1
}

# =============================================================================
# QUERY CLI
# =============================================================================
cmd_query() {
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

    echo ""
    gum style \
        --foreground 212 --border-foreground 212 --border normal \
        --width 70 --padding "0 2" \
        "🔍 Alert Query — last ${last_n} | sev=${filter_sev:-ALL} | mod=${filter_mod:-ALL}"
    echo ""

    local rows=()
    rows+=("$(gum style --bold --foreground 212 "$(printf '%-22s %-10s %-20s %s' 'TIMESTAMP' 'SEVERITY' 'MODULE' 'DETAIL')")")
    rows+=("$(gum style --foreground 240 "$(printf '%-22s %-10s %-20s %s' '──────────────────────' '──────────' '────────────────────' '──────')")")

    while IFS= read -r line; do
        local color=82
        echo "${line}" | grep -q "CRITICAL" && color=196
        echo "${line}" | grep -q "WARN"     && color=214
        rows+=("$(gum style --foreground "${color}" "${line}")")
    done < <(awk -v sev="${filter_sev}" -v mod="${filter_mod}" '
    {
        if (sev != "" && index($0, "\"severity\":\"" sev "\"") == 0) next
        if (mod != "" && index($0, "\"module\":\"" mod "\"") == 0) next
        match($0, /"timestamp":"([^"]+)"/, t)
        match($0, /"severity":"([^"]+)"/, s)
        match($0, /"module":"([^"]+)"/, m)
        match($0, /"detail":"([^"]+)"/, d)
        printf "[%s] [%-8s] [%-18s] %s\n", t[1], s[1], m[1], d[1]
    }' "${ALERT_LOG}" | tail -"${last_n}")

    gum style \
        --border rounded --border-foreground 212 \
        --width 70 --padding "0 1" \
        "${rows[@]}"
    echo ""
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    local digest_status=0

    generate_report
    send_email_digest || digest_status=$?

    if [[ "${digest_status}" -ne 0 ]]; then
        maybe_prompt_email_setup failed || true
    elif ! _mail_config_ready; then
        maybe_prompt_email_setup missing || true
    fi
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    load_config
    if [[ "${1:-}" == "--query" ]]; then
        shift
        cmd_query "$@"
    else
        main
    fi
fi

