#!/usr/bin/env bash
# =============================================================================
# mod_users.sh — Module 2: User Activity Monitor (GUM Edition)
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lib_utils.sh"
load_config

MOD="mod_users"
_worst=0
_flag() { [[ "$1" -gt "${_worst}" ]] && _worst="$1" || true; }

_AUTH_LOG=""
for _candidate in /var/log/auth.log /var/log/secure; do
    [[ -r "${_candidate}" ]] && _AUTH_LOG="${_candidate}" && break
done

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

info_box() {
    gum style \
        --border rounded --border-foreground 33 \
        --width 68 --padding "0 2" "$@"
}

alert_box() {
    gum style \
        --border rounded --border-foreground 196 \
        --width 68 --padding "0 2" "$@"
}

warn_box() {
    gum style \
        --border rounded --border-foreground 214 \
        --width 68 --padding "0 2" "$@"
}

ok_box() {
    gum style \
        --border rounded --border-foreground 82 \
        --width 68 --padding "0 2" "$@"
}

# =============================================================================
# SESSIONS ACTIVES
# =============================================================================
check_current_sessions() {
    section_header "👤 Active Sessions"

    local session_count
    session_count=$(who 2>/dev/null | wc -l)

    if [[ "${session_count}" -eq 0 ]]; then
        ok_box "$(badge OK) No active sessions"
        return
    fi

    # Construire le tableau des sessions
    local rows=()
    rows+=("$(gum style --bold --foreground 212 "$(printf '%-12s %-10s %-25s %s' 'USER' 'TTY' 'SINCE' 'SOURCE')")")
    rows+=("$(gum style --foreground 240 "$(printf '%-12s %-10s %-25s %s' '────────────' '──────────' '─────────────────────────' '──────────')")")

    local has_alert=0
    while IFS= read -r line; do
        local user tty login_time host
        user=$(echo "${line}" | awk '{print $1}')
        tty=$(echo "${line}" | awk '{print $2}')
        login_time=$(echo "${line}" | awk '{print $3, $4}')
        host=$(echo "${line}" | awk '{print $5}' | tr -d '()' || echo "local")

        local status="OK"
        if [[ -n "${TRUSTED_SSH_SOURCES}" && -n "${host}" && "${host}" != "local" ]]; then
            local trusted=0
            IFS=',' read -ra trusted_list <<< "${TRUSTED_SSH_SOURCES}"
            for src in "${trusted_list[@]}"; do
                [[ "${host}" == *"${src}"* ]] && trusted=1 && break
            done
            [[ "${trusted}" -eq 0 ]] && status="REVIEW" && has_alert=1
        fi

        local color=82
        [[ "$status" == "REVIEW" ]] && color=214

        rows+=("$(gum style --foreground "${color}" "$(printf '%-12s %-10s %-25s %s' "${user}" "${tty}" "${login_time}" "${host:-local}")")")

        if [[ "$status" == "REVIEW" ]]; then
            emit_alert --severity WARN --module "${MOD}" --event untrusted_session \
                --detail "Active session from untrusted source: ${user}@${host}" \
                --target "${user}"
            _flag 1
        fi
    done < <(who 2>/dev/null)

    # Vérifier session root SSH
    if who | grep -q '^root .* (.*\..*\..*\..*)'; then
        emit_alert --severity CRITICAL --module "${MOD}" --event root_ssh_session \
            --detail "Root user has an active remote SSH session" --target "root"
        _flag 2
        has_alert=2
    fi

    local box_color=82
    [[ $has_alert -eq 1 ]] && box_color=214
    [[ $has_alert -eq 2 ]] && box_color=196

    gum style \
        --border rounded --border-foreground "${box_color}" \
        --width 70 --padding "0 1" \
        "${rows[@]}"

    # Compteur sessions
    echo ""
    paste \
        <(gum style --border rounded --border-foreground 82 --width 33 --padding "0 1" \
            "$(gum style --foreground 82 --bold "Active Sessions")" \
            "$(gum style --foreground 255 --bold "    ${session_count}")" \
            "$(badge OK) currently logged in") \
        <(gum style --border rounded --border-foreground 214 --width 33 --padding "0 1" \
            "$(gum style --foreground 214 --bold "Root Sessions")" \
            "$(gum style --foreground 255 --bold "    $(who | grep -c '^root' || echo 0)")" \
            "$(badge OK) remote root sessions")
}

# =============================================================================
# FAILED LOGINS
# =============================================================================
check_failed_logins() {
    section_header "🔐 Failed Login Attempts (24h)"

    [[ -z "${_AUTH_LOG}" ]] && ok_box "$(badge INFO) No auth log available" && return

    local failures
    if command -v journalctl &>/dev/null; then
        failures=$(journalctl -u sshd --since "24 hours ago" 2>/dev/null | \
            grep "Failed password\|Invalid user\|authentication failure" || true)
    else
        failures=$(tail -5000 "${_AUTH_LOG}" 2>/dev/null | \
            grep "Failed password\|Invalid user\|authentication failure" || true)
    fi

    if [[ -z "${failures}" ]]; then
        ok_box "$(badge OK) No failed login attempts in last 24h"
        return
    fi

    local total_failures
    total_failures=$(echo "${failures}" | wc -l)

    # Top IPs
    local rows=()
    rows+=("$(gum style --bold --foreground 212 "$(printf '%-8s %-18s %s' 'COUNT' 'SOURCE IP' 'STATUS')")")
    rows+=("$(gum style --foreground 240 "$(printf '%-8s %-18s %s' '────────' '──────────────────' '──────')")")

    while IFS= read -r line; do
        local count ip
        count=$(echo "${line}" | awk '{print $1}')
        ip=$(echo "${line}" | awk '{print $2}')

        if [[ "${count}" -ge "${THRESHOLD_FAILED_LOGINS}" ]]; then
            rows+=("$(gum style --foreground 196 "$(printf '%-8s %-18s %s' "${count}" "${ip}" "⚠ BRUTE FORCE")")")
            emit_alert --severity CRITICAL --module "${MOD}" --event brute_force \
                --detail "Source IP ${ip} has ${count} failed login attempts (threshold: ${THRESHOLD_FAILED_LOGINS})" \
                --target "${ip}"
            _flag 2
        else
            rows+=("$(gum style --foreground 214 "$(printf '%-8s %-18s %s' "${count}" "${ip}" "REVIEW")")")
            _flag 1
        fi
    done < <(echo "${failures}" | grep -oP '(\d+\.){3}\d+' 2>/dev/null | sort | uniq -c | sort -rn | head -10)

    warn_box \
        "$(gum style --foreground 214 --bold "⚠  Total failed attempts: ${total_failures}")" \
        "" \
        "${rows[@]}"
}

# =============================================================================
# SUDO ACTIVITY
# =============================================================================
check_sudo_activity() {
    section_header "🔑 Sudo Activity Details (24h)"

    [[ -z "${_AUTH_LOG}" ]] && ok_box "$(badge INFO) No auth log available" && return

    local sudo_lines
    if command -v journalctl &>/dev/null; then
        sudo_lines=$(journalctl --since "24 hours ago" 2>/dev/null | grep "sudo:" || true)
    else
        sudo_lines=$(tail -5000 "${_AUTH_LOG}" 2>/dev/null | grep "sudo:" || true)
    fi

    # Filter for failures
    local sudo_failures
    sudo_failures=$(echo "${sudo_lines}" | grep -iE "incorrect|failure|NOT in sudoers" || true)

    if [[ -z "${sudo_failures}" ]]; then
        ok_box "$(badge OK) No failed sudo attempts in last 24h"
        return
    fi

    # Build the Detail Table
    local rows=()
    rows+=("$(gum style --bold --foreground 212 "$(printf '%-16s %-12s %s' 'TIMESTAMP' 'USER' 'REASON')")")
    rows+=("$(gum style --foreground 240 "$(printf '%-16s %-12s %s' '────────────────' '────────────' '──────────────')")")

    while IFS= read -r line; do
        # Extracting data using awk based on standard /var/log/auth.log format
        local timestamp user reason
        timestamp=$(echo "$line" | awk '{print $1, $2, $3}')
        user=$(echo "$line" | grep -oP '(?<=user=)\S+' || echo "unknown")
        
        # Determine the reason for the display
        if [[ "$line" == *"NOT in sudoers"* ]]; then
            reason="Unauthorized"
        else
            reason="Wrong Password"
        fi

        rows+=("$(gum style --foreground 196 "$(printf '%-16s %-12s %s' "$timestamp" "$user" "$reason")")")
        
        # Trigger your existing alert logic
        emit_alert --severity WARN --module "${MOD}" --event sudo_failure \
            --detail "Failed sudo: $user ($reason)" --target "$user"
        _flag 1
    done <<< "${sudo_failures}"

    warn_box \
        "$(gum style --foreground 196 --bold "🚨 Detected Failed Sudo Attempts")" \
        "" \
        "${rows[@]}"
}

# =============================================================================
# NOUVEAUX COMPTES
# =============================================================================
check_new_accounts() {
    section_header "👥 User Accounts"

    local bl_users="${HIDS_DATA_DIR}/baseline/users.list"
    if [[ ! -f "${bl_users}" ]]; then
        info_box "$(badge INFO) No user baseline — skipping account diff"
        return
    fi

    local new_accounts
    new_accounts=$(awk -F: '{print $1":"$3}' /etc/passwd | \
        while IFS=: read -r uname uid; do
            grep -q "^${uname}:" "${bl_users}" 2>/dev/null || echo "${uname}:${uid}"
        done || true)

    # UID 0 check
    local uid0_count
    uid0_count=$(awk -F: '$3 == 0' /etc/passwd | wc -l)
    local uid0_users
    uid0_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | tr '\n' ' ')

    if [[ -z "${new_accounts}" && "${uid0_count}" -le 1 ]]; then
        ok_box \
            "$(badge OK) No new user accounts since baseline" \
            "$(badge OK) UID 0 account: ${uid0_users}(root only — expected)"
        return
    fi

    if [[ -n "${new_accounts}" ]]; then
        while IFS=: read -r uname uid; do
            local sev="WARN"
            [[ "${uid}" -eq 0 ]] && sev="CRITICAL"
            emit_alert --severity "${sev}" --module "${MOD}" --event new_account \
                --detail "User account created since baseline: ${uname} (uid=${uid})" \
                --target "${uname}"
            _flag 2
        done <<< "${new_accounts}"

        alert_box \
            "$(gum style --foreground 196 --bold "🚨 New accounts detected since baseline:")" \
            "" \
            "$(echo "${new_accounts}" | while IFS=: read -r u id; do
                echo "  $(badge ALERT) ${u} (uid=${id})"
            done)"
    fi

    if [[ "${uid0_count}" -gt 1 ]]; then
        alert_box \
            "$(gum style --foreground 196 --bold "🚨 Multiple UID 0 accounts: ${uid0_users}")"
        emit_alert --severity CRITICAL --module "${MOD}" --event uid0_duplicate \
            --detail "Multiple UID 0 accounts: ${uid0_users}" --target "/etc/passwd"
        _flag 2
    fi
}

# =============================================================================
# GROUPES SENSIBLES
# =============================================================================
check_group_membership() {
    section_header "🔒 Sensitive Group Membership"

    local bl_groups="${HIDS_DATA_DIR}/baseline/groups.list"
    if [[ ! -f "${bl_groups}" ]]; then
        info_box "$(badge INFO) No group baseline — skipping"
        return
    fi

    local rows=()
    rows+=("$(gum style --bold --foreground 212 "$(printf '%-12s %-30s %s' 'GROUP' 'MEMBERS' 'STATUS')")")
    rows+=("$(gum style --foreground 240 "$(printf '%-12s %-30s %s' '────────────' '──────────────────────────────' '──────')")")

    local has_changes=0
    IFS=',' read -ra sensitive_list <<< "${SENSITIVE_GROUPS}"
    for grp in "${sensitive_list[@]}"; do
        local current_members baseline_members new_members
        current_members=$(awk -F: -v g="${grp}" '$1==g {print $4}' /etc/group 2>/dev/null || echo "")
        baseline_members=$(awk -F: -v g="${grp}" '$1==g {print $3}' "${bl_groups}" 2>/dev/null || echo "")

        local current_sorted baseline_sorted
        current_sorted=$(echo "${current_members}" | tr ',' '\n' | sort)
        baseline_sorted=$(echo "${baseline_members}" | tr ',' '\n' | sort)
        new_members=$(comm -23 <(echo "${current_sorted}") <(echo "${baseline_sorted}") | tr '\n' ' ')

        if [[ -n "${new_members// /}" ]]; then
            rows+=("$(gum style --foreground 196 "$(printf '%-12s %-30s %s' "${grp}" "${new_members}" "⚠ CHANGED")")")
            emit_alert --severity CRITICAL --module "${MOD}" --event group_membership_change \
                --detail "New member(s) in group '${grp}': ${new_members}" --target "${grp}"
            _flag 2
            has_changes=1
        else
            rows+=("$(gum style --foreground 82 "$(printf '%-12s %-30s %s' "${grp}" "${current_members:-none}" "✓ unchanged")")")
        fi
    done

    local box_color=82
    [[ $has_changes -eq 1 ]] && box_color=196

    gum style \
        --border rounded --border-foreground "${box_color}" \
        --width 70 --padding "0 1" \
        "${rows[@]}"
}

# =============================================================================
# SSH AUTHORIZED KEYS
# =============================================================================
check_authorized_keys() {
    section_header "🗝️  SSH Authorized Keys"

    local modified_keys=0
    local bl_epoch=0

    [[ -f "${HIDS_DATA_DIR}/baseline/meta.conf" ]] && \
        bl_epoch=$(awk -F= '/BASELINE_EPOCH/{print $2}' \
            "${HIDS_DATA_DIR}/baseline/meta.conf" 2>/dev/null || echo 0)

    while IFS=: read -r uname _ uid _ _ home _; do
        local keyfile="${home}/.ssh/authorized_keys"
        [[ ! -f "${keyfile}" ]] && continue
        local file_mtime
        file_mtime=$(stat -c %Y "${keyfile}" 2>/dev/null || echo 0)
        if [[ "${file_mtime}" -gt "${bl_epoch}" ]]; then
            alert_box \
                "$(gum style --foreground 196 --bold "🚨 authorized_keys modified: ${keyfile}")" \
                "   User: ${uname} | Modified: $(date -d @${file_mtime} '+%Y-%m-%d %H:%M:%S')"
            emit_alert --severity CRITICAL --module "${MOD}" --event authorized_keys_modified \
                --detail "SSH authorized_keys modified since baseline: ${keyfile} (user: ${uname})" \
                --target "${keyfile}"
            _flag 2
            (( modified_keys++ )) || true
        fi
    done < /etc/passwd

    [[ "${modified_keys}" -eq 0 ]] && \
        ok_box "$(badge OK) No authorized_keys modifications detected"
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    # Header
    echo ""
    gum style \
        --foreground 212 --border-foreground 212 --border double \
        --align center --width 72 --padding "1 2" \
        "👤  HIDS — USER ACTIVITY MONITOR" \
        "Host: $(hostname) | $(date '+%Y-%m-%d %H:%M:%S')"

    check_current_sessions
    check_failed_logins
    check_sudo_activity
    check_new_accounts
    check_group_membership
    check_authorized_keys

    # Assessment
    echo ""
    local assess_color=82
    local assess_icon="✅"
    local assess_msg="All user activity checks passed"
    case "${_worst}" in
        1) assess_color=214; assess_icon="⚠️ "; assess_msg="Some user activity requires attention" ;;
        2) assess_color=196; assess_icon="🚨"; assess_msg="Critical user activity detected!" ;;
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


# =============================================================================
# FAILED LOGINS
# =============================================================================
check_failed_logins() {
    section_header "🔐 Failed Login Attempts (24h)"

    [[ -z "${_AUTH_LOG}" ]] && ok_box "$(badge INFO) No auth log available" && return

    local failures
    if command -v journalctl &>/dev/null; then
        failures=$(journalctl -u sshd --since "24 hours ago" 2>/dev/null | \
            grep "Failed password\|Invalid user\|authentication failure" || true)
    else
        failures=$(tail -5000 "${_AUTH_LOG}" 2>/dev/null | \
            grep "Failed password\|Invalid user\|authentication failure" || true)
    fi

    if [[ -z "${failures}" ]]; then
        ok_box "$(badge OK) No failed login attempts in last 24h"
        return
    fi

    local total_failures
    total_failures=$(echo "${failures}" | wc -l)

    # Top IPs
    local rows=()
    rows+=("$(gum style --bold --foreground 212 "$(printf '%-8s %-18s %s' 'COUNT' 'SOURCE IP' 'STATUS')")")
    rows+=("$(gum style --foreground 240 "$(printf '%-8s %-18s %s' '────────' '──────────────────' '──────')")")

    while IFS= read -r line; do
        local count ip
        count=$(echo "${line}" | awk '{print $1}')
        ip=$(echo "${line}" | awk '{print $2}')

        if [[ "${count}" -ge "${THRESHOLD_FAILED_LOGINS}" ]]; then
            rows+=("$(gum style --foreground 196 "$(printf '%-8s %-18s %s' "${count}" "${ip}" "⚠ BRUTE FORCE")")")
            emit_alert --severity CRITICAL --module "${MOD}" --event brute_force \
                --detail "Source IP ${ip} has ${count} failed login attempts (threshold: ${THRESHOLD_FAILED_LOGINS})" \
                --target "${ip}"
            _flag 2
        else
            rows+=("$(gum style --foreground 214 "$(printf '%-8s %-18s %s' "${count}" "${ip}" "REVIEW")")")
            _flag 1
        fi
    done < <(echo "${failures}" | grep -oP '(\d+\.){3}\d+' 2>/dev/null | sort | uniq -c | sort -rn | head -10)

    warn_box \
        "$(gum style --foreground 214 --bold "⚠  Total failed attempts: ${total_failures}")" \
        "" \
        "${rows[@]}"
}

# =============================================================================
# SUDO ACTIVITY
# =============================================================================
check_sudo_activity() {
    section_header "🔑 Sudo Activity (24h)"

    [[ -z "${_AUTH_LOG}" ]] && ok_box "$(badge INFO) No auth log available" && return

    local sudo_lines
    if command -v journalctl &>/dev/null; then
        sudo_lines=$(journalctl --since "24 hours ago" 2>/dev/null | grep "sudo:" || true)
    else
        sudo_lines=$(tail -5000 "${_AUTH_LOG}" 2>/dev/null | grep "sudo:" || true)
    fi

    if [[ -z "${sudo_lines}" ]]; then
        ok_box "$(badge OK) No sudo activity in last 24h"
        return
    fi

    local sudo_count
    sudo_count=$(echo "${sudo_lines}" | wc -l)

    local sudo_failures
    sudo_failures=$(echo "${sudo_lines}" | grep "incorrect password\|user NOT in sudoers" || true)
    local fail_count=0
    [[ -n "${sudo_failures}" ]] && fail_count=$(echo "${sudo_failures}" | wc -l)

    local box_color=82
    local status_badge
    if [[ "${fail_count}" -gt 0 ]]; then
        box_color=214
        status_badge=$(badge REVIEW)
        emit_alert --severity WARN --module "${MOD}" --event sudo_failure \
            --detail "${fail_count} failed sudo attempts in last 24h" --target "sudo"
        _flag 1
    else
        status_badge=$(badge OK)
    fi

    paste \
        <(gum style --border rounded --border-foreground "${box_color}" --width 33 --padding "0 1" \
            "$(gum style --foreground 212 --bold "Sudo Commands")" \
            "$(gum style --foreground 255 --bold "    ${sudo_count}")" \
            "${status_badge} in last 24h") \
        <(gum style --border rounded --border-foreground 196 --width 33 --padding "0 1" \
            "$(gum style --foreground 196 --bold "Failed Sudo")" \
            "$(gum style --foreground 255 --bold "    ${fail_count}")" \
            "$(badge $([ $fail_count -eq 0 ] && echo OK || echo ALERT)) attempts")
}

# =============================================================================
# NOUVEAUX COMPTES
# =============================================================================
check_new_accounts() {
    section_header "👥 User Accounts"

    local bl_users="${HIDS_DATA_DIR}/baseline/users.list"
    if [[ ! -f "${bl_users}" ]]; then
        info_box "$(badge INFO) No user baseline — skipping account diff"
        return
    fi

    local new_accounts
    new_accounts=$(awk -F: '{print $1":"$3}' /etc/passwd | \
        while IFS=: read -r uname uid; do
            grep -q "^${uname}:" "${bl_users}" 2>/dev/null || echo "${uname}:${uid}"
        done || true)

    # UID 0 check
    local uid0_count
    uid0_count=$(awk -F: '$3 == 0' /etc/passwd | wc -l)
    local uid0_users
    uid0_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | tr '\n' ' ')

    if [[ -z "${new_accounts}" && "${uid0_count}" -le 1 ]]; then
        ok_box \
            "$(badge OK) No new user accounts since baseline" \
            "$(badge OK) UID 0 account: ${uid0_users}(root only — expected)"
        return
    fi

    if [[ -n "${new_accounts}" ]]; then
        while IFS=: read -r uname uid; do
            local sev="WARN"
            [[ "${uid}" -eq 0 ]] && sev="CRITICAL"
            emit_alert --severity "${sev}" --module "${MOD}" --event new_account \
                --detail "User account created since baseline: ${uname} (uid=${uid})" \
                --target "${uname}"
            _flag 2
        done <<< "${new_accounts}"

        alert_box \
            "$(gum style --foreground 196 --bold "🚨 New accounts detected since baseline:")" \
            "" \
            "$(echo "${new_accounts}" | while IFS=: read -r u id; do
                echo "  $(badge ALERT) ${u} (uid=${id})"
            done)"
    fi

    if [[ "${uid0_count}" -gt 1 ]]; then
        alert_box \
            "$(gum style --foreground 196 --bold "🚨 Multiple UID 0 accounts: ${uid0_users}")"
        emit_alert --severity CRITICAL --module "${MOD}" --event uid0_duplicate \
            --detail "Multiple UID 0 accounts: ${uid0_users}" --target "/etc/passwd"
        _flag 2
    fi
}

# =============================================================================
# GROUPES SENSIBLES
# =============================================================================
check_group_membership() {
    section_header "🔒 Sensitive Group Membership"

    local bl_groups="${HIDS_DATA_DIR}/baseline/groups.list"
    if [[ ! -f "${bl_groups}" ]]; then
        info_box "$(badge INFO) No group baseline — skipping"
        return
    fi

    local rows=()
    rows+=("$(gum style --bold --foreground 212 "$(printf '%-12s %-30s %s' 'GROUP' 'MEMBERS' 'STATUS')")")
    rows+=("$(gum style --foreground 240 "$(printf '%-12s %-30s %s' '────────────' '──────────────────────────────' '──────')")")

    local has_changes=0
    IFS=',' read -ra sensitive_list <<< "${SENSITIVE_GROUPS}"
    for grp in "${sensitive_list[@]}"; do
        local current_members baseline_members new_members
        current_members=$(awk -F: -v g="${grp}" '$1==g {print $4}' /etc/group 2>/dev/null || echo "")
        baseline_members=$(awk -F: -v g="${grp}" '$1==g {print $3}' "${bl_groups}" 2>/dev/null || echo "")

        local current_sorted baseline_sorted
        current_sorted=$(echo "${current_members}" | tr ',' '\n' | sort)
        baseline_sorted=$(echo "${baseline_members}" | tr ',' '\n' | sort)
        new_members=$(comm -23 <(echo "${current_sorted}") <(echo "${baseline_sorted}") | tr '\n' ' ')

        if [[ -n "${new_members// /}" ]]; then
            rows+=("$(gum style --foreground 196 "$(printf '%-12s %-30s %s' "${grp}" "${new_members}" "⚠ CHANGED")")")
            emit_alert --severity CRITICAL --module "${MOD}" --event group_membership_change \
                --detail "New member(s) in group '${grp}': ${new_members}" --target "${grp}"
            _flag 2
            has_changes=1
        else
            rows+=("$(gum style --foreground 82 "$(printf '%-12s %-30s %s' "${grp}" "${current_members:-none}" "✓ unchanged")")")
        fi
    done

    local box_color=82
    [[ $has_changes -eq 1 ]] && box_color=196

    gum style \
        --border rounded --border-foreground "${box_color}" \
        --width 70 --padding "0 1" \
        "${rows[@]}"
}

# =============================================================================
# SSH AUTHORIZED KEYS
# =============================================================================
check_authorized_keys() {
    section_header "🗝️  SSH Authorized Keys"

    local modified_keys=0
    local bl_epoch=0

    [[ -f "${HIDS_DATA_DIR}/baseline/meta.conf" ]] && \
        bl_epoch=$(awk -F= '/BASELINE_EPOCH/{print $2}' \
            "${HIDS_DATA_DIR}/baseline/meta.conf" 2>/dev/null || echo 0)

    while IFS=: read -r uname _ uid _ _ home _; do
        local keyfile="${home}/.ssh/authorized_keys"
        [[ ! -f "${keyfile}" ]] && continue
        local file_mtime
        file_mtime=$(stat -c %Y "${keyfile}" 2>/dev/null || echo 0)
        if [[ "${file_mtime}" -gt "${bl_epoch}" ]]; then
            alert_box \
                "$(gum style --foreground 196 --bold "🚨 authorized_keys modified: ${keyfile}")" \
                "   User: ${uname} | Modified: $(date -d @${file_mtime} '+%Y-%m-%d %H:%M:%S')"
            emit_alert --severity CRITICAL --module "${MOD}" --event authorized_keys_modified \
                --detail "SSH authorized_keys modified since baseline: ${keyfile} (user: ${uname})" \
                --target "${keyfile}"
            _flag 2
            (( modified_keys++ )) || true
        fi
    done < /etc/passwd

    [[ "${modified_keys}" -eq 0 ]] && \
        ok_box "$(badge OK) No authorized_keys modifications detected"
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    # Header
    echo ""
    gum style \
        --foreground 212 --border-foreground 212 --border double \
        --align center --width 72 --padding "1 2" \
        "👤  HIDS — USER ACTIVITY MONITOR" \
        "Host: $(hostname) | $(date '+%Y-%m-%d %H:%M:%S')"

    check_current_sessions
    check_failed_logins
    check_sudo_activity
    check_new_accounts
    check_group_membership
    check_authorized_keys

    # Assessment
    echo ""
    local assess_color=82
    local assess_icon="✅"
    local assess_msg="All user activity checks passed"
    case "${_worst}" in
        1) assess_color=214; assess_icon="⚠️ "; assess_msg="Some user activity requires attention" ;;
        2) assess_color=196; assess_icon="🚨"; assess_msg="Critical user activity detected!" ;;
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

