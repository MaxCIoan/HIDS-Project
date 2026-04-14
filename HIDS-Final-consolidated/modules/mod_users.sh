#!/usr/bin/env bash
# =============================================================================
# mod_users.sh — Module 2: User Activity Monitor
# =============================================================================
# Inspects current sessions, login history, failed auth attempts, sudo usage,
# account modifications, and sensitive group membership changes.
#
# Data sources:
#   /var/log/auth.log (Debian) or /var/log/secure (RHEL)
#   /var/log/wtmp  → last(1)
#   /var/log/btmp  → lastb(1)
#   /var/log/lastlog → lastlog(1)
#   /etc/passwd, /etc/group, /etc/sudoers
#   /proc/[pid]/loginuid
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lib_utils.sh"
load_config

MOD="mod_users"
_worst=0
_flag() { [[ "$1" -gt "${_worst}" ]] && _worst="$1" || true; }

# Detect the auth log path (Debian vs RHEL layout)
_AUTH_LOG=""
for _candidate in /var/log/auth.log /var/log/secure; do
    [[ -r "${_candidate}" ]] && _AUTH_LOG="${_candidate}" && break
done

# =============================================================================
# CURRENT SESSIONS
# =============================================================================

check_current_sessions() {
    # Lists all currently logged-in users via who(1).
    # Flags logins from sources outside TRUSTED_SSH_SOURCES.
    local session_count
    session_count=$(who 2>/dev/null | wc -l)
    report_line "Active sessions: ${session_count}"

    if [[ "${session_count}" -eq 0 ]]; then
        print_ok "No active sessions"
        return
    fi

    print_info "Active sessions:"
    who 2>/dev/null | while read -r user tty login_time host; do
        print_info "  ${user} via ${tty} from ${host:-local} (since ${login_time})"

        # Check against trusted sources list if configured
        if [[ -n "${TRUSTED_SSH_SOURCES}" && -n "${host}" ]]; then
            local trusted=0
            IFS=',' read -ra trusted_list <<< "${TRUSTED_SSH_SOURCES}"
            for src in "${trusted_list[@]}"; do
                [[ "${host}" == *"${src}"* ]] && trusted=1 && break
            done
            if [[ "${trusted}" -eq 0 ]]; then
                emit_alert --severity WARN --module "${MOD}" --event untrusted_session \
                    --detail "Active session from untrusted source: ${user}@${host}" \
                    --target "${user}"
                _flag 1
            fi
        fi
    done

    # Check if any root sessions are active via SSH (should be forbidden)
    if who | grep -q '^root .* (.*\..*\..*\..*)'; then
        emit_alert --severity CRITICAL --module "${MOD}" --event root_ssh_session \
            --detail "Root user has an active remote SSH session" --target "root"
        _flag 2
    fi
}

# =============================================================================
# OFF-HOURS LOGIN DETECTION
# =============================================================================

check_off_hours_logins() {
    # Reads recent logins from wtmp via last(1) and flags logins during
    # configured OFF_HOURS. Only checks logins from the last 24 hours.
    [[ -z "${OFF_HOURS}" ]] && return

    if ! command -v last &>/dev/null; then
        print_info "last not available — skipping off-hours login history check"
        report_line "Off-hours login history: skipped (last unavailable)"
        return
    fi

    IFS=',' read -ra off_hours_list <<< "${OFF_HOURS}"

    last -F -w 2>/dev/null | grep -v '^reboot\|^wtmp\|^ ' | \
    while read -r user tty host dow mon day time year rest; do
        # Extract the hour from the time field (HH:MM:SS)
        local hour="${time%%:*}"
        hour=$(( 10#${hour} ))  # Force base-10 interpretation

        for oh in "${off_hours_list[@]}"; do
            if [[ "${hour}" -eq "${oh}" ]]; then
                emit_alert --severity WARN --module "${MOD}" --event off_hours_login \
                    --detail "Login during off-hours (hour ${hour}): ${user} from ${host:-local}" \
                    --target "${user}"
                _flag 1
                break
            fi
        done
    done | head -50  # Cap to recent logins to avoid flooding on first run
}

# =============================================================================
# FAILED LOGIN ATTEMPTS (BRUTE FORCE DETECTION)
# =============================================================================

check_failed_logins() {
    # Parses the auth log for recent SSH authentication failures.
    # Groups by source IP and alerts when a single IP exceeds the threshold.
    [[ -z "${_AUTH_LOG}" ]] && return

    # Look at failures from the last 24 hours only — use journalctl if available
    local failures
    if command -v journalctl &>/dev/null; then
        failures=$(journalctl -u sshd --since "24 hours ago" 2>/dev/null | \
            grep "Failed password\|Invalid user\|authentication failure" || true)
    else
        # Fall back to auth log — read last 5000 lines for recency
        failures=$(tail -5000 "${_AUTH_LOG}" 2>/dev/null | \
            grep "Failed password\|Invalid user\|authentication failure" || true)
    fi

    [[ -z "${failures}" ]] && print_ok "No failed login attempts in last 24h" && return

    local total_failures
    total_failures=$(echo "${failures}" | wc -l)
    report_line "Failed logins (24h): ${total_failures}"

    # Group by source IP, alert on sources exceeding the threshold
    echo "${failures}" | grep -oP '(\d+\.){3}\d+' 2>/dev/null | sort | uniq -c | sort -rn | \
    while read -r count ip; do
        if [[ "${count}" -ge "${THRESHOLD_FAILED_LOGINS}" ]]; then
            print_critical "Brute force candidate: ${ip} — ${count} failed attempts"
            emit_alert --severity CRITICAL --module "${MOD}" --event brute_force \
                --detail "Source IP ${ip} has ${count} failed login attempts in 24h (threshold: ${THRESHOLD_FAILED_LOGINS})" \
                --target "${ip}"
            _flag 2
        fi
    done

    print_info "Total failed login attempts (24h): ${total_failures}"
}

# =============================================================================
# SUDO ACTIVITY
# =============================================================================

check_sudo_activity() {
    # Parses the auth log for sudo commands executed in the last 24 hours.
    # Lists all sudo activity. Flags any sudo run as root from unexpected users.
    [[ -z "${_AUTH_LOG}" ]] && return

    local sudo_lines
    if command -v journalctl &>/dev/null; then
        sudo_lines=$(journalctl --since "24 hours ago" 2>/dev/null | grep "sudo:" || true)
    else
        sudo_lines=$(tail -5000 "${_AUTH_LOG}" 2>/dev/null | grep "sudo:" || true)
    fi

    if [[ -z "${sudo_lines}" ]]; then
        print_ok "No sudo activity in last 24h"
        report_line "Sudo activity: none in last 24h"
        return
    fi

    local sudo_count
    sudo_count=$(echo "${sudo_lines}" | wc -l)
    report_line "Sudo activity (24h): ${sudo_count} commands"
    print_info "Sudo commands in last 24h: ${sudo_count}"

    # Highlight failed sudo attempts (could indicate privilege escalation probing)
    local sudo_failures
    sudo_failures=$(echo "${sudo_lines}" | grep "incorrect password\|user NOT in sudoers" || true)
    if [[ -n "${sudo_failures}" ]]; then
        local fail_count
        fail_count=$(echo "${sudo_failures}" | wc -l)
        print_warn "Failed sudo attempts: ${fail_count}"
        emit_alert --severity WARN --module "${MOD}" --event sudo_failure \
            --detail "${fail_count} failed sudo attempts in last 24h" --target "sudo"
        _flag 1
    fi
}

# =============================================================================
# NEW USER ACCOUNTS
# =============================================================================

check_new_accounts() {
    # Compares current /etc/passwd against the baseline user list.
    # Any new account — especially UID 0 duplicates — triggers an alert.
    local bl_users="${HIDS_DATA_DIR}/baseline/users.list"
    [[ ! -f "${bl_users}" ]] && print_info "No user baseline — skipping account diff" && return

    local new_accounts
    new_accounts=$(awk -F: '{print $1":"$3}' /etc/passwd | \
        while IFS=: read -r uname uid; do
            grep -q "^${uname}:" "${bl_users}" 2>/dev/null || echo "${uname}:${uid}"
        done || true)

    if [[ -z "${new_accounts}" ]]; then
        print_ok "No new user accounts since baseline"
    else
        while IFS=: read -r uname uid; do
            local sev="WARN"
            [[ "${uid}" -eq 0 ]] && sev="CRITICAL"
            print_critical "New user account: ${uname} (uid=${uid})"
            emit_alert --severity "${sev}" --module "${MOD}" --event new_account \
                --detail "User account created since baseline: ${uname} (uid=${uid})" \
                --target "${uname}"
            _flag 2
        done <<< "${new_accounts}"
    fi

    # Check for UID 0 duplicates — a common attacker persistence technique
    local uid0_users
    uid0_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | tr '\n' ' ')
    local uid0_count
    uid0_count=$(awk -F: '$3 == 0' /etc/passwd | wc -l)
    if [[ "${uid0_count}" -gt 1 ]]; then
        print_critical "Multiple UID 0 accounts: ${uid0_users}"
        emit_alert --severity CRITICAL --module "${MOD}" --event uid0_duplicate \
            --detail "Multiple UID 0 accounts found: ${uid0_users}" --target "/etc/passwd"
        _flag 2
    fi
}

# =============================================================================
# SENSITIVE GROUP MEMBERSHIP CHANGES
# =============================================================================

check_group_membership() {
    # Compares current group membership for SENSITIVE_GROUPS against the baseline.
    # Any new member of sudo/wheel/docker/etc. triggers a CRITICAL alert.
    local bl_groups="${HIDS_DATA_DIR}/baseline/groups.list"
    [[ ! -f "${bl_groups}" ]] && print_info "No group baseline — skipping group diff" && return

    IFS=',' read -ra sensitive_list <<< "${SENSITIVE_GROUPS}"
    for grp in "${sensitive_list[@]}"; do
        # Get current members from /etc/group (4th field, comma-separated)
        local current_members
        current_members=$(awk -F: -v g="${grp}" '$1==g {print $4}' /etc/group 2>/dev/null || echo "")
        local baseline_members
        baseline_members=$(awk -F: -v g="${grp}" '$1==g {print $3}' "${bl_groups}" 2>/dev/null || echo "")

        # Compare the member lists as sorted sets
        local current_sorted baseline_sorted
        current_sorted=$(echo "${current_members}" | tr ',' '\n' | sort)
        baseline_sorted=$(echo "${baseline_members}" | tr ',' '\n' | sort)

        local new_members
        new_members=$(comm -23 <(echo "${current_sorted}") <(echo "${baseline_sorted}") | tr '\n' ' ')

        if [[ -n "${new_members// /}" ]]; then
            print_critical "New member(s) in group '${grp}': ${new_members}"
            emit_alert --severity CRITICAL --module "${MOD}" --event group_membership_change \
                --detail "New member(s) added to sensitive group '${grp}': ${new_members}" \
                --target "${grp}"
            _flag 2
        else
            print_ok "Group '${grp}': membership unchanged"
        fi
    done
}

# =============================================================================
# SSH AUTHORIZED KEYS CHANGES
# =============================================================================

check_authorized_keys() {
    # Checks all .ssh/authorized_keys files for changes since the baseline.
    # A new or modified authorized_keys file is a persistence mechanism.
    local modified_keys=0

    # Check root and all users with a home directory
    while IFS=: read -r uname _ uid _ _ home _; do
        local keyfile="${home}/.ssh/authorized_keys"
        [[ ! -f "${keyfile}" ]] && continue

        # Check mtime — flag if modified more recently than the baseline epoch
        if [[ -f "${HIDS_DATA_DIR}/baseline/meta.conf" ]]; then
            local bl_epoch
            bl_epoch=$(awk -F= '/BASELINE_EPOCH/{print $2}' "${HIDS_DATA_DIR}/baseline/meta.conf" 2>/dev/null || echo 0)
            local file_mtime
            file_mtime=$(stat -c %Y "${keyfile}" 2>/dev/null || echo 0)
            if [[ "${file_mtime}" -gt "${bl_epoch}" ]]; then
                print_critical "authorized_keys modified since baseline: ${keyfile}"
                emit_alert --severity CRITICAL --module "${MOD}" --event authorized_keys_modified \
                    --detail "SSH authorized_keys modified since baseline: ${keyfile} (user: ${uname})" \
                    --target "${keyfile}"
                _flag 2
                (( modified_keys++ )) || true
            fi
        fi
    done < /etc/passwd

    [[ "${modified_keys}" -eq 0 ]] && print_ok "No authorized_keys modifications detected"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    print_section_header "User Activity" "👤"

    check_current_sessions
    check_off_hours_logins
    check_failed_logins
    check_sudo_activity
    check_new_accounts
    check_group_membership
    check_authorized_keys

    return "${_worst}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    load_config
    main
    exit "${_worst}"
fi
