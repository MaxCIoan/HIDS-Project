#!/usr/bin/env bash
# =============================================================================
# mod_integrity.sh — Module 4: File Integrity Monitor (GUM Edition)
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lib_utils.sh"
load_config

MOD="mod_integrity"
_worst=0
_flag() { [[ "$1" -gt "${_worst}" ]] && _worst="$1" || true; }

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
    gum style --border rounded --border-foreground "${color}" --width 21 --padding "0 1" \
        "$(gum style --foreground "${color}" --bold "${title}")" \
        "$(gum style --foreground 255 --bold "  ${count}")" \
        "$(badge "${status}") ${msg}"
}

# =============================================================================
# FILE HASH INTEGRITY
# =============================================================================
check_file_hashes() {
    section_header "🔒 File Hash Integrity"

    local bl_hashes="${HIDS_DATA_DIR}/baseline/file_hashes.db"
    if [[ ! -f "${bl_hashes}" ]]; then
        info_box "$(badge INFO) No file hash baseline — run: baseline.sh --init"
        return
    fi

    local modified=0 missing=0 new_files=0
    local current_tmp
    current_tmp=$(mktemp)

    for f in ${INTEGRITY_WATCH}; do
        [[ -f "${f}" ]] && sha256sum "${f}" 2>/dev/null >> "${current_tmp}" || true
    done
    for d in ${INTEGRITY_WATCH_DIRS}; do
        [[ -d "${d}" ]] || continue
        find "${d}" -maxdepth "${INTEGRITY_DEPTH}" -type f 2>/dev/null | \
            while read -r file; do sha256sum "${file}" 2>/dev/null || true; done >> "${current_tmp}"
    done
    sort "${current_tmp}" -o "${current_tmp}"

    local modified_rows=()
    local missing_rows=()
    local new_rows=()

    while IFS=' ' read -r bl_hash bl_path; do
        bl_path="${bl_path# }"
        local cur_hash
        cur_hash=$(grep " ${bl_path}$" "${current_tmp}" 2>/dev/null | awk '{print $1}' || echo "")
        if [[ -z "${cur_hash}" ]]; then
            if [[ ! -f "${bl_path}" ]]; then
                missing_rows+=("  $(badge REVIEW) DELETED: ${bl_path}")
                emit_alert --severity WARN --module "${MOD}" --event file_deleted \
                    --detail "Watched file deleted since baseline: ${bl_path}" --target "${bl_path}"
                _flag 1; (( missing++ )) || true
            fi
        elif [[ "${cur_hash}" != "${bl_hash}" ]]; then
            modified_rows+=("  $(badge ALERT) MODIFIED: ${bl_path}")
            modified_rows+=("    was: ${bl_hash:0:32}…")
            modified_rows+=("    now: ${cur_hash:0:32}…")
            emit_alert --severity CRITICAL --module "${MOD}" --event hash_mismatch \
                --detail "File modified since baseline: ${bl_path} | was: ${bl_hash:0:16}… now: ${cur_hash:0:16}…" \
                --target "${bl_path}"
            _flag 2; (( modified++ )) || true
        fi
    done < "${bl_hashes}"

    while IFS=' ' read -r cur_hash cur_path; do
        cur_path="${cur_path# }"
        if ! grep -q " ${cur_path}$" "${bl_hashes}" 2>/dev/null; then
            new_rows+=("  $(badge REVIEW) NEW: ${cur_path}")
            emit_alert --severity WARN --module "${MOD}" --event new_watched_file \
                --detail "New file appeared in watched directory since baseline: ${cur_path}" \
                --target "${cur_path}"
            _flag 1; (( new_files++ )) || true
        fi
    done < "${current_tmp}"

    rm -f "${current_tmp}"

    echo ""
    paste \
        <(counter_box "Modified 🔴" "${modified}"  "$([ $modified  -eq 0 ] && echo OK || echo ALERT)"  "hash mismatches") \
        <(counter_box "Deleted 🟡"  "${missing}"   "$([ $missing   -eq 0 ] && echo OK || echo REVIEW)" "since baseline") \
        <(counter_box "New 🟡"      "${new_files}" "$([ $new_files -eq 0 ] && echo OK || echo REVIEW)" "since baseline") 2>/dev/null || true
    echo ""

    [[ "${modified}"  -gt 0 ]] && alert_box \
        "$(gum style --foreground 196 --bold "🚨 Hash mismatches:")" "" "${modified_rows[@]}"
    [[ "${missing}"   -gt 0 ]] && warn_box \
        "$(gum style --foreground 214 --bold "⚠  Deleted files:")" "" "${missing_rows[@]}"
    [[ "${new_files}" -gt 0 ]] && warn_box \
        "$(gum style --foreground 214 --bold "⚠  New files:")" "" "${new_rows[@]}"

    if [[ "${modified}" -eq 0 && "${missing}" -eq 0 && "${new_files}" -eq 0 ]]; then
        ok_box "$(badge OK) All watched files match baseline hashes"
    fi
}

# =============================================================================
# SUID / SGID BINARY AUDIT
# =============================================================================
check_suid_binaries() {
    section_header "⚡ SUID/SGID Binary Audit"

    local bl_suid="${HIDS_DATA_DIR}/baseline/suid_binaries.list"
    local exclude_args=()
    for excl in ${SUID_SCAN_EXCLUDE}; do
        exclude_args+=(-path "${excl}" -prune -o)
    done

    local current_suid
    current_suid=$(mktemp)
    find ${SUID_SCAN_PATHS} "${exclude_args[@]}" -perm /6000 -type f -print 2>/dev/null | \
        sort > "${current_suid}"

    local total_suid
    total_suid=$(wc -l < "${current_suid}")

    if [[ ! -f "${bl_suid}" ]]; then
        info_box "$(badge INFO) No SUID baseline — ${total_suid} binaries found"
        rm -f "${current_suid}"
        return
    fi

    local new_suid
    new_suid=$(comm -23 "${current_suid}" "${bl_suid}" 2>/dev/null || true)
    local new_count=0
    local alert_rows=()

    if [[ -n "${new_suid}" ]]; then
        while IFS= read -r bin; do
            [[ -z "${bin}" ]] && continue
            if [[ -f "${WHITELIST_SUID_FILE}" ]] && grep -qxF "${bin}" "${WHITELIST_SUID_FILE}" 2>/dev/null; then
                continue
            fi
            local perm
            perm=$(stat -c "%A %U %G" "${bin}" 2>/dev/null || echo "unknown")
            alert_rows+=("  $(badge ALERT) ${bin} (${perm})")
            emit_alert --severity CRITICAL --module "${MOD}" --event new_suid_binary \
                --detail "New SUID/SGID binary since baseline: ${bin} (${perm})" --target "${bin}"
            _flag 2; (( new_count++ )) || true
        done <<< "${new_suid}"
    fi

    rm -f "${current_suid}"

    echo ""
    paste \
        <(counter_box "Total SUID ⚡" "${total_suid}" "OK"    "binaries found") \
        <(counter_box "New 🚨"        "${new_count}"  "$([ $new_count -eq 0 ] && echo OK || echo ALERT)" "new binaries") 2>/dev/null || true
    echo ""

    if [[ "${new_count}" -gt 0 ]]; then
        alert_box "$(gum style --foreground 196 --bold "🚨 New SUID/SGID binaries:")" "" "${alert_rows[@]}"
    else
        ok_box "$(badge OK) SUID/SGID inventory matches baseline"
    fi
}

# =============================================================================
# WORLD-WRITABLE FILES
# =============================================================================
check_world_writable() {
    section_header "🌍 World-Writable Files in Critical Directories"

    local found=0
    local alert_rows=()

    for dir in ${WORLD_WRITABLE_SCAN}; do
        [[ -d "${dir}" ]] || continue
        while IFS= read -r file; do
            local perm owner
            perm=$(stat -c "%A" "${file}" 2>/dev/null || echo "?")
            owner=$(stat -c "%U:%G" "${file}" 2>/dev/null || echo "?")
            alert_rows+=("  $(badge ALERT) ${file} (${perm} ${owner})")
            emit_alert --severity CRITICAL --module "${MOD}" --event world_writable_file \
                --detail "World-writable file: ${file} | perm=${perm} owner=${owner}" \
                --target "${file}"
            _flag 2; (( found++ )) || true
        done < <(find "${dir}" -maxdepth 3 -type f -perm -o+w 2>/dev/null)
    done

    if [[ "${found}" -gt 0 ]]; then
        alert_box "$(gum style --foreground 196 --bold "🚨 World-writable files:")" "" "${alert_rows[@]}"
    else
        ok_box "$(badge OK) No world-writable files in critical directories"
    fi
}

# =============================================================================
# EXECUTABLES IN /tmp
# =============================================================================
check_executables_in_tmp() {
    section_header "🎯 Executables in World-Writable Paths"

    local found=0
    local alert_rows=()

    for dir in /tmp /var/tmp /dev/shm /run/shm; do
        [[ -d "${dir}" ]] || continue
        while IFS= read -r file; do
            local perm owner
            perm=$(stat -c "%A" "${file}" 2>/dev/null || echo "?")
            owner=$(stat -c "%U" "${file}" 2>/dev/null || echo "?")
            alert_rows+=("  $(badge ALERT) ${file} (owner=${owner} perm=${perm})")
            emit_alert --severity CRITICAL --module "${MOD}" --event executable_in_tmp \
                --detail "Executable in world-writable dir: ${file} | owner=${owner}" \
                --target "${file}"
            _flag 2; (( found++ )) || true
        done < <(find "${dir}" -maxdepth 5 -type f -executable 2>/dev/null)
    done

    if [[ "${found}" -gt 0 ]]; then
        alert_box "$(gum style --foreground 196 --bold "🚨 Executables in world-writable paths:")" "" "${alert_rows[@]}"
    else
        ok_box "$(badge OK) No executables found in /tmp, /var/tmp, /dev/shm"
    fi
}

# =============================================================================
# CRONTAB INTEGRITY
# =============================================================================
check_crontabs() {
    section_header "⏰ Crontab Integrity"

    local bl_crons="${HIDS_DATA_DIR}/baseline/crontabs.db"
    if [[ ! -f "${bl_crons}" ]]; then
        info_box "$(badge INFO) No crontab baseline — skipping"
        return
    fi

    local current_crons
    current_crons=$(mktemp)
    for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
        [[ -f "${f}" ]] && sha256sum "${f}" 2>/dev/null >> "${current_crons}" || true
    done
    sort "${current_crons}" -o "${current_crons}"

    local modified=0
    local alert_rows=()
    local new_rows=()

    while IFS=' ' read -r bl_hash bl_path; do
        bl_path="${bl_path# }"
        local cur_hash
        cur_hash=$(grep " ${bl_path}$" "${current_crons}" 2>/dev/null | awk '{print $1}' || echo "")
        if [[ -n "${cur_hash}" && "${cur_hash}" != "${bl_hash}" ]]; then
            alert_rows+=("  $(badge ALERT) MODIFIED: ${bl_path}")
            emit_alert --severity CRITICAL --module "${MOD}" --event crontab_modified \
                --detail "Crontab modified since baseline: ${bl_path}" --target "${bl_path}"
            _flag 2; (( modified++ )) || true
        fi
    done < "${bl_crons}"

    while IFS=' ' read -r cur_hash cur_path; do
        cur_path="${cur_path# }"
        if ! grep -q " ${cur_path}$" "${bl_crons}" 2>/dev/null; then
            new_rows+=("  $(badge REVIEW) NEW: ${cur_path}")
            emit_alert --severity WARN --module "${MOD}" --event new_crontab \
                --detail "New crontab entry since baseline: ${cur_path}" --target "${cur_path}"
            _flag 1
        fi
    done < "${current_crons}"

    rm -f "${current_crons}"

    if [[ "${modified}" -gt 0 ]]; then
        alert_box "$(gum style --foreground 196 --bold "🚨 Crontab modifications:")" "" "${alert_rows[@]}"
    elif [[ "${#new_rows[@]}" -gt 0 ]]; then
        warn_box "$(gum style --foreground 214 --bold "⚠  New crontab entries:")" "" "${new_rows[@]}"
    else
        ok_box "$(badge OK) All crontabs match baseline"
    fi
}

# =============================================================================
# RECENT MODIFICATIONS
# =============================================================================
check_recent_modifications() {
    section_header "🕐 Recent File Modifications (last ${INTEGRITY_RECENT_MINUTES}min)"

    [[ "${INTEGRITY_RECENT_MINUTES}" -eq 0 ]] && \
        info_box "$(badge INFO) Recent modification check disabled" && return

    local found=0
    local warn_rows=()

    for dir in /etc /bin /sbin /usr/bin /usr/sbin /usr/local/bin /root; do
        [[ -d "${dir}" ]] || continue
        while IFS= read -r file; do
            local mtime
            mtime=$(stat -c "%y" "${file}" 2>/dev/null | cut -d. -f1 || echo "?")
            warn_rows+=("  $(badge REVIEW) ${file}  →  ${mtime}")
            emit_alert --severity WARN --module "${MOD}" --event recent_modification \
                --detail "Critical file modified in last ${INTEGRITY_RECENT_MINUTES}min: ${file} (at ${mtime})" \
                --target "${file}"
            _flag 1; (( found++ )) || true
        done < <(find "${dir}" -maxdepth 2 -type f -mmin "-${INTEGRITY_RECENT_MINUTES}" 2>/dev/null)
    done

    if [[ "${found}" -gt 0 ]]; then
        warn_box \
            "$(gum style --foreground 214 --bold "⚠  ${found} file(s) recently modified:")" \
            "" "${warn_rows[@]}"
    else
        ok_box "$(badge OK) No recent modifications in critical directories"
    fi
}

# =============================================================================
# LD_PRELOAD DETECTION
# =============================================================================
check_ld_preload() {
    section_header "🔍 LD_PRELOAD / Library Injection"

    local ld_preload_procs=0
    local alert_rows=()

    if [[ -f /etc/ld.so.preload ]]; then
        local content
        content=$(cat /etc/ld.so.preload 2>/dev/null || echo "")
        if [[ -n "${content}" ]]; then
            alert_box \
                "$(gum style --foreground 196 --bold "🚨 Non-empty /etc/ld.so.preload detected!")" \
                "   Content: ${content:0:100}"
            emit_alert --severity CRITICAL --module "${MOD}" --event ld_preload_set \
                --detail "/etc/ld.so.preload non-empty — possible rootkit: ${content:0:200}" \
                --target "/etc/ld.so.preload"
            _flag 2
        fi
    fi

    for pid_dir in /proc/[0-9]*/; do
        local pid
        pid=$(basename "${pid_dir}")
        local environ
        environ=$(cat "${pid_dir}environ" 2>/dev/null | tr '\0' '\n' | grep '^LD_PRELOAD' || echo "")
        if [[ -n "${environ}" ]]; then
            local pname
            pname=$(awk '/^Name:/{print $2}' "${pid_dir}status" 2>/dev/null || echo "unknown")
            if echo "${pname}" | grep -qE "^(snapd|snap-confine|snapd-desktop)"; then
                continue
            fi
            alert_rows+=("  $(badge ALERT) pid=${pid} name=${pname}")
            alert_rows+=("    ${environ}")
            emit_alert --severity CRITICAL --module "${MOD}" --event ld_preload_env \
                --detail "Process has LD_PRELOAD: ${pname} (pid=${pid}) — ${environ}" \
                --target "${pname}" --pid "${pid}"
            _flag 2; (( ld_preload_procs++ )) || true
        fi
    done

    if [[ "${ld_preload_procs}" -gt 0 ]]; then
        alert_box \
            "$(gum style --foreground 196 --bold "🚨 Processes with LD_PRELOAD:")" \
            "" "${alert_rows[@]}"
    else
        ok_box \
            "$(badge OK) /etc/ld.so.preload does not exist (expected)" \
            "$(badge OK) No LD_PRELOAD in process environments"
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
        "🔒  HIDS — FILE INTEGRITY MONITOR" \
        "Host: $(hostname) | $(date '+%Y-%m-%d %H:%M:%S')"

    check_file_hashes
    check_suid_binaries
    check_world_writable
    check_executables_in_tmp
    check_crontabs
    check_recent_modifications
    check_ld_preload

    echo ""
    local assess_color=82
    local assess_icon="✅"
    local assess_msg="All file integrity checks passed"
    case "${_worst}" in
        1) assess_color=214; assess_icon="⚠️ "; assess_msg="Some integrity items require attention" ;;
        2) assess_color=196; assess_icon="🚨"; assess_msg="Critical integrity violations detected!" ;;
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
