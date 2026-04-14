#!/usr/bin/env bash
# =============================================================================
# mod_integrity.sh — Module 4: File Integrity Monitor
# =============================================================================
# Detects file modifications, dangerous permissions, and attacker persistence
# mechanisms by comparing current filesystem state against the baseline.
#
# Checks:
#   - SHA256 hash comparison of all watched files against baseline
#   - SUID/SGID binary inventory diff against baseline and whitelist
#   - World-writable files in critical directories
#   - Executables in world-writable paths (/tmp, /dev/shm, etc.)
#   - Crontab modifications
#   - Recent modifications to critical files (recency check)
#   - LD_PRELOAD / /etc/ld.so.preload (library injection vector)
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
# FILE HASH INTEGRITY
# =============================================================================

check_file_hashes() {
    # Recomputes SHA256 hashes for all watched files and compares against
    # the baseline database. Any mismatch is a CRITICAL finding.
    local bl_hashes="${HIDS_DATA_DIR}/baseline/file_hashes.db"

    if [[ ! -f "${bl_hashes}" ]]; then
        print_info "No file hash baseline — run: baseline.sh --init"
        return
    fi

    print_info "Verifying file integrity..."
    local modified=0 missing=0 new_files=0

    # Build current hash set
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

    # Compare: for each baseline entry, check current state
    while IFS=' ' read -r bl_hash bl_path; do
        bl_path="${bl_path# }"  # strip leading space from sha256sum output
        local cur_hash
        cur_hash=$(grep " ${bl_path}$" "${current_tmp}" 2>/dev/null | awk '{print $1}' || echo "")

        if [[ -z "${cur_hash}" ]]; then
            if [[ ! -f "${bl_path}" ]]; then
                print_warn "File deleted since baseline: ${bl_path}"
                emit_alert --severity WARN --module "${MOD}" --event file_deleted \
                    --detail "Watched file deleted since baseline: ${bl_path}" --target "${bl_path}"
                _flag 1; (( missing++ )) || true
            fi
        elif [[ "${cur_hash}" != "${bl_hash}" ]]; then
            print_critical "Hash mismatch: ${bl_path}"
            print_info "  Expected: ${bl_hash}"
            print_info "  Current:  ${cur_hash}"
            emit_alert --severity CRITICAL --module "${MOD}" --event hash_mismatch \
                --detail "File modified since baseline: ${bl_path} | was: ${bl_hash:0:16}… now: ${cur_hash:0:16}…" \
                --target "${bl_path}"
            _flag 2; (( modified++ )) || true
        fi
    done < "${bl_hashes}"

    # Detect new files not in the baseline
    while IFS=' ' read -r cur_hash cur_path; do
        cur_path="${cur_path# }"
        if ! grep -q " ${cur_path}$" "${bl_hashes}" 2>/dev/null; then
            print_warn "New file in watched directory: ${cur_path}"
            emit_alert --severity WARN --module "${MOD}" --event new_watched_file \
                --detail "New file appeared in watched directory since baseline: ${cur_path}" \
                --target "${cur_path}"
            _flag 1; (( new_files++ )) || true
        fi
    done < "${current_tmp}"

    rm -f "${current_tmp}"

    if [[ "${modified}" -eq 0 && "${missing}" -eq 0 && "${new_files}" -eq 0 ]]; then
        print_ok "All watched files match baseline hashes"
    fi
    report_line "File integrity: ${modified} modified, ${missing} deleted, ${new_files} new"
}

# =============================================================================
# SUID / SGID BINARY AUDIT
# =============================================================================

check_suid_binaries() {
    # Finds all SUID/SGID binaries on the system. Cross-references against:
    #   1. The baseline SUID list (changes = suspicious)
    #   2. The whitelist file (known-good binaries to suppress)
    print_info "Scanning for SUID/SGID binaries..."

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
    report_line "SUID/SGID binaries: ${total_suid} total"

    if [[ ! -f "${bl_suid}" ]]; then
        print_info "No SUID baseline — displaying current inventory:"
        while IFS= read -r bin; do
            print_info "  ${bin}"
        done < "${current_suid}"
        rm -f "${current_suid}"
        return
    fi

    # New SUID binaries not in the baseline
    local new_suid
    new_suid=$(comm -23 "${current_suid}" "${bl_suid}" 2>/dev/null || true)
    local new_count=0

    if [[ -n "${new_suid}" ]]; then
        while IFS= read -r bin; do
            [[ -z "${bin}" ]] && continue
            # Check whitelist
            if [[ -f "${WHITELIST_SUID_FILE}" ]] && grep -qxF "${bin}" "${WHITELIST_SUID_FILE}" 2>/dev/null; then
                continue
            fi
            print_critical "New SUID binary: ${bin}"
            local perm
            perm=$(stat -c "%A %U %G" "${bin}" 2>/dev/null || echo "unknown")
            emit_alert --severity CRITICAL --module "${MOD}" --event new_suid_binary \
                --detail "New SUID/SGID binary since baseline: ${bin} (${perm})" --target "${bin}"
            _flag 2; (( new_count++ )) || true
        done <<< "${new_suid}"
    fi

    [[ "${new_count}" -eq 0 ]] && print_ok "SUID/SGID inventory matches baseline"

    rm -f "${current_suid}"
}

# =============================================================================
# WORLD-WRITABLE FILES IN CRITICAL DIRECTORIES
# =============================================================================

check_world_writable() {
    # Scans WORLD_WRITABLE_SCAN directories for world-writable files.
    # World-writable files in system directories are dangerous by definition.
    print_info "Scanning for world-writable files in critical directories..."
    local found=0

    for dir in ${WORLD_WRITABLE_SCAN}; do
        [[ -d "${dir}" ]] || continue
        find "${dir}" -maxdepth 3 -type f -perm -o+w 2>/dev/null | \
        while IFS= read -r file; do
            local perm owner
            perm=$(stat -c "%A" "${file}" 2>/dev/null || echo "?")
            owner=$(stat -c "%U:%G" "${file}" 2>/dev/null || echo "?")
            print_critical "World-writable file: ${file} (${perm} ${owner})"
            emit_alert --severity CRITICAL --module "${MOD}" --event world_writable_file \
                --detail "World-writable file in critical directory: ${file} | perm=${perm} owner=${owner}" \
                --target "${file}"
            _flag 2; (( found++ )) || true
        done
    done

    [[ "${found}" -eq 0 ]] && print_ok "No world-writable files in critical directories"
    report_line "World-writable files in critical dirs: ${found}"
}

# =============================================================================
# EXECUTABLES IN WORLD-WRITABLE PATHS (STAGED MALWARE)
# =============================================================================

check_executables_in_tmp() {
    # Detects executable files in world-writable directories like /tmp and /dev/shm.
    # Legitimate services do not place executables there; malware frequently does.
    local found=0

    for dir in /tmp /var/tmp /dev/shm /run/shm; do
        [[ -d "${dir}" ]] || continue
        find "${dir}" -maxdepth 5 -type f -executable 2>/dev/null | \
        while IFS= read -r file; do
            local perm owner
            perm=$(stat -c "%A" "${file}" 2>/dev/null || echo "?")
            owner=$(stat -c "%U" "${file}" 2>/dev/null || echo "?")
            print_critical "Executable in world-writable path: ${file}"
            emit_alert --severity CRITICAL --module "${MOD}" --event executable_in_tmp \
                --detail "Executable file in world-writable directory: ${file} | owner=${owner} perm=${perm}" \
                --target "${file}"
            _flag 2; (( found++ )) || true
        done
    done

    [[ "${found}" -eq 0 ]] && print_ok "No executables found in /tmp, /var/tmp, /dev/shm"
    report_line "Executables in world-writable paths: ${found}"
}

# =============================================================================
# CRONTAB INTEGRITY
# =============================================================================

check_crontabs() {
    # Compares SHA256 hashes of all system and user crontabs against baseline.
    # Unexpected cron changes are a classic attacker persistence technique.
    local bl_crons="${HIDS_DATA_DIR}/baseline/crontabs.db"

    if [[ ! -f "${bl_crons}" ]]; then
        print_info "No crontab baseline — skipping"
        return
    fi

    local current_crons
    current_crons=$(mktemp)
    for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
        [[ -f "${f}" ]] && sha256sum "${f}" 2>/dev/null >> "${current_crons}" || true
    done
    sort "${current_crons}" -o "${current_crons}"

    local modified=0

    while IFS=' ' read -r bl_hash bl_path; do
        bl_path="${bl_path# }"
        local cur_hash
        cur_hash=$(grep " ${bl_path}$" "${current_crons}" 2>/dev/null | awk '{print $1}' || echo "")
        if [[ -n "${cur_hash}" && "${cur_hash}" != "${bl_hash}" ]]; then
            print_critical "Crontab modified: ${bl_path}"
            emit_alert --severity CRITICAL --module "${MOD}" --event crontab_modified \
                --detail "Crontab file modified since baseline: ${bl_path}" --target "${bl_path}"
            _flag 2; (( modified++ )) || true
        fi
    done < "${bl_crons}"

    # New crontab files not in baseline
    while IFS=' ' read -r cur_hash cur_path; do
        cur_path="${cur_path# }"
        if ! grep -q " ${cur_path}$" "${bl_crons}" 2>/dev/null; then
            print_warn "New crontab file: ${cur_path}"
            emit_alert --severity WARN --module "${MOD}" --event new_crontab \
                --detail "New crontab entry appeared since baseline: ${cur_path}" --target "${cur_path}"
            _flag 1
        fi
    done < "${current_crons}"

    rm -f "${current_crons}"
    [[ "${modified}" -eq 0 ]] && print_ok "All crontabs match baseline"
}

# =============================================================================
# RECENT FILE MODIFICATIONS IN CRITICAL DIRECTORIES
# =============================================================================

check_recent_modifications() {
    # Finds files modified in the last INTEGRITY_RECENT_MINUTES minutes within
    # critical directories. Useful for catching in-progress attacks.
    [[ "${INTEGRITY_RECENT_MINUTES}" -eq 0 ]] && return

    print_info "Checking for files modified in last ${INTEGRITY_RECENT_MINUTES}min..."
    local found=0

    for dir in /etc /bin /sbin /usr/bin /usr/sbin /usr/local/bin /root; do
        [[ -d "${dir}" ]] || continue
        find "${dir}" -maxdepth 2 -type f \
            -mmin "-${INTEGRITY_RECENT_MINUTES}" 2>/dev/null | \
        while IFS= read -r file; do
            local mtime
            mtime=$(stat -c "%y" "${file}" 2>/dev/null | cut -d. -f1 || echo "?")
            print_warn "Recently modified: ${file} (at ${mtime})"
            emit_alert --severity WARN --module "${MOD}" --event recent_modification \
                --detail "Critical file modified in last ${INTEGRITY_RECENT_MINUTES}min: ${file} (at ${mtime})" \
                --target "${file}"
            _flag 1; (( found++ )) || true
        done
    done

    [[ "${found}" -eq 0 ]] && print_ok "No recent modifications in critical directories"
    report_line "Recent critical file modifications (${INTEGRITY_RECENT_MINUTES}min): ${found}"
}

# =============================================================================
# LD_PRELOAD / LIBRARY INJECTION DETECTION
# =============================================================================

check_ld_preload() {
    # /etc/ld.so.preload forces a shared library to be loaded into every process.
    # Rootkits and hijacking tools often write to this file to achieve persistence.
    # Any non-empty /etc/ld.so.preload file is suspicious unless explicitly documented.

    if [[ -f /etc/ld.so.preload ]]; then
        local content
        content=$(cat /etc/ld.so.preload 2>/dev/null || echo "")
        if [[ -n "${content}" ]]; then
            print_critical "Non-empty /etc/ld.so.preload detected!"
            emit_alert --severity CRITICAL --module "${MOD}" --event ld_preload_set \
                --detail "/etc/ld.so.preload is non-empty — possible rootkit/library injection: ${content:0:200}" \
                --target "/etc/ld.so.preload"
            _flag 2
        else
            print_ok "/etc/ld.so.preload exists but is empty"
        fi
    else
        print_ok "/etc/ld.so.preload does not exist (expected)"
    fi

    # Also check environment of all running processes for LD_PRELOAD
    local ld_preload_procs=0
    for pid_dir in /proc/[0-9]*/; do
        local pid
        pid=$(basename "${pid_dir}")
        local environ
        environ=$(cat "${pid_dir}environ" 2>/dev/null | tr '\0' '\n' | grep '^LD_PRELOAD' || echo "")
        if [[ -n "${environ}" ]]; then
            local pname
            pname=$(awk '/^Name:/{print $2}' "${pid_dir}status" 2>/dev/null || echo "unknown")
            print_critical "LD_PRELOAD set in process environment: pid=${pid} name=${pname}"
            emit_alert --severity CRITICAL --module "${MOD}" --event ld_preload_env \
                --detail "Process has LD_PRELOAD in environment: ${pname} (pid=${pid}) — ${environ}" \
                --target "${pname}" --pid "${pid}"
            _flag 2; (( ld_preload_procs++ )) || true
        fi
    done
    [[ "${ld_preload_procs}" -eq 0 ]] && print_ok "No LD_PRELOAD in process environments"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    print_section_header "File Integrity" "🔒"

    check_file_hashes
    check_suid_binaries
    check_world_writable
    check_executables_in_tmp
    check_crontabs
    check_recent_modifications
    check_ld_preload

    return "${_worst}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    load_config
    main
    exit "${_worst}"
fi
