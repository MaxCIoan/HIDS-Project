#!/usr/bin/env bash
# =============================================================================
# baseline.sh — Dynamic baseline snapshot and diff engine
# =============================================================================
# On first run (or when called with --init), snapshots the current system
# state into HIDS_DATA_DIR/baseline/. On subsequent runs, diffs the current
# state against the stored baseline and emits alerts via emit_alert().
#
# Usage:
#   baseline.sh --init          Force a fresh baseline (overwrite existing)
#   baseline.sh --check         Compare current state against baseline
#   baseline.sh --status        Show baseline metadata (date, counts)
#
# Called by hids.sh. Can also be run independently.
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "${SCRIPT_DIR}/lib/lib_utils.sh"
load_config "${SCRIPT_DIR}/config.conf"

# Baseline storage paths
BL_DIR="${HIDS_DATA_DIR}/baseline"
BL_META="${BL_DIR}/meta.conf"
BL_FILE_HASHES="${BL_DIR}/file_hashes.db"
BL_SUID_LIST="${BL_DIR}/suid_binaries.list"
BL_USERS="${BL_DIR}/users.list"
BL_GROUPS="${BL_DIR}/groups.list"
BL_PORTS="${BL_DIR}/listening_ports.list"
BL_HEALTH="${BL_DIR}/health_averages.conf"
BL_CRONS="${BL_DIR}/crontabs.db"

# =============================================================================
# BASELINE EXISTENCE CHECK
# =============================================================================

baseline_exists() {
    [[ -f "${BL_META}" && -f "${BL_FILE_HASHES}" ]]
}

baseline_age_hours() {
    [[ ! -f "${BL_META}" ]] && echo 9999 && return
    local bl_epoch now_epoch
    bl_epoch=$(awk -F= '/BASELINE_EPOCH/{print $2}' "${BL_META}" 2>/dev/null || echo 0)
    now_epoch=$(epoch_now)
    echo $(( (now_epoch - bl_epoch) / 3600 ))
}

# =============================================================================
# SNAPSHOT FUNCTIONS
# =============================================================================

_snapshot_file_hashes() {
    # Computes SHA256 hashes for all files in INTEGRITY_WATCH and INTEGRITY_WATCH_DIRS.
    print_info "Hashing watched files..."
    local tmp
    tmp=$(mktemp)

    for f in ${INTEGRITY_WATCH}; do
        [[ -f "${f}" ]] && sha256sum "${f}" 2>/dev/null >> "${tmp}" || true
    done

    for d in ${INTEGRITY_WATCH_DIRS}; do
        [[ -d "${d}" ]] || continue
        find "${d}" -maxdepth "${INTEGRITY_DEPTH}" -type f 2>/dev/null | \
            while read -r file; do
                sha256sum "${file}" 2>/dev/null || true
            done >> "${tmp}"
    done

    sort "${tmp}" > "${BL_FILE_HASHES}"
    rm -f "${tmp}"
    print_ok "Hashed $(wc -l < "${BL_FILE_HASHES}") files"
}

_snapshot_suid_binaries() {
    # Finds all SUID/SGID binaries across the filesystem.
    print_info "Scanning for SUID/SGID binaries (may take a moment)..."
    local exclude_args=()
    for excl in ${SUID_SCAN_EXCLUDE}; do
        exclude_args+=(-path "${excl}" -prune -o)
    done

    find ${SUID_SCAN_PATHS} \
        "${exclude_args[@]}" \
        -perm /6000 -type f -print 2>/dev/null | \
        sort > "${BL_SUID_LIST}"

    # Auto-populate the SUID whitelist on first baseline
    if [[ ! -f "${WHITELIST_SUID_FILE}" ]]; then
        mkdir -p "$(dirname "${WHITELIST_SUID_FILE}")"
        cp "${BL_SUID_LIST}" "${WHITELIST_SUID_FILE}"
        print_ok "SUID whitelist auto-populated: $(wc -l < "${WHITELIST_SUID_FILE}") entries"
    fi

    print_ok "Found $(wc -l < "${BL_SUID_LIST}") SUID/SGID binaries"
}

_snapshot_users() {
    # Snapshots user and group databases for change detection.
    # Fields stored: username:uid:gid:home:shell
    awk -F: '{print $1":"$3":"$4":"$6":"$7}' /etc/passwd 2>/dev/null | sort > "${BL_USERS}"
    # Fields stored: groupname:gid:members
    awk -F: '{print $1":"$3":"$4}' /etc/group 2>/dev/null | sort > "${BL_GROUPS}"
    print_ok "Snapshotted $(wc -l < "${BL_USERS}") users, $(wc -l < "${BL_GROUPS}") groups"
}

_snapshot_ports() {
    # Snapshots all currently listening TCP/UDP sockets with PID and process name.
    # Format per line: protocol:port:pid:process_name
    ss -tulnp 2>/dev/null | awk 'NR>1 {
    	proto = $1
    	n = split($5, a, ":"); port = a[n]
    	proc = $6
    	gsub(/.*users:\(\("/, "", proc); gsub(/".*/, "", proc)
    	pid = $6
    	gsub(/.*pid=/, "", pid); gsub(/,.*/, "", pid)
    	print proto ":" port ":" pid ":" proc
    }' | sort -t: -k2 -n > "${BL_PORTS}"
    print_ok "Snapshotted $(wc -l < "${BL_PORTS}") listening sockets"
}

_snapshot_health_baseline() {
    # Records system reference values: CPU count, total RAM.
    local load_1min nproc total_ram_kb
    load_1min=$(awk '{print $1}' /proc/loadavg)
    nproc=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)
    total_ram_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo)
    {
        printf 'BASELINE_LOAD_1MIN=%s\n' "${load_1min}"
        printf 'BASELINE_NPROC=%s\n' "${nproc}"
        printf 'BASELINE_TOTAL_RAM_KB=%s\n' "${total_ram_kb}"
    } > "${BL_HEALTH}"
    print_ok "Health reference: load=${load_1min}, nproc=${nproc}, RAM=$(( total_ram_kb / 1024 ))MB"
}

_snapshot_crontabs() {
    # Snapshots SHA256 hashes of system and user crontab files.
    local tmp
    tmp=$(mktemp)
    for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/*; do
        [[ -f "${f}" ]] && sha256sum "${f}" 2>/dev/null >> "${tmp}" || true
    done
    sort "${tmp}" > "${BL_CRONS}"
    rm -f "${tmp}"
    print_ok "Snapshotted $(wc -l < "${BL_CRONS}") crontab files"
}

# =============================================================================
# INIT — Take a full system baseline
# =============================================================================

cmd_init() {
    require_root
    ensure_dirs
    mkdir -p "${BL_DIR}"

    print_section_header "Initialising HIDS Baseline" "▶"
    printf '  %sBaseline directory:%s %s\n' "${C_CYAN}" "${C_RESET}" "${BL_DIR}"
    printf '  %sTimestamp:%s %s\n\n' "${C_CYAN}" "${C_RESET}" "$(now_human)"

    _snapshot_file_hashes
    _snapshot_suid_binaries
    _snapshot_users
    _snapshot_ports
    _snapshot_health_baseline
    _snapshot_crontabs

    # Write baseline metadata
    {
        printf 'BASELINE_EPOCH=%s\n' "$(epoch_now)"
        printf 'BASELINE_DATE=%s\n' "$(now_iso)"
        printf 'BASELINE_HOST=%s\n' "${_HIDS_HOST}"
        printf 'BASELINE_VERSION=1\n'
    } > "${BL_META}"

    print_section_header "Baseline Complete" "✓"
    printf '  Stored in %s\n' "${BL_DIR}"
    printf '  Run "hids.sh" to begin monitoring.\n\n'
}

# =============================================================================
# CHECK — Compare current state against stored baseline
# =============================================================================

_FINDINGS_COUNT=0

_check_file_hashes() {
    # Compares current SHA256 hashes against the baseline.
    [[ ! -f "${BL_FILE_HASHES}" ]] && return

    local current_hashes
    current_hashes=$(mktemp)

    for f in ${INTEGRITY_WATCH}; do
        [[ -f "${f}" ]] && sha256sum "${f}" 2>/dev/null >> "${current_hashes}" || true
    done
    for d in ${INTEGRITY_WATCH_DIRS}; do
        [[ -d "${d}" ]] || continue
        find "${d}" -maxdepth "${INTEGRITY_DEPTH}" -type f 2>/dev/null | \
            while read -r file; do sha256sum "${file}" 2>/dev/null || true; done >> "${current_hashes}"
    done
    sort "${current_hashes}" -o "${current_hashes}"

    # Modified or deleted files
    while IFS=' ' read -r bl_hash bl_path; do
        bl_path="${bl_path# }"
        local cur_hash
        cur_hash=$(grep " ${bl_path}$" "${current_hashes}" 2>/dev/null | awk '{print $1}' || echo "")

        if [[ -z "${cur_hash}" ]] && [[ ! -f "${bl_path}" ]]; then
            emit_alert --severity WARN --module baseline --event file_deleted \
                --detail "Watched file removed since baseline: ${bl_path}" --target "${bl_path}"
            (( _FINDINGS_COUNT++ )) || true
        elif [[ -n "${cur_hash}" && "${cur_hash}" != "${bl_hash}" ]]; then
            emit_alert --severity CRITICAL --module baseline --event hash_mismatch \
                --detail "File modified since baseline: ${bl_path} (was ${bl_hash:0:16}… now ${cur_hash:0:16}…)" \
                --target "${bl_path}"
            (( _FINDINGS_COUNT++ )) || true
        fi
    done < "${BL_FILE_HASHES}"

    # New files not in baseline
    while IFS=' ' read -r cur_hash cur_path; do
        cur_path="${cur_path# }"
        grep -q " ${cur_path}$" "${BL_FILE_HASHES}" 2>/dev/null || {
            emit_alert --severity WARN --module baseline --event new_watched_file \
                --detail "New file in watched directory since baseline: ${cur_path}" --target "${cur_path}"
            (( _FINDINGS_COUNT++ )) || true
        }
    done < "${current_hashes}"

    rm -f "${current_hashes}"
}

_check_suid_binaries() {
    # Diffs current SUID/SGID inventory against baseline.
    [[ ! -f "${BL_SUID_LIST}" ]] && return

    local current_suid exclude_args=()
    current_suid=$(mktemp)
    for excl in ${SUID_SCAN_EXCLUDE}; do
        exclude_args+=(-path "${excl}" -prune -o)
    done
    find ${SUID_SCAN_PATHS} "${exclude_args[@]}" -perm /6000 -type f -print 2>/dev/null | \
        sort > "${current_suid}"

    # New SUID binaries not in baseline — CRITICAL unless whitelisted
    while IFS= read -r bin; do
        if ! grep -qxF "${bin}" "${BL_SUID_LIST}" 2>/dev/null; then
            if [[ -f "${WHITELIST_SUID_FILE}" ]] && grep -qxF "${bin}" "${WHITELIST_SUID_FILE}" 2>/dev/null; then
                continue
            fi
            emit_alert --severity CRITICAL --module baseline --event new_suid_binary \
                --detail "New SUID/SGID binary not in baseline: ${bin}" --target "${bin}"
            (( _FINDINGS_COUNT++ )) || true
        fi
    done < "${current_suid}"

    rm -f "${current_suid}"
}

_check_users() {
    # Detects new user accounts, UID changes, and UID 0 duplicates.
    [[ ! -f "${BL_USERS}" ]] && return

    while IFS=: read -r uname uid gid home shell; do
        if ! grep -q "^${uname}:" "${BL_USERS}" 2>/dev/null; then
            local sev="WARN"
            [[ "${uid}" -eq 0 ]] && sev="CRITICAL"
            emit_alert --severity "${sev}" --module baseline --event new_user \
                --detail "New user account since baseline: ${uname} (uid=${uid})" --target "${uname}"
            (( _FINDINGS_COUNT++ )) || true
        fi
    done < <(awk -F: '{print $1":"$3":"$4":"$6":"$7}' /etc/passwd)

    # UID 0 duplicates — always critical
    local uid0_count
    uid0_count=$(awk -F: '$3 == 0' /etc/passwd | wc -l)
    if [[ "${uid0_count}" -gt 1 ]]; then
        local uid0_users
        uid0_users=$(awk -F: '$3 == 0 {printf "%s ", $1}' /etc/passwd)
        emit_alert --severity CRITICAL --module baseline --event uid0_duplicate \
            --detail "Multiple UID 0 accounts: ${uid0_users}" --target "/etc/passwd"
        (( _FINDINGS_COUNT++ )) || true
    fi
}

_check_ports() {
    # Detects new listening ports not present at baseline time.
    [[ ! -f "${BL_PORTS}" ]] && return

    ss -tulnp 2>/dev/null | awk 'NR>1 {
        n=split($5,a,":"); port=a[n]
        match($NF,/"([^"]+)"/,proc); print port":"proc[1]
    }' | sort -t: -k1 -n | while IFS=: read -r port proc; do
        [[ -z "${port}" ]] && continue
        if ! grep -q ":${port}:" "${BL_PORTS}" 2>/dev/null; then
            local sev="WARN"
            local wl_regex
            wl_regex=$(echo "${WHITELIST_PORTS}" | tr ',' '|')
            echo "${port}" | grep -qE "^(${wl_regex})$" 2>/dev/null && sev="INFO"
            emit_alert --severity "${sev}" --module baseline --event new_listening_port \
                --detail "New listening port since baseline: ${port} (${proc})" --target "${port}"
            (( _FINDINGS_COUNT++ )) || true
        fi
    done
}

cmd_check() {
    # Runs all baseline diff checks. Returns the number of findings.
    if ! baseline_exists; then
        echo "[baseline] No baseline found — run: baseline.sh --init" >&2
        return 1
    fi
    _check_file_hashes
    _check_suid_binaries
    _check_users
    _check_ports
    echo "${_FINDINGS_COUNT}"
}

cmd_status() {
    # Displays stored baseline metadata.
    if ! baseline_exists; then
        print_warn "No baseline exists. Run: ${BASH_SOURCE[0]} --init"
        return 1
    fi
    print_section_header "Baseline Status" "i"
    while IFS='=' read -r key val; do
        [[ -n "${key}" ]] && printf '  %-25s %s\n' "${key}" "${val}"
    done < "${BL_META}"
    printf '  %-25s %s hours ago\n' "Age" "$(baseline_age_hours)"
    printf '  %-25s %s files\n' "Watched files" "$(wc -l < "${BL_FILE_HASHES}" 2>/dev/null || echo 0)"
    printf '  %-25s %s binaries\n' "SUID inventory" "$(wc -l < "${BL_SUID_LIST}" 2>/dev/null || echo 0)"
}

# =============================================================================
# ENTRY POINT
# =============================================================================

case "${1:-}" in
    --init)   cmd_init ;;
    --check)  cmd_check ;;
    --status) cmd_status ;;
    *)
        if ! baseline_exists; then
            echo "[baseline] No baseline found — initialising now..."
            cmd_init
        else
            cmd_check
        fi
        ;;
esac
