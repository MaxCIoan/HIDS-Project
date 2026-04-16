#!/usr/bin/env bash
# =============================================================================
# lib_utils.sh — Shared utility library for HIDS
# =============================================================================
# Sourced by all modules and the orchestrator. Provides:
#   - Color output with TTY detection and tput fallback
#   - Structured JSON alert writing with severity filtering
#   - Alert deduplication via a persistent state file
#   - Config loading with sane defaults
#   - Common helper functions (timestamp, hostname, log rotation)
# =============================================================================

# Guard against double-sourcing
[[ -n "${_LIB_UTILS_LOADED:-}" ]] && return 0
readonly _LIB_UTILS_LOADED=1

_LAST_MAIL_ERROR=""

# =============================================================================
# DEFAULTS — overridden by config.conf if loaded
# =============================================================================
: "${HIDS_DATA_DIR:=/var/lib/hids}"
: "${HIDS_OUTPUT_DIR:=/var/log/hids}"
: "${ALERT_LOG:=${HIDS_OUTPUT_DIR}/alerts.json}"
: "${ALERT_STATE_FILE:=${HIDS_DATA_DIR}/alert_state.db}"
: "${REPORT_FILE:=${HIDS_OUTPUT_DIR}/report.txt}"
: "${LOG_MIN_SEVERITY:=INFO}"
: "${DISPLAY_MIN_SEVERITY:=WARN}"
: "${EMAIL_MIN_SEVERITY:=CRITICAL}"
: "${EMAIL_SEND_TIMEOUT_SECONDS:=20}"
: "${EMAIL_SETUP_TEST_TIMEOUT_SECONDS:=30}"
: "${DEDUP_WINDOW_SECONDS:=300}"
: "${ALERT_LOG_MAX_LINES:=10000}"
: "${ALERT_EMAIL:=}"
: "${MAIL_CMD:=sendmail}"
: "${MSMTP_CONFIG_FILE:=${HIDS_DATA_DIR}/msmtp.conf}"
: "${SMTP_ACCOUNT:=gmail}"
: "${SMTP_HOST:=smtp.gmail.com}"
: "${SMTP_PORT:=587}"
: "${SMTP_TLS:=on}"
: "${SMTP_TLS_STARTTLS:=on}"
: "${SMTP_FROM:=${ALERT_EMAIL}}"
: "${HIDS_HOSTNAME:=}"

# =============================================================================
# COLOR SYSTEM — tput with TTY detection
# =============================================================================
# Colors are only emitted when stdout is a TTY. In cron/non-TTY contexts, all
# color variables are set to empty strings so output remains clean plain text.

_init_colors() {
    if [[ -t 1 ]] && command -v tput &>/dev/null && tput colors &>/dev/null && [[ "$(tput colors)" -ge 8 ]]; then
        C_RESET=$(tput sgr0)
        C_BOLD=$(tput bold)
        C_RED=$(tput setaf 1)
        C_YELLOW=$(tput setaf 3)
        C_GREEN=$(tput setaf 2)
        C_CYAN=$(tput setaf 6)
        C_BLUE=$(tput setaf 4)
        C_MAGENTA=$(tput setaf 5)
        C_DIM=$(tput dim 2>/dev/null || echo "")
        C_BG_RED=$(tput setab 1)
        C_WHITE=$(tput setaf 7)
    else
        C_RESET="" C_BOLD="" C_RED="" C_YELLOW="" C_GREEN=""
        C_CYAN="" C_BLUE="" C_MAGENTA="" C_DIM="" C_BG_RED="" C_WHITE=""
    fi
    readonly C_RESET C_BOLD C_RED C_YELLOW C_GREEN C_CYAN C_BLUE C_MAGENTA C_DIM C_BG_RED C_WHITE
}
_init_colors

# =============================================================================
# SEVERITY HELPERS
# =============================================================================
# Maps severity strings to numeric weights for comparison.
#   INFO=0  WARN=1  CRITICAL=2

_severity_weight() {
    # Returns an integer weight for the given severity string
    case "${1^^}" in
        INFO)     echo 0 ;;
        WARN)     echo 1 ;;
        CRITICAL) echo 2 ;;
        *)        echo 0 ;;
    esac
}

_severity_passes() {
    # Returns 0 (true) if $1 severity >= $2 minimum severity
    local event_weight min_weight
    event_weight=$(_severity_weight "$1")
    min_weight=$(_severity_weight "$2")
    [[ "${event_weight}" -ge "${min_weight}" ]]
}

_severity_color() {
    # Returns the color escape for a given severity level
    case "${1^^}" in
        CRITICAL) printf '%s' "${C_BOLD}${C_RED}" ;;
        WARN)     printf '%s' "${C_YELLOW}" ;;
        INFO)     printf '%s' "${C_CYAN}" ;;
        *)        printf '%s' "${C_RESET}" ;;
    esac
}

# =============================================================================
# TIMESTAMP
# =============================================================================

now_iso() {
    # Returns current UTC time in ISO 8601 format: 2025-04-13T14:32:01Z
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

now_human() {
    # Returns current local time in a human-readable format for reports
    date +"%Y-%m-%d %H:%M:%S %Z"
}

epoch_now() {
    # Returns current Unix timestamp (seconds since epoch)
    date +%s
}

# =============================================================================
# HOSTNAME RESOLUTION
# =============================================================================

_get_hostname() {
    # Returns the configured hostname override or falls back to system hostname
    if [[ -n "${HIDS_HOSTNAME}" ]]; then
        echo "${HIDS_HOSTNAME}"
    else
        hostname -f 2>/dev/null || hostname 2>/dev/null || echo "unknown"
    fi
}
# Cache the hostname to avoid repeated subprocess forks
# Not declared readonly to allow re-sourcing in subshell contexts
_HIDS_HOST=${_HIDS_HOST:-$(_get_hostname)}

# =============================================================================
# DEDUPLICATION ENGINE
# =============================================================================
# The state file is a flat text database:
#   <alert_key>\t<epoch_timestamp>
# Where alert_key = "<module>:<event>:<target>"
# Entries expire after DEDUP_WINDOW_SECONDS seconds.

_ensure_state_dir() {
    # Creates the data directory and state file if they do not exist
    mkdir -p "${HIDS_DATA_DIR}" 2>/dev/null || true
    touch "${ALERT_STATE_FILE}" 2>/dev/null || true
}

_dedup_key() {
    # Builds a deduplication key from module, event type, and target string
    # Arguments: module event target
    local module="${1}" event="${2}" target="${3:-global}"
    printf '%s:%s:%s' "${module}" "${event}" "${target}"
}

_dedup_check() {
    # Returns 0 (true) if this alert should be suppressed (seen within dedup window)
    # Returns 1 (false) if the alert is new and should be emitted
    local key="${1}"
    [[ "${DEDUP_WINDOW_SECONDS}" -eq 0 ]] && return 1

    _ensure_state_dir
    local now last_seen window_start
    now=$(epoch_now)
    window_start=$(( now - DEDUP_WINDOW_SECONDS ))

    # Read the last seen timestamp for this key from the state file
    last_seen=$(awk -F'\t' -v key="${key}" '$1 == key { print $2 }' "${ALERT_STATE_FILE}" 2>/dev/null)

    if [[ -n "${last_seen}" ]] && [[ "${last_seen}" -ge "${window_start}" ]]; then
        # Alert seen within the dedup window — suppress it
        return 0
    fi

    # Upsert: remove old entry for this key, then append the new timestamp
    local tmp
    tmp=$(mktemp "${HIDS_DATA_DIR}/.state.XXXXXX")
    grep -v "^${key}	" "${ALERT_STATE_FILE}" 2>/dev/null > "${tmp}" || true
    printf '%s\t%s\n' "${key}" "${now}" >> "${tmp}"
    mv "${tmp}" "${ALERT_STATE_FILE}"

    # Prune entries older than the dedup window to prevent unbounded file growth
    local pruned_tmp
    pruned_tmp=$(mktemp "${HIDS_DATA_DIR}/.state.XXXXXX")
    awk -F'\t' -v cutoff="${window_start}" '$2 >= cutoff' "${ALERT_STATE_FILE}" 2>/dev/null > "${pruned_tmp}" || true
    mv "${pruned_tmp}" "${ALERT_STATE_FILE}"

    return 1
}

# =============================================================================
# ALERT LOG ROTATION
# =============================================================================

_rotate_alert_log() {
    # Rotates the JSON alert log if it exceeds ALERT_LOG_MAX_LINES lines.
    # Keeps the most recent ALERT_LOG_MAX_LINES entries.
    [[ ! -f "${ALERT_LOG}" ]] && return
    local line_count
    line_count=$(wc -l < "${ALERT_LOG}" 2>/dev/null || echo 0)
    if [[ "${line_count}" -gt "${ALERT_LOG_MAX_LINES}" ]]; then
        local rotated="${ALERT_LOG}.$(date +%Y%m%d%H%M%S)"
        mv "${ALERT_LOG}" "${rotated}"
        gzip "${rotated}" 2>/dev/null || true
        touch "${ALERT_LOG}"
    fi
}

# =============================================================================
# CORE ALERT FUNCTION
# =============================================================================

emit_alert() {
    # Emit a structured JSON alert with deduplication, log writing, and display.
    #
    # Usage:
    #   emit_alert \
    #     --severity CRITICAL \
    #     --module   mod_integrity \
    #     --event    hash_mismatch \
    #     --detail   "/etc/passwd modified — expected a3f1… got 9b2c…" \
    #     --target   "/etc/passwd" \
    #     [--pid     1234]
    #
    # Outputs to:
    #   - ALERT_LOG (JSON, if severity >= LOG_MIN_SEVERITY)
    #   - Terminal   (color, if severity >= DISPLAY_MIN_SEVERITY, and TTY)
    #   - Email      (if severity >= EMAIL_MIN_SEVERITY and ALERT_EMAIL set)

    local severity="" module="" event="" detail="" target="" pid="null"

    # Parse named arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --severity) severity="${2^^}"; shift 2 ;;
            --module)   module="$2";      shift 2 ;;
            --event)    event="$2";       shift 2 ;;
            --detail)   detail="$2";      shift 2 ;;
            --target)   target="$2";      shift 2 ;;
            --pid)      pid="$2";         shift 2 ;;
            *)          shift ;;
        esac
    done

    # Validate required fields
    if [[ -z "${severity}" || -z "${module}" || -z "${event}" || -z "${detail}" ]]; then
        echo "${C_RED}[lib_utils] emit_alert: missing required argument(s)${C_RESET}" >&2
        return 1
    fi

    # Deduplication check
    local dedup_key
    dedup_key=$(_dedup_key "${module}" "${event}" "${target:-global}")
    if _dedup_check "${dedup_key}"; then
        # Suppressed — alert already seen within dedup window
        return 0
    fi

    local timestamp host
    timestamp=$(now_iso)
    host="${_HIDS_HOST}"

    # Build the JSON object (one alert per line — NDJSON format)
    # Escape double quotes in detail and target to keep JSON valid
    local detail_escaped target_escaped
    detail_escaped="${detail//\"/\\\"}"
    target_escaped="${target//\"/\\\"}"

    local json
    json=$(printf '{"timestamp":"%s","severity":"%s","module":"%s","event":"%s","detail":"%s","target":"%s","host":"%s","pid":%s}' \
        "${timestamp}" "${severity}" "${module}" "${event}" \
        "${detail_escaped}" "${target_escaped}" "${host}" "${pid}")

    # Write to JSON log if severity meets the minimum log threshold
    if _severity_passes "${severity}" "${LOG_MIN_SEVERITY}"; then
        mkdir -p "${HIDS_OUTPUT_DIR}" 2>/dev/null || true
        _rotate_alert_log
        echo "${json}" >> "${ALERT_LOG}"
    fi

    # Display in terminal if severity meets the display threshold
    if _severity_passes "${severity}" "${DISPLAY_MIN_SEVERITY}"; then
        local sev_color
        sev_color=$(_severity_color "${severity}")
        printf '%s[%s]%s %s[%s]%s %s[%s]%s %s\n' \
            "${C_DIM}" "${timestamp}" "${C_RESET}" \
            "${sev_color}${C_BOLD}" "${severity}" "${C_RESET}" \
            "${C_CYAN}" "${module}" "${C_RESET}" \
            "${detail}" >&1
    fi

    # Send email notification for high-severity alerts
    if _severity_passes "${severity}" "${EMAIL_MIN_SEVERITY}" && [[ -n "${ALERT_EMAIL}" ]]; then
        _send_alert_email "${severity}" "${module}" "${event}" "${detail}" "${host}" "${timestamp}"
    fi
}

# =============================================================================
# EMAIL NOTIFICATION
# =============================================================================

_mail_config_ready() {
    [[ -n "${ALERT_EMAIL}" ]] || return 1
    command -v "${MAIL_CMD}" >/dev/null 2>&1 || return 1

    if [[ "${MAIM_CMD}" == "msmtp" && -n "${MSMTP_CONFIG_FILE:-}" ]]; then
        [[ -r "${MSMTP_CONFIG_FILE}" ]] || return 1
    fi

    return 0
}

_send_mail_message() {
    local recipient="$1" subject="$2" body="$3" timeout_seconds="${4:-${EMAIL_SEND_TIMEOUT_SECONDS}}"
    local from_addr="${SMTP_FROM:-${ALERT_EMAIL:-${recipient}}}"
    local rc=0
    local -a mail_cmd=("${MAIM_CMD}")
    local err_file=""

    _LAST_MAIL_ERROR=""

    if ! command -v "${MAIL_CMD}" >/dev/null 2>&1; then
        _LAST_MAIL_ERROR="mail command not found: ${MAIL_CMD}"
        echo "[lib_utils] Warning: ${_LAST_MAIL_ERROR}" >&2
        return 1
    fi

    if [[ "${MAIL_CMD}" == "msmtp" && -n "${MSMTP_CONFIG_FILE:-}" ]]; then
        if [[ ! -r "${MSMTP_CONFIG_FILE}" ]]; then
            _LAST_MAIL_ERROR="msmtp config not found: ${MSMTP_CONFIG_FILE}"
            echo "[lib_utils] Warning: ${_LAST_MAIL_ERROR}" >&2
            return 1
        fi
        mail_cmd+=("--file=${MSMTP_CONFIG_FILE}")
    fi

    err_file=$(mktemp "${HIDS_DATA_DIR}/.mail.XXXXXX" 2>/dev/null || mktemp)

    if command -v timeout >/dev/null 2>&1; then
        {
            printf 'To: %s\n' "${recipient}"
            printf 'From: %s\n' "${from_addr}"
            printf 'Subject: %s\n' "${subject}"
            printf 'Content-Type: text/plain; charset=UTF-8\n\n'
            printf '%s\n' "${body}"
        } | timeout "${timeout_seconds}s" "${mail_cmd[@]}" "${recipient}" >/dev/null 2>"${err_file}"
        rc=$?
    else
        {
            printf 'To: %s\n' "${recipient}"
            printf 'From: %s\n' "${from_addr}"
            printf 'Subject: %s\n' "${subject}"
            printf 'Content-Type: text/plain; charset=UTF-8\n\n'
            printf '%s\n' "${body}"
        } | "${mail_cmd[@]}" "${recipient}" >/dev/null 2>"${err_file}"
        rc=$?
    fi

    if [[ "${rc}" -eq 124 ]]; then
        _LAST_MAIL_ERROR="email alert timed out after ${timeout_seconds}s via ${MAIL_CMD}"
        echo "[lib_utils] Warning: ${_LAST_MAIL_ERROR}" >&2
        rm -f "${err_file}"
        return 1
    fi

    if [[ "${rc}" -ne 0 ]]; then
        _LAST_MAIL_ERROR=$(tr '\n' ' ' < "${err_file}" | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//')
        [[ -n "${_LAST_MAIL_ERROR}" ]] || _LAST_MAIL_ERROR="failed to send email via ${MAIL_CMD}"
        echo "[lib_utils] Warning: ${_LAST_MAIL_ERROR}" >&2
        rm -f "${err_file}"
        return 1
    fi

    rm -f "${err_file}"
    return 0
}

_send_alert_email() {
    # Sends a plain-text email alert via MAIL_CMD.
    # Arguments: severity module event detail host timestamp
    local severity="$1" module="$2" event="$3" detail="$4" host="$5" ts="$6"
    local subject="[HIDS] ${severity}: ${event} on ${host}"
    local body

    body=$(
        printf 'HIDS Alert\n'
        printf '==========\n\n'
        printf 'Host:      %s\n' "${host}"
        printf 'Time:      %s\n' "${ts}"
        printf 'Severity:  %s\n' "${severity}"
        printf 'Module:    %s\n' "${module}"
        printf 'Event:     %s\n' "${event}"
        printf 'Detail:    %s\n' "${detail}"
    )

    _send_mail_message "${ALERT_EMAIL}" "${subject}" "${body}"
}

_prompt_yes_no() {
    local prompt="$1"
    local answer=""

    if command -v gum >/dev/null 2>&1; then
        gum confirm "${prompt}"
        return $?
    fi

    read -r -p "${prompt} [y/N]: " answer
    [[ "${answer}" =~ ^[Yy]$ ]]
}

_prompt_text() {
    local prompt="$1" placeholder="${2:-}"
    if command -v gum >/dev/null 2>&1; then
        gum input --prompt "${prompt}: " --placeholder "${placeholder}"
    else
        local value=""
        read -r -p "${prompt}: " value
        printf '%s\n' "${value}"
    fi
}

_prompt_secret() {
    local prompt="$1"
    if command -v gum >/dev/null 2>&1; then
        gum input --password --prompt "${prompt}: "
    else
        local value=""
        read -rsp "${prompt}: " value
        printf '\n' >&2
        printf '%s\n' "${value}"
    fi
}

_hids_local_config_path() {
    if [[ -n "${_HIDS_CONFIG_PATH:-}" && "${_HIDS_CONFIG_PATH}" == */config.conf ]]; then
        printf '%s\n' "${_HIDS_CONFIG_PATH%config.conf}config.local.conf"
        return
    fi

    printf '%s\n' "/etc/hids/config.local.conf"
}

_persist_email_setup() {
    local email="$1" password="$2"
    local config_local_path msmtp_file config_dir mail_dir

    config_local_path=$(_hids_local_config_path)
    config_dir=$(dirname "${config_local_path}")
    msmtp_file="${MSMTP_CONFIG_FILE:-}"

    if ! mkdir -p "${config_dir}" 2>/dev/null; then
        echo "[lib_utils] Warning: cannot create config directory ${config_dir}" >&2
        return 1
    fi

    if [[ -z "${msmtp_file}" || "${msmtp_file}" == "${HIDS_DATA_DIR}/msmtp.conf" ]]; then
        msmtp_file="${config_dir}/msmtp.conf"
    fi

    mail_dir=$(dirname "${msmtp_file}")
    if ! mkdir -p "${mail_dir}" 2>/dev/null; then
        msmtp_file="${config_dir}/msmtp.conf"
        mail_dir=$(dirname "${msmtp_file}")
        mkdir -p "${mail_dir}" 2>/dev/null || return 1
    fi

    cat > "${config_local_path}" <<EOF
ALERT_EMAIL="${email}"
MAIL_CMD="msmtp"
MSMTP_CONFIG_FILE="${msmtp_file}"
SMTP_FROM="${email}"
EOF
    chmod 600 "${config_local_path}" 2>/dev/null || true

    cat > "${msmtp_file}" <<EOF
# Generated by HIDS interactive email setup
defaults
auth           on
tls            ${SMTP_TLS:-on}
tls_starttls   ${SMTP_TLS_STARTTLS:-on}
tls_trust_file /etc/ssl/certs/ca-certificates.crt
account        ${SMTP_ACCOUNT:-gmail}
host           ${SMTP_HOST:-smtp.gmail.com}
port           ${SMTP_PORT:-587}
from           ${email}
user           ${email}
password       ${password}
account default : ${SMTP_ACCOUNT:-gmail}
EOF
    chmod 600 "${msmtp_file}" 2>/dev/null || true

    if [[ "$(id -u)" -eq 0 && -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
        chown "${SUDO_UID}:${SUDO_GID}" "${config_local_path}" "${msmtp_file}" 2>/dev/null || true
    fi

    return 0
}

configure_email_interactively() {
    local email password test_subject test_body

    [[ -t 0 && -t 1 ]] || return 1

    email=$(_prompt_text "Alert email" "you@example.com")
    [[ -n "${email}" ]] || {
        print_warn "Email setup skipped — no address entered"
        return 1
    }

    password=$(_prompt_secret "App password")
    [[ -n "${password}" ]] || {
        print_warn "Email setup skipped — no password entered"
        return 1
    }

    if ! _persist_email_setup "${email}" "${password}"; then
        print_warn "Failed to save local email configuration"
        return 1
    fi

    load_config "${_HIDS_CONFIG_PATH:-}"

    test_subject="[HIDS] email configuration test"
    test_body=$(printf 'HIDS email alerts are now configured for %s on %s.\n' "${ALERT_EMAIL}" "${_HIDS_HOST}")

    if _send_mail_message "${ALERT_EMAIL}" "${test_subject}" "${test_body}" "${EMAIL_SETUP_TEST_TIMEOUT_SECONDS}"; then
        print_ok "Email alerts configured for ${ALERT_EMAIL}"
        print_ok "Test email sent successfully"
        return 0
    fi

    [[ -n "${_LAST_MAIL_ERROR:-}" ]] && print_warn "Mail test failed: ${_LAST_MAIL_ERROR}"
    print_warn "Email settings were saved, but the test email failed"
    return 1
}

maybe_prompt_email_setup() {
    local reason="${1:-missing}"
    local prompt="Configure email alerts now for future runs?"

    [[ -t 0 && -t 1 ]] || return 1

    if [[ "${reason}" != "failed" ]] && _mail_config_ready; then
        return 0
    fi

    if [[ "${reason}" == "failed" ]]; then
        prompt="Email delivery failed. Reconfigure email alerts now?"
    fi

    _prompt_yes_no "${prompt}" || return 1
    configure_email_interactively
}

# =============================================================================
# SECTION DISPLAY HELPERS
# =============================================================================

print_section_header() {
    # Prints a formatted section header for terminal report output.
    # Usage: print_section_header "Module Name" "icon_char"
    local title="${1}" icon="${2:--}"
    local width=72
    local padding=$(( (width - ${#title} - 4) / 2 ))
    printf '\n%s%s%s %s %s%s%s\n' \
        "${C_BOLD}${C_BLUE}" \
        "$(printf '─%.0s' $(seq 1 "${padding}"))" \
        " ${icon} ${title} ${icon}" \
        "$(printf '─%.0s' $(seq 1 "${padding}"))" \
        "${C_RESET}"
}

print_ok() {
    # Prints a green OK status line.
    printf '  %s✓%s  %s\n' "${C_GREEN}${C_BOLD}" "${C_RESET}" "$*"
}

print_warn() {
    # Prints a yellow warning line.
    printf '  %s⚠%s  %s\n' "${C_YELLOW}${C_BOLD}" "${C_RESET}" "$*"
}

print_critical() {
    # Prints a red critical alert line.
    printf '  %s✗%s  %s%s%s\n' "${C_RED}${C_BOLD}" "${C_RESET}" "${C_RED}" "$*" "${C_RESET}"
}

print_info() {
    # Prints a dimmed informational line.
    printf '  %s·%s  %s\n' "${C_DIM}" "${C_RESET}" "$*"
}

# =============================================================================
# REPORT HELPERS
# =============================================================================

# Accumulates report lines in memory; written to REPORT_FILE at end of run
_REPORT_BUFFER=""

report_line() {
    # Appends a line to the in-memory report buffer (plain text, no color codes)
    _REPORT_BUFFER+="$*"$'\n'
}

flush_report() {
    # Writes the accumulated report buffer to REPORT_FILE.
    mkdir -p "${HIDS_OUTPUT_DIR}" 2>/dev/null || true
    {
        printf '=%.0s' {1..72}; printf '\n'
        printf 'HIDS Run Report — %s\n' "$(now_human)"
        printf 'Host: %s\n' "${_HIDS_HOST}"
        printf '=%.0s' {1..72}; printf '\n\n'
        printf '%s' "${_REPORT_BUFFER}"
        printf '\n=%.0s' {1..72}; printf '\n'
        printf 'End of report — %s\n' "$(now_human)"
    } > "${REPORT_FILE}"
}

# =============================================================================
# CONFIG LOADER
# =============================================================================

load_config() {
    # Loads config.conf from the given path (or default locations).
    # Then loads config.local.conf from the same location when present.
    # Usage: load_config [/path/to/config.conf]
    local config_path="${1:-}"
    local path=""
    local loaded_path=""
    local override_path=""

    local search_paths=(
        "${config_path}"
        "$(dirname "$(readlink -f "${BASH_SOURCE[0]:-$0}")")/../config.conf"
        "/etc/hids/config.conf"
        "/opt/hids/config.conf"
    )

    for path in "${search_paths[@]}"; do
        [[ -z "${path}" ]] && continue
        if [[ -f "${path}" && -r "${path}" ]]; then
            set -a
            # shellcheck disable=SC1090
            source "${path}" 2>/dev/null || true
            set +a
            loaded_path="${path}"
            _HIDS_CONFIG_PATH="${path}"
            break
        fi
    done

    if [[ -z "${loaded_path}" ]]; then
        echo "[lib_utils] Warning: config.conf not found — using built-in defaults" >&2
        return 1
    fi

    case "${loaded_path}" in
        */config.conf)
            override_path="${loaded_path%config.conf}config.local.conf"
            ;;
    esac

    _HIDS_CONFIG_LOCAL_PATH=""
    if [[ -n "${override_path}" && -f "${override_path}" && -r "${override_path}" ]]; then
        set -a
        # shellcheck disable=SC1090
        source "${override_path}" 2>/dev/null || true
        set +a
        _HIDS_CONFIG_LOCAL_PATH="${override_path}"
    fi

    return 0
}

# =============================================================================
# NUMERIC HELPERS
# =============================================================================

bc_calc() {
    # Evaluates a math expression using awk (avoids bc dependency).
    # Usage: bc_calc "2.5 * 4"
    awk "BEGIN { printf \"%.2f\", $* }"
}

int_gt() {
    # Returns 0 (true) if integer $1 > integer $2
    [[ "${1}" -gt "${2}" ]] 2>/dev/null
}

float_gt() {
    # Returns 0 (true) if float $1 > float $2, using awk comparison
    awk "BEGIN { exit !(($1+0) > ($2+0)) }"
}

# =============================================================================
# FILESYSTEM HELPERS
# =============================================================================

ensure_dirs() {
    # Creates HIDS_DATA_DIR and HIDS_OUTPUT_DIR with correct permissions.
    # Should be called once at startup by the orchestrator.
    for dir in "${HIDS_DATA_DIR}" "${HIDS_OUTPUT_DIR}" "${HIDS_DATA_DIR}/baseline"; do
        if ! mkdir -p "${dir}" 2>/dev/null; then
            echo "[lib_utils] Error: cannot create directory ${dir} — run as root?" >&2
            return 1
        fi
        chmod 750 "${dir}" 2>/dev/null || true
    done
}

is_root() {
    # Returns 0 (true) if the script is running as root
    [[ "$(id -u)" -eq 0 ]]
}

require_root() {
    # Exits with an error message if not running as root
    if ! is_root; then
        printf '%sError: HIDS must be run as root.%s\n' "${C_RED}" "${C_RESET}" >&2
        exit 1
    fi
}


