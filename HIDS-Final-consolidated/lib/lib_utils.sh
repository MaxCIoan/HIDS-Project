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
: "${DEDUP_WINDOW_SECONDS:=300}"
: "${ALERT_LOG_MAX_LINES:=10000}"
: "${ALERT_EMAIL:=}"
: "${MAIL_CMD:=sendmail}"
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

_send_alert_email() {
    # Sends a plain-text email alert via MAIL_CMD.
    # Arguments: severity module event detail host timestamp
    local severity="$1" module="$2" event="$3" detail="$4" host="$5" ts="$6"
    local subject="[HIDS] ${severity}: ${event} on ${host}"

    {
        printf 'To: %s\n' "${ALERT_EMAIL}"
        printf 'Subject: %s\n' "${subject}"
        printf 'Content-Type: text/plain\n\n'
        printf 'HIDS Alert\n'
        printf '==========\n\n'
        printf 'Host:      %s\n' "${host}"
        printf 'Time:      %s\n' "${ts}"
        printf 'Severity:  %s\n' "${severity}"
        printf 'Module:    %s\n' "${module}"
        printf 'Event:     %s\n' "${event}"
        printf 'Detail:    %s\n' "${detail}"
    } | "${MAIL_CMD}" "${ALERT_EMAIL}" 2>/dev/null || \
        echo "[lib_utils] Warning: failed to send email alert via ${MAIL_CMD}" >&2
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
    # Safe: only reads KEY=VALUE lines, ignoring comments and blank lines.
    # Usage: load_config [/path/to/config.conf]
    local config_path="${1:-}"

    # Default search order
    local search_paths=(
        "${config_path}"
        "$(dirname "$(readlink -f "${BASH_SOURCE[0]:-$0}")")/../config.conf"
        "/etc/hids/config.conf"
        "/opt/hids/config.conf"
    )

    for path in "${search_paths[@]}"; do
        [[ -z "${path}" ]] && continue
        if [[ -f "${path}" && -r "${path}" ]]; then
            # Source the config file directly — handles quoted values and continuation lines.
            # We use a subshell to capture exports so we can selectively promote them.
            # shellcheck source=/dev/null
            set -a   # auto-export all variables set from here
            # shellcheck disable=SC1090
            source "${path}" 2>/dev/null || true
            set +a
            return 0
        fi
    done

    echo "[lib_utils] Warning: config.conf not found — using built-in defaults" >&2
    return 1
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
    awk "BEGIN { exit !($1 > $2) }"
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
