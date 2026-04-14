#!/usr/bin/env bash
# =============================================================================
# hids.sh — HIDS Orchestrator
# =============================================================================
# Entry point for the Host Intrusion Detection System.
# Loads config, checks dependencies, runs all modules in sequence, and
# produces the final report.
#
# Usage:
#   hids.sh                  One-shot run (default)
#   hids.sh --once           Alias for default one-shot run
#   hids.sh --live           Launch continuous live monitor (live_monitor.sh)
#   hids.sh --baseline       Re-initialise the baseline snapshot
#   hids.sh --status         Show baseline status and last report summary
#   hids.sh --query [opts]   Query the alert log (delegates to mod_alert.sh)
#   hids.sh --help           Show this help
#
# Must be run as root.
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# Resolve the directory this script lives in, even through symlinks
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"

# Source the shared library first (provides load_config, color, etc.)
source "${SCRIPT_DIR}/lib/lib_utils.sh"

# Load user configuration (falls back to built-in defaults if not found)
load_config "${SCRIPT_DIR}/config.conf"

# Record the epoch at which this run started (used by mod_alert for log slicing)
export RUN_EPOCH
RUN_EPOCH=$(epoch_now)

# =============================================================================
# DEPENDENCY CHECK
# =============================================================================

check_dependencies() {
    # Verifies that required external commands are available.
    # HIDS is designed to use as few external tools as possible. Optional tools
    # like last/lastlog improve login-history coverage but should not block runs.
    local missing=()
    local required=(ss sha256sum find stat awk sort uniq wc who)
    local optional=(last lastlog)

    for cmd in "${required[@]}"; do
        command -v "${cmd}" &>/dev/null || missing+=("${cmd}")
    done

    if [[ "${#missing[@]}" -gt 0 ]]; then
        printf '%sError: missing required commands: %s%s\n' \
            "${C_RED}" "${missing[*]}" "${C_RESET}" >&2
        exit 1
    fi

    for cmd in "${optional[@]}"; do
        if ! command -v "${cmd}" &>/dev/null; then
            printf '%sWarning:%s optional command not found: %s\n' \
                "${C_YELLOW}" "${C_RESET}" "${cmd}" >&2
        fi
    done
}

# =============================================================================
# USAGE / HELP
# =============================================================================

usage() {
    cat <<USAGE
${C_BOLD}hids.sh${C_RESET} — Host Intrusion Detection System

${C_BOLD}Usage:${C_RESET}
  hids.sh [OPTIONS]

${C_BOLD}Options:${C_RESET}
  (none) / --once     One-shot monitoring run
  --live              Continuous live monitor (refreshes every ${LIVE_REFRESH_SECONDS}s)
  --baseline          Re-initialise the system baseline
  --status            Show baseline status and alert log summary
  --query [opts]      Query the alert log
                        --severity CRITICAL|WARN|INFO
                        --module   mod_health|mod_users|mod_process|mod_integrity
                        --last N   (default: 50)
  --help              Show this help

${C_BOLD}Examples:${C_RESET}
  sudo ./hids.sh                        # Run once from the cloned repo
  sudo ./hids.sh --live                 # Continuous monitoring
  sudo ./hids.sh --baseline             # Re-baseline after system changes
  sudo ./hids.sh --query --severity CRITICAL --last 20

${C_BOLD}Scheduling:${C_RESET}
  Add to crontab:  */5 * * * * cd /path/to/HIDS-Final-Publish/HIDS-Final-consolidate && ./hids.sh --once
  Or install the provided systemd timer unit.

${C_BOLD}Config:${C_RESET}
  ${SCRIPT_DIR}/config.conf

${C_BOLD}Outputs:${C_RESET}
  Alert log:   ${ALERT_LOG}
  Report:      ${REPORT_FILE}
  Baselines:   ${HIDS_DATA_DIR}/baseline/
USAGE
}

# =============================================================================
# BANNER
# =============================================================================

print_banner() {
    printf '%s\n' "${C_BOLD}${C_BLUE}"
    printf ' ██╗  ██╗██╗██████╗ ███████╗\n'
    printf ' ██║  ██║██║██╔══██╗██╔════╝\n'
    printf ' ███████║██║██║  ██║███████╗\n'
    printf ' ██╔══██║██║██║  ██║╚════██║\n'
    printf ' ██║  ██║██║██████╔╝███████║\n'
    printf ' ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝\n'
    printf '%s' "${C_RESET}"
    printf ' Host Intrusion Detection System\n'
    printf ' Host: %s  |  Run started: %s\n\n' "${_HIDS_HOST}" "$(now_human)"
}

# =============================================================================
# MODULE RUNNER
# =============================================================================

run_module() {
    # Runs a module script and captures its exit code.
    # Exit codes: 0 = clean, 1 = WARN, 2 = CRITICAL
    # Arguments: module_path display_name
    local module_path="${1}" display_name="${2}"
    local exit_code=0

    report_line ""
    report_line "=== ${display_name} ==="

    bash "${module_path}" || exit_code=$?

    return "${exit_code}"
}

# =============================================================================
# ONE-SHOT RUN
# =============================================================================

cmd_once() {
    require_root
    check_dependencies
    ensure_dirs

    [[ -t 1 ]] && print_banner

    # Auto-initialise baseline if it doesn't exist yet
    if [[ ! -f "${HIDS_DATA_DIR}/baseline/meta.conf" ]]; then
        printf '%s[hids] No baseline found — running initial baseline snapshot...%s\n' \
            "${C_YELLOW}" "${C_RESET}"
        bash "${SCRIPT_DIR}/baseline.sh" --init
    fi

    # Track the overall worst finding across all modules
    local overall_worst=0
    local mod_result

    # ── Module 1: System Health ───────────────────────────────────────────────
    mod_result=0
    run_module "${SCRIPT_DIR}/modules/mod_health.sh" "System Health" || mod_result=$?
    [[ "${mod_result}" -gt "${overall_worst}" ]] && overall_worst="${mod_result}"

    # ── Module 2: User Activity ───────────────────────────────────────────────
    mod_result=0
    run_module "${SCRIPT_DIR}/modules/mod_users.sh" "User Activity" || mod_result=$?
    [[ "${mod_result}" -gt "${overall_worst}" ]] && overall_worst="${mod_result}"

    # ── Module 3: Process and Network Audit ───────────────────────────────────
    mod_result=0
    run_module "${SCRIPT_DIR}/modules/mod_process.sh" "Process and Network" || mod_result=$?
    [[ "${mod_result}" -gt "${overall_worst}" ]] && overall_worst="${mod_result}"

    # ── Module 4: File Integrity ──────────────────────────────────────────────
    mod_result=0
    run_module "${SCRIPT_DIR}/modules/mod_integrity.sh" "File Integrity" || mod_result=$?
    [[ "${mod_result}" -gt "${overall_worst}" ]] && overall_worst="${mod_result}"

    # ── Module 5: Alert Aggregation and Report ────────────────────────────────
    bash "${SCRIPT_DIR}/modules/mod_alert.sh"

    # Exit code reflects worst finding: 0=clean, 1=warn, 2=critical
    exit "${overall_worst}"
}

# =============================================================================
# STATUS
# =============================================================================

cmd_status() {
    bash "${SCRIPT_DIR}/baseline.sh" --status

    if [[ -f "${ALERT_LOG}" ]]; then
        printf '\n%sRecent alerts (last 10):%s\n' "${C_BOLD}" "${C_RESET}"
        bash "${SCRIPT_DIR}/modules/mod_alert.sh" --query --last 10
    fi

    if [[ -f "${REPORT_FILE}" ]]; then
        printf '\n%sLast report:%s %s\n' "${C_BOLD}" "${C_RESET}" "${REPORT_FILE}"
        head -5 "${REPORT_FILE}"
    fi
}

# =============================================================================
# ENTRY POINT — ARGUMENT DISPATCH
# =============================================================================

case "${1:-}" in
    ""| --once)
        cmd_once
        ;;
    --live)
        exec bash "${SCRIPT_DIR}/live_monitor.sh"
        ;;
    --baseline)
        require_root
        bash "${SCRIPT_DIR}/baseline.sh" --init
        ;;
    --status)
        cmd_status
        ;;
    --query)
        shift
        bash "${SCRIPT_DIR}/modules/mod_alert.sh" --query "$@"
        ;;
    --help | -h)
        usage
        ;;
    *)
        printf '%sUnknown option: %s%s\n' "${C_RED}" "$1" "${C_RESET}" >&2
        usage >&2
        exit 1
        ;;
esac
