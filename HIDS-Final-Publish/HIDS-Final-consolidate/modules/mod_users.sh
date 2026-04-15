#!/usr/bin/env bash
# =============================================================================
# mod_users.sh — Advanced Forensic Activity & Integrity Monitor
# =============================================================================

# 1. ROBUST PATH RESOLUTION
CURRENT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
PROJECT_ROOT=$(cd "${CURRENT_DIR}/.." &> /dev/null && pwd)

# 2. LOAD DEPENDENCIES
if [[ -f "${PROJECT_ROOT}/lib/lib_utils.sh" ]]; then
    source "${PROJECT_ROOT}/lib/lib_utils.sh"
    load_config "${PROJECT_ROOT}/config.conf"
else
    echo "[-] ERROR: Missing lib_utils.sh at ${PROJECT_ROOT}/lib/"
    exit 1
fi

# 3. ROOT CHECK
if [[ $EUID -ne 0 ]]; then
   echo "[-] ERROR: Forensic modules require root to access /etc/shadow and logs."
   exit 1
fi

# Initialize State
declare -A FORENSICS
BG_RED='\033[41;97m'; BG_ORANGE='\033[43;30m'; BG_GREEN='\033[42;30m'; BG_RESET='\033[0m'

# -----------------------------------------------------------------------------
# FORENSIC FUNCTIONS
# -----------------------------------------------------------------------------

check_accounts() {
    local bl_users="${HIDS_DATA_DIR}/baseline/users.list"
    if [[ -f "$bl_users" ]]; then
        local current=$(awk -F: '$3 >= 1000 || $3 == 0 {print $1}' /etc/passwd | sort)
        local baseline=$(cat "$bl_users" | sort)
        local added=$(comm -13 <(echo "$baseline") <(echo "$current") | xargs)
        
        if [[ -n "$added" ]]; then
            # WHEN: Get exact mtime of the user database
            local mtime=$(stat -c '%y' /etc/passwd | cut -d'.' -f1)
            FORENSICS["Accounts"]="${BG_RED} NEW: $added | MODIFIED: $mtime ${BG_RESET}"
            emit_alert "CRITICAL" "mod_users" "Unauthorized users added: $added"
        else
            FORENSICS["Accounts"]="${BG_GREEN} CLEAN (Matches Baseline) ${BG_RESET}"
        fi
    else
        FORENSICS["Accounts"]="${C_YELLOW} NO BASELINE FOUND ${C_RESET}"
    fi
}

check_hidden_admins() {
    # WHO: Find any user besides 'root' that has UID 0
    local superusers=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | xargs)
    
    if [[ -n "$superusers" ]]; then
        FORENSICS["Hidden_Admins"]="${BG_RED} ALERT: Non-root UID 0: $superusers ${BG_RESET}"
        emit_alert "CRITICAL" "mod_users" "Privilege Escalation: $superusers has root rights!"
    else
        FORENSICS["Hidden_Admins"]="${BG_GREEN} OK: Only root has UID 0 ${BG_RESET}"
    fi
}

check_auth_forensics() {
    local auth_log="/var/log/auth.log"
    [[ ! -f "$auth_log" ]] && auth_log="/var/log/secure"
    
    # Extract details of the MOST RECENT failed login (WHO/WHERE/WHEN)
    local last_fail=$(grep "Failed password" "$auth_log" 2>/dev/null | tail -n 1)
    
    if [[ -n "$last_fail" ]]; then
        local ts=$(echo "$last_fail" | awk '{print $1,$2,$3}')
        local user=$(echo "$last_fail" | grep -oP 'for \K[^ ]+')
        local ip=$(echo "$last_fail" | grep -oP 'from \K[^ ]+')
        local count=$(grep "Failed password" "$auth_log" | tail -n 50 | wc -l)
        
        if [ "$count" -ge "${THRESHOLD_FAILED_LOGINS:-5}" ]; then
            FORENSICS["Auth"]="${BG_ORANGE} $count FAILS | LAST: $user @ $ip ($ts) ${BG_RESET}"
        else
            FORENSICS["Auth"]="${BG_GREEN} CLEAN ($count Fails) ${BG_RESET}"
        fi
    else
        FORENSICS["Auth"]="${BG_GREEN} NO LOG DATA ${BG_RESET}"
    fi
}

check_process_forensics() {
    # HOW: Look for shells (bash/sh) running under web service accounts
    local target_users="www-data|nginx|apache|daemon"
    local susp_proc=$(ps -ef | grep -E "sh|bash|zsh" | grep -E "$target_users" | grep -v "grep" | head -n 1)
    
    if [[ -n "$susp_proc" ]]; then
        local user=$(echo "$susp_proc" | awk '{print $1}')
        local pid=$(echo "$susp_proc" | awk '{print $2}')
        local ppid=$(ps -o ppid= -p "$pid" | xargs)
        local cmd=$(echo "$susp_proc" | awk '{print $8}')
        
        FORENSICS["Processes"]="${BG_RED} WEB-SHELL! $user (PID: $pid, Parent: $ppid) CMD: $cmd ${BG_RESET}"
        emit_alert "CRITICAL" "mod_users" "Active Web-Shell detected! User: $user PID: $pid"
    else
        FORENSICS["Processes"]="${BG_GREEN} CLEAN (No Suspicious Shells) ${BG_RESET}"
    fi
}

check_persistence_forensics() {
    # WHERE: Check for any cron modifications in the last hour
    local mod_file=$(find /etc/cron.d /var/spool/cron/crontabs -mmin -60 -type f -printf '%p|%T+\n' 2>/dev/null | head -n 1)
    
    if [[ -n "$mod_file" ]]; then
        local path=$(echo "$mod_file" | cut -d'|' -f1)
        local raw_time=$(echo "$mod_file" | cut -d'|' -f2 | cut -d'.' -f1)
        FORENSICS["Persistence"]="${BG_RED} MOD: $(basename "$path") @ $raw_time ${BG_RESET}"
        emit_alert "CRITICAL" "mod_users" "Persistence mechanism modified: $path"
    else
        FORENSICS["Persistence"]="${BG_GREEN} CLEAN (No Recent Changes) ${BG_RESET}"
    fi
}

# -----------------------------------------------------------------------------
# EXECUTION & REPORTING
# -----------------------------------------------------------------------------

# Run all forensic modules
check_accounts
check_hidden_admins
check_auth_forensics
check_process_forensics
check_persistence_forensics

echo -e "\n${C_BOLD}🔍 HIDS FORENSIC ACTIVITY REPORT${C_RESET}"
echo -e "------------------------------------------------------------------------------------------"
printf "${C_BOLD}%-15s | %-70s${C_RESET}\n" "Metric" "Evidence (Who / What / When / Where)"
echo -e "------------------------------------------------------------------------------------------"

# Define the order of the table rows
METRICS=("Accounts" "Hidden_Admins" "Auth" "Processes" "Persistence")

for m in "${METRICS[@]}"; do
    printf "%-15s | %b\n" "$m" "${FORENSICS[$m]:-N/A}"
done
echo -e "------------------------------------------------------------------------------------------\n"
