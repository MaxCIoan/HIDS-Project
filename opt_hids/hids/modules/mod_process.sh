#!/usr/bin/env bash
# =============================================================================
# mod_process.sh — Module 4: Process and Network Audit (GUM Edition)
# =============================================================================
# Full visibility audit of running processes and network activity.
# Philosophy: show EVERYTHING with context — nothing hidden, everything classified.
#
# Data sources:
#   /proc/[pid]/exe, /proc/[pid]/status → process info (no ps dependency)
#   ss -tulnpe                           → listening ports with full details
#   ss -tunp state established           → established connections
#   /proc/[pid]/environ                  → environment (suspicious path detection)
#
# Port classification:
#   OK     → well-known legitimate service port
#   REVIEW → unusual or dynamic port worth noting
#   ALERT  → known attacker/backdoor port
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lib_utils.sh"
load_config

MOD="mod_process"
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
    gum style --border rounded --border-foreground "${color}" --width 33 --padding "0 1" \
        "$(gum style --foreground "${color}" --bold "${title}")" \
        "$(gum style --foreground 255 --bold "    ${count}")" \
        "$(badge "${status}") ${msg}"
}

# =============================================================================
# PORT KNOWLEDGE BASE — Classification intelligente
# =============================================================================
classify_port() {
    # Returns: STATUS|DESCRIPTION
    # STATUS: OK=well-known, REVIEW=unusual, ALERT=dangerous
    local port="$1" proto="$2"

    # ── Ports dangereux / attaquants connus ───────────────────────────────────
    case "${port}" in
        4444|1337|31337|6666|6667|1524|12345|31338|54321|9999|8888|1234|4321)
            echo "ALERT|⚠ Known attacker/backdoor port"
            return ;;
        6660|6661|6662|6663|6664|6665|6668|6669|6697)
            echo "ALERT|⚠ IRC — potential C2 channel"
            return ;;
        4445|5554|9090|8080)
            echo "ALERT|⚠ Common reverse shell / C2 port"
            return ;;
    esac

    # ── Ports légitimes bien connus ───────────────────────────────────────────
    case "${port}" in
        21)   echo "OK|FTP — File Transfer Protocol" ;;
        22)   echo "OK|SSH — Secure Shell" ;;
        23)   echo "REVIEW|Telnet — unencrypted (insecure!)" ;;
        25)   echo "OK|SMTP — Mail Transfer" ;;
        53)   echo "OK|DNS — Domain Name System" ;;
        80)   echo "OK|HTTP — Web Server" ;;
        110)  echo "OK|POP3 — Mail Retrieval" ;;
        111)  echo "REVIEW|RPC portmapper" ;;
        123)  echo "OK|NTP — Network Time Protocol" ;;
        143)  echo "OK|IMAP — Mail Access" ;;
        161)  echo "REVIEW|SNMP — Network Management" ;;
        389)  echo "REVIEW|LDAP — Directory Service" ;;
        443)  echo "OK|HTTPS — Secure Web" ;;
        445)  echo "REVIEW|SMB — Windows File Sharing" ;;
        465)  echo "OK|SMTPS — Secure Mail" ;;
        512)  echo "ALERT|⚠ rexec — Remote Execution (insecure!)" ;;
        513)  echo "ALERT|⚠ rlogin — Remote Login (insecure!)" ;;
        514)  echo "ALERT|⚠ rsh — Remote Shell (insecure!)" ;;
        587)  echo "OK|SMTP Submission" ;;
        631)  echo "OK|CUPS — Printing Service" ;;
        993)  echo "OK|IMAPS — Secure Mail Access" ;;
        995)  echo "OK|POP3S — Secure Mail Retrieval" ;;
        1099) echo "REVIEW|Java RMI Registry" ;;
        1433) echo "REVIEW|MSSQL — Microsoft SQL Server" ;;
        2049) echo "REVIEW|NFS — Network File System" ;;
        2121) echo "REVIEW|ProFTPD alternate port" ;;
        3000) echo "OK|Dev server / Node.js" ;;
        3306) echo "OK|MySQL — Database" ;;
        3389) echo "REVIEW|RDP — Remote Desktop" ;;
        4000) echo "REVIEW|Custom application port" ;;
        5000) echo "REVIEW|Flask dev server / UPnP" ;;
        5353) echo "OK|mDNS — Avahi/Bonjour discovery" ;;
        5432) echo "OK|PostgreSQL — Database" ;;
        5900) echo "REVIEW|VNC — Remote Desktop (unencrypted)" ;;
        6000) echo "REVIEW|X11 — Display Server" ;;
        8008) echo "REVIEW|HTTP alternate" ;;
        8009) echo "REVIEW|Apache JServ (AJP)" ;;
        8080) echo "REVIEW|HTTP alternate / Proxy" ;;
        8180) echo "REVIEW|Apache Tomcat" ;;
        8443) echo "OK|HTTPS alternate" ;;
        8888) echo "REVIEW|Jupyter Notebook / HTTP alt" ;;
        9200) echo "REVIEW|Elasticsearch REST API" ;;
        9300) echo "REVIEW|Elasticsearch cluster" ;;
        11434) echo "OK|Ollama — Local AI server" ;;
        27017) echo "REVIEW|MongoDB — Database" ;;
        *)    echo "REVIEW|Unknown port — verify manually" ;;
    esac
}

# =============================================================================
# EXTRACT SERVICE FROM CGROUP
# =============================================================================
extract_service() {
    # Extracts the systemd service name from a cgroup path
    # e.g. /system.slice/avahi-daemon.service → avahi-daemon
    local cgroup="$1"
    echo "${cgroup}" | grep -oP '[^/]+\.service' | sed 's/\.service//' || echo "unknown"
}

# =============================================================================
# GET USERNAME FROM UID
# =============================================================================
uid_to_user() {
    local uid="$1"
    getent passwd "${uid}" 2>/dev/null | cut -d: -f1 || echo "uid:${uid}"
}

# =============================================================================
# PROCESS AUDIT
# =============================================================================
check_suspicious_processes() {
    section_header "⚡ Process Audit"

    local suspicious_path_regex
    suspicious_path_regex=$(echo "${SUSPICIOUS_PATHS}" | tr ',' '|' | sed 's|/|\\/|g')

    local whitelist_proc_regex=""
    if [[ -n "${WHITELIST_SUSPICIOUS_PROCS:-}" ]]; then
        whitelist_proc_regex=$(echo "${WHITELIST_SUSPICIOUS_PROCS}" | tr ',' '|')
    fi

    local flagged=0 proc_count=0
    local alert_rows=() warn_rows=()

    for pid_dir in /proc/[0-9]*/; do
        local pid
        pid=$(basename "${pid_dir}")
        [[ ! -d "${pid_dir}" ]] && continue
        local exe
        exe=$(readlink "${pid_dir}exe" 2>/dev/null || echo "")
        [[ -z "${exe}" ]] && continue
        local pname uid
        pname=$(awk '/^Name:/{print $2}' "${pid_dir}status" 2>/dev/null || echo "unknown")
        uid=$(awk '/^Uid:/{print $2}' "${pid_dir}status" 2>/dev/null || echo "?")
        (( proc_count++ )) || true

        # Check 1: suspicious path
        if echo "${exe}" | grep -qE "(${suspicious_path_regex/,/|})"; then
            local whitelisted=0
            [[ -n "${whitelist_proc_regex}" ]] && \
                echo "${pname}" | grep -qE "(${whitelist_proc_regex})" && whitelisted=1
            if [[ "${whitelisted}" -eq 0 ]]; then
                local cmdline
                cmdline=$(tr '\0' ' ' < "${pid_dir}cmdline" 2>/dev/null | head -c 80 || echo "")
                alert_rows+=("  $(badge ALERT) PID=${pid} name=${pname}")
                alert_rows+=("    exe:  ${exe}")
                alert_rows+=("    cmd:  ${cmdline}")
                emit_alert --severity CRITICAL --module "${MOD}" --event suspicious_path_process \
                    --detail "Process from suspicious path: ${exe} (pid=${pid}, uid=${uid})" \
                    --target "${exe}" --pid "${pid}"
                _flag 2; (( flagged++ )) || true
            fi
        fi

        # Check 2: deleted binary
        if [[ "${exe}" == *" (deleted)" ]]; then
            alert_rows+=("  $(badge ALERT) PID=${pid} name=${pname} — DELETED BINARY!")
            alert_rows+=("    exe: ${exe}")
            emit_alert --severity CRITICAL --module "${MOD}" --event deleted_binary \
                --detail "Process binary deleted: ${exe} (pid=${pid})" \
                --target "${exe}" --pid "${pid}"
            _flag 2; (( flagged++ )) || true
        fi

        # Check 3: root process from home directory
        if [[ "${uid}" == "0" ]] && echo "${exe}" | grep -qE '^/home/|^/root/'; then
            warn_rows+=("  $(badge REVIEW) PID=${pid} name=${pname} — root from home dir")
            warn_rows+=("    exe: ${exe}")
            emit_alert --severity WARN --module "${MOD}" --event root_home_process \
                --detail "Root process from home dir: ${exe} (pid=${pid})" \
                --target "${exe}" --pid "${pid}"
            _flag 1; (( flagged++ )) || true
        fi
    done

    echo ""
    paste \
        <(counter_box "Running Processes ⚡" "${proc_count}" "OK" "active") \
        <(counter_box "Suspicious 🚨" "${flagged}" \
            "$([ $flagged -eq 0 ] && echo OK || echo ALERT)" "flagged") 2>/dev/null || true
    echo ""

    [[ "${#alert_rows[@]}" -gt 0 ]] && alert_box \
        "$(gum style --foreground 196 --bold "🚨 Suspicious processes:")" "" "${alert_rows[@]}"
    [[ "${#warn_rows[@]}" -gt 0 ]] && warn_box \
        "$(gum style --foreground 214 --bold "⚠  Processes requiring review:")" "" "${warn_rows[@]}"
    [[ "${flagged}" -eq 0 ]] && ok_box "$(badge OK) No suspicious processes found"
}

# =============================================================================
# HIGH CPU / RAM
# =============================================================================
check_resource_hogs() {
    section_header "📊 Resource Usage (Top Consumers)"

    # Afficher le top 5 processus CPU et RAM même sans seuil d'alerte
    local rows=()
    rows+=("$(gum style --bold --foreground 212 \
        "$(printf '%-7s %-14s %-6s %-6s %-8s %-8s %-6s %s' \
            'PID' 'NAME' 'CPU%' 'MEM%' 'USER' 'STAT' 'START' 'TIME')")")
    rows+=("$(gum style --foreground 240 \
        "$(printf '%-7s %-14s %-6s %-6s %-8s %-8s %-6s %s' \
            '───────' '──────────────' '──────' '──────' '────────' '────────' '──────' '──────')")")
    local has_alert=0
    while IFS= read -r line; do
        local pid cpu mem cmd user exe status color vsz rss stat start time
        pid=$(echo "${line}"   | awk '{print $2}')
        cpu=$(echo "${line}"   | awk '{print $3}')
        mem=$(echo "${line}"   | awk '{print $4}')
        vsz=$(echo "${line}"   | awk '{print $5}')
        rss=$(echo "${line}"   | awk '{print $6}')
        stat=$(echo "${line}"  | awk '{print $8}')
        start=$(echo "${line}" | awk '{print $9}')
        time=$(echo "${line}"  | awk '{print $10}')
        cmd=$(echo "${line}"   | awk '{print $11}' | xargs basename 2>/dev/null || echo "?")
        user=$(echo "${line}"  | awk '{print $1}')
        exe=$(readlink "/proc/${pid}/exe" 2>/dev/null || echo "?")

        # Classifier
        local cpu_int=${cpu%.*}
        local mem_int=${mem%.*}
        color=82; status="OK"
        if [[ "${THRESHOLD_PROC_CPU}" -gt 0 ]] && \
           awk "BEGIN { exit !(${cpu}+0 >= ${THRESHOLD_PROC_CPU}+0) }"; then
            color=196; status="ALERT"
            emit_alert --severity WARN --module "${MOD}" --event high_cpu_process \
                --detail "Process ${cmd} (pid=${pid}) consuming ${cpu}% CPU" \
                --target "${cmd}" --pid "${pid}"
            _flag 1; has_alert=1
        elif awk "BEGIN { exit !(${cpu}+0 >= 50) }"; then
            color=214; status="REVIEW"
        fi
        if [[ "${THRESHOLD_PROC_MEM}" -gt 0 ]] && \
           awk "BEGIN { exit !(${mem}+0 >= ${THRESHOLD_PROC_MEM}+0) }"; then
            color=196; status="ALERT"
            emit_alert --severity WARN --module "${MOD}" --event high_mem_process \
                --detail "Process ${cmd} (pid=${pid}) consuming ${mem}% RAM" \
                --target "${cmd}" --pid "${pid}"
            _flag 1; has_alert=1
        fi

        # Détecter processus zombie ou uninterruptible (dangereux)
        local stat_color="${color}"
        [[ "${stat}" == Z* ]] && stat_color=196   # Zombie = rouge
        [[ "${stat}" == D* ]] && stat_color=214   # Uninterruptible = orange

         rows+=("$(gum style --foreground "${color}" --bold \
            "$(printf '%-7s %-14s %-6s %-6s %-8s %-8s %-6s %s' \
                "${pid}" "${cmd:0:13}" "${cpu}%" "${mem}%" \
                "${user:0:7}" "${stat}" "${start}" "${time}")")")
        rows+=("$(gum style --foreground 245 \
            "$(printf '         ↳ exe: %s' "${exe}")")")
    done < <(ps aux --no-headers 2>/dev/null | sort -k3 -rn | head -8)

    gum style --border rounded \
        --border-foreground "$([ $has_alert -eq 1 ] && echo 196 || echo 82)" \
        --width 70 --padding "0 1" "${rows[@]}"
}

# =============================================================================
# LISTENING PORTS — FULL DETAIL
# =============================================================================
check_listening_ports() {
    section_header "🔌 Listening Ports — Full Inventory"

    local wl_ports="${WHITELIST_PORTS:-}"
    if [[ -f "${WHITELIST_PORTS_FILE}" ]]; then
        local file_ports
        file_ports=$(grep -v '^\s*#' "${WHITELIST_PORTS_FILE}" 2>/dev/null | \
            grep -oP '^\d+' | tr '\n' ',' || echo "")
        wl_ports="${wl_ports},${file_ports}"
    fi

    # Ports connus dangereux — toujours ALERT
    local danger_ports="4444,1337,31337,6666,6667,1524,12345,31338,54321,512,513,514"
    local danger_regex
    danger_regex=$(echo "${danger_ports}" | tr ',' '|')

    local total=0 ok_count=0 review_count=0 alert_count=0
    local all_rows=() alert_rows=() warn_rows=()

    # En-tête du tableau
    all_rows+=("$(gum style --bold --foreground 212 \
        "$(printf '%-8s %-6s %-22s %-6s %-18s %-8s %s' \
            'STATUS' 'PROTO' 'LOCAL ADDRESS' 'PORT' 'SERVICE/PROCESS' 'UID/USER' 'DESCRIPTION')")")
    all_rows+=("$(gum style --foreground 240 \
        "$(printf '%-8s %-6s %-22s %-6s %-18s %-8s %s' \
            '────────' '──────' '──────────────────────' '──────' '──────────────────' '────────' '───────────')")")

    # Lire tous les ports avec informations complètes via ss -tulnpe
    while IFS= read -r line; do
        local proto state local_addr port uid_raw cgroup_raw service user classification desc color

        proto=$(echo "${line}"      | awk '{print $1}')
        state=$(echo "${line}"      | awk '{print $2}')
        local_addr=$(echo "${line}" | awk '{print $5}')
        port=$(echo "${local_addr}" | rev | cut -d: -f1 | rev)
        [[ "${port}" == "*" || -z "${port}" || ! "${port}" =~ ^[0-9]+$ ]] && continue

        # Extraire UID depuis la ligne ss
        uid_raw=$(echo "${line}" | grep -oP 'uid:\K[0-9]+' || echo "")
        user=$([ -n "${uid_raw}" ] && uid_to_user "${uid_raw}" || echo "system")

        # Extraire le cgroup (= service systemd)
        cgroup_raw=$(echo "${line}" | grep -oP 'cgroup:\K\S+' || echo "")
        service=$(extract_service "${cgroup_raw}")
        [[ "${service}" == "unknown" ]] && \
            service=$(echo "${line}" | grep -oP '"[^"]+"' | head -1 | tr -d '"' || echo "unknown")

        # Adresse locale simplifiée
        local addr_short
        addr_short=$(echo "${local_addr}" | sed 's/127\.0\.0\.[0-9]*/localhost/g' | \
                     sed 's/0\.0\.0\.0/0.0.0.0/g' | sed 's/\[::1\]/[::1]/g' | \
                     sed 's/\[::\]/[::]/g')
        addr_short="${addr_short%:*}"  # enlever le port

        (( total++ )) || true

        # Classification du port
        local class_result
        class_result=$(classify_port "${port}" "${proto}")
        classification=$(echo "${class_result}" | cut -d'|' -f1)
        desc=$(echo "${class_result}" | cut -d'|' -f2)

        # Override : ports dangereux = toujours ALERT
        if echo "${port}" | grep -qE "^(${danger_regex})$"; then
            classification="ALERT"
        fi

        # Couleur selon classification
        case "${classification}" in
            OK)     color=82;  (( ok_count++ ))     || true ;;
            REVIEW) color=214; (( review_count++ ))  || true ;;
            ALERT)  color=196; (( alert_count++ ))   || true ;;
        esac

        # Ligne du tableau
        all_rows+=("$(gum style --foreground "${color}" \
            "$(printf '%-8s %-6s %-22s %-6s %-18s %-8s %s' \
                "${classification}" \
                "${proto}" \
                "${addr_short:0:21}" \
                "${port}" \
                "${service:0:17}" \
                "${user:0:7}" \
                "${desc}")")")

        # Alertes pour ports dangereux
        if [[ "${classification}" == "ALERT" ]]; then
            alert_rows+=("  $(badge ALERT) Port ${port}/${proto} — ${service} (user: ${user})")
            alert_rows+=("    Address: ${local_addr}  |  ${desc}")
            emit_alert --severity CRITICAL --module "${MOD}" --event dangerous_port \
                --detail "Dangerous port listening: ${port}/${proto} — ${service} (${desc})" \
                --target "${port}"
            _flag 2
        fi

        # Alertes pour ports REVIEW non whitelistés
        if [[ "${classification}" == "REVIEW" ]]; then
            warn_rows+=("  $(badge REVIEW) Port ${port}/${proto} — ${service} (user: ${user}) — ${desc}")
            emit_alert --severity WARN --module "${MOD}" --event unexpected_port \
                --detail "Unusual port: ${port}/${proto} — ${service} (${desc})" \
                --target "${port}"
            _flag 1
        fi

    done < <(ss -tulnpe 2>/dev/null | awk 'NR>1')

    # Compteurs
    echo ""
    paste \
        <(counter_box "Total 🔌" "${total}"        "OK"     "listening") \
        <(counter_box "OK ✅"    "${ok_count}"     "OK"     "known services") \
        <(counter_box "Review ⚠️" "${review_count}" "$([ $review_count -eq 0 ] && echo OK || echo REVIEW)" "check") \
        <(counter_box "Alert 🚨"  "${alert_count}"  "$([ $alert_count  -eq 0 ] && echo OK || echo ALERT)"  "danger") \
        2>/dev/null || true

    echo ""

    # Tableau complet
    gum style \
        --border rounded \
        --border-foreground "$([ $alert_count -gt 0 ] && echo 196 || [ $review_count -gt 0 ] && echo 214 || echo 82)" \
        --width 70 --padding "0 1" \
        "${all_rows[@]}"

    echo ""

    # Alertes spécifiques
    [[ "${#alert_rows[@]}" -gt 0 ]] && alert_box \
        "$(gum style --foreground 196 --bold "🚨 DANGEROUS ports detected:")" "" "${alert_rows[@]}"

    [[ "${#warn_rows[@]}" -gt 0 ]] && warn_box \
        "$(gum style --foreground 214 --bold "⚠  Ports requiring attention:")" "" "${warn_rows[@]}"

    [[ "${alert_count}" -eq 0 && "${review_count}" -eq 0 ]] && \
        ok_box "$(badge OK) All listening ports are well-known legitimate services"
}

# =============================================================================
# ESTABLISHED CONNECTIONS — FULL DETAIL
# =============================================================================
check_established_connections() {
    section_header "🌐 Established Connections"

    local flagged_ports_regex
    flagged_ports_regex=$(echo "${ALERT_OUTBOUND_PORTS}" | tr ',' '|')

    local total=0 flagged=0
    local alert_rows=() info_rows=()

    # En-tête
    info_rows+=("$(gum style --bold --foreground 212 \
        "$(printf '%-8s %-6s %-22s %-22s %-18s %s' \
            'STATUS' 'PROTO' 'LOCAL' 'REMOTE' 'PROCESS' 'NOTE')")")
    info_rows+=("$(gum style --foreground 240 \
        "$(printf '%-8s %-6s %-22s %-22s %-18s %s' \
            '────────' '──────' '──────────────────────' '──────────────────────' '──────────────────' '────')")")

    while IFS= read -r line; do
        local proto local_addr peer_addr peer_port peer_ip proc pid exe color status note

        proto=$(echo "${line}"      | awk '{print $1}')
        local_addr=$(echo "${line}" | awk '{print $5}')
        peer_addr=$(echo "${line}"  | awk '{print $6}')
        peer_port=$(echo "${peer_addr}" | rev | cut -d: -f1 | rev)
        peer_ip=$(echo "${peer_addr}"   | rev | cut -d: -f2- | rev)

        local users_col
        users_col=$(echo "${line}" | awk '{print $NF}')
        proc=$(echo "${users_col}" | grep -oP '"[^"]*"' | head -1 | tr -d '"' || echo "unknown")
        pid=$(echo "${users_col}"  | grep -oP 'pid=\d+' | head -1 | grep -oP '\d+' || echo "?")

        (( total++ )) || true
        color=82; status="OK"; note="normal"

        # Check 1: port dangereux sortant
        if echo "${peer_port}" | grep -qE "^(${flagged_ports_regex})$" 2>/dev/null; then
            color=196; status="ALERT"; note="⚠ flagged outbound port!"
            alert_rows+=("  $(badge ALERT) ${proc} (pid=${pid}) → ${peer_ip}:${peer_port}")
            alert_rows+=("    Outbound connection to known attacker port — investigate immediately!")
            emit_alert --severity CRITICAL --module "${MOD}" --event suspicious_outbound \
                --detail "Outbound to flagged port ${peer_port} → ${peer_ip} (${proc})" \
                --target "${peer_ip}:${peer_port}" --pid "${pid}"
            _flag 2; (( flagged++ )) || true
        fi

        # Check 2: processus depuis chemin suspect
        if [[ -n "${pid}" && "${pid}" != "?" ]]; then
            exe=$(readlink "/proc/${pid}/exe" 2>/dev/null || echo "")
            local suspicious_regex
            suspicious_regex=$(echo "${SUSPICIOUS_PATHS}" | tr ',' '|')
            if [[ -n "${exe}" ]] && echo "${exe}" | grep -qE "(${suspicious_regex})"; then
                color=196; status="ALERT"; note="⚠ suspicious path process!"
                alert_rows+=("  $(badge ALERT) ${exe} → ${peer_ip}:${peer_port}")
                emit_alert --severity CRITICAL --module "${MOD}" --event suspicious_path_network \
                    --detail "Suspicious process connected: ${exe} → ${peer_ip}:${peer_port}" \
                    --target "${exe}" --pid "${pid}"
                _flag 2; (( flagged++ )) || true
            fi
        fi

        # Classification de la connexion distante
        local class_result desc
        class_result=$(classify_port "${peer_port}" "${proto}")
        local port_class
        port_class=$(echo "${class_result}" | cut -d'|' -f1)
        desc=$(echo "${class_result}" | cut -d'|' -f2)
        [[ "${port_class}" == "REVIEW" && "${status}" == "OK" ]] && \
            color=214 && status="REVIEW" && note="${desc}"
        [[ "${port_class}" == "ALERT" && "${status}" == "OK" ]] && \
            color=196 && status="ALERT" && note="⚠ ${desc}"

        info_rows+=("$(gum style --foreground "${color}" \
            "$(printf '%-8s %-6s %-22s %-22s %-18s %s' \
                "${status}" "${proto}" \
                "${local_addr:0:21}" "${peer_addr:0:21}" \
                "${proc:0:17}" "${note}")")")

    done < <(ss -tunp state established 2>/dev/null | awk 'NR>1')

    if [[ "${total}" -eq 0 ]]; then
        ok_box "$(badge OK) No established connections"
        return
    fi

    echo ""
    paste \
        <(counter_box "Connections 🌐" "${total}"   "OK"    "established") \
        <(counter_box "Suspicious 🚨"  "${flagged}" "$([ $flagged -eq 0 ] && echo OK || echo ALERT)" "flagged") \
        2>/dev/null || true
    echo ""

    gum style \
        --border rounded \
        --border-foreground "$([ $flagged -gt 0 ] && echo 196 || echo 82)" \
        --width 70 --padding "0 1" \
        "${info_rows[@]}"

    echo ""
    [[ "${#alert_rows[@]}" -gt 0 ]] && alert_box \
        "$(gum style --foreground 196 --bold "🚨 Suspicious connections:")" "" "${alert_rows[@]}"
    [[ "${flagged}" -eq 0 ]] && ok_box "$(badge OK) No suspicious established connections"
}

# =============================================================================
# PORT BASELINE DIFF
# =============================================================================
check_port_baseline_diff() {
    section_header "📋 Port Changes vs Baseline"

    local bl_ports="${HIDS_DATA_DIR}/baseline/listening_ports.list"
    if [[ ! -f "${bl_ports}" ]]; then
        info_box "$(badge INFO) No port baseline — skipping comparison"
        return
    fi

    local current_ports
    current_ports=$(ss -tulnp 2>/dev/null | \
        awk 'NR>1 {n=split($5,a,":"); print a[n]}' | \
        grep -E '^[0-9]+$' | sort -n | uniq)

    local baseline_ports
    baseline_ports=$(awk -F: '{print $2}' "${bl_ports}" | sort -n | uniq)

    local new_ports closed_ports
    new_ports=$(comm -23 \
        <(echo "${current_ports}") \
        <(echo "${baseline_ports}") 2>/dev/null || true)
    closed_ports=$(comm -13 \
        <(echo "${current_ports}") \
        <(echo "${baseline_ports}") 2>/dev/null || true)

    local has_changes=0

    if [[ -n "${new_ports}" ]]; then
        has_changes=1
        local warn_rows=()
        warn_rows+=("$(gum style --foreground 214 --bold "⚠  New ports since baseline:")")
        warn_rows+=("")
        while IFS= read -r port; do
            [[ -z "${port}" ]] && continue
            local class_result desc
            class_result=$(classify_port "${port}" "tcp")
            desc=$(echo "${class_result}" | cut -d'|' -f2)
            local cls
            cls=$(echo "${class_result}" | cut -d'|' -f1)
            warn_rows+=("  $(badge "${cls}") Port ${port} — ${desc}")
            emit_alert --severity WARN --module "${MOD}" --event new_port_since_baseline \
                --detail "New listening port since baseline: ${port} (${desc})" \
                --target "${port}"
            _flag 1
        done <<< "${new_ports}"
        warn_box "${warn_rows[@]}"
    fi

    if [[ -n "${closed_ports}" ]]; then
        has_changes=1
        local info_rows=()
        info_rows+=("$(gum style --foreground 33 --bold "ℹ  Ports closed since baseline:")")
        info_rows+=("")
        while IFS= read -r port; do
            [[ -z "${port}" ]] && continue
            info_rows+=("  $(badge INFO) Port ${port} — no longer listening")
        done <<< "${closed_ports}"
        info_box "${info_rows[@]}"
    fi

    [[ "${has_changes}" -eq 0 ]] && \
        ok_box "$(badge OK) Port inventory matches baseline — no changes detected"
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    echo ""
    gum style \
        --foreground 212 --border-foreground 212 --border double \
        --align center --width 72 --padding "1 2" \
        "⚡  HIDS — PROCESS AND NETWORK AUDIT" \
        "Host: $(hostname) | $(date '+%Y-%m-%d %H:%M:%S')"

    check_suspicious_processes
    check_resource_hogs
    check_listening_ports
    check_established_connections
    check_port_baseline_diff

    echo ""
    local assess_color=82
    local assess_icon="✅"
    local assess_msg="All process and network checks passed"
    case "${_worst}" in
        1) assess_color=214; assess_icon="⚠️ "; assess_msg="Some process/network activity requires attention" ;;
        2) assess_color=196; assess_icon="🚨"; assess_msg="Critical process or network threat detected!" ;;
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
