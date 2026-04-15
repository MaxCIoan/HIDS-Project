#!/usr/bin/env bash
# =============================================================================
# mod_history.sh — Module 6: Health History & Trend Analysis (GUM Edition)
# =============================================================================
# Records CPU load, RAM usage, and disk usage at every scan run.
# Detects dangerous trends (steadily rising load, shrinking RAM, filling disk).
# Displays ASCII sparkline charts of the last N data points.
#
# Data source:
#   /proc/loadavg      → CPU load average
#   /proc/meminfo      → RAM usage
#   df                 → Disk usage
#
# Storage:
#   ${HIDS_DATA_DIR}/history/cpu.csv
#   ${HIDS_DATA_DIR}/history/ram.csv
#   ${HIDS_DATA_DIR}/history/disk.csv
#   Format: epoch,timestamp,value
#
# Returns:
#   0 = all trends healthy
#   1 = at least one concerning trend (WARN)
#   2 = at least one dangerous trend (CRITICAL)
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/lib_utils.sh"
load_config

MOD="mod_history"
_worst=0
_flag() { [[ "$1" -gt "${_worst}" ]] && _worst="$1" || true; }

# --- Configuration ---
HISTORY_DIR="${HIDS_DATA_DIR}/history"
HISTORY_MAX_POINTS=288        # 288 points × 5min = 24h de données
TREND_WINDOW=12               # 12 derniers points pour calculer la tendance (1h)
SPARKLINE_WIDTH=40            # Largeur du graphique ASCII

mkdir -p "${HISTORY_DIR}"

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

ok_box()    { gum style --border rounded --border-foreground 82  --width 68 --padding "0 2" "$@"; }
warn_box()  { gum style --border rounded --border-foreground 214 --width 68 --padding "0 2" "$@"; }
alert_box() { gum style --border rounded --border-foreground 196 --width 68 --padding "0 2" "$@"; }
info_box()  { gum style --border rounded --border-foreground 33  --width 68 --padding "0 2" "$@"; }

# =============================================================================
# COLLECTE DES DONNÉES
# =============================================================================
collect_datapoints() {
    # Collecte CPU load (1min), RAM used%, Disk used% (partition /)
    # et les ajoute dans les fichiers CSV historiques.

    local epoch ts
    epoch=$(date +%s)
    ts=$(date '+%Y-%m-%d %H:%M')

    # --- CPU load (1min) ---
    local cpu_load
    cpu_load=$(awk '{print $1}' /proc/loadavg)
    echo "${epoch},${ts},${cpu_load}" >> "${HISTORY_DIR}/cpu.csv"

    # --- RAM used% ---
    local mem_total mem_avail mem_used_pct
    mem_total=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
    mem_avail=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
    mem_used_pct=$(awk "BEGIN { printf \"%.1f\", (1 - ${mem_avail}/${mem_total}) * 100 }")
    echo "${epoch},${ts},${mem_used_pct}" >> "${HISTORY_DIR}/ram.csv"

    # --- Disk used% (partition /) ---
    local disk_pct
    disk_pct=$(df / 2>/dev/null | awk 'NR==2 {gsub(/%/,""); print $5}')
    echo "${epoch},${ts},${disk_pct}" >> "${HISTORY_DIR}/disk.csv"

    # --- Rotation : garder seulement les N derniers points ---
    for f in "${HISTORY_DIR}/cpu.csv" "${HISTORY_DIR}/ram.csv" "${HISTORY_DIR}/disk.csv"; do
        local lines
        lines=$(wc -l < "${f}" 2>/dev/null || echo 0)
        if [[ "${lines}" -gt "${HISTORY_MAX_POINTS}" ]]; then
            local excess=$(( lines - HISTORY_MAX_POINTS ))
            tail -n "+$((excess + 1))" "${f}" > "${f}.tmp" && mv "${f}.tmp" "${f}"
        fi
    done
}

# =============================================================================
# SPARKLINE ASCII
# =============================================================================
draw_sparkline() {
    # Dessine un graphique ASCII de la tendance.
    # Usage: draw_sparkline <fichier.csv> <largeur> <min> <max>
    local csvfile="$1"
    local width="${2:-${SPARKLINE_WIDTH}}"
    local force_min="${3:-}"
    local force_max="${4:-}"

    # Extraire les N dernières valeurs
    local values
    values=$(tail -n "${width}" "${csvfile}" 2>/dev/null | awk -F',' '{print $3}' || echo "")

    [[ -z "${values}" ]] && echo "(pas encore de données)" && return

    local min max
    if [[ -n "${force_min}" ]]; then
        min="${force_min}"
        max="${force_max}"
    else
        min=$(echo "${values}" | awk 'BEGIN{m=999999} {if($1+0<m+0)m=$1} END{printf "%.1f",m}')
        max=$(echo "${values}" | awk 'BEGIN{m=-999999} {if($1+0>m+0)m=$1} END{printf "%.1f",m}')
    fi

    # Caractères sparkline du plus bas au plus haut
    local chars="▁▂▃▄▅▆▇█"
    local spark=""

    while IFS= read -r val; do
        [[ -z "${val}" ]] && continue
        local normalized
        # Normaliser entre 0 et 7
        normalized=$(awk -v v="${val}" -v mn="${min}" -v mx="${max}" \
            'BEGIN {
                range = mx - mn
                if (range == 0) { print 3; exit }
                idx = int((v - mn) / range * 7)
                if (idx < 0) idx = 0
                if (idx > 7) idx = 7
                print idx
            }')
        local char="${chars:${normalized}:1}"
        spark+="${char}"
    done <<< "${values}"

    echo "${spark}"
}

# =============================================================================
# ANALYSE DE TENDANCE
# =============================================================================
analyze_trend() {
    # Calcule la tendance linéaire sur les N derniers points.
    # Retourne: "rising", "falling", "stable"
    # et le delta (différence entre premier et dernier point de la fenêtre)
    local csvfile="$1"
    local window="${2:-${TREND_WINDOW}}"

    local values
    values=$(tail -n "${window}" "${csvfile}" 2>/dev/null | awk -F',' '{print $3}' || echo "")

    local count
    count=$(echo "${values}" | grep -c '.' 2>/dev/null || echo 0)

    [[ "${count}" -lt 3 ]] && echo "stable|0" && return

    # Calculer la tendance par régression linéaire simple
    local trend_info
    trend_info=$(echo "${values}" | awk '
    {
        vals[NR] = $1
        sum += $1
        n++
    }
    END {
        if (n < 2) { print "stable|0"; exit }
        mean = sum / n
        # Calcul pente (slope) par méthode des moindres carrés
        sumxy = 0; sumx2 = 0
        for (i = 1; i <= n; i++) {
            x = i - (n+1)/2
            sumxy += x * (vals[i] - mean)
            sumx2 += x * x
        }
        slope = (sumx2 > 0) ? sumxy / sumx2 : 0
        first = vals[1]; last = vals[n]
        delta = last - first
        if (slope > 0.5) direction = "rising"
        else if (slope < -0.5) direction = "falling"
        else direction = "stable"
        printf "%s|%.1f|%.1f|%.1f\n", direction, delta, first, last
    }')

    echo "${trend_info}"
}

# =============================================================================
# MODULE CPU HISTORY
# =============================================================================
check_cpu_history() {
    section_header "📈 CPU Load — Historical Trend"

    local csvfile="${HISTORY_DIR}/cpu.csv"
    local nproc
    nproc=$(nproc 2>/dev/null || echo 2)
    local threshold
    threshold=$(awk "BEGIN { printf \"%.1f\", ${LOAD_MULTIPLIER} * ${nproc} }")

    local count
    count=$(wc -l < "${csvfile}" 2>/dev/null || echo 0)

    if [[ "${count}" -lt 2 ]]; then
        info_box "$(badge INFO) Not enough data yet — need at least 2 scans ($(( 2 - count )) more scan(s) needed)"
        return
    fi

    # Tendance
    local trend_info direction delta first last
    trend_info=$(analyze_trend "${csvfile}")
    direction=$(echo "${trend_info}" | cut -d'|' -f1)
    delta=$(echo "${trend_info}" | cut -d'|' -f2)
    first=$(echo "${trend_info}" | cut -d'|' -f3)
    last=$(echo "${trend_info}" | cut -d'|' -f4)

    # Dernière valeur et max
    local current max_val
    current=$(tail -1 "${csvfile}" | awk -F',' '{print $3}')
    max_val=$(awk -F',' 'BEGIN{m=0} {if($3+0>m+0)m=$3} END{printf "%.2f",m}' "${csvfile}")

    # Sparkline
    local spark
    spark=$(draw_sparkline "${csvfile}" 40 0 "${threshold}")

    # Évaluation
    local status trend_icon trend_msg
    case "${direction}" in
        rising)
            if awk "BEGIN { exit !(${last}+0 > ${threshold}*0.8+0) }"; then
                status="ALERT"; trend_icon="📈🔴"
                trend_msg="CPU load rising dangerously toward threshold!"
                emit_alert --severity CRITICAL --module "${MOD}" --event cpu_trend_critical \
                    --detail "CPU load trending UP: ${first} → ${last} (threshold: ${threshold})" \
                    --target "cpu"
                _flag 2
            else
                status="REVIEW"; trend_icon="📈🟡"
                trend_msg="CPU load is rising — monitor closely"
                _flag 1
            fi
            ;;
        falling) status="OK"; trend_icon="📉🟢"; trend_msg="CPU load is decreasing — good sign" ;;
        stable)  status="OK"; trend_icon="➡️ 🟢"; trend_msg="CPU load is stable" ;;
    esac

    echo ""
    # Afficher le graphique
    gum style --border rounded --border-foreground "$([ "$status" = "OK" ] && echo 82 || [ "$status" = "REVIEW" ] && echo 214 || echo 196)" \
        --width 68 --padding "0 2" \
        "$(gum style --foreground 212 --bold "CPU Load Trend (last ${count} scans × 5min = ~$((count * 5))min)")" \
        "" \
        "$(gum style --foreground 82 "${spark}")" \
        "" \
        "$(gum style --foreground 245 "Min: 0.00  Max: ${max_val}  Threshold: ${threshold}  nproc: ${nproc}")"

    echo ""
    paste \
        <(gum style --border rounded --border-foreground 33 --width 20 --padding "0 1" \
            "$(gum style --foreground 33 --bold "Current")" \
            "$(gum style --foreground 255 --bold " ${current}")" \
            "load avg") \
        <(gum style --border rounded --border-foreground 33 --width 20 --padding "0 1" \
            "$(gum style --foreground 33 --bold "Peak")" \
            "$(gum style --foreground 255 --bold " ${max_val}")" \
            "max observed") \
        <(gum style --border rounded --border-foreground 33 --width 20 --padding "0 1" \
            "$(gum style --foreground 33 --bold "Delta")" \
            "$(gum style --foreground 255 --bold " ${delta}")" \
            "over window") 2>/dev/null || true

    echo ""
    local box_color=82; [[ "$status" == "REVIEW" ]] && box_color=214; [[ "$status" == "ALERT" ]] && box_color=196
    gum style --border rounded --border-foreground "${box_color}" --width 68 --padding "0 2" \
        "$(badge "${status}") ${trend_icon} ${trend_msg}"
}

# =============================================================================
# MODULE RAM HISTORY
# =============================================================================
check_ram_history() {
    section_header "🧠 RAM Usage — Historical Trend"

    local csvfile="${HISTORY_DIR}/ram.csv"

    local count
    count=$(wc -l < "${csvfile}" 2>/dev/null || echo 0)

    if [[ "${count}" -lt 2 ]]; then
        info_box "$(badge INFO) Not enough data yet — need at least 2 scans ($(( 2 - count )) more scan(s) needed)"
        return
    fi

    local trend_info direction delta first last
    trend_info=$(analyze_trend "${csvfile}")
    direction=$(echo "${trend_info}" | cut -d'|' -f1)
    delta=$(echo "${trend_info}" | cut -d'|' -f2)
    first=$(echo "${trend_info}" | cut -d'|' -f3)
    last=$(echo "${trend_info}" | cut -d'|' -f4)

    local current max_val
    current=$(tail -1 "${csvfile}" | awk -F',' '{print $3}')
    max_val=$(awk -F',' 'BEGIN{m=0} {if($3+0>m+0)m=$3} END{printf "%.1f",m}' "${csvfile}")

    local spark
    spark=$(draw_sparkline "${csvfile}" 40 0 100)

    # RAM qui monte = mauvais signe (mémoire se remplit)
    local status trend_icon trend_msg
    case "${direction}" in
        rising)
            if awk "BEGIN { exit !(${last}+0 > 85) }"; then
                status="ALERT"; trend_icon="📈🔴"
                trend_msg="RAM usage rising critically — possible memory leak!"
                emit_alert --severity CRITICAL --module "${MOD}" --event ram_trend_critical \
                    --detail "RAM usage trending UP: ${first}% → ${last}% (>85%)" \
                    --target "ram"
                _flag 2
            elif awk "BEGIN { exit !(${last}+0 > 70) }"; then
                status="REVIEW"; trend_icon="📈🟡"
                trend_msg="RAM usage increasing — watch for memory pressure"
                emit_alert --severity WARN --module "${MOD}" --event ram_trend_warn \
                    --detail "RAM usage trending UP: ${first}% → ${last}%" \
                    --target "ram"
                _flag 1
            else
                status="OK"; trend_icon="📈🟢"; trend_msg="RAM usage rising but within normal range"
            fi
            ;;
        falling) status="OK"; trend_icon="📉🟢"; trend_msg="RAM usage is decreasing — freeing up memory" ;;
        stable)  status="OK"; trend_icon="➡️ 🟢"; trend_msg="RAM usage is stable" ;;
    esac

    echo ""
    gum style --border rounded --border-foreground "$([ "$status" = "OK" ] && echo 82 || [ "$status" = "REVIEW" ] && echo 214 || echo 196)" \
        --width 68 --padding "0 2" \
        "$(gum style --foreground 212 --bold "RAM Usage Trend (last ${count} scans × 5min = ~$((count * 5))min)")" \
        "" \
        "$(gum style --foreground 82 "${spark}")" \
        "" \
        "$(gum style --foreground 245 "Range: 0%–100%  Peak: ${max_val}%  Warning: >70%  Critical: >85%")"

    echo ""
    paste \
        <(gum style --border rounded --border-foreground 33 --width 20 --padding "0 1" \
            "$(gum style --foreground 33 --bold "Current")" \
            "$(gum style --foreground 255 --bold " ${current}%")" \
            "RAM used") \
        <(gum style --border rounded --border-foreground 33 --width 20 --padding "0 1" \
            "$(gum style --foreground 33 --bold "Peak")" \
            "$(gum style --foreground 255 --bold " ${max_val}%")" \
            "max observed") \
        <(gum style --border rounded --border-foreground 33 --width 20 --padding "0 1" \
            "$(gum style --foreground 33 --bold "Delta")" \
            "$(gum style --foreground 255 --bold " ${delta}%")" \
            "over window") 2>/dev/null || true

    echo ""
    local box_color=82; [[ "$status" == "REVIEW" ]] && box_color=214; [[ "$status" == "ALERT" ]] && box_color=196
    gum style --border rounded --border-foreground "${box_color}" --width 68 --padding "0 2" \
        "$(badge "${status}") ${trend_icon} ${trend_msg}"
}

# =============================================================================
# MODULE DISK HISTORY
# =============================================================================
check_disk_history() {
    section_header "💽 Disk Usage — Historical Trend (/)"

    local csvfile="${HISTORY_DIR}/disk.csv"

    local count
    count=$(wc -l < "${csvfile}" 2>/dev/null || echo 0)

    if [[ "${count}" -lt 2 ]]; then
        info_box "$(badge INFO) Not enough data yet — need at least 2 scans ($(( 2 - count )) more scan(s) needed)"
        return
    fi

    local trend_info direction delta first last
    trend_info=$(analyze_trend "${csvfile}")
    direction=$(echo "${trend_info}" | cut -d'|' -f1)
    delta=$(echo "${trend_info}" | cut -d'|' -f2)
    first=$(echo "${trend_info}" | cut -d'|' -f3)
    last=$(echo "${trend_info}" | cut -d'|' -f4)

    local current max_val
    current=$(tail -1 "${csvfile}" | awk -F',' '{print $3}')
    max_val=$(awk -F',' 'BEGIN{m=0} {if($3+0>m+0)m=$3} END{print m}' "${csvfile}")

    local spark
    spark=$(draw_sparkline "${csvfile}" 40 0 100)

    # Calculer projection : dans combien de temps le disque sera plein
    local eta_msg=""
    if [[ "${direction}" == "rising" ]] && awk "BEGIN { exit !(${delta}+0 > 0) }"; then
        # Taux de croissance par scan (5min)
        local rate_per_scan
        rate_per_scan=$(awk "BEGIN { printf \"%.4f\", ${delta} / ${TREND_WINDOW} }")
        local remaining
        remaining=$(awk "BEGIN { printf \"%.1f\", 100 - ${current} }")
        if awk "BEGIN { exit !(${rate_per_scan}+0 > 0) }"; then
            local scans_to_full
            scans_to_full=$(awk "BEGIN { printf \"%.0f\", ${remaining} / ${rate_per_scan} }")
            local hours_to_full=$(( scans_to_full * 5 / 60 ))
            eta_msg=" — estimated full in ~${hours_to_full}h at current rate"
        fi
    fi

    local status trend_icon trend_msg
    case "${direction}" in
        rising)
            if awk "BEGIN { exit !(${last}+0 > ${THRESHOLD_DISK_PCT}+0) }"; then
                status="ALERT"; trend_icon="📈🔴"
                trend_msg="Disk filling up FAST — immediate action required!${eta_msg}"
                emit_alert --severity CRITICAL --module "${MOD}" --event disk_trend_critical \
                    --detail "Disk / trending UP: ${first}% → ${last}% (>${THRESHOLD_DISK_PCT}%)${eta_msg}" \
                    --target "/"
                _flag 2
            elif awk "BEGIN { exit !(${last}+0 > $(( THRESHOLD_DISK_PCT - 15 ))+0) }"; then
                status="REVIEW"; trend_icon="📈🟡"
                trend_msg="Disk usage increasing — monitor disk space${eta_msg}"
                _flag 1
            else
                status="OK"; trend_icon="📈🟢"; trend_msg="Disk growing slowly — normal${eta_msg}"
            fi
            ;;
        falling) status="OK"; trend_icon="📉🟢"; trend_msg="Disk usage decreasing — files freed" ;;
        stable)  status="OK"; trend_icon="➡️ 🟢"; trend_msg="Disk usage stable" ;;
    esac

    echo ""
    gum style --border rounded --border-foreground "$([ "$status" = "OK" ] && echo 82 || [ "$status" = "REVIEW" ] && echo 214 || echo 196)" \
        --width 68 --padding "0 2" \
        "$(gum style --foreground 212 --bold "Disk Usage Trend (last ${count} scans × 5min = ~$((count * 5))min)")" \
        "" \
        "$(gum style --foreground 82 "${spark}")" \
        "" \
        "$(gum style --foreground 245 "Range: 0%–100%  Peak: ${max_val}%  Threshold: ${THRESHOLD_DISK_PCT}%")"

    echo ""
    paste \
        <(gum style --border rounded --border-foreground 33 --width 20 --padding "0 1" \
            "$(gum style --foreground 33 --bold "Current")" \
            "$(gum style --foreground 255 --bold " ${current}%")" \
            "disk used") \
        <(gum style --border rounded --border-foreground 33 --width 20 --padding "0 1" \
            "$(gum style --foreground 33 --bold "Peak")" \
            "$(gum style --foreground 255 --bold " ${max_val}%")" \
            "max observed") \
        <(gum style --border rounded --border-foreground 33 --width 20 --padding "0 1" \
            "$(gum style --foreground 33 --bold "Delta")" \
            "$(gum style --foreground 255 --bold " ${delta}%")" \
            "over window") 2>/dev/null || true

    echo ""
    local box_color=82; [[ "$status" == "REVIEW" ]] && box_color=214; [[ "$status" == "ALERT" ]] && box_color=196
    gum style --border rounded --border-foreground "${box_color}" --width 68 --padding "0 2" \
        "$(badge "${status}") ${trend_icon} ${trend_msg}"
}

# =============================================================================
# VUE D'ENSEMBLE HISTORIQUE
# =============================================================================
check_overview() {
    section_header "📊 History Overview"

    local cpu_count ram_count disk_count
    cpu_count=$(wc -l < "${HISTORY_DIR}/cpu.csv"  2>/dev/null || echo 0)
    ram_count=$(wc -l < "${HISTORY_DIR}/ram.csv"  2>/dev/null || echo 0)
    disk_count=$(wc -l < "${HISTORY_DIR}/disk.csv" 2>/dev/null || echo 0)

    local oldest_ts="N/A"
    if [[ "${cpu_count}" -gt 0 ]]; then
        oldest_ts=$(head -1 "${HISTORY_DIR}/cpu.csv" | awk -F',' '{print $2}')
    fi
    local newest_ts="N/A"
    if [[ "${cpu_count}" -gt 0 ]]; then
        newest_ts=$(tail -1 "${HISTORY_DIR}/cpu.csv" | awk -F',' '{print $2}')
    fi

    local duration_min=$(( cpu_count * 5 ))
    local duration_h=$(( duration_min / 60 ))
    local duration_m=$(( duration_min % 60 ))

    echo ""
    paste \
        <(gum style --border rounded --border-foreground 212 --width 20 --padding "0 1" \
            "$(gum style --foreground 212 --bold "Data Points")" \
            "$(gum style --foreground 255 --bold "  ${cpu_count}")" \
            "recorded") \
        <(gum style --border rounded --border-foreground 212 --width 20 --padding "0 1" \
            "$(gum style --foreground 212 --bold "Coverage")" \
            "$(gum style --foreground 255 --bold "  ${duration_h}h${duration_m}m")" \
            "of history") \
        <(gum style --border rounded --border-foreground 212 --width 20 --padding "0 1" \
            "$(gum style --foreground 212 --bold "Max History")" \
            "$(gum style --foreground 255 --bold "  24h")" \
            "rolling window") 2>/dev/null || true

    echo ""
    gum style --border rounded --border-foreground 33 --width 68 --padding "0 2" \
        "$(gum style --foreground 33 --bold "📅 Time Range:")" \
        "   From: ${oldest_ts}" \
        "   To:   ${newest_ts}"
}

# =============================================================================
# COMMANDE QUERY : afficher l'historique brut
# =============================================================================
cmd_history_query() {
    # Usage: mod_history.sh --show [cpu|ram|disk] [--last N]
    local metric="${1:-cpu}"
    local last_n="${2:-20}"
    local csvfile="${HISTORY_DIR}/${metric}.csv"

    [[ ! -f "${csvfile}" ]] && echo "No history for: ${metric}" && return 1

    echo ""
    gum style \
        --foreground 212 --border-foreground 212 --border normal \
        --width 70 --padding "0 2" \
        "📊 History: ${metric} — last ${last_n} entries"
    echo ""

    local rows=()
    rows+=("$(gum style --bold --foreground 212 "$(printf '%-20s %-10s %s' 'TIMESTAMP' 'VALUE' 'BAR')")")
    rows+=("$(gum style --foreground 240 "$(printf '%-20s %-10s %s' '────────────────────' '──────────' '────────────────────')")")

    tail -n "${last_n}" "${csvfile}" | while IFS=',' read -r epoch ts val; do
        local bar_len
        bar_len=$(awk -v v="${val}" 'BEGIN { printf "%d", v * 0.2 }')
        local bar=""
        for (( i=0; i<bar_len && i<20; i++ )); do bar+="█"; done
        local color=82
        awk "BEGIN { exit !(${val}+0 > 70) }" && color=214
        awk "BEGIN { exit !(${val}+0 > 85) }" && color=196
        rows+=("$(gum style --foreground "${color}" "$(printf '%-20s %-10s %s' "${ts}" "${val}" "${bar}")")")
    done

    gum style \
        --border rounded --border-foreground 212 \
        --width 70 --padding "0 1" \
        "${rows[@]}"
    echo ""
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    echo ""
    gum style \
        --foreground 212 --border-foreground 212 --border double \
        --align center --width 72 --padding "1 2" \
        "📈  HIDS — HEALTH HISTORY & TREND ANALYSIS" \
        "Host: $(hostname) | $(date '+%Y-%m-%d %H:%M:%S')"

    # 1. Collecter les données de cette exécution
    collect_datapoints

    # 2. Vue d'ensemble
    check_overview

    # 3. Analyser les tendances
    check_cpu_history
    check_ram_history
    check_disk_history

    # 4. Assessment final
    echo ""
    local assess_color=82
    local assess_icon="✅"
    local assess_msg="All trends are healthy"
    case "${_worst}" in
        1) assess_color=214; assess_icon="⚠️ "; assess_msg="Some trends require attention" ;;
        2) assess_color=196; assess_icon="🚨"; assess_msg="Dangerous trends detected — act now!" ;;
    esac

    gum style \
        --border double --border-foreground "${assess_color}" \
        --align center --width 72 --padding "0 2" \
        "$(gum style --foreground "${assess_color}" --bold "${assess_icon}  ASSESSMENT: ${assess_msg}")"
    echo ""

    return "${_worst}"
}

# =============================================================================
# ENTRY POINT
# =============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    load_config
    if [[ "${1:-}" == "--show" ]]; then
        shift
        cmd_history_query "${1:-cpu}" "${2:-20}"
    else
        main
        exit "${_worst}"
    fi
fi
