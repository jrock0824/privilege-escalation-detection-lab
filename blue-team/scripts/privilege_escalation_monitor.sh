#!/usr/bin/env bash
# ============================================================
# privilege_escalation_monitor.sh
# Blue Team — Privilege Escalation Detection
# MITRE ATT&CK: T1548.001, T1548.003, T1003, T1547.006, T1053.003
# ============================================================
set -euo pipefail

# ── Config (set via environment or .env file) ─────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ALERT_FILE="${REPO_ROOT}/blue-team/evidence/sanitized/alerts.log"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
ALERT_EMAIL="${ALERT_EMAIL:-}"
WEBHOOK_ENABLED="${WEBHOOK_ENABLED:-false}"
SUID_BASELINE="/etc/security/suid_baseline.txt"

mkdir -p "$(dirname "$ALERT_FILE")"

# ── Central alert function ─────────────────────────────────────────────────
log_alert() {
    local severity="$1"
    local detection_id="$2"
    local message="$3"
    local timestamp
    timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

    echo "[$timestamp] [$severity] [$detection_id] $message" | tee -a "$ALERT_FILE"

    if [[ "$WEBHOOK_ENABLED" == "true" ]] && [[ -n "$SLACK_WEBHOOK_URL" ]]; then
        send_slack_alert "$severity" "$detection_id" "$message"
    fi

    if [[ -n "$ALERT_EMAIL" ]] && command -v mail &>/dev/null; then
        echo "$message" | mail -s "[$severity] $detection_id on $(hostname)" "$ALERT_EMAIL" 2>/dev/null
    fi
}

# ── Slack webhook ──────────────────────────────────────────────────────────
send_slack_alert() {
    local severity="$1"
    local detection_id="$2"
    local message="$3"
    local color
    case "$severity" in
        CRITICAL) color="#FF0000" ;;
        HIGH)     color="#FFA500" ;;
        MEDIUM)   color="#FFFF00" ;;
        *)        color="#808080" ;;
    esac

    local payload
    payload=$(cat <<EOF
{
  "attachments": [{
    "color": "${color}",
    "title": "🚨 [${severity}] ${detection_id}",
    "text": "${message}",
    "fields": [
      {"title": "Host",      "value": "$(hostname)", "short": true},
      {"title": "Timestamp", "value": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')", "short": true},
      {"title": "Severity",  "value": "${severity}", "short": true}
    ],
    "footer": "privilege-escalation-detection-lab | auditd"
  }]
}
EOF
)
    curl -s -X POST "$SLACK_WEBHOOK_URL" \
         -H "Content-Type: application/json" \
         -d "$payload" > /dev/null 2>&1
}

# ── Detection: Failed sudo / sudo config change (T1548.003) ───────────────
detect_sudo_abuse() {
    local RESULTS
    RESULTS=$(ausearch -k sudo-exec --start today 2>/dev/null | grep "exit=-13" || true)
    if [[ -n "$RESULTS" ]]; then
        local COUNT
        COUNT=$(echo "$RESULTS" | grep -c "type=SYSCALL" || true)
        log_alert "HIGH" "FAILED_SUDO" \
            "MITRE T1548.003 - $COUNT failed sudo attempt(s) detected today."
    fi

    local CONFIG_CHANGE
    CONFIG_CHANGE=$(ausearch -k sudo-config --start today 2>/dev/null || true)
    if [[ -n "$CONFIG_CHANGE" ]]; then
        log_alert "CRITICAL" "SUDOERS_MODIFIED" \
            "MITRE T1548.003 - sudoers file or directory was modified."
    fi
}

# ── Detection: Sensitive file access (T1003) ──────────────────────────────
detect_sensitive_file_access() {
    local RESULTS
    RESULTS=$(ausearch -k sensitive_file_access --start today 2>/dev/null || true)
    if [[ -n "$RESULTS" ]]; then
        log_alert "HIGH" "SENSITIVE_FILE_ACCESS" \
            "MITRE T1003 - /etc/shadow or /etc/passwd was accessed today."
    fi
}

# ── Detection: SUID binary abuse (T1548.001) ──────────────────────────────
detect_suid_abuse() {
    local RESULTS
    RESULTS=$(ausearch -k suid_modification --start today 2>/dev/null || true)
    if [[ -n "$RESULTS" ]]; then
        local COUNT
        COUNT=$(echo "$RESULTS" | grep -c "type=SYSCALL" || true)
        log_alert "HIGH" "SUID_MODIFICATION" \
            "MITRE T1548.001 - SUID bit modification detected ($COUNT event(s))."
    fi

    if [[ -f "$SUID_BASELINE" ]]; then
        local UNEXPECTED
        UNEXPECTED=$(find / -perm -4000 -type f 2>/dev/null | sort \
            | comm -23 - "$SUID_BASELINE" || true)
        if [[ -n "$UNEXPECTED" ]]; then
            log_alert "CRITICAL" "SUID_NEW_BINARY" \
                "MITRE T1548.001 - New SUID binary not in baseline: $UNEXPECTED"
        fi
    fi
}

# ── Detection: Kernel module loading (T1547.006) ──────────────────────────
detect_kernel_module_loading() {
    local RESULTS
    RESULTS=$(ausearch -k module_loading --start today 2>/dev/null || true)
    if [[ -n "$RESULTS" ]]; then
        local MODULES
        MODULES=$(echo "$RESULTS" | grep "comm=" | \
            sed 's/.*comm="\([^"]*\)".*/\1/' | sort -u | tr '\n' ' ')
        log_alert "CRITICAL" "KERNEL_MODULE_LOAD" \
            "MITRE T1547.006 - Kernel module loading detected. Commands: ${MODULES:-unknown}"
    fi
}

# ── Detection: Cron tampering (T1053.003) ─────────────────────────────────
detect_cron_tampering() {
    local RESULTS
    RESULTS=$(ausearch -k cron_tampering --start today 2>/dev/null || true)
    if [[ -n "$RESULTS" ]]; then
        local FILES
        FILES=$(echo "$RESULTS" | grep "name=" | \
            sed 's/.*name="\([^"]*\)".*/\1/' | sort -u | tr '\n' ' ')
        local ACTOR
        ACTOR=$(echo "$RESULTS" | grep "auid=" | \
            sed 's/.*auid=\([0-9]*\).*/\1/' | sort -u | tr '\n' ' ')
        log_alert "HIGH" "CRON_TAMPERING" \
            "MITRE T1053.003 - Cron path modified. Files: ${FILES:-unknown} | Actor UID: ${ACTOR:-unknown}"
    fi
}

# ── Main ───────────────────────────────────────────────────────────────────
main() {
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] Starting privilege escalation monitor..."
    detect_sudo_abuse
    detect_sensitive_file_access
    detect_suid_abuse
    detect_kernel_module_loading
    detect_cron_tampering
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] Scan complete. Alerts written to: $ALERT_FILE"
}

main "$@"
