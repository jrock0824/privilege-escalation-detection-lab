#!/bin/bash
# ==========================================================
# privilege_escalation_monitor.sh
# Phase 9 — Privilege Escalation Detection Automation
# Blue Team / SOC Analyst Focus
# ==========================================================

set -euo pipefail

# -----------------------------
# Global Variables
# -----------------------------
SCRIPT_NAME="Privilege Escalation Monitor"
RUN_TIME="$(date)"
HOSTNAME="$(hostname)"
REPORT_FILE="/tmp/privilege_escalation_report.txt"
ALERT_FILE="/tmp/privilege_escalation_alerts.log"
AUDIT_LOG="/var/log/audit/audit.log"

# -----------------------------
# Trap Handling (Fail Safely)
# -----------------------------
cleanup() {
    echo "[INFO] Cleanup complete."
}
trap cleanup EXIT

error_handler() {
    echo "[ERROR] Script failed at line $1"
}
trap 'error_handler $LINENO' ERR

# -----------------------------
# Logging Helpers
# -----------------------------
log_info()  { echo "[INFO]  $1"; }
log_warn()  { echo "[WARN]  $1"; }
log_error() { echo "[ERROR] $1"; }

# -----------------------------
# Initialize Report
# -----------------------------
init_report() {
    cat <<EOF > "$REPORT_FILE"
==================================================
$SCRIPT_NAME
Generated: $RUN_TIME
Host: $HOSTNAME
==================================================

EOF

    touch "$ALERT_FILE"
}

# -----------------------------
# Detection 1: Failed sudo attempts
# -----------------------------
detect_failed_sudo() {
    log_info "Checking for failed sudo attempts..."

    local COUNT
    COUNT=$(ausearch -k sudo-exec -i 2>/dev/null | grep -c "success=no" || true)

    if [[ "$COUNT" -gt 0 ]]; then
        log_warn "Detected $COUNT failed sudo attempt(s)"
        echo "[HIGH] Failed sudo attempts detected: $COUNT" >> "$ALERT_FILE"

        {
            echo "=== Failed sudo attempts ==="
            ausearch -k sudo-exec -i | grep "success=no"
            echo ""
        } >> "$REPORT_FILE"
    else
        echo "No failed sudo attempts detected." >> "$REPORT_FILE"
    fi
}

# -----------------------------
# Detection 2: Sensitive file access
# -----------------------------
detect_sensitive_file_access() {
    log_info "Checking access to /etc/passwd and /etc/shadow..."

    local SHADOW_EVENTS
    SHADOW_EVENTS=$(ausearch -k shadow-access -i 2>/dev/null | grep -c "type=SYSCALL" || true)

    if [[ "$SHADOW_EVENTS" -gt 0 ]]; then
        log_warn "Detected access to /etc/shadow"
        echo "[CRITICAL] /etc/shadow access detected" >> "$ALERT_FILE"

        {
            echo "=== /etc/shadow access events ==="
            ausearch -k shadow-access -i
            echo ""
        } >> "$REPORT_FILE"
    else
        echo "No /etc/shadow access detected." >> "$REPORT_FILE"
    fi

    {
        echo "=== /etc/passwd modification attempts ==="
        ausearch -k passwd-changes -i || echo "No passwd changes detected."
        echo ""
    } >> "$REPORT_FILE"
}

# -----------------------------
# Detection 3: Summary Reports
# -----------------------------
generate_summary() {
    log_info "Generating audit summaries..."

    {
        echo "=== Failed Event Summary ==="
        aureport --failed --summary
        echo ""

        echo "=== User Activity Summary ==="
        aureport -u --summary
        echo ""
    } >> "$REPORT_FILE"
}

# -----------------------------
# Severity Scoring
# -----------------------------
severity_scoring() {
    local SCORE=0

    grep -q "Failed sudo attempts" "$ALERT_FILE" && SCORE=$((SCORE + 3))
    grep -q "/etc/shadow" "$ALERT_FILE" && SCORE=$((SCORE + 5))

    echo "=== Severity Assessment ===" >> "$REPORT_FILE"

    if [[ "$SCORE" -ge 5 ]]; then
        echo "Overall Severity: CRITICAL" >> "$REPORT_FILE"
    elif [[ "$SCORE" -ge 3 ]]; then
        echo "Overall Severity: HIGH" >> "$REPORT_FILE"
    elif [[ "$SCORE" -ge 1 ]]; then
        echo "Overall Severity: MEDIUM" >> "$REPORT_FILE"
    else
        echo "Overall Severity: LOW" >> "$REPORT_FILE"
    fi

    echo "" >> "$REPORT_FILE"
}

# -----------------------------
# Main Execution
# -----------------------------
main() {
    init_report
    detect_failed_sudo
    detect_sensitive_file_access
    generate_summary
    severity_scoring

    log_info "Detection complete."
    log_info "Report saved to: $REPORT_FILE"
    log_info "Alerts saved to: $ALERT_FILE"

    echo
    echo "========== REPORT =========="
    cat "$REPORT_FILE"
}

main "$@"
