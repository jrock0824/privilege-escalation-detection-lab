#!/bin/bash
################################################################################
# sanitize_audit_evidence.sh
#
# Purpose: Sanitize lab audit evidence for academic/portfolio submission
# - Removes sensitive identifiers (usernames, emails, IPs, credentials)
# - Preserves forensic integrity (timestamps, event IDs, audit structure)
# - Creates audit trail of sanitization process
# - Mirrors SOC evidence handling procedures
#
# Usage: ./sanitize_audit_evidence.sh
################################################################################

set -euo pipefail
IFS=$'\n\t'

# Terminal colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Directory setup
RAW_DIR="$HOME/evidence_raw"
SAN_DIR="$HOME/evidence_sanitized"
LOG_DIR="$HOME/evidence_sanitization_logs"

mkdir -p "$RAW_DIR" "$SAN_DIR" "$LOG_DIR"

# Logging function
log_action() {
    local action="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $action" | tee -a "$LOG_DIR/sanitization.log"
}

# Error handling
error_exit() {
    local message="$1"
    log_action "ERROR: $message"
    exit 1
}

# Sanitization patterns
declare -A SANITIZE_RULES=(
    ["partner1"]="USER1"
    ["partner2"]="USER2"
    ["admin1"]="ADMIN1"
    ["root"]="ROOT_USER"
)

sanitize_file() {
    local infile="$1"
    local outfile="$2"
    local description="${3:-Unknown file}"
    
    [[ -f "$infile" ]] || error_exit "Input file not found: $infile"
    
    log_action "Sanitizing: $description ($infile)"
    
    sed -E \
        -e 's/\bpartner1\b/USER1/g' \
        -e 's/\bpartner2\b/USER2/g' \
        -e 's/\badmin1\b/ADMIN1/g' \
        -e 's/\broot\b/ROOT_USER/g' \
        -e 's/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/user@example.com/g' \
        -e 's/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/LAB_IP/g' \
        -e 's/password=[^ ]+/password=****/g' \
        -e 's/passwd=[^ ]+/passwd=****/g' \
        -e 's/sudo_password=[^ ]+/sudo_password=****/g' \
        "$infile" > "$outfile"
    
    local in_lines=$(wc -l < "$infile")
    local out_lines=$(wc -l < "$outfile")
    log_action "✓ Sanitized: $in_lines lines → $out_lines lines"
}

verify_timestamps() {
    local file="$1"
    local desc="$2"
    local count=$(grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' "$file" | wc -l)
    if [[ $count -gt 0 ]]; then
        log_action "✓ Timestamps preserved in $desc ($count found)"
    else
        log_action "WARN: No timestamps found in $desc"
    fi
}

verify_event_ids() {
    local file="$1"
    local desc="$2"
    local count=$(grep -oE 'type=[A-Z_]+' "$file" | wc -l)
    if [[ $count -gt 0 ]]; then
        log_action "✓ Event IDs preserved in $desc ($count found)"
    else
        log_action "WARN: No event IDs found in $desc"
    fi
}

echo -e "${YELLOW}===== Evidence Sanitization Started =====${NC}"
log_action "=== Sanitization Session Started ==="

# Process files
for file in audit.log ausearch_output.txt aureport_output.txt; do
    if [[ -f "$RAW_DIR/$file" ]]; then
        outfile="$SAN_DIR/${file%.txt}_sanitized.txt"
        [[ "$file" == "audit.log" ]] && outfile="$SAN_DIR/audit_sanitized.log"
        echo -e "${GREEN}[+] Processing $file${NC}"
        sanitize_file "$RAW_DIR/$file" "$outfile" "$file"
        verify_timestamps "$outfile" "$outfile"
        verify_event_ids "$outfile" "$outfile"
    else
        log_action "SKIP: $file not found in $RAW_DIR"
    fi
done

# Create README
cat > "$SAN_DIR/README_SANITIZATION.txt" <<'README'
Sanitized Evidence Documentation
--------------------------------
Purpose:
- Forensically sound audit evidence
- Sensitive identifiers removed
- Timestamps and event IDs preserved

Files included:
- audit_sanitized.log
- ausearch_sanitized.txt
- aureport_sanitized.txt
- SANITIZATION_AUDIT.log
- README_SANITIZATION.txt
README

# Create audit trail
cp "$LOG_DIR/sanitization.log" "$SAN_DIR/SANITIZATION_AUDIT.log"
log_action "✓ Sanitization README and audit trail created"

echo -e "${GREEN}===== Evidence Sanitization Complete =====${NC}"
echo "Sanitized evidence location: $SAN_DIR"
ls -1 "$SAN_DIR"
