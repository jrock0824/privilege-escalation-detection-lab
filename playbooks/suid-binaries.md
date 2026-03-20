# Playbook: SUID Binary Abuse

**MITRE ATT&CK:** T1548.001 — Abuse Elevation Control Mechanism: Setuid and Setgid  
**Severity:** HIGH / CRITICAL  
**auditd key:** suid_modification, suid_execution  

## Trigger
Fires when SUID bit is set on a file or a new SUID binary appears outside the baseline.

## Triage
1. `ausearch -k suid_modification --start today -i`
2. Find all current SUID binaries: `find / -perm -4000 -type f 2>/dev/null | sort`
3. Compare against baseline: `comm -23 <(find / -perm -4000 -type f 2>/dev/null | sort) /etc/security/suid_baseline.txt`
4. Identify actor: `ausearch -k suid_modification | grep auid=` → `getent passwd <uid>`

## Containment
- Remove SUID bit: `sudo chmod u-s /path/to/binary`
- Lock actor account if unauthorized: `sudo usermod -L <username>`

## Remediation
- Verify binary is not needed with SUID
- Update baseline if change was authorized: `sudo find / -perm -4000 -type f 2>/dev/null | sort | sudo tee /etc/security/suid_baseline.txt`

## Post-Incident
- Run full SUID audit: `find / -perm -4000 -type f 2>/dev/null`
- Update incident timeline
