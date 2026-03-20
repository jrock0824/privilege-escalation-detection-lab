# Playbook: Sensitive File Access (/etc/shadow, /etc/passwd)

**MITRE ATT&CK:** T1003 — OS Credential Dumping  
**Severity:** HIGH  
**auditd key:** sensitive_file_access  

## Trigger
Fires when /etc/shadow or /etc/passwd is read, written, or executed by a non-system process.

## Triage
1. `ausearch -k sensitive_file_access --start today -i`
2. Identify the process: check `exe=` field in audit log
3. Identify the user: `ausearch -k sensitive_file_access | grep auid=`
4. Check if credentials may have been exfiltrated: review bash history for the actor

## Containment
- `sudo usermod -L <username>` if unauthorized access confirmed
- Kill any active sessions: `pkill -u <username>`

## Remediation
- Rotate passwords if /etc/shadow was read by unauthorized process
- `sudo passwd <user>` to force password resets for affected accounts

## Post-Incident
- Check for persistence mechanisms (new cron jobs, SSH keys)
- Update incident timeline
