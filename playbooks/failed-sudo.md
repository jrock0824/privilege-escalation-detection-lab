# Playbook: Failed Sudo / Sudo Abuse

**MITRE ATT&CK:** T1548.003 — Abuse Elevation Control Mechanism: Sudo  
**Severity:** HIGH  
**auditd key:** sudo-exec, sudo-config  

## Trigger
Fires when failed sudo attempts are detected or sudoers configuration is modified.

## Triage
1. `ausearch -k sudo-exec --start today -i | grep "exit=-13"`
2. `ausearch -k sudo-config --start today -i`
3. Identify actor: `ausearch -k sudo-exec | grep auid=` → `getent passwd <uid>`
4. Check sudoers: `sudo visudo -c`

## Containment
- `sudo usermod -L <username>` — lock the account
- `sudo visudo` — review and revert unauthorized sudoers changes

## Remediation
- Remove unauthorized sudo privileges
- Enforce principle of least privilege in sudoers

## Post-Incident
- Document in `docs/Incident_Timeline.md`
- Review who has sudo access: `grep -Po '^sudo.+:\K.*$' /etc/group`
