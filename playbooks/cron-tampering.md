# Playbook: Cron Tampering

**MITRE ATT&CK:** T1053.003 — Scheduled Task/Job: Cron  
**Severity:** HIGH  
**auditd key:** cron_tampering  

## Trigger
Fires when any file under /etc/crontab, /etc/cron.d/, or /var/spool/cron/ is written or modified.

## Triage
1. `ausearch -k cron_tampering --start today -i`
2. Review all cron entries:
   - `cat /etc/crontab`
   - `ls -la /etc/cron.d/`
   - `for user in $(cut -f1 -d: /etc/passwd); do crontab -l -u $user 2>/dev/null; done`
3. Identify actor: `ausearch -k cron_tampering | grep auid=` → `getent passwd <uid>`
4. Check modification timestamps: `stat /etc/crontab`

## Containment
- Remove unauthorized cron entry manually
- Lock actor account: `sudo usermod -L <username>`

## Remediation
- Restore cron files from backup or known-good state
- Audit all user crontabs for persistence payloads

## Post-Incident
- Check for related persistence (new SSH keys, modified .bashrc/.profile)
- Update incident timeline
