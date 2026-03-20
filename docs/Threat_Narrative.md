# Threat Narrative

## Engagement Summary

This exercise simulates a realistic attack-and-detection workflow across two
operators on separate systems, mirroring how enterprise red and blue teams engage.

---

## Attack Chain

[T1566] Phishing Email (Red Team)
↓
Victim clicks link / opens attachment
↓
[TA0001] Initial Access achieved
↓
[T1548.003] Sudo misconfiguration abuse attempted
↓
[T1003] /etc/shadow credential access attempted
↓
[T1548.001] SUID binary abuse attempted
↓
[T1053.003] Cron persistence planted
↓
[T1547.006] Kernel module loaded (rootkit attempt)
↓
[DETECTED] Blue team auditd monitor fires alerts

text

---

## Red Team (Abdi)

- **Vector:** Phishing email via Social-Engineer Toolkit (SET)
- **Goal:** Simulate initial access through social engineering
- **Technique:** T1566 — HTML-formatted spoofed email with malicious link
- **Constraint:** All activity in closed lab; fake recipient; simulated SMTP

Full report: `red-team/reports/Abdis-Project-3-Report-2.pdf`

---

## Blue Team (Jaylen)

- **Goal:** Detect privilege escalation attempts following initial access
- **Method:** Linux auditd + automated bash analysis
- **Coverage:** 5 MITRE ATT&CK techniques across TA0003 and TA0004

| Technique | ID | Detection Key |
|-----------|-----|--------------|
| Sudo abuse | T1548.003 | sudo-exec, sudo-config |
| Credential access | T1003 | sensitive_file_access |
| SUID binary abuse | T1548.001 | suid_execution |
| Cron tampering | T1053.003 | cron_tampering |
| Kernel module loading | T1547.006 | module_loading |

Full detection script: `blue-team/scripts/privilege_escalation_monitor.sh`

---

## Outcome

- Red team successfully simulated phishing-based initial access
- Blue team detected all five privilege escalation vectors
- No successful root compromise observed
- All detections logged with timestamps to `blue-team/evidence/sanitized/alerts.log`
