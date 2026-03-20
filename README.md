# Red & Blue Team Privilege Escalation Detection Lab

![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red?logo=mitre)
![Platform](https://img.shields.io/badge/platform-Linux-blue?logo=linux)
![CIS Controls](https://img.shields.io/badge/CIS%20Controls-6%20%26%208-orange)
![NIST CSF](https://img.shields.io/badge/NIST%20CSF-PR.AC%20%7C%20DE.CM-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

Collaborative adversary simulation with separated red/blue team roles, mirroring enterprise red team engagements. The blue team component implements a host-based telemetry pipeline using Linux auditd, covering 5 MITRE ATT&CK techniques across TA0003 and TA0004, with per-detection incident response playbooks and Slack-integrated alerting.

---

## Team Roles

| Role | Operator | Responsibilities |
|------|----------|-----------------|
| Red Team | Abdi | Phishing-based initial access simulation via SET — see [red-team/README.md](red-team/README.md) |
| Blue Team | Jaylen | Detection engineering, auditd rules, scripted analysis, IR playbooks, SOC reporting |

Full threat narrative linking both sides: [docs/Threat_Narrative.md](docs/Threat_Narrative.md)

---

## MITRE ATT&CK Coverage

![ATT&CK Navigator](docs/mitre-navigator-screenshot.png)

Full layer file: [docs/mitre-attack-layer.json](docs/mitre-attack-layer.json)

| Technique | ID | Detection Method | Playbook |
|-----------|-----|-----------------|---------|
| Sudo abuse | T1548.003 | auditd: sudo-exec, sudo-config | [playbooks/failed-sudo.md](playbooks/failed-sudo.md) |
| Credential access via shadow | T1003 | auditd: sensitive_file_access | [playbooks/shadow-access.md](playbooks/shadow-access.md) |
| SUID binary abuse | T1548.001 | auditd: suid_modification + baseline diff | [playbooks/suid-binaries.md](playbooks/suid-binaries.md) |
| Kernel module loading | T1547.006 | auditd: module_loading | [playbooks/kernel-module-loading.md](playbooks/kernel-module-loading.md) |
| Cron tampering | T1053.003 | auditd: cron_tampering | [playbooks/cron-tampering.md](playbooks/cron-tampering.md) |



