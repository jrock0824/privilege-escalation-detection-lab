# Red Team: Phishing-Based Initial Access

**Operator:** Abdi Osman  
**MITRE ATT&CK:** T1566 — Phishing (Initial Access, TA0001)  
**Tool:** Social-Engineer Toolkit (SET v8.0.3 "Maverick")  
**Environment:** Kali Linux on VirtualBox (Windows 11 host)

---

## Objective

Simulate a realistic phishing email attack to demonstrate how social engineering
achieves initial access — the first step before privilege escalation is attempted.

---

## Attack Chain


---

## Steps Executed

| Step | Action | Tool |
|------|--------|------|
| 1 | Launched SET: `sudo setoolkit` | SET |
| 2 | Selected: Social-Engineering Attacks → Mass Mailer → Single Address | SET |
| 3 | Composed spoofed HTML phishing email ("Suspicious Login Detected") | SET |
| 4 | Used fake recipient: `mr.mittens23@proton.me` | SET |
| 5 | Delivered via simulated local Sendmail server (no real server contacted) | Sendmail |

---

## Phishing Email Details

- **Subject:** [Action Required] Suspicious Login Detected  
- **Format:** HTML  
- **Lure:** Fake account security warning with malicious link  
- **Delivery:** Local Sendmail simulation — no real recipients contacted  

---

## Outcome

Successfully demonstrated how a spoofed, HTML-formatted phishing email can
be crafted and "sent" with minimal technical overhead. No real systems or
individuals were targeted. All activity was contained within the lab environment.

---

## Blue Team Relevance

This simulated initial access establishes the threat narrative for the blue team
detection work. An attacker who gains initial access via phishing would then
attempt privilege escalation — exactly what the blue team detection scripts monitor for.

See: `blue-team/scripts/privilege_escalation_monitor.sh`

---

## Full Report

See `red-team/reports/Abdis-Project-3-Report-2.pdf` for the complete write-up.
