Red & Blue Team Privilege Escalation Detection Lab

Overview

This repository documents a collaborative red-team/blue-team cybersecurity exercise designed to simulate a realistic attack-and-detection workflow. The project demonstrates how phishing-based initial access can lead to attempted privilege escalation via sudo misconfiguration, and how host-based monitoring can detect and contain that activity.

The work is structured and documented using SOC-style incident reporting, with clear role separation, evidence handling, metrics, and alignment with compliance.

---

Team Roles & Collaboration

This project was completed as a group exercise across two systems, reflecting real-world security operations where attackers and defenders operate on separate hosts.

* Red Team (Abdi)
Simulated phishing-based initial access using the Social-Engineer Toolkit (SET) in a controlled lab environment.
* Blue Team (Jaylen)
Implemented privilege escalation detection using auditd, developed automated analysis scripts, constructed an incident timeline, classified findings, handled evidence sanitization, and produced SOC-style reporting.

This separation mirrors enterprise environments, where red and blue teams operate independently and share artifacts after engagement.

---

Attack & Detection Summary

* Compromised User (Simulated): partner1
* Attack Objective: Obtain root-level privileges
* Attack Vector: Abuse of sudo configuration
* Detection Point: Privilege escalation phase (TA0004)
* Detection Method: Linux auditd with scripted analysis
* Outcome: Privilege escalation attempts detected; no successful root compromise observed

Tools & Technologies

* Linux auditd, ausearch, aureport
* Bash automation (detection & evidence sanitization)
* MITRE ATT&CK Framework
* CIS Critical Security Controls
* NIST Cybersecurity Framework (CSF)

---

Repository Structure

privilege-escalation-detection-lab/
├── README.md # Project overview
├── docs/ # Formal SOC-style documentation
├── blue-team/ # Detection scripts, audit rules, evidence
│ ├── scripts/
│ ├── auditd/
│ ├── evidence/
│ └── screenshots/
├── red-team/ # Phishing simulation artifacts
└── .gitignore # Prevents sensitive data exposure

This structure mirrors how incident response and security engineering teams organize case files.

---

Documentation Included

The /docs directory contains production-style reports, including:

* Threat Narrative
* Incident Timeline
* MITRE ATT&CK Mapping
* Findings & Severity Classification
* Metrics & Business Impact
* Compliance Mapping (CIS & NIST)
* Full Incident Investigation Report

Each document is written in professional SOC language and can be reviewed independently.

---

Evidence Handling

All audit logs and outputs included in this repository have been sanitized:

* Usernames and sensitive identifiers removed
* No passwords or secrets stored
* Original timestamps and event IDs preserved
* Sanitization process documented with an audit trail.

This approach reflects real SOC practices where raw logs are retained internally and sanitized artifacts are shared for reporting or training.

---

Compliance Alignment

This project explicitly aligns with:

* CIS Control 6: Access Control Management
* CIS Control 8: Audit Log Management
* NIST CSF: PR.AC, DE.CM, DE.AE

Mappings and justifications are documented in /docs/Compliance_Mapping.md.

---

Limitations & Future Work

* Detection is host-based only; no SIEM or EDR integration.
* Phishing detection is not implemented at the email gateway layer.
* Future enhancements could include SIEM ingestion, correlation rules, and alerting workflows.

---

Purpose

This repository serves as:

* A group project
* A professional cybersecurity portfolio artifact
* An example of SOC-style incident detection and reporting

It is intentionally written to reflect real-world security operations rather than a traditional academic lab.
