# Splunk SOC Investigation: Triage & Threat Analysis

## Objective
Act as a Level 1 SOC Analyst to triage and investigate a series of security alerts using Splunk, uncovering malicious activity across Linux, Windows, and web server environments.

## Core Scenario
Investigated three distinct attack scenarios to demonstrate proficiency in log analysis, threat hunting, and incident correlation:
1.  **Linux Brute-Force & Privilege Escalation:** Identified a successful SSH brute-force attack leading to root access and backdoor creation.
2.  **Windows Malicious Persistence:** Uncovered a malicious scheduled task designed to download and execute a payload from a remote server.
3.  **Web Server Compromise:** Detected an uploaded web shell and related brute-force attempts against a web application.

## Tools & Platforms
*   **Splunk** (Primary SIEM for investigation)
*   **Threat Intelligence Platforms** (AbuseIPDB, VirusTotal)
*   **MITRE ATT&CK Framework** (For technique mapping)

## Key Achievements & Metrics
*   **Comprehensive Threat Uncovery:** Successfully identified and documented three separate attack chains, from initial access to final objective.
*   **Precise Attack Attribution:** Correlated 591 failed login attempts in 5 minutes to a single source IP, confirming a brute-force attack against a user account.
*   **Threat Intelligence Integration:** Validated attacker IP (`171.251.232.40`) against external sources, confirming over 12,500 community reports of malicious activity.
*   **Cross-Platform Analysis:** Applied Splunk investigative techniques to audit logs (`auth.log`), Windows Event Logs, and web server logs (`access.log`).

## Attack Narrative Summary
1.  **Linux Compromise:** Detected a brute-force attack against user `john.smith`, leading to privilege escalation to `root` and the creation of a persistent user account (`system-utm`).
2.  **Windows Persistence:** Analyzed a malicious scheduled task (`AssessmentTaskOne`) that used `certutil.exe` to download a remote payload, and traced the attacker's lateral movement from `DEV-QA-SERVER`.
3.  **Web Shell Attack:** Discovered a `b374k.php` web shell upload and linked it to prior brute-force attempts against `/wp-login.php` using the `Hydra` tool.

## Skills Demonstrated
*   **Advanced Splunk Querying:** Constructed complex SPL searches to filter, correlate, and visualize log data across diverse sources.
*   **Incident Scoping & Impact Analysis:** Determined the full scope of compromises, including lateral movement and persistence mechanisms.
*   **Threat Intelligence Correlation:** Used open-source intelligence (OSINT) to enrich findings and confirm malicious indicators.
*   **MITRE ATT&CK Mapping:** Accurately mapped attacker actions to specific techniques (e.g., `T1110`, `T1053.005`, `T1505.003`) for clear threat reporting.

---
**See the full technical analysis:** [detailed_analysis.md](detailed_analysis.md)
