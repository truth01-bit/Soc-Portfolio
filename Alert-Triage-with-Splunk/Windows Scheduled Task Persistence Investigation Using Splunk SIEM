# Windows Scheduled Task Persistence Investigation Using Splunk SIEM

## Executive Summary

A SIEM alert identified the creation of a suspicious scheduled task on a Windows endpoint, suggesting a potential persistence mechanism. Using Splunk Enterprise, Windows Security and Sysmon logs were analyzed to validate the alert, determine how the scheduled task was created, identify the associated processes, and investigate any additional post-compromise activity.

The investigation confirmed that a malicious scheduled task downloaded and executed a remote payload using PowerShell and `certutil.exe`. Additional analysis showed evidence of system discovery through local group enumeration, indicating the attacker had begun post-exploitation reconnaissance. The alert was classified as a **True Positive**.

---

# Investigation Overview

| Category | Details |
| --- | --- |
| SIEM Platform | Splunk Enterprise |
| Operating System | Windows |
| Data Sources | Windows Security Logs & Sysmon |
| Alert Type | Scheduled Task Persistence |
| Host | WIN-H015 |
| User | oliver.thompson |
| Investigation Type | SOC Alert Triage |

---

# Alert Summary

A Level 1 SOC analyst received an alert indicating that a suspicious scheduled task named **AssessmentTaskOne** had been created on the Windows host **WIN-H015**. Scheduled tasks are commonly abused by threat actors to establish persistence by executing malicious commands at predefined intervals or during system startup.

**Evidence**

📷 **Screenshot:** `Screenshot 2026-07-30 at 12.31.35`

---

# Evidence 1 – Scheduled Task Creation Confirmed

Windows Event ID **4698** confirmed the creation of the scheduled task **AssessmentTaskOne** by the user **oliver.thompson**. The event provided the task name, creation timestamp, and host information, validating the SIEM alert.

**Evidence**

📷 **Screenshot:** `Screenshot 2026-07-30 at 12.44.26`

---

# Evidence 2 – Malicious Task Content Identified

Inspection of the scheduled task XML revealed that the task executed **PowerShell** and **certutil.exe** to download a remote executable (`rv.exe`) from an external web server before launching it from the user's temporary directory.

This behaviour is consistent with common Living-off-the-Land (LotL) techniques, where legitimate Windows utilities are abused to retrieve and execute malicious payloads.

**Evidence**

📷 **Screenshot:** `Screenshot 2026-07-30 at 12.44.31`

---

# Evidence 3 – Process Attribution

Further investigation linked the scheduled task to **Process ID 5816** (`schtasks.exe`), confirming that the persistence mechanism was created through the Windows Task Scheduler service.

Analysis also identified the parent process as **cmd.exe**, showing that the scheduled task creation originated from a command shell rather than normal administrative activity.

**Evidence**

📷 **Screenshot:** `Screenshot 2026-07-30 at 12.57.26`

---

# Evidence 4 – Post-Exploitation Discovery Activity

Sysmon process creation logs showed execution of the Windows **net.exe** utility with the command:

`net localgroup Administrators`

This command enumerates local administrator group membership and is commonly used during the Discovery phase of an intrusion to identify privileged accounts.

**Evidence**

📷 **Screenshot:** `Screenshot 2026-07-30 at 12.58.39`

---

# Evidence 5 – Source Workstation Identified

Authentication-related log fields identified **DEV-QA-SERVER** as the workstation from which the attacker authenticated to the compromised host.

Identifying the originating workstation is critical for scoping the incident and determining whether additional systems may also be compromised.

**Evidence**

📷 **Screenshot:** `Screenshot 2026-07-30 at 13.06.29`

---

# Indicators of Compromise (IOCs)

| Indicator | Value | Description |
| --- | --- | --- |
| Host | `WIN-H015` | Compromised Windows endpoint |
| User | `oliver.thompson` | Account associated with the malicious task |
| Scheduled Task | `AssessmentTaskOne` | Persistence mechanism |
| Event ID | `4698` | Scheduled task creation |
| Process ID | `5816` | Process responsible for creating the task |
| Parent Process | `cmd.exe` | Process that launched `schtasks.exe` |
| LOLBin | `certutil.exe` | Used to download the payload |
| LOLBin | `powershell.exe` | Used to execute the payload |
| Payload | `rv.exe` | Downloaded executable |
| Workstation | `DEV-QA-SERVER` | Origin of attacker activity |

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ID |
| --- | --- | --- |
| Persistence | Scheduled Task/Job | **T1053.005** |
| Command and Scripting Interpreter | PowerShell | **T1059.001** |
| Command and Scripting Interpreter | Windows Command Shell | **T1059.003** |
| System Binary Proxy Execution | Certutil | **T1218** |
| Discovery | Permission Groups Discovery | **T1069.001** |

---

# SOC Assessment

Analysis confirmed that the scheduled task alert represented a **True Positive**. The attacker established persistence by creating a scheduled task that leveraged legitimate Windows utilities (`powershell.exe` and `certutil.exe`) to download and execute a malicious payload. Subsequent execution of `net.exe` to enumerate the local Administrators group indicated that the attacker had progressed beyond persistence into the discovery phase. These findings suggest an active compromise requiring immediate containment and further investigation.

---

# Recommended Response Actions

- Disable and remove the malicious scheduled task.
- Isolate the compromised endpoint from the network.
- Remove the downloaded payload and any associated artifacts.
- Investigate activity originating from **DEV-QA-SERVER**.
- Reset credentials for **oliver.thompson** and review privileged account activity.
- Search the environment for additional scheduled tasks using similar execution patterns.
- Review PowerShell and Sysmon logs for further attacker activity.
- Block execution of unauthorized PowerShell and `certutil.exe` where operationally appropriate through application control policies.

---

# Lessons Learned

This investigation demonstrated how Windows scheduled tasks can be abused to establish persistence while leveraging trusted system binaries to avoid detection. By correlating Windows Security events with Sysmon process creation logs in Splunk, it was possible to reconstruct the attack chain, identify the responsible processes, uncover malicious task content, and trace the attacker's post-compromise discovery activity. This investigation highlights the importance of correlating multiple log sources during SOC alert triage.

---
