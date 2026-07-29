# Investigation 3.1 – Registry Persistence via PowerShell

## Executive Summary

A forensic investigation was conducted on the provided **Investigation-3.1.evtx** Sysmon log to determine how the attacker established persistence on the compromised endpoint. Analysis of the Sysmon events revealed suspicious PowerShell execution, registry modifications, and outbound network communication associated with the Empire Command and Control (C2) framework. The findings indicate that the attacker successfully established registry-based persistence before communicating with a remote host.

---

## Investigation Questions

| Question | Answer |
| --- | --- |
| What was the suspected adversary IP? | **172.30.1.253** |
| Which registry key was modified? | **HKLM\Software\Microsoft\Network\debug** |
| Which process modified the registry? | **powershell.exe** |
| What persistence mechanism was identified? | **Registry-Based Persistence** |

---

## Investigation Objective

Investigate the Sysmon logs to determine how persistence was established, identify the process responsible for the registry modification, analyse the registry changes, and document evidence of outbound communication with the suspected adversary.

---

## Investigation Methodology

The investigation began by loading the provided **Investigation-3.1.evtx** file into **Windows Event Viewer**. Review of the available Sysmon events identified suspicious **Process Creation (Event ID 1)**, **Registry Value Set (Event ID 13)** and **Network Connection (Event ID 3)** events occurring in sequence, indicating that the attacker established persistence before initiating communication with a remote host.

**Screenshot 2026-07-29 **

*Investigation overview showing the available Sysmon events.*

---

## Process Execution Analysis

The investigation focused on **Sysmon Event ID 1 (Process Creation)** to identify the process responsible for the suspicious activity.

Analysis showed **powershell.exe** executing commands associated with the persistence mechanism. PowerShell is a legitimate Windows administration tool but is frequently abused by threat actors to execute malicious commands directly in memory while reducing the likelihood of detection.

The execution timeline showed PowerShell launching immediately before the registry modification and outbound network communication.

**Screenshot 2026-07-29 here**

*Event ID 1 showing PowerShell execution.*

---

## Registry Persistence Analysis

The next phase examined **Sysmon Event ID 13 (Registry Value Set)**.

The investigation revealed **powershell.exe** modifying the following registry location:

`HKLM\Software\Microsoft\Network\debug`

Registry modifications within this location indicate that the attacker attempted to establish persistence, enabling malicious code to remain active after system reboots or future user sessions.

**Screenshot 2026-07-29  here**

*Event ID 13 showing the registry modification performed by PowerShell.*

---

## Network Connection Analysis

The investigation then examined **Sysmon Event ID 3 (Network Connection)**.

The network event showed outbound communication from the compromised endpoint to the suspected adversary.

The investigation identified:

- Process: **powershell.exe**
- Destination IP: **172.30.1.253**

The communication occurred immediately after the registry modification, suggesting the attacker successfully established persistence before communicating with the Empire Command-and-Control server.

**Screenshot 2026-07-29  here**

*Event ID 3 showing the outbound connection to the suspected adversary.*

---

# Findings

- **PowerShell** was used to execute the persistence mechanism.
- **Sysmon Event ID 13** recorded registry modifications under **HKLM\Software\Microsoft\Network\debug**.
- Registry-based persistence was successfully established.
- **Sysmon Event ID 3** confirmed outbound communication with **172.30.1.253**.
- The observed sequence (**PowerShell Execution → Registry Modification → Network Connection**) demonstrates a successful persistence technique followed by command-and-control communication.

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ATT&CK ID |
| --- | --- | --- |
| Execution | PowerShell | T1059.001 |
| Persistence | Registry Run Keys / Startup Items | T1547 |
| Command and Control | Application Layer Protocol | T1071 |
| Defence Evasion | PowerShell | T1059.001 |

---

# SOC Analyst Conclusion

The investigation identified registry-based persistence established through **PowerShell**, followed by outbound communication with the suspected adversary at **172.30.1.253**. The observed attack sequence (**PowerShell Execution → Registry Modification → Network Communication**) indicates the attacker successfully maintained persistence while establishing communication with an Empire Command-and-Control server. This behaviour is consistent with post-exploitation activity designed to provide long-term remote access to the compromised endpoint.

---

## Tools Used

- Windows Event Viewer
- Microsoft Sysmon Operational Logs
- PowerShell
- MITRE ATT&CK Framework

---
