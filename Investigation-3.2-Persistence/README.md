

---

# Investigation 3.2 – Scheduled Task Persistence and Credential Access

## Executive Summary

A forensic investigation was conducted on the provided **Investigation-3.2.evtx** Sysmon log to determine how the attacker maintained persistence on the compromised endpoint. Analysis of the Sysmon events revealed the creation of a malicious scheduled task, execution of a PowerShell payload, and suspicious access to the **LSASS** process. The findings indicate that the attacker established persistence through Windows Task Scheduler while attempting to access sensitive credential information.

---

## Investigation Questions

| Question                             | Answer                          |
| ------------------------------------ | ------------------------------- |
| What was the adversary IP?           | **172.168.103.188**             |
| Where was the payload stored?        | **C:\Users\q\AppData\blah.txt** |
| What persistence mechanism was used? | **Scheduled Task**              |
| What sensitive process was accessed? | **lsass.exe**                   |

---

## Investigation Objective

Investigate the Sysmon logs to identify how persistence was established, analyse the scheduled task created by the attacker, examine the payload execution, and document evidence of credential access.

---

## Investigation Methodology

The investigation began by loading the provided **Investigation-3.2.evtx** file into **Windows Event Viewer**. Analysis of the available Sysmon events identified **Process Creation (Event ID 1)**, **Network Connection (Event ID 3)**, **Process Access (Event ID 10)** and **File Creation (Event ID 11)** events occurring in sequence, indicating that the attacker established persistence before attempting credential access.

---

## Scheduled Task Analysis

The investigation focused on **Sysmon Event ID 1 (Process Creation)**.

Analysis showed **schtasks.exe** being executed to create a scheduled task named **Updater**.

The command observed was:

```text
"C:\Windows\System32\schtasks.exe" /Create /F /SC DAILY /ST 09:00 /TN Updater /TR "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe ..."
```

This scheduled task ensured the malicious PowerShell payload would execute automatically every day, providing persistence after system reboots.

 Screenshot 2026-07-28 

*Event ID 1 showing the scheduled task created by schtasks.exe.*

---

## Payload Analysis

Further analysis identified the payload location used by the scheduled task.

The malicious payload was stored at:

```text
C:\Users\q\AppData\blah.txt
```

Rather than storing a traditional executable, the attacker referenced a text file containing the malicious PowerShell payload, helping evade simple file-based detection.

Screenshot 2026-07-28 
*Event showing the payload location referenced by the scheduled task.*

---

## Credential Access Analysis

The investigation then examined **Sysmon Event ID 10 (Process Access)**.

Analysis revealed **schtasks.exe** accessing:

```text
lsass.exe
```

The **Local Security Authority Subsystem Service (LSASS)** stores user credentials, authentication tokens and password hashes in memory. Access to this process is commonly associated with credential dumping techniques used by attackers after gaining persistence.

This behaviour represents a significant indicator of post-exploitation activity.

 Screenshot 2026-07-28 

*Event ID 10 showing access to lsass.exe.*

---

## Network Activity Analysis

The investigation also identified outbound communication with the remote adversary.

The destination IP identified during the investigation was:

```text
172.168.103.188
```

This indicates the compromised endpoint communicated with the attacker's infrastructure after persistence had been established.

Screenshot 2026-07-28 
*Network connection showing communication with the suspected adversary.*

---

# Findings

* **schtasks.exe** was used to establish persistence.
* A scheduled task named **Updater** was created to execute a PowerShell payload daily.
* The payload was stored at **C:\Users\q\AppData\blah.txt**.
* **Sysmon Event ID 10** recorded suspicious access to **lsass.exe**.
* Network communication was established with **172.168.103.188**.
* The observed attack sequence (**Scheduled Task → Payload Execution → Credential Access → Network Communication**) demonstrates a typical post-exploitation persistence technique.

---

# MITRE ATT&CK Mapping

| Tactic              | Technique                  | ATT&CK ID |
| ------------------- | -------------------------- | --------- |
| Persistence         | Scheduled Task/Job         | T1053.005 |
| Execution           | PowerShell                 | T1059.001 |
| Credential Access   | OS Credential Dumping      | T1003.001 |
| Command and Control | Application Layer Protocol | T1071     |

---

# SOC Analyst Conclusion

The investigation identified the creation of a malicious scheduled task used to execute a PowerShell payload on a daily basis, providing persistence on the compromised endpoint. Following persistence, the attacker accessed **lsass.exe**, indicating an attempt to obtain user credentials, before communicating with the remote adversary at **172.168.103.188**. The observed attack sequence (**Scheduled Task → Payload Execution → Credential Access → Network Communication**) is consistent with attacker behaviour following successful compromise.
