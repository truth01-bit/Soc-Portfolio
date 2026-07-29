# Investigation 2 – Malicious HTA Execution via mshta.exe

## Executive Summary

A forensic investigation was conducted on the provided **Investigation-2.evtx** Sysmon log to determine how a malicious payload was executed and identify any subsequent network communication. Analysis of the Sysmon events revealed the abuse of the trusted Windows binary **mshta.exe** to execute a malicious HTA payload, followed by an outbound network connection to a remote host. The findings indicate a Living-off-the-Land (LotL) technique used to evade detection while establishing command and control (C2) communication.

---

## Investigation Questions

| Question | Answer |
| --- | --- |
| What signed binary executed the payload? | **mshta.exe** |
| Where was the payload stored? | **C:\Users\IEUser\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\S97WTYG7\update.hta** |
| What file did the payload disguise itself as? | **C:\Users\IEUser\Downloads\update.html** |
| What was the adversary IP? | **10.0.2.18** |
| What port was used for the back connection? | **4443** |

---

## Investigation Objective

Investigate the Sysmon logs to determine how the malicious payload was executed, identify the signed Windows binary involved, analyse the network connection established by the malware, and document indicators of compromise.

---

## Investigation Methodology

The investigation began by loading the provided **Investigation-2.evtx** file into **Windows Event Viewer**. Review of the available Sysmon events identified two **Process Creation (Event ID 1)** events and one **Network Connection (Event ID 3)** event occurring within seconds of each other, indicating a short but complete attack chain.

**Screenshot 2026-07-28 at 18.42.37 here**

*Investigation overview showing the available Sysmon events.*

---

## Process Execution Analysis

The investigation focused on **Sysmon Event ID 1 (Process Creation)** to identify how the payload was executed.

Analysis showed the trusted Windows binary **C:\Windows\System32\mshta.exe** executing an HTA payload located within the user's Temporary Internet Files directory.

The command line showed:

`C:\Users\IEUser\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\S97WTYG7\update.hta`

The parent process was identified as **Internet Explorer (iexplore.exe)**, which referenced the file:

`C:\Users\IEUser\Downloads\update.html`

This suggests the victim opened or downloaded a malicious HTML file that launched the embedded HTA payload through **mshta.exe**, allowing malicious code to execute while using a trusted Microsoft binary.

**Screenshot 2026-07-28 at 18.23.16 here**

*Event ID 1 showing mshta.exe executing the malicious HTA payload.*

**Screenshot 2026-07-28 at 18.42.37 (XML View) here**

*XML View showing Internet Explorer as the parent process and the original update.html file.*

---

## Network Connection Analysis

The investigation then examined **Sysmon Event ID 3 (Network Connection)**.

The network event showed **mshta.exe** initiating an outbound TCP connection immediately after executing the HTA payload.

The event identified:

- Process: **C:\Windows\System32\mshta.exe**
- Destination IP: **10.0.2.18**
- Destination Port: **4443**

The sequence of events indicates the executed payload successfully established communication with the remote adversary over TCP port **4443**, consistent with malware establishing a Command-and-Control (C2) channel.

**Screenshot 2026-07-28 at 18.34.38 here**

*Event ID 3 showing the outbound network connection initiated by mshta.exe.*

---

# Findings

- The attacker abused the legitimate Windows binary **mshta.exe** to execute a malicious HTA payload.
- The payload was located within the user's **Temporary Internet Files** directory.
- The attack originated from a malicious **update.html** file opened through **Internet Explorer**.
- **Sysmon Event ID 3** confirmed outbound communication to **10.0.2.18**.
- The malware established a connection over **TCP port 4443**, indicating successful command-and-control communication.

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ATT&CK ID |
| --- | --- | --- |
| Execution | Signed Binary Proxy Execution (mshta.exe) | T1218.005 |
| Execution | User Execution | T1204 |
| Defence Evasion | Masquerading | T1036 |
| Command and Control | Application Layer Protocol | T1071 |

---

# SOC Analyst Conclusion

The investigation identified a malicious HTA payload executed through the legitimate Windows utility **mshta.exe**, a common Living-off-the-Land technique used to evade detection. The payload originated from a downloaded HTML file before establishing an outbound TCP connection to **10.0.2.18** over **port 4443**. The observed attack chain (**HTML File → mshta.exe → HTA Payload → Network Connection**) is consistent with malware execution followed by command-and-control communication.

---

## Tools Used

- Windows Event Viewer
- Microsoft Sysmon Operational Logs
- Event Viewer XML View
- MITRE ATT&CK Framework
