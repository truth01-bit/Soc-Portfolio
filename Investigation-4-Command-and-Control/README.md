
# Investigation 4 – Empire Command and Control Communication

## Executive Summary

A forensic investigation was conducted on the provided **Investigation-4.evtx** Sysmon log to determine the attacker's command-and-control (C2) activity following compromise. Analysis of the Sysmon events revealed persistent outbound network communication between the compromised endpoint and a remote Empire C2 server. The findings indicate that the attacker maintained remote control of the endpoint through the Empire framework over HTTP.

---

## Investigation Questions

| Question                                            | Answer                       |
| --------------------------------------------------- | ---------------------------- |
| What was the adversary IP?                          | **172.30.1.253**             |
| What port was used?                                 | **80**                       |
| Which Command and Control framework was identified? | **Empire**                   |
| What attack phase was observed?                     | **Command and Control (C2)** |

---

## Investigation Objective

Investigate the Sysmon logs to identify the attacker's command-and-control infrastructure, analyse the outbound network communication, and document indicators associated with the Empire C2 framework.

---

## Investigation Methodology

The investigation began by loading the provided **Investigation-4.evtx** file into **Windows Event Viewer**. Analysis of the available Sysmon events identified multiple **Network Connection (Event ID 3)** events showing repeated communication between the compromised endpoint and a remote server, indicating an active command-and-control channel.

Screenshot 2026-07-28 

*Investigation overview showing the available Sysmon events.*

---

## Network Connection Analysis

The investigation focused on **Sysmon Event ID 3 (Network Connection)**.

Analysis identified repeated outbound communication from the compromised endpoint to:

* **Destination IP:** `172.30.1.253`
* **Destination Port:** `80`

The use of HTTP traffic over the default web port allows attackers to blend malicious traffic with legitimate network activity, reducing the likelihood of detection.

Screenshot 2026-07-28 

*Event ID 3 showing outbound communication with the remote server.*

---

## Command and Control Analysis

Further analysis confirmed the remote infrastructure was operating the **Empire** Command and Control framework.

Empire is a post-exploitation framework commonly used by attackers to maintain persistence, execute remote commands, transfer files, and control compromised systems after initial access.

The repeated network connections observed throughout the investigation indicate the compromised endpoint remained under the attacker's control.

 Screenshot 2026-07-28 
*Evidence identifying the Empire C2 framework.*

---

## Attack Timeline

The observed activity followed the sequence:

* Initial compromise established in previous investigations.
* Persistent outbound communication initiated.
* Communication maintained with the Empire C2 server.
* Remote control of the compromised endpoint remained active.

Screenshot 2026-07-28 

*Timeline showing continued communication with the Empire server.*

---

# Findings

* **Sysmon Event ID 3** identified repeated outbound communication.
* The remote adversary IP was **172.30.1.253**.
* Communication occurred over **TCP port 80**.
* The attacker utilised the **Empire** Command-and-Control framework.
* The observed activity confirms the compromised endpoint remained under active remote control.

---

# MITRE ATT&CK Mapping

| Tactic              | Technique                      | ATT&CK ID |
| ------------------- | ------------------------------ | --------- |
| Command and Control | Application Layer Protocol     | T1071     |
| Command and Control | Non-Application Layer Protocol | T1095     |
| Persistence         | External Remote Services       | T1133     |

---

# SOC Analyst Conclusion

The investigation confirmed persistent command-and-control communication between the compromised endpoint and the remote adversary at **172.30.1.253** over **TCP port 80**. Analysis of the Sysmon network events identified the **Empire** framework as the attacker's C2 platform. The repeated outbound connections demonstrate that the attacker successfully maintained remote access to the compromised host following the earlier stages of the intrusion. This behaviour is consistent with the command-and-control phase of the cyber kill chain and highlights the importance of monitoring outbound network traffic for signs of persistent malicious communication.

---

## Tools Used

* Windows Event Viewer
* Microsoft Sysmon Operational Logs
* MITRE ATT&CK Framework

---


 
