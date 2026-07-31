Investigation 1 – Initial Access via Malicious USB
Executive Summary
A forensic investigation was conducted on the provided Investigation-1.evtx Sysmon log to identify how the attacker gained initial access and determine the actions performed on the compromised endpoint. Analysis of the Sysmon events revealed suspicious process execution, registry modifications, and raw disk access associated with a connected USB storage device. The findings indicate activity consistent with malware interacting with removable media and attempting to access the local disk directly.

Investigation Questions
Question	Answer
What process was observed during the investigation?	svchost.exe
Which registry key was modified?	HKLM\System\CurrentControlSet\Enum\WpdBusEnumRoot
Which device was accessed using RawAccessRead?	\Device\HarddiskVolume3
What was the suspected initial access vector?	USB Storage Device (Removable Media)
Investigation Objective
Investigate the Sysmon logs to determine the suspected initial access vector, identify the process involved, analyse registry modifications, and document evidence of raw disk access.

Investigation Methodology
The investigation began by loading the provided Investigation-1.evtx file into Windows Event Viewer. A review of the available Sysmon events showed multiple Process Creation (Event ID 1), Registry Value Set (Event ID 13), Process Termination (Event ID 5) and RawAccessRead (Event ID 9) events occurring within a very short period, indicating suspicious activity associated with a connected USB device.

!Screenshot 2026-07-28 at 17.04.09.png

Investigation overview showing the available Sysmon events.

Process Execution Analysis
The investigation focused on Sysmon Event ID 1 (Process Creation) to identify which executable was active during the incident.

The analysis identified svchost.exe as the primary process associated with the recorded Sysmon events. Although svchost.exe is a legitimate Windows system process, its activity immediately preceding the registry modifications and raw disk access warranted further investigation.

The event timeline showed the process executing shortly before additional suspicious activity occurred, allowing the attack sequence to be reconstructed.

Registry Modification Analysis
The next phase examined Sysmon Event ID 13 (Registry Value Set) using both Event Viewer and PowerShell.

The registry events showed svchost.exe modifying USB-related registry entries under:

HKLM\System\CurrentControlSet\Enum\WpdBusEnumRoot

These registry modifications indicate interaction with a connected removable storage device and provide evidence supporting the suspected USB-based initial access.

!Screenshot 2026-07-28 at 17.40.42.png

Event ID 13 showing Registry Value Set performed by svchost.exe.

Raw Disk Access Analysis
The investigation then examined Sysmon Event ID 9 (RawAccessRead).

Multiple RawAccessRead events were identified showing direct access to:

\Device\HarddiskVolume3

Raw disk access is uncommon during normal user activity and is often associated with malware attempting to bypass normal filesystem operations to inspect or interact directly with storage devices.

These events occurred shortly after the registry modifications, strengthening the timeline of suspicious activity.

!Screenshot 2026-07-28 at 17.52.18.png

Event Viewer showing the RawAccessRead event.

!Screenshot 2026-07-28 at 17.56.15.png

PowerShell output displaying the RawAccessRead event details.

Findings
Evidence indicates the activity was associated with a connected USB storage device.
Sysmon Event ID 1 identified svchost.exe as the process involved during the investigation.
Sysmon Event ID 13 recorded registry modifications related to the connected USB device.
Sysmon Event ID 9 showed direct access to \Device\HarddiskVolume3.
The event sequence (Process Creation → Registry Modification → RawAccessRead) demonstrates a clear timeline of suspicious activity involving removable media.
MITRE ATT&CK Mapping
Tactic	Technique	ATT&CK ID
Initial Access	Replication Through Removable Media	T1091
Execution	Windows Command and Scripting Interpreter	T1059
Discovery	Peripheral Device Discovery	T1120
Defence Evasion	Masquerading	T1036
SOC Analyst Conclusion
The investigation identified suspicious activity associated with removable media. Sysmon telemetry showed svchost.exe executing shortly before USB-related registry modifications and raw disk access events were recorded. While svchost.exe is a legitimate Windows process, the sequence of events observed in this investigation suggests it was involved in suspicious activity linked to the connected USB device. Based on the available evidence, the attack followed a timeline of Process Creation → Registry Modification → RawAccessRead, indicating behaviour commonly associated with malware interacting with removable media.

Tools Used
Windows Event Viewer
Microsoft Sysmon Operational Logs
PowerShell (Get-WinEvent)
MITRE ATT&CK Framework
