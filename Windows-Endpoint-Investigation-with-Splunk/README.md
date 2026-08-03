# Windows Endpoint Investigation with Splunk

## Executive Summary

A Windows endpoint investigation was conducted using Splunk Enterprise after suspicious activity was identified on a compromised host. Analysis of Windows Event Logs revealed that an attacker successfully created an unauthorized local account, modified account-related artifacts, and executed suspicious commands consistent with persistence techniques.

Using Splunk Search Processing Language (SPL), the investigation reconstructed the attack timeline and identified indicators of compromise (IOCs) associated with the intrusion.

---

# Overview

This investigation demonstrates how Splunk can be used to analyze Windows event logs during a Security Operations Center (SOC) investigation.

The primary objectives were to:

- Verify log ingestion
- Identify attacker activity
- Investigate malicious process execution
- Analyze user account management events
- Detect persistence techniques
- Reconstruct attacker actions

---

# Environment

| Item | Details |
|------|---------|
| Platform | TryHackMe |
| SIEM | Splunk Enterprise 8.2.6 |
| Data Source | Windows Event Logs |
| Investigation Type | Endpoint Log Analysis |

---

# Skills Demonstrated

- Splunk Search Processing Language (SPL)
- Windows Event Log Analysis
- Threat Hunting
- IOC Identification
- Process Creation Analysis
- User Account Investigation
- Windows Security Event Analysis
- SOC Incident Investigation

---

# Investigation Workflow

## 1. Verify Log Ingestion

The investigation began by confirming that all Windows logs had been successfully ingested into the **main** index before beginning threat hunting activities.

### SPL Query

```spl
index=main
```

### Evidence

![Initial Log Search](images/01-initial-log-search.png)

---

## 2. Identify Suspicious Account Creation

The next phase focused on identifying suspicious account management activity.

Searching for the **net user** command revealed that an attacker executed a command to create an unauthorized local account named **Alberto**, indicating an attempt to establish persistence.

### SPL Query

```spl
index=main "net user"
```

### Evidence

![User Account Creation](images/02-user-account-creation-investigation.png)

---

## 3. Analyze Process Creation Events

To validate the malicious activity, Windows **Event ID 4688 (Process Creation)** was examined.

The event confirmed execution of the following command:

```cmd
net user /add Alberto paw0rd1
```

This confirmed successful creation of a backdoor account on the compromised endpoint.

### SPL Query

```spl
index=main "Alberto" EventID=4688
```

### Evidence

![Process Creation](images/03-process-creation-event-4688.png)

---

## 4. Investigate User Account Management

Further analysis identified **Event ID 4726**, indicating additional account management activity involving the malicious account.

Reviewing these events helped reconstruct the attack timeline and understand the attacker's actions after persistence had been established.

### SPL Query

```spl
index=main Alberto
```

### Evidence

![User Account Management](images/04-user-account-deletion-event-4726.png)

---

# Investigation Findings

The investigation identified several indicators of compromise:

- Unauthorized local account creation (**Alberto**)
- Malicious execution of the `net user` command
- Windows Event ID **4688** confirming process creation
- Windows Event ID **4726** showing account management activity
- Registry modifications associated with the created account
- Attempted user impersonation
- Suspicious PowerShell execution
- Encoded PowerShell initiating outbound network communication

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
|---------|-----------|
| Persistence | T1136 – Create Account |
| Execution | T1059 – Command and Scripting Interpreter |
| Execution | T1059.001 – PowerShell |
| Discovery | T1087 – Account Discovery |
| Defense Evasion | T1112 – Modify Registry |

---

# SOC Assessment

Analysis indicates that the attacker established persistence by creating an unauthorized local account and executing administrative commands on the compromised endpoint.

Subsequent account management events and PowerShell activity suggest the attacker attempted to maintain long-term access while preparing for additional post-compromise actions.

Although the investigation was performed within a controlled lab environment, the techniques observed closely resemble those encountered during real-world Windows endpoint investigations.

---

# Recommendations

- Remove unauthorized user accounts immediately.
- Investigate all account management events for suspicious activity.
- Enable PowerShell Script Block Logging and Module Logging.
- Monitor Windows Event IDs 4688, 4720, 4726, and PowerShell Operational logs.
- Alert on suspicious usage of `net user`, `wmic`, and PowerShell.
- Review registry modifications associated with newly created accounts.

---

# Tools Used

- Splunk Enterprise 8.2.6
- Windows Event Logs
- TryHackMe
