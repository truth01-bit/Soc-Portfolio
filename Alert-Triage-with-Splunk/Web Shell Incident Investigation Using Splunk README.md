# 

---

# Investigation 3 – Web Shell Alerts

## Executive Summary

A Splunk investigation was conducted after an alert indicated a possible web shell upload to the web server **web.trywinme.thm**. Analysis of web server access logs confirmed that the attacker successfully brute-forced the WordPress login page using Hydra before interacting with a malicious PHP web shell. Further investigation showed multiple HTTP POST requests originating from the same external IP address, indicating active command execution through the uploaded web shell.

---

## Alert Overview

| Field | Value |
| --- | --- |
| Alert | Potential Web Shell Upload Detected |
| Time | 14 September 2025 09:31:51 |
| Target | web.trywinme.thm |
| Attacker IP | 171.251.232.40 |
| Log Source | Splunk (web-alert index) |

---

## Investigation Findings

### Evidence 1 – Alert Details

The investigation began with a Splunk alert indicating a suspected web shell upload against the vulnerable web server. The alert identified the external source IP responsible for the activity and provided the starting point for the investigation.

**Screenshot:**

`Screenshot 2026-07-30 at 13.07.16`

---

### Evidence 2 – Hydra Brute Force Activity

Searching the access logs revealed numerous requests containing the **Hydra** user agent. The earliest events showed repeated login attempts against the WordPress login page (`/wp-login.php`), confirming that Hydra was used to brute-force credentials before the attacker gained access.

**Findings**

- External IP: **171.251.232.40**
- Tool Used: **Hydra**
- Target Endpoint: `/wp-login.php`

**Screenshot:**

`Screenshot 2026-07-30 at 13.18.47`

---

### Evidence 3 – Web Shell Interaction

Filtering the access logs by attacker IP and user agent revealed several HTTP **POST** requests made after the successful compromise. These requests targeted PHP resources associated with the uploaded web shell, demonstrating active interaction with the compromised server.

The captured user agent identified the attacker using a standard Chrome browser after initial access, indicating manual interaction following the automated brute-force attack.

**Findings**

- HTTP Method: **POST**
- User Agent: **Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36**
- Multiple POST requests observed from the same attacker IP.

**Screenshot:**

`Screenshot 2026-07-30 at 13.22.40`

---

### Evidence 4 – Request Frequency

Using Splunk statistics, the investigation confirmed that the attacker submitted **four** POST requests to the malicious PHP web shell.

This behaviour is consistent with attackers issuing commands remotely through an uploaded web shell after obtaining access.

**Screenshot:**

`Screenshot 2026-07-30 at 13.29.35`

---

## Indicators of Compromise (IOCs)

| Indicator | Value |
| --- | --- |
| Attacker IP | 171.251.232.40 |
| Initial Attack Tool | Hydra |
| Target | web.trywinme.thm |
| Target Endpoint | /wp-login.php |
| HTTP Method | POST |
| Number of Web Shell Requests | 4 |
| Browser User Agent | Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/138.0.0.0 |

---

## MITRE ATT&CK Mapping

| Tactic | Technique |
| --- | --- |
| Credential Access | T1110 – Brute Force |
| Initial Access | T1190 – Exploit Public-Facing Application |
| Persistence | T1505.003 – Web Shell |
| Command and Control | T1071.001 – Web Protocols |

---

## SOC Assessment

The investigation confirmed that the alert represented genuine malicious activity rather than a false positive. The attacker first used **Hydra** to brute-force authentication against the WordPress login page before interacting with an uploaded PHP web shell using multiple HTTP POST requests. This sequence demonstrates a complete attack chain consisting of credential compromise followed by remote command execution.

---

## Recommended Response Actions

- Immediately isolate the compromised web server.
- Remove the malicious web shell from the server.
- Reset all compromised credentials.
- Block the attacker IP address (**171.251.232.40**).
- Review web server logs for additional persistence mechanisms.
- Enable multi-factor authentication for administrative accounts.
- Restrict unnecessary access to WordPress administrative interfaces.
