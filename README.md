# Detection Engineering Library

![Detection Engineering](https://img.shields.io/badge/Detection-Engineering-red)
![Microsoft Defender XDR](https://img.shields.io/badge/Microsoft-Defender_XDR-blue)
![KQL](https://img.shields.io/badge/KQL-Advanced_Hunting-green)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-orange)

## Overview

This repository contains threat detections, KQL analytics, MITRE ATT&CK mappings, investigation procedures, tuning guidance, and response recommendations developed through threat hunting and incident response investigations.

The objective is to transform real-world threat hunting findings into reusable detections that can be operationalized within enterprise security environments.

---

## Detection Categories

### Exfiltration

| Detection | Description |
|------------|------------|
| Discord Webhook Exfiltration | Detects unauthorized file uploads to Discord webhooks using HTTPS-based exfiltration channels. |

---

## Technologies

- Microsoft Defender XDR
- Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- MITRE ATT&CK

---

## Detection Development Process

```text
Threat Hunt
    ↓
Finding
    ↓
Detection Logic
    ↓
KQL Analytics
    ↓
MITRE Mapping
    ↓
Tuning
    ↓
Operational Detection
```

---

## Current Detections

### Exfiltration

- [Discord Webhook Exfiltration](./Discord-Webhook-Exfiltration)

---

## Future Detections

### Exfiltration

- SCP Exfiltration Detection

### Defense Evasion

- Linux Log Tampering Detection
- Timestomping Detection

### Persistence

- Scheduled Task Creation Detection
- Registry Run Key Persistence Detection

### Credential Access

- Credential Dumping Detection

---

## Disclaimer

This repository is intended for educational and defensive cybersecurity purposes.

All examples are based on sanctioned lab environments, threat hunting exercises, security research, and simulated attack scenarios.

No unauthorized activity was performed.
