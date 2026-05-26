# T1082 — System Information Discovery

## Overview
Detects execution of tools commonly used by attackers during the reconnaissance phase to understand the compromised system — OS version, installed software, domain membership.

## ATT&CK Mapping
- **Tactic:** Discovery
- **Technique:** T1082 — System Information Discovery
- **Severity:** Low (high value when chained with other alerts)

## Log Source
- Sysmon Event ID 1 (Process Create)

## Note on Chaining
Low severity on its own. Use correlation searches to chain: if the same host triggers T1082 + T1087.001 + T1021.002 within 10 minutes, escalate to critical — this is a classic post-exploitation discovery sweep.

## Atomic Red Team Validation
```powershell
Invoke-AtomicTest T1082 -TestNumbers 1
```
