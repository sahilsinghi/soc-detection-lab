# T1021.002 — SMB Admin Share Access

## Overview
Detects access to Windows administrative shares (ADMIN$, C$, IPC$) which attackers use for lateral movement — copying tools to remote systems or executing commands via PsExec.

## ATT&CK Mapping
- **Tactic:** Lateral Movement
- **Technique:** T1021.002 — Remote Services: SMB/Windows Admin Shares
- **Severity:** High

## Log Source
- Windows Security Event ID 5140 (A network share object was accessed)

## False Positives
- **Domain controllers** legitimately access ADMIN$ for Group Policy distribution
- **SCCM/backup agents** use C$ for file operations — add known service accounts to exclusions

## Atomic Red Team Validation
```powershell
Invoke-AtomicTest T1021.002 -TestNumbers 1
```

## Response Actions
1. Identify source IP and correlate with asset inventory
2. Check what files were copied to the share (Event 5145)
3. If PsExec was used, check for service creation events on the target (Event 7045)
