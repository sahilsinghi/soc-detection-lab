# T1059.001 — PowerShell Encoded Command

## Overview
Detects PowerShell launched with `-EncodedCommand`, `-enc`, or `-ec` flags, which base64-encode commands to evade simple string-based detection.

## ATT&CK Mapping
- **Tactic:** Execution
- **Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell
- **Severity:** High

## Log Source
- `Endpoint.Processes` datamodel (Sysmon Event ID 1 — Process Create)
- Requires Sysmon with Olaf Hartong config

## Why Attackers Use This
Tools like Empire, Cobalt Strike, and most commodity malware use encoded PowerShell to hide their actual command from defenders scanning process command lines. The base64 payload is decoded at runtime so string-matching rules miss it.

## False Positives
- **SCCM / ConfigMgr** deployments occasionally use `-EncodedCommand` for legitimate software installs
- **Fix:** Whitelist the SCCM service account: `NOT user="sccm_service"`
- **Some admin scripts** from IT teams — review with the sysadmin team and add a known-good hash exclusion

## Atomic Red Team Validation
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1
```

## Response Actions
1. Decode the base64 payload: `[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('<payload>'))`
2. Check parent process — PowerShell spawned by Word/Excel is high-confidence malicious
3. Isolate endpoint if decoded payload contains download cradles or known C2 domains
4. Pull full Sysmon process tree for the host in the last 24 hours
