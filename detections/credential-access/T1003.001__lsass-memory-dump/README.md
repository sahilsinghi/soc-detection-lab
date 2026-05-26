# T1003.001 — LSASS Memory Dump

## Overview
Detects when a process opens a handle to lsass.exe — the Windows process that stores credential hashes in memory. Tools like Mimikatz, ProcDump, and Task Manager can dump LSASS to extract NTLM hashes and Kerberos tickets.

## ATT&CK Mapping
- **Tactic:** Credential Access
- **Technique:** T1003.001 — OS Credential Dumping: LSASS Memory
- **Severity:** Critical

## Log Source
- Sysmon Event ID 10 (ProcessAccess) — fires when any process opens a handle to another

## The Key Field: GrantedAccess
The `GrantedAccess` value tells you what the attacker's process is allowed to do with LSASS:
- `0x1010` — Read + Query info — classic Mimikatz value
- `0x1fffff` — Full access — very suspicious
- `0x410` — Used by some legitimate tools

## False Positives
- **Windows Defender (MsMpEng.exe)** — legitimately scans LSASS for malware signatures → excluded in rule
- **Antivirus products** — add your AV executable path to the NOT clause
- **Sysmon itself** — excluded via wininit.exe/csrss.exe exclusions

## Atomic Red Team Validation
```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 1
```

## Response Actions
1. Immediately isolate the endpoint from the network
2. Assume all credentials on this host are compromised — trigger password resets
3. Check if attacker used PsExec or WMI to move laterally using stolen hashes
4. Pull GrantedAccess value — `0x1fffff` = full dump, treat as critical breach
