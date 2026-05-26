# T1059.003 — Suspicious CMD Execution

## Overview
Detects cmd.exe running reconnaissance or suspicious commands, particularly when spawned from unexpected parent processes.

## ATT&CK Mapping
- **Tactic:** Execution
- **Technique:** T1059.003 — Command and Scripting Interpreter: Windows Command Shell
- **Severity:** Medium

## Log Source
- Sysmon Event ID 1 (Process Create)

## False Positives
- Help desk staff running `ipconfig` or `systeminfo` legitimately — tune by user whitelist
- Monitoring agents that use cmd.exe internally

## Atomic Red Team Validation
```powershell
Invoke-AtomicTest T1059.003 -TestNumbers 1
```

## Response Actions
1. Focus on the ParentImage — cmd.exe from Word/Excel is very high confidence
2. Build a process tree from the host to understand the full chain
