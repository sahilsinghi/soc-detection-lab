# T1547.001 — Registry Run Key Persistence

## Overview
Detects writes to the Windows Registry Run keys, a classic persistence mechanism used by malware to survive reboots. Any executable path written here will run automatically when the user logs in.

## ATT&CK Mapping
- **Tactic:** Persistence
- **Technique:** T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys
- **Severity:** High

## Log Source
- Sysmon Event ID 13 (RegistryEvent — Value Set)

## False Positives
- **Software installers (msiexec.exe, setup.exe)** — legitimately write to Run keys during installation → excluded
- **Legitimate software** like Teams, Slack, OneDrive adds itself to Run keys — tune by adding known-good `Details` values to a whitelist lookup

## Atomic Red Team Validation
```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1
```

## Response Actions
1. Note the `Details` field — this is the executable path that will auto-run
2. Check if the executable exists and submit to VirusTotal
3. Remove the registry key: `reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v MalwareName /f`
4. Determine how the key was written — check parent process chain
