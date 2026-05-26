# T1562.001 — Disable Windows Defender

## Overview
Detects attempts to disable Windows Defender via registry edits, PowerShell Set-MpPreference, or service control commands. Attackers do this before deploying ransomware or running post-exploitation tools that would otherwise be caught.

## ATT&CK Mapping
- **Tactic:** Defense Evasion
- **Technique:** T1562.001 — Impair Defenses: Disable or Modify Tools
- **Severity:** High

## Log Sources
- Sysmon Event ID 13 (Registry write to Defender policy keys)
- Sysmon Event ID 1 (Process create with Set-MpPreference command)

## False Positives
- **Security testing teams** running authorized AV disable scripts — coordinate with IT
- **Some enterprise AV products** temporarily disable Defender during installation

## Atomic Red Team Validation
```powershell
Invoke-AtomicTest T1562.001 -TestNumbers 1,2
```

## Response Actions
1. Immediately re-enable Defender: `Set-MpPreference -DisableRealtimeMonitoring $false`
2. Check what ran AFTER Defender was disabled — this is the actual payload
3. High confidence of follow-on attack — escalate immediately
