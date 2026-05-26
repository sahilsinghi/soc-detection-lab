# T1110.001 — Password Brute Force

## Overview
Detects more than 10 failed logon attempts against the same account within 5 minutes. Classic brute force or password spray pattern.

## ATT&CK Mapping
- **Tactic:** Credential Access
- **Technique:** T1110.001 — Brute Force: Password Guessing
- **Severity:** High

## Log Source
- Windows Security Event ID 4625 (An account failed to log on)

## Tuning Notes
- Threshold of 10 in 5 minutes is a starting point — tune based on your environment's baseline
- **LogonType=3** (Network) is most suspicious; LogonType=2 (Interactive) suggests local access

## False Positives
- **Users who forget their password** — usually 3-5 attempts, not 10+
- **Misconfigured services** with stale credentials — check IpAddress against asset inventory

## Atomic Red Team Validation
```powershell
Invoke-AtomicTest T1110.001 -TestNumbers 1
```

## Response Actions
1. Check if any 4624 (success) follows the 4625 failures — account may be compromised
2. Lock account temporarily: `net user <username> /active:no`
3. Identify source IP and block at firewall if external
