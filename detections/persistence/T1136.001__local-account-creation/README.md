# T1136.001 — Local Account Creation

## Overview
Detects creation of new local user accounts via Windows Security Event 4720. Attackers create backdoor accounts for persistent access, often naming them to blend in with legitimate accounts.

## ATT&CK Mapping
- **Tactic:** Persistence
- **Technique:** T1136.001 — Create Account: Local Account
- **Severity:** Medium

## Log Source
- Windows Security Event ID 4720 (A user account was created)

## False Positives
- **IT helpdesk** creating accounts during provisioning — correlate with a change ticket
- **Software installers** that create service accounts — check SubjectUserName for installer processes

## Atomic Red Team Validation
```powershell
Invoke-AtomicTest T1136.001 -TestNumbers 1
```

## Response Actions
1. Check if the new account was added to Administrators group (Event 4732)
2. Disable the account immediately if unauthorized: `net user <username> /active:no`
3. Check for logon events (4624) from the new account — may already be in use
