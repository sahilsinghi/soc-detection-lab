# Detection Validation Log

End-to-end proof that scheduled rules fire on real attack telemetry: **attack → Windows log → Sysmon → Splunk UF → indexed → scheduled SPL → result**.

---

## T1110.001 — Password Brute Force (Validated 2026-05-27)

### Attack
25 failed SMB logons against a non-existent local account from PowerShell on the same host:

```powershell
1..25 | % { net use \\127.0.0.1\C$ /user:adminTarget WrongPass$_ 2>$null }
```

### Telemetry captured
- **Sourcetype:** `WinEventLog:Security`
- **EventCode:** 4625 (account failed to log on)
- **Account_Name:** `adminTarget` × 25
- **Window:** 11:01:22 → 11:02:16 IST
- **Failure reason:** Unknown user name or bad password (Status `0xC000006D` / SubStatus `0xC0000064`)
- **Logon Type:** 3 (network)
- **Auth Package:** NTLM
- **Source IP:** 127.0.0.1

### Scheduled rule outcome
Saved search `MITRE T1110.001 - Password Brute Force` fired at 11:05 IST scheduled run (cron `*/5 * * * *`, dispatch window `-15m`). Result:

| _time (5-min bucket) | host | Account_Name | count |
|---|---|---|---|
| 2026-05-27 11:00 IST | WIN-G086Q4H1K5D | adminTarget | **25** |

Threshold `count > 10` exceeded → detection hit. Dispatched job: `scheduler__admin__search__RMD55634d80b505f325c_at_1779860100_1375` (`resultCount=2`, `eventCount=25`).

---

## T1003.001 — LSASS Memory Dump (Rule alive, FP tuning needed)

### Outcome
Same 11:05 scheduled run, `MITRE T1003.001 - LSASS Memory Dump` produced **25 results**. All hits had this shape:

```
SourceImage  = C:\WINDOWS\system32\svchost.exe
TargetImage  = C:\WINDOWS\system32\lsass.exe
GrantedAccess = 0x1000
```

### Analysis
`GrantedAccess: 0x1000` = `PROCESS_QUERY_LIMITED_INFORMATION` — a status-only query, **not** memory read. Legitimate Windows services routinely open this kind of handle on LSASS to retrieve auth context. These are **false positives**.

Credential-theft tools (ProcDump, Mimikatz, comsvcs.dll) typically request `0x1010` or `0x1410`, which include `PROCESS_VM_READ` (`0x0010`).

### Proposed tuning
Add a clause to drop status-only svchost queries:

```spl
... NOT (SourceImage="*svchost.exe" AND GrantedAccess="0x1000") ...
```

This is the kind of FP tuning a SOC analyst owns. Documented here as a known follow-up.

**Applied 2026-05-27:** Patched the saved search via Splunk REST (`POST /servicesNS/admin/search/saved/searches/MITRE%20T1003.001%20-%20LSASS%20Memory%20Dump`) to add `NOT (SourceImage="*svchost.exe" AND GrantedAccess="0x1000")`. Repo rule file (`detections/credential-access/T1003.001__lsass-memory-dump/rule.spl`) updated to match.

---

## Pipeline State Confirmed Healthy (2026-05-27)

| Sourcetype | Events / 10 min |
|---|---|
| `WinEventLog:Microsoft-Windows-Sysmon/Operational` | 41,035 |
| `WinEventLog:Security` | 111 |
| `WinEventLog:System` | 10 |

All 7 scheduled MITRE rules running cleanly every 5 minutes; latest dispatches verified via the `saved/searches/.../history` REST endpoint.

---

## Lessons Captured During Validation

These hit us in this session — keeping them here so future-me doesn't re-discover:

1. **UTM Windows VM clock drifts during sleep/reboot.** Local time can stay correct visually but the host's UTC offset gets mangled, putting indexed event `_time` in the future relative to Splunk's `now` — every `earliest=-Xm latest=now` search misses live data. Re-set the date with `Set-Date` or `w32tm /resync` after every VM reboot until a persistent fix is in place.

2. **Saved-search dispatch windows are tight.** The default `earliest=-5m latest=now` means scheduled rules only see the last 5 minutes. Widened the T1110 search to `-15m` so post-attack runs still catch the brute force.

3. **ASR blocks T1003.001 procdump silently.** On a default Win11 install, the LSASS ASR rule (`9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`) kills procdump before any Sysmon EventCode 1 fires. Either set the rule to `AuditMode` or disable Tamper Protection via the GUI to actually capture the attack telemetry.

4. **Audit policy was not capturing 4625 events out of the box.** Enabled with `auditpol /set /subcategory:"Logon" /failure:enable /success:enable` before T1110 produced anything Splunk could see.

5. **Atomic test definitions for T1562.001 weren't downloaded** with the default Atomic Red Team install — likely got filtered by Defender at pull time. Pivoted to T1110.001 instead.
