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

## T1059.001 — PowerShell Encoded Command (Validated 2026-05-27)

### Attack
On the Windows VM, executed a base64-encoded PowerShell payload:

```powershell
$e = "VwByAGkAdABlAC0ASABvAHMAdAAgACcAUwBPAEMALQBMAEEAQgAtAFQAMQAwADUAOQAtAFQARQBTAFQAJwA="
powershell.exe -EncodedCommand $e
```

Decoded payload: `Write-Host 'SOC-LAB-T1059-TEST'` — benign, but matches the TTP signature attackers use to evade plaintext-string detection.

### Telemetry captured
- **Sourcetype:** `WinEventLog:Microsoft-Windows-Sysmon/Operational`
- **EventCode:** 1 (process creation)
- **Host:** WIN-G086Q4H1K5D
- **CommandLine:** `"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -EncodedCommand "VwByAGkAdABl..."`

### Scheduled rule outcome
Manually dispatched `MITRE T1059.001 - PowerShell Encoded Command` immediately after the test. Job returned **10 results** — the test payload plus surrounding ambient encoded-command activity (PowerShell modules use `-EncodedCommand` internally for splatting, so this rule will need ambient-noise tuning later, similar to T1003.001).

---

## T1562.001 — Disable Windows Defender (Validated 2026-05-27)

### Attack
Custom simulator (no upstream Atomic Red Team coverage for T1562 — see lesson #5 below):

```powershell
$c = "Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue"
powershell.exe -Command $c
```

Tamper Protection blocks the actual config change. That's fine — the detection target is the *attempt*, not the outcome. Sysmon EID 1 still fires for the `powershell.exe -Command Set-MpPreference ...` process creation.

### Telemetry captured
- **Sourcetype:** `WinEventLog:Microsoft-Windows-Sysmon/Operational`
- **EventCode:** 1
- **Host:** WIN-G086Q4H1K5D
- **CommandLine:** `"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -Command "Set-MpPreference -DisableRealtimeMonitoring True -ErrorAction SilentlyContinue"`

### Scheduled rule outcome
Saved search `MITRE T1562.001 - Disable Windows Defender` originally had the legacy `sourcetype="XmlWinEventLog*"` and a `process` field that doesn't exist on the new sourcetype — same root cause as the T1003.001 stale-sourcetype bug. Patched via REST to use `WinEventLog:Microsoft-Windows-Sysmon/Operational` + the `CommandLine` field, then re-dispatched. **1 hit returned**, exactly matching the test command. Repo `rule.spl` synced.

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

5. **T1562.001 has no Atomic Red Team coverage upstream.** Initial assumption was Defender filtered the YAML at pull time — wrong. The `atomics/` directory in `redcanaryco/atomic-red-team@master` jumps T1560 → T1563. No T1562, T1562.001, or any T1562.xxx folders exist. Verified via the GitHub Contents API. So the "Disable Defender" TTP needs a custom simulator (e.g., `Set-MpPreference -DisableRealtimeMonitoring $true` driven via a local PS1) rather than an atomic. On a hardened endpoint Tamper Protection blocks this call entirely, so even the custom simulator only works with TP off or AuditMode set on the relevant ASR rule. **The detection rule itself is still valid** — it watches for Sysmon EID 1 with `CommandLine="*Set-MpPreference*"` and a `Disable*` flag, which fires regardless of whether the call succeeded.
