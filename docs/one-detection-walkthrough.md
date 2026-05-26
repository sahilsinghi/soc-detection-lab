# Detection Deep-Dive: T1003.001 — LSASS Memory Dump

> This walkthrough demonstrates one complete detection from attack simulation to alert in Splunk.

## The Attack Technique

**LSASS** (Local Security Authority Subsystem Service) is a Windows process that stores credential hashes in memory. Attackers use tools like **Mimikatz** or **ProcDump** to read LSASS memory and extract:
- NTLM password hashes (can be cracked offline or used in Pass-the-Hash attacks)
- Kerberos tickets (for Pass-the-Ticket attacks)
- Cleartext passwords (if WDigest is enabled)

This is one of the most common post-exploitation steps in real-world breaches — used by ransomware groups, APTs, and red teams alike.

## Step 1 — Generate the Attack

On the Windows VM (PowerShell as Admin):
```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 1
```

This runs ProcDump against LSASS:
```
procdump.exe -ma lsass.exe lsass.dmp
```

## Step 2 — What Sysmon Captures

Sysmon Event ID 10 (ProcessAccess) fires immediately:

```xml
<Event>
  <EventID>10</EventID>
  <SourceImage>C:\Tools\procdump.exe</SourceImage>
  <TargetImage>C:\Windows\System32\lsass.exe</TargetImage>
  <GrantedAccess>0x1fffff</GrantedAccess>
  <CallTrace>C:\Windows\SYSTEM32\ntdll.dll|UNKNOWN</CallTrace>
</Event>
```

Key fields:
- `TargetImage` = lsass.exe → the process being accessed
- `GrantedAccess` = 0x1fffff → full access (extremely suspicious)
- `SourceImage` = procdump.exe → the tool used

## Step 3 — The SPL Detection Query

```splunk
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=10 TargetImage="*\\lsass.exe"
NOT (SourceImage="*\\MsMpEng.exe"
  OR SourceImage="*\\csrss.exe"
  OR SourceImage="*\\wininit.exe"
  OR SourceImage="*\\svchost.exe")
| eval mitre_technique="T1003.001", severity="critical"
| table _time, host, SourceImage, TargetImage, GrantedAccess, mitre_technique, severity
```

## Step 4 — False Positive Analysis

**Windows Defender (MsMpEng.exe)** legitimately opens LSASS to scan for in-memory malware. Without the exclusion, every Defender scan fires this alert — generating hundreds of false positives per day.

**Resolution:** Add `NOT SourceImage="*\\MsMpEng.exe"` to exclude Defender. Add your EDR/AV vendor's process path if needed.

**Lesson:** Understanding what's normal in your environment is the core skill of detection engineering. The rule itself is simple — the tuning is where the expertise lives.

## Step 5 — Alert in Splunk

The scheduled search runs every 60 seconds. When the atomic fires, within ~60 seconds you see:

```
_time          host              SourceImage         TargetImage              GrantedAccess  severity
2026-05-23     WIN10-ENDPOINT1   C:\Tools\procdump   C:\Windows\...\lsass.exe  0x1fffff      critical
```

## Step 6 — Response Actions

1. Immediately isolate the endpoint (disable its NIC)
2. Assume ALL credentials on this host are compromised
3. Trigger emergency password reset for all accounts that logged into this machine
4. Check for lateral movement (4624 events from this host to others in the last 2 hours)
5. Preserve the lsass.dmp file if found — it's forensic evidence

## Interview Talking Points

- "I detected LSASS access using Sysmon Event ID 10 (ProcessAccess), specifically filtering on the TargetImage field for lsass.exe"
- "The GrantedAccess value of 0x1fffff indicates full memory access — this is what Mimikatz and ProcDump request"
- "My main false positive was Windows Defender, which I excluded by filtering on SourceImage"
- "When this fires in a real environment, the first call is to the IR team because credential compromise changes the entire incident scope"
