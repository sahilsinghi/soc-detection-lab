# Setup Guide — Reproducing the SOC Detection Lab

> Estimated time: 4 hours | Cost: INR 0

## Prerequisites

| Requirement | Details |
|-------------|---------|
| RAM | 16 GB (8 GB for VMs, 8 GB for host) |
| Disk | 120 GB free SSD |
| OS | macOS, Windows, or Linux |
| Hypervisor | UTM (macOS ARM) or VirtualBox 7.x |

## Step 1 — Install Splunk on macOS

```bash
# Download from splunk.com → Mac OS → ARM → .dmg
# Double-click the .dmg and drag to Applications

cd /Applications/Splunk/bin
sudo ./splunk start --accept-license
# Set admin username: admin
# Set password: (your choice)
```

Verify Splunk is running: open http://localhost:8000 in your browser.

**Configure receiving port:**
```bash
sudo ./splunk enable listen 9997 -auth admin:yourpassword
sudo ./splunk restart
```

## Step 2 — Create Windows VMs in UTM

### Windows 10 Endpoint VM
- Download Windows 10 Enterprise Eval ISO from Microsoft Evaluation Center
- In UTM: New VM → Virtualize → Windows → 4 GB RAM, 30 GB disk
- Boot and complete Windows setup

### Windows Server 2022 Endpoint VM
- Download Windows Server 2022 Eval ISO
- Same UTM settings — 4 GB RAM, 30 GB disk

## Step 3 — Install Sysmon on Each Windows VM

Run PowerShell as Administrator on each Windows VM:

```powershell
.\scripts\install-sysmon.ps1
```

Verify: Open Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational. You should see events flowing.

## Step 4 — Install Splunk Universal Forwarder on Each Windows VM

Find your Mac's UTM network IP (usually 192.168.64.1):
```bash
# On your Mac terminal:
ifconfig | grep "192.168"
```

Run on each Windows VM (PowerShell as Admin):
```powershell
.\scripts\install-splunk-uf.ps1 -SplunkServer "192.168.64.1"
```

## Step 5 — Verify Log Ingestion in Splunk

In Splunk web UI → Search & Reporting → run:
```splunk
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=-15m
| stats count by host, sourcetype
```

You should see events from both Windows endpoints.

## Step 6 — Deploy Detection Rules

In Splunk: Settings → Searches, Reports & Alerts → New Alert for each rule in `/detections/`.

Or import them via Splunk CLI:
```bash
cd /Applications/Splunk/bin
sudo ./splunk add saved-search "DETECT - T1059.001" -search "$(cat /path/to/detections/execution/T1059.001__powershell-encoded-command/rule.spl)"
```

## Step 7 — Run Atomic Red Team Simulations

On each Windows VM (PowerShell as Admin — ISOLATED NETWORK ONLY):
```powershell
.\scripts\run-atomics.ps1
```

## Step 8 — Import Coverage Dashboard

In Splunk: Settings → User Interface → Dashboards → Import → paste contents of `dashboards/coverage.xml`

## Step 9 — View MITRE ATT&CK Navigator

1. Go to https://mitre-attack.github.io/attack-navigator/
2. Click "Open Existing Layer" → "Upload from local"
3. Upload `navigator/soc-lab-coverage.json`
4. Screenshot the result for your README
