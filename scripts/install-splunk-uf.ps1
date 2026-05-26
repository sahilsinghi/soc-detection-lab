# install-splunk-uf.ps1
# Installs Splunk Universal Forwarder and configures inputs for SIEM forwarding
# Run as Administrator on Windows endpoints
# USAGE: .\install-splunk-uf.ps1 -SplunkServer "192.168.64.1" -SplunkPort 9997

#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$true)]
    [string]$SplunkServer,          # IP of your Splunk SIEM (Mac host: usually 192.168.64.1)
    [int]$SplunkPort = 9997,
    [string]$SplunkUFVersion = "9.2.1"
)

$InstallerUrl = "https://download.splunk.com/products/universalforwarder/releases/$SplunkUFVersion/windows/splunkforwarder-$SplunkUFVersion-windows-x64.msi"
$TempDir = "$env:TEMP\splunk-uf"

Write-Host "[*] Downloading Splunk Universal Forwarder $SplunkUFVersion..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
Invoke-WebRequest -Uri $InstallerUrl -OutFile "$TempDir\splunkuf.msi"

Write-Host "[*] Installing Splunk UF silently..." -ForegroundColor Cyan
Start-Process msiexec.exe -ArgumentList "/i `"$TempDir\splunkuf.msi`" RECEIVING_INDEXER=`"$SplunkServer`:$SplunkPort`" WINEVENTLOG_SEC_ENABLE=1 WINEVENTLOG_SYS_ENABLE=1 AGREETOLICENSE=Yes /quiet" -Wait

Write-Host "[*] Configuring inputs.conf..." -ForegroundColor Cyan
$InputsConf = @"
[WinEventLog://Security]
disabled = false
index = main

[WinEventLog://System]
disabled = false
index = main

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
renderXml = true
index = main

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = false
index = main
"@

$InputsPath = "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"
$InputsConf | Out-File -FilePath $InputsPath -Encoding UTF8 -Force

Write-Host "[*] Restarting Splunk UF service..." -ForegroundColor Cyan
Restart-Service SplunkForwarder

Write-Host "[+] Splunk UF installed and forwarding to $SplunkServer`:$SplunkPort" -ForegroundColor Green
