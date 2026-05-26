# install-sysmon.ps1
# Installs Sysmon with Olaf Hartong's sysmon-modular config
# Run as Administrator on Windows endpoints

#Requires -RunAsAdministrator

$SysmonUrl    = "https://download.sysinternals.com/files/Sysmon.zip"
$ConfigUrl    = "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml"
$TempDir      = "$env:TEMP\sysmon-install"

Write-Host "[*] Creating temp directory..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $TempDir | Out-Null

Write-Host "[*] Downloading Sysmon..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $SysmonUrl -OutFile "$TempDir\Sysmon.zip"
Expand-Archive -Path "$TempDir\Sysmon.zip" -DestinationPath $TempDir -Force

Write-Host "[*] Downloading Olaf Hartong sysmon-modular config..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $ConfigUrl -OutFile "$TempDir\sysmonconfig.xml"

Write-Host "[*] Installing Sysmon64 with config..." -ForegroundColor Cyan
& "$TempDir\Sysmon64.exe" -accepteula -i "$TempDir\sysmonconfig.xml"

Write-Host "[+] Verifying Sysmon service status..." -ForegroundColor Green
Get-Service Sysmon64 | Select-Object Name, Status, StartType

Write-Host "[+] Sysmon installed successfully!" -ForegroundColor Green
Write-Host "    Check logs at: Applications and Services Logs > Microsoft > Windows > Sysmon > Operational"
