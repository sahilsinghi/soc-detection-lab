# run-atomics.ps1
# Installs Invoke-AtomicRedTeam and runs all mapped atomic tests
# Run as Administrator on Windows endpoints
# WARNING: Only run in isolated lab VMs. These are real attack simulations.

#Requires -RunAsAdministrator

Write-Host "========================================" -ForegroundColor Red
Write-Host "  ATOMIC RED TEAM — SOC LAB VALIDATION  " -ForegroundColor Red
Write-Host "  WARNING: Run only in isolated VMs!    " -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red

# Install Invoke-AtomicRedTeam
Write-Host "[*] Installing Invoke-AtomicRedTeam..." -ForegroundColor Cyan
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force

Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

# Test mapping from atomic-mappings.csv
$techniques = @(
    "T1059.001", "T1059.003", "T1204.002", "T1053.005",
    "T1547.001", "T1136.001", "T1543.003", "T1197",
    "T1055.001", "T1134.001", "T1562.001", "T1070.004",
    "T1218.011", "T1003.001", "T1110.001", "T1555.003",
    "T1552.001", "T1082",     "T1083",     "T1087.001",
    "T1021.002", "T1021.001", "T1550.002", "T1005",
    "T1114.001", "T1071.001", "T1095",     "T1041",
    "T1486",     "T1566.001", "T1190",     "T1543.003"
)

$logPath = "C:\AtomicRedTeam\execution_log.csv"
"timestamp,technique,result,notes" | Out-File $logPath -Encoding UTF8

foreach ($technique in $techniques) {
    Write-Host "`n[*] Running: $technique" -ForegroundColor Yellow
    try {
        Invoke-AtomicTest $technique -TestNumbers 1 -TimeoutSeconds 60 -ErrorAction Stop
        $result = "EXECUTED"
        Write-Host "[+] $technique — EXECUTED" -ForegroundColor Green
    } catch {
        $result = "ERROR: $($_.Exception.Message)"
        Write-Host "[-] $technique — ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$technique,$result,TestNumber-1" | Add-Content $logPath
    Start-Sleep -Seconds 5  # Give Splunk time to index the event
}

Write-Host "`n[+] All atomics executed. Log saved to: $logPath" -ForegroundColor Green
Write-Host "[*] Now check Splunk for alerts — search: index=main earliest=-1h" -ForegroundColor Cyan
