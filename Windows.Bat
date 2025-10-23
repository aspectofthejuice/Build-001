<#
.SYNOPSIS
  Harden-WindowsHost.ps1 (CyberPatriot Edition)
.DESCRIPTION
  Defensive hardening script for Windows 10/11 and Server 2022 environments.
  Aligns with CyberPatriot, CIS Benchmarks, and DoD STIG principles.
  Applies secure configurations, logs all actions, and supports dry-run auditing.
  Must be run as Administrator.
.NOTES
  - Author: John CyberPatriot (AI Assistant)
  - Ethical use only. No offensive operations.
  - Safe to re-run (idempotent).
  - Logs and summaries stored in %ProgramData%\WindowsHardeningLogs
.PARAMETER DryRun
  Run in audit-only mode (reports changes without applying).
.EXAMPLE
  .\Harden-WindowsHost.ps1 -DryRun
  .\Harden-WindowsHost.ps1
#>

param([switch]$DryRun)

#region === Logging Setup ===
$logRoot = Join-Path $env:ProgramData "WindowsHardeningLogs"
$null = New-Item -Path $logRoot -ItemType Directory -Force
$timestamp = (Get-Date -Format "yyyyMMdd_HHmmss")
$logFile = "$logRoot\Hardening_$timestamp.log"
$csvFile = "$logRoot\Summary_$timestamp.csv"
$summary = @()

function Log($msg, $lvl="INFO") {
    $time = (Get-Date -Format "u")
    $line = "[$time][$lvl] $msg"
    switch ($lvl) {
        "INFO" { Write-Host $msg -ForegroundColor Cyan }
        "WARN" { Write-Host $msg -ForegroundColor Yellow }
        "ERROR" { Write-Host $msg -ForegroundColor Red }
        "OK" { Write-Host $msg -ForegroundColor Green }
    }
    Add-Content $logFile $line
}

function Add-Summary($setting,$old,$new,$status){
    $summary += [PSCustomObject]@{
        Timestamp=(Get-Date)
        Setting=$setting; Previous=$old; New=$new; Status=$status
    }
}
function Do-Action($name,[scriptblock]$action){
    if ($DryRun){ Log "DryRun: would apply $name" "WARN"; Add-Summary $name "-" "Pending" "DryRun"; return }
    try{ & $action; Log "$name applied" "OK"; Add-Summary $name "-" "-" "Applied" }
    catch{ Log "$name failed: $($_.Exception.Message)" "ERROR"; Add-Summary $name "-" "-" "Failed" }
}

Log "=== Starting Windows Hardening ($(if($DryRun){"DryRun Mode"}else{"Live Mode"})) ==="
#endregion

#region === 1. Password & Lockout Policy ===
Do-Action "Password & Lockout Policy" {
@"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength = 12
MaximumPasswordAge = 90
MinimumPasswordAge = 1
PasswordComplexity = 1
PasswordHistorySize = 24
[Lockout Policy]
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
"@ | Out-File "$env:TEMP\policy.inf" -Encoding ASCII
secedit /configure /db "$env:windir\security\database\secedit.sdb" /cfg "$env:TEMP\policy.inf" /areas SECURITYPOLICY | Out-Null
}

#region === 2. Firewall ===
Do-Action "Enable Windows Firewall" {
Import-Module NetSecurity
foreach ($p in "Domain","Private","Public"){
    Set-NetFirewallProfile -Profile $p -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow
}
}

#region === 3. Windows Update ===
Do-Action "Windows Update Service" {
Set-Service -Name "wuauserv" -StartupType Automatic
Start-Service "wuauserv" -ErrorAction SilentlyContinue
}

#region === 4. Disable Insecure Services ===
Do-Action "Disable SMBv1" {
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
}
Do-Action "Disable Telnet" {
Stop-Service "TlntSvr" -ErrorAction SilentlyContinue
Set-Service "TlntSvr" -StartupType Disabled -ErrorAction SilentlyContinue
}
Do-Action "Disable RemoteRegistry" {
Stop-Service "RemoteRegistry" -ErrorAction SilentlyContinue
Set-Service "RemoteRegistry" -StartupType Disabled -ErrorAction SilentlyContinue
}
Do-Action "Disable AutoRun/AutoPlay" {
$reg="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
New-Item -Path $reg -Force | Out-Null
Set-ItemProperty $reg NoDriveTypeAutoRun 255
Set-ItemProperty $reg NoDriveAutoRun 1
}

#region === 5. Enforce UAC ===
Do-Action "User Account Control" {
$reg="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty $reg EnableLUA 1
Set-ItemProperty $reg ConsentPromptBehaviorAdmin 2
}

#region === 6. Disable Guest/Test Accounts ===
Do-Action "Disable Guest & Test Accounts" {
Get-LocalUser | Where-Object {$_.Name -match 'guest|test|demo|sample'} | ForEach-Object {
    Disable-LocalUser $_.Name -ErrorAction SilentlyContinue
}
}

#region === 7. Disable Remote Desktop ===
Do-Action "Disable Remote Desktop" {
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" fDenyTSConnections 1
}

#region === 8. Ensure Defender Running ===
Do-Action "Ensure Windows Defender" {
Set-Service WinDefend -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service WinDefend -ErrorAction SilentlyContinue
}

#region === 9. Enable Auditing ===
Do-Action "Configure Auditing Policies" {
$subs = "Logon","Account Management","Policy Change","Privilege Use","System"
foreach ($s in $subs){ auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null }
}

#region === 10. Final Report ===
$summary | Export-Csv $csvFile -NoTypeInformation
Log "=== Hardening complete ===" "OK"
Log "Detailed log: $logFile"
Log "CSV summary: $csvFile"
Write-Host "`nTop Security Actions Summary:`n" -ForegroundColor Green
$summary | Select Setting,Status | Format-Table -AutoSize
#endregion

# END
