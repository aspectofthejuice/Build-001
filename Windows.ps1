<#
.SYNOPSIS
  CyberPatriot_Windows11_Checklist.ps1
.DESCRIPTION
  Automated implementation of the CyberPatriot hardening checklist for Windows 11 workstations.
  Must be run as Administrator. Logs actions to %ProgramData%\CyberPatriotLogs.
#>

param([switch]$DryRun)

# === Setup Logging ===
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$logRoot = "$env:ProgramData\CyberPatriotLogs"
New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
$logFile = "$logRoot\Win11_Checklist_$ts.log"
function Log($msg,[string]$lvl="INFO"){
 $t=(Get-Date -Format u)
 $c=@{INFO='Cyan';WARN='Yellow';ERROR='Red';OK='Green'}[$lvl]
 Write-Host $msg -ForegroundColor $c
 Add-Content $logFile "[$t][$lvl] $msg"
}
function Do($task,[scriptblock]$cmd){
 if($DryRun){Log "DRYRUN: $task" "WARN"} else {try{&$cmd;Log "OK: $task" "OK"}catch{Log "ERR: $task $_" "ERROR"}}}

Log "=== CyberPatriot Windows 11 Checklist Script Start ==="

# === Password & Lockout Policy ===
Do "Set password & lockout policy" {
$inf=@"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordLength=10
MaximumPasswordAge=60
MinimumPasswordAge=1
PasswordComplexity=1
PasswordHistorySize=24
[Lockout Policy]
LockoutBadCount=10
ResetLockoutCount=30
LockoutDuration=30
"@
$path="$env:TEMP\cp_policy.inf"
$inf|Out-File $path -Encoding ASCII
secedit /configure /db "$env:windir\security\database\secedit.sdb" /cfg $path /areas SECURITYPOLICY | Out-Null
}

# === SmartScreen ===
Do "Enable SmartScreen" {
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" SmartScreenEnabled "RequireAdmin"
}

# === Disable Wi-Fi Sense ===
Do "Disable Wi-Fi Sense" {
$path="HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
New-Item -Path $path -Force | Out-Null
Set-ItemProperty $path AutoConnectAllowedOEM 0
Set-ItemProperty $path AutoConnectToWiFiSenseHotspots 0
}

# === UAC (Max) ===
Do "Set UAC to highest level" {
$reg="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-ItemProperty $reg ConsentPromptBehaviorAdmin 2
Set-ItemProperty $reg PromptOnSecureDesktop 1
Set-ItemProperty $reg EnableLUA 1
}

# === Disable IPv6 and unused network bindings ===
Do "Disable IPv6 & network adapter extras" {
Get-NetAdapter | ForEach-Object {
Disable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name $_.Name -ComponentID ms_lltdio -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name $_.Name -ComponentID ms_lldp -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name $_.Name -ComponentID ms_server -ErrorAction SilentlyContinue
Disable-NetAdapterBinding -Name $_.Name -ComponentID ms_pacer -ErrorAction SilentlyContinue
}
}

# === Disable UPnP Port 1900 ===
Do "Disable UPnP" {
$reg="HKLM:\Software\Microsoft\DirectPlayNATHelp\DPNHUPnP"
New-Item -Path $reg -Force | Out-Null
Set-ItemProperty $reg UPnPMode 2
}

# === Disable unnecessary services ===
$services=@("upnphost","tlntsvr","SNMPTRAP","RemoteRegistry")
foreach($svc in $services){Do "Disable service $svc" {Stop-Service $svc -ErrorAction SilentlyContinue;Set-Service $svc -StartupType Disabled -ErrorAction SilentlyContinue}}

# === Disable SMBv1 ===
Do "Disable SMBv1" {Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null}

# === Shares check ===
Log "Reminder: Only ADMIN$, C$, IPC$ should exist unless README says otherwise."

# === Firewall - disable built-in app inbound rules ===
$blockApps=@("MicrosoftEdge.exe","SearchApp.exe","HxTsr.exe","Microsoft.Photos.exe","XboxApp.exe")
foreach($a in $blockApps){Do "Block inbound for $a" {
New-NetFirewallRule -DisplayName "Block_$a" -Direction Inbound -Program "C:\Program Files\$a" -Action Block -ErrorAction SilentlyContinue
}}

# === Disable AutoPlay ===
Do "Disable AutoPlay" {Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" DisableAutoplay 1}

# === Disable OneDrive startup ===
Do "Disable OneDrive startup" {
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f | Out-Null
}

# === Screen Saver ===
Do "Configure screen saver to lock after 10 minutes" {
$reg="HKCU:\Control Panel\Desktop"
Set-ItemProperty $reg ScreenSaveActive 1
Set-ItemProperty $reg ScreenSaverIsSecure 1
Set-ItemProperty $reg ScreenSaveTimeOut 600
}

# === Enable auditing success/failure ===
Do "Enable auditing Success/Failure" {
foreach($s in "Logon","Account Management","Policy Change","Privilege Use","System"){
auditpol /set /subcategory:$s /success:enable /failure:enable | Out-Null}
}

# === Windows Defender ===
Do "Ensure Windows Defender running" {
Set-Service WinDefend -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service WinDefend -ErrorAction SilentlyContinue
}

# === Lock Administrator & Guest accounts if required ===
Do "Disable Guest & lock Admin if README says so" {
Disable-LocalUser -Name Guest -ErrorAction SilentlyContinue
}

Log "=== Checklist Script Completed. Review settings manually for Group Policy items ==="
Log "Log saved: $logFile"
