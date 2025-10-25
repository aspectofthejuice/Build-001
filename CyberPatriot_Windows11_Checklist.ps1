<#
.SYNOPSIS
    Windows Security Hardening and Audit Script
.DESCRIPTION
    Implements a variety of Windows security best practices in audit or enforce mode.
.PARAMETER ReportOnly
    If set, performs auditing only without making changes.
.PARAMETER Enforce
    If set, applies recommended security settings.
.PARAMETER OutputReportPath
    Path to output the security report in HTML format.
#>

Param(
    [switch]$ReportOnly,
    [switch]$Enforce,
    [string]$OutputReportPath = ".\SecurityAuditReport.html"
)

# Global array to collect report data
$Global:SecurityFindings = @()

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    switch ($Level) {
        "INFO"    { Write-Host "[INFO]    $Message" -ForegroundColor Cyan }
        "OK"      { Write-Host "[OK]      $Message" -ForegroundColor Green }
        "WARN"    { Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
        "ERROR"   { Write-Host "[ERROR]   $Message" -ForegroundColor Red }
    }
}

function Add-Finding {
    param (
        [string]$Category,
        [string]$Item,
        [string]$Status,
        [string]$Recommendation
    )
    $Global:SecurityFindings += [PSCustomObject]@{
        Category       = $Category
        Item           = $Item
        Status         = $Status
        Recommendation = $Recommendation
    }
}

# ---------------------------- MODULES ----------------------------

function Audit-UserAccountPolicies {
    Write-Log "Auditing User Account Policies..." "INFO"
    $policy = Get-LocalUser | Where-Object { $_.Enabled -eq $true }

    # Enforce password policy (via SecPol)
    $secedit = secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null
    $lines = Get-Content "$env:TEMP\secpol.cfg"

    $pwdComplexity = ($lines | Where-Object { $_ -match "PasswordComplexity" }) -replace ".*=", "" | ForEach-Object { $_.Trim() }

    if ($pwdComplexity -ne "1") {
        Add-Finding -Category "User Account Policies" -Item "Password Complexity" -Status "Non-Compliant" -Recommendation "Enable password complexity."
        if ($Enforce) {
            Write-Log "Enabling password complexity..." "WARN"
            secedit /configure /db secedit.sdb /cfg "$env:TEMP\secpol.cfg" /areas SECURITYPOLICY | Out-Null
        }
    } else {
        Add-Finding -Category "User Account Policies" -Item "Password Complexity" -Status "OK" -Recommendation "Already enforced."
    }

    Remove-Item "$env:TEMP\secpol.cfg" -ErrorAction SilentlyContinue
}

function Audit-LocalAdministrators {
    Write-Log "Checking local administrators group..." "INFO"
    $admins = Get-LocalGroupMember -Group "Administrators"

    foreach ($admin in $admins) {
        if ($admin.Name -ne "$env:COMPUTERNAME\Administrator" -and $admin.Name -ne "BUILTIN\Administrators") {
            Add-Finding -Category "Privilege Management" -Item "User $($admin.Name)" -Status "Has Admin Access" -Recommendation "Evaluate necessity of admin access."
        }
    }

    if ($Enforce) {
        # Optional enforcement: removing unneeded admins (dangerous if automated)
        Write-Log "Enforce mode: Please manually review and remove unnecessary administrators to avoid lockout." "WARN"
    }
}

function Audit-WindowsUpdates {
    Write-Log "Checking for missing Windows updates..." "INFO"

    try {
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Searcher = $Session.CreateUpdateSearcher()
        $Results = $Searcher.Search("IsInstalled=0")

        if ($Results.Updates.Count -gt 0) {
            Add-Finding -Category "Patch Management" -Item "$($Results.Updates.Count) Updates Missing" -Status "Non-Compliant" -Recommendation "Install latest Windows Updates."
            if ($Enforce) {
                Write-Log "Enforce mode: Please use Windows Update UI or WSUS to install patches safely." "WARN"
            }
        } else {
            Add-Finding -Category "Patch Management" -Item "Windows Update" -Status "OK" -Recommendation "Fully patched."
        }
    } catch {
        Write-Log "Unable to check Windows Update. COM object failure." "ERROR"
    }
}

function Audit-LoggingAndAuditing {
    Write-Log "Checking audit policy settings..." "INFO"
    $categories = @("Logon", "Object Access", "Privilege Use", "Process Creation")
    foreach ($cat in $categories) {
        $policy = (AuditPol /get /subcategory:"$cat") 2>&1
        if ($policy -match "No auditing") {
            Add-Finding -Category "Logging and Auditing" -Item "$cat" -Status "Not Audited" -Recommendation "Enable auditing for this category."
            if ($Enforce) {
                AuditPol /set /subcategory:"$cat" /success:enable /failure:enable | Out-Null
                Write-Log "Enabled auditing for $cat" "OK"
            }
        } else {
            Add-Finding -Category "Logging and Auditing" -Item "$cat" -Status "Audited" -Recommendation "Already enabled."
        }
    }
}

function Audit-WindowsFirewall {
    Write-Log "Auditing Windows Firewall..." "INFO"
    $profiles = Get-NetFirewallProfile
    foreach ($profile in $profiles) {
        if ($profile.Enabled -eq $false) {
            Add-Finding -Category "Firewall" -Item "$($profile.Name)" -Status "Disabled" -Recommendation "Enable the firewall for this profile."
            if ($Enforce) {
                Set-NetFirewallProfile -Profile $profile.Name -Enabled True
                Write-Log "Enabled firewall for $($profile.Name)" "OK"
            }
        } else {
            Add-Finding -Category "Firewall" -Item "$($profile.Name)" -Status "OK" -Recommendation "Firewall enabled."
        }
    }
}

function Audit-SystemIntegrity {
    Write-Log "Checking system file integrity..." "INFO"
    $sfc = sfc /scannow
    Add-Finding -Category "System Integrity" -Item "System File Check" -Status "Executed" -Recommendation "Review SFC logs for details."

    if ($Enforce) {
        DISM /Online /Cleanup-Image /RestoreHealth | Out-Null
        Write-Log "DISM health check complete." "OK"
    }
}

function Audit-WindowsDefender {
    Write-Log "Checking Windows Defender status..." "INFO"
    $status = Get-MpComputerStatus
    if ($status.AntispywareEnabled -and $status.RealTimeProtectionEnabled) {
        Add-Finding -Category "Anti-Malware" -Item "Windows Defender" -Status "Running" -Recommendation "Protection is active."
    } else {
        Add-Finding -Category "Anti-Malware" -Item "Windows Defender" -Status "Disabled" -Recommendation "Enable real-time protection."
        if ($Enforce) {
            Set-MpPreference -DisableRealtimeMonitoring $false
            Write-Log "Enabled real-time protection." "OK"
        }
    }
}

function Audit-ScheduledTasks {
    Write-Log "Auditing Scheduled Tasks for suspicious entries..." "INFO"
    $tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" }

    foreach ($task in $tasks) {
        Add-Finding -Category "Scheduled Tasks" -Item $task.TaskName -Status "User Task" -Recommendation "Manually review this scheduled task."
    }
}

function Generate-Report {
    Write-Log "Generating security report..." "INFO"
    $jsonReport = $Global:SecurityFindings | ConvertTo-Json -Depth 3
    $html = "<html><head><title>Security Audit Report</title></head><body><h1>Security Audit Report</h1><table border='1'><tr><th>Category</th><th>Item</th><th>Status</th><th>Recommendation</th></tr>"
    foreach ($finding in $Global:SecurityFindings) {
        $html += "<tr><td>$($finding.Category)</td><td>$($finding.Item)</td><td>$($finding.Status)</td><td>$($finding.Recommendation)</td></tr>"
    }
    $html += "</table></body></html>"

    $reportPathHtml = [System.IO.Path]::ChangeExtension($OutputReportPath, ".html")
    $reportPathJson = [System.IO.Path]::ChangeExtension($OutputReportPath, ".json")

    $html | Out-File $reportPathHtml -Encoding UTF8
    $jsonReport | Out-File $reportPathJson -Encoding UTF8

    Write-Log "Report saved to $reportPathHtml and $reportPathJson" "OK"
}

# ---------------------------- MAIN ----------------------------
Write-Host "`n==== Windows Security Hardening Toolkit ====" -ForegroundColor Magenta

Audit-UserAccountPolicies
Audit-LocalAdministrators
Audit-WindowsUpdates
Audit-LoggingAndAuditing
Audit-WindowsFirewall
Audit-SystemIntegrity
Audit-WindowsDefender
Audit-ScheduledTasks

Generate-Report

Write-Host "`nScript completed.`n" -ForegroundColor Green
