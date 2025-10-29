#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Enable-TaskHuntingLogs.ps1 - Enable required logging for Hunt-HiddenScheduledTasks.ps1
    
.DESCRIPTION
    This script enables the necessary Windows event logging to support hidden scheduled task detection:
    - Security log: Scheduled Task auditing (Events 4698/4699/4700/4701/4702)
    - Security log: Process Creation auditing (Event 4688)
    - Task Scheduler Operational log
    
    Note: Sysmon installation/configuration is separate and optional.
    
.EXAMPLE
    .\Enable-TaskHuntingLogs.ps1
    
.NOTES
    Author: Michael Haag
    Requires: Administrative privileges
#>

[CmdletBinding()]
param()

function Write-SetupLog {
    param([string]$Message, [string]$Level = "Info")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch($Level) {
        "Error" { "Red" }
        "Warning" { "Yellow" }
        "Success" { "Green" }
        "Critical" { "Magenta" }
        default { "Cyan" }
    }
    Write-Host "[$timestamp] [SETUP] $Message" -ForegroundColor $color
}

try {
    Write-SetupLog "Enabling Windows Event Logging for Hidden Task Hunting" "Success"
    Write-SetupLog "=======================================================" "Success"
    
    # Enable Scheduled Task auditing in Security log
    Write-SetupLog "`nConfiguring Scheduled Task Auditing..." "Info"
    
    # Check current audit policy
    $currentAudit = auditpol /get /subcategory:"Other Object Access Events" 2>&1
    Write-SetupLog "Current audit policy: $currentAudit" "Info"
    
    # Enable audit policy for scheduled tasks (Events 4698, 4699, 4700, 4701, 4702)
    $result = auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-SetupLog "[SUCCESS] Scheduled Task auditing enabled (Events 4698/4699/4700/4701/4702)" "Success"
    } else {
        Write-SetupLog "[WARNING] Failed to enable scheduled task auditing: $result" "Warning"
    }
    
    # Enable Process Creation auditing (Event 4688)
    Write-SetupLog "`nConfiguring Process Creation Auditing..." "Info"
    
    $currentProcessAudit = auditpol /get /subcategory:"Process Creation" 2>&1
    Write-SetupLog "Current process audit policy: $currentProcessAudit" "Info"
    
    $result = auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-SetupLog "[SUCCESS] Process Creation auditing enabled (Event 4688)" "Success"
    } else {
        Write-SetupLog "[WARNING] Failed to enable process creation auditing: $result" "Warning"
    }
    
    # Enable command line logging for Event 4688
    Write-SetupLog "`nEnabling Command Line Logging in Process Creation Events..." "Info"
    
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    
    Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
    Write-SetupLog "[SUCCESS] Command line logging enabled for Event 4688" "Success"
    
    # Ensure Task Scheduler Operational log is enabled
    Write-SetupLog "`nVerifying Task Scheduler Operational Log..." "Info"
    
    $taskSchedulerLog = Get-WinEvent -ListLog "Microsoft-Windows-TaskScheduler/Operational" -ErrorAction SilentlyContinue
    if ($taskSchedulerLog) {
        if (-not $taskSchedulerLog.IsEnabled) {
            Write-SetupLog "Enabling Task Scheduler Operational log..." "Info"
            $taskSchedulerLog.IsEnabled = $true
            $taskSchedulerLog.SaveChanges()
        }
        Write-SetupLog "[SUCCESS] Task Scheduler Operational log is enabled (Events 106/200)" "Success"
    } else {
        Write-SetupLog "[WARNING] Task Scheduler Operational log not found" "Warning"
    }
    
    # Check Sysmon status
    Write-SetupLog "`nChecking Sysmon Status..." "Info"
    
    $sysmonLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
    if ($sysmonLog -and $sysmonLog.IsEnabled) {
        Write-SetupLog "[SUCCESS] Sysmon is installed and enabled" "Success"
        Write-SetupLog "Verify Sysmon config includes registry monitoring for TaskCache paths" "Info"
    } else {
        Write-SetupLog "[INFO] Sysmon not detected - this is optional but recommended" "Warning"
        Write-SetupLog "Download Sysmon: https://learn.microsoft.com/sysinternals/downloads/sysmon" "Info"
        Write-SetupLog "Install with: sysmon.exe -accepteula -i sysmonconfig.xml" "Info"
    }
    
    # Summary
    Write-SetupLog "`n=======================================================" "Success"
    Write-SetupLog "CONFIGURATION SUMMARY" "Success"
    Write-SetupLog "=======================================================" "Success"
    
    $auditCheck = auditpol /get /subcategory:"Other Object Access Events" | Select-String "Success"
    $processCheck = auditpol /get /subcategory:"Process Creation" | Select-String "Success"
    $cmdLineCheck = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
    
    Write-SetupLog "`nScheduled Task Auditing: $(if($auditCheck){'ENABLED'}else{'DISABLED'})" "$(if($auditCheck){'Success'}else{'Warning'})"
    Write-SetupLog "Process Creation Auditing: $(if($processCheck){'ENABLED'}else{'DISABLED'})" "$(if($processCheck){'Success'}else{'Warning'})"
    Write-SetupLog "Command Line Logging: $(if($cmdLineCheck.ProcessCreationIncludeCmdLine_Enabled -eq 1){'ENABLED'}else{'DISABLED'})" "$(if($cmdLineCheck.ProcessCreationIncludeCmdLine_Enabled -eq 1){'Success'}else{'Warning'})"
    Write-SetupLog "Task Scheduler Operational Log: $(if($taskSchedulerLog -and $taskSchedulerLog.IsEnabled){'ENABLED'}else{'DISABLED'})" "$(if($taskSchedulerLog -and $taskSchedulerLog.IsEnabled){'Success'}else{'Warning'})"
    Write-SetupLog "Sysmon: $(if($sysmonLog -and $sysmonLog.IsEnabled){'INSTALLED'}else{'NOT INSTALLED (optional)'})" "$(if($sysmonLog -and $sysmonLog.IsEnabled){'Success'}else{'Info'})"
    
    Write-SetupLog "`nNext Steps:" "Info"
    Write-SetupLog "1. Wait a few seconds for audit policies to take effect" "Info"
    Write-SetupLog "2. Run .\Test-HiddenTaskAbuse.ps1 to generate test events" "Info"
    Write-SetupLog "3. Run .\Hunt-HiddenScheduledTasks.ps1 to validate detection" "Info"
    Write-SetupLog "4. (Optional) Install Sysmon for enhanced registry hiding detection" "Info"
    
    Write-SetupLog "`nConfiguration complete!" "Success"
    
} catch {
    Write-SetupLog "Setup failed: $($_.Exception.Message)" "Error"
    throw
}

