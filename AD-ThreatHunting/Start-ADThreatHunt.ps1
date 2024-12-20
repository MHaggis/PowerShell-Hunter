<#
.SYNOPSIS
Performs threat hunting analysis across Active Directory to detect suspicious activities and potential attacks.

.DESCRIPTION
This script analyzes Active Directory security events and configurations to identify potential security threats including:

- Password spraying attacks
- Brute force login attempts 
- Account lockouts
- Suspicious login patterns and timing
- Privilege escalation attempts
- Unusual account behavior

The script collects events from domain controllers (primarily the PDC Emulator) and performs correlation analysis
to surface suspicious patterns. Results can be exported in various formats for further analysis.

Key features:
- Configurable time window for analysis
- Optional targeting of specific accounts
- Advanced threat detection capabilities
- Flexible export options (CSV, JSON, HTML)
- Support for both WinRM and RPC collection methods

.PARAMETER Identity
Optional username to focus analysis on a specific account

.PARAMETER Hours 
Number of hours to look back for events (default: 24)

.PARAMETER SkipPrerequisiteCheck
Skip the initial environment prerequisite validation

.PARAMETER UseWinRM
Force using WinRM instead of RPC for remote collection

.PARAMETER ExportPath
Path to export results file

.PARAMETER ExportFormat
Format for exporting results (CSV, JSON, or HTML)

.EXAMPLE
.\Start-ADThreatHunt.ps1 -Hours 48 -ExportFormat CSV -ExportPath "C:\Reports\threats.csv"

.EXAMPLE
.\Start-ADThreatHunt.ps1 -Identity "jsmith" -IncludeAdvancedThreats

.NOTES
Author: The Haag
Requires: Active Directory PowerShell module, administrative privileges
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$Identity,
    
    [Parameter()]
    [int]$Hours = 24,
    
    [Parameter()]
    [switch]$SkipPrerequisiteCheck,

    [Parameter()]
    [switch]$UseWinRM,

    [Parameter()]
    [string]$ExportPath,

    [Parameter()]
    [ValidateSet('CSV', 'JSON', 'HTML')]
    [string]$ExportFormat = 'CSV'
)

try {
    # Import functions
    Get-ChildItem -Path "$PSScriptRoot\functions\*.ps1" | ForEach-Object { 
        try {
            . $_.FullName
        }
        catch {
            Write-Error "Failed to import function file $($_.Name): $($_.Exception.Message)"
            throw
        }
    }

    # Check prerequisites
    if (-not $SkipPrerequisiteCheck) {
        Write-Host "`nChecking prerequisites..." -ForegroundColor Cyan
        $prereqCheck = Test-ADPrerequisites
        
        foreach ($message in $prereqCheck.Messages) {
            if ($message -match '^\✓') {
                Write-Host $message -ForegroundColor Green
            } 
            elseif ($message -match '^\s\s') {
                Write-Host $message -ForegroundColor Yellow
            }
            else {
                Write-Host $message -ForegroundColor Red
            }
        }
        
        if (-not $prereqCheck.Success) {
            throw "Prerequisites check failed. Please resolve the issues above and try again."
        }
        Write-Host "`nPrerequisites check passed.`n" -ForegroundColor Green
    }

    # Run threat hunt
    Write-Host "Starting threat hunt..." -ForegroundColor Cyan
    Write-Progress -Activity "AD Threat Hunt" -Status "Initializing..." -PercentComplete 0

    # Run threat hunt with progress updates
    Write-Progress -Activity "AD Threat Hunt" -Status "Collecting Events..." -PercentComplete 30
    $results = Get-ADSuspiciousActivity -Hours $Hours -Identity $Identity -UseWinRM:$UseWinRM -ErrorAction Stop
    Write-Progress -Activity "AD Threat Hunt" -Status "Analyzing Results..." -PercentComplete 60

    # Add before the report section
    Write-Progress -Activity "AD Threat Hunt" -Status "Generating Report..." -PercentComplete 90

    # Format and display results
    Write-Host "`n=== AD Threat Hunting Report ===" -ForegroundColor Cyan
    Write-Host "Time Range: $($results.TimeRange)" -ForegroundColor Yellow
    Write-Host "Domain Controller: $((Get-ADDomain).PDCEmulator)" -ForegroundColor Yellow
    Write-Host

    if ($results.NoActivityFound) {
        Write-Host "No suspicious activity found in the specified time period." -ForegroundColor Green
        Write-Host "This could mean either:"
        Write-Host "1. No failed logins or account lockouts occurred"
        Write-Host "2. Event logging is not properly configured"
        Write-Host "3. Events have been cleared"
        
        # Add audit policy check
        Write-Host "`nChecking Audit Policy Configuration..." -ForegroundColor Yellow
        $auditPolicy = auditpol /get /category:"Account Logon","Account Management","Logon/Logoff" /r | ConvertFrom-Csv
        $relevantPolicies = $auditPolicy | Where-Object { 
            $_."Subcategory" -match "Account Lockout|Logon|Credential Validation" 
        }
        
        Write-Host "`nCurrent Audit Policy Settings:" -ForegroundColor Yellow
        $relevantPolicies | Format-Table "Subcategory", "Inclusion Setting" -AutoSize

        Write-Host "`nTips:" -ForegroundColor Yellow
        Write-Host "1. Try increasing the time range with -Hours parameter"
        Write-Host "2. Verify audit policies are properly configured"
        Write-Host "3. Check Event Viewer directly on DC: eventvwr.msc"
        return
    }

    Write-Progress -Activity "AD Threat Hunt" -Completed

    if ($results.PossiblePasswordSpray) {
        Write-Host "!!! Possible Password Spray Detected !!!" -ForegroundColor Red
        $results.PossiblePasswordSpray | Format-Table
    }

    if ($results.PossibleBruteForce) {
        Write-Host "!!! Possible Brute Force Attempts Detected !!!" -ForegroundColor Red
        $results.PossibleBruteForce | Format-Table
    }

    if ($results.DetailedFailedLogins) {
        Write-Host "Failed Login Summary:" -ForegroundColor Yellow
        $results.DetailedFailedLogins | 
            Group-Object LogonType | 
            Select-Object @{N='LogonType';E={$_.Name}}, Count |
            Format-Table
    }

    if ($results.DetailedLockouts) {
        Write-Host "Account Lockouts:" -ForegroundColor Yellow
        $results.DetailedLockouts | Format-Table
    }

    Write-Host "`nRunning Advanced Threat Detection..." -ForegroundColor Yellow
    $advancedThreats = Get-ADAdvancedThreats -Hours $Hours -UseWinRM:$UseWinRM

    if ($advancedThreats.OffHourLogins) {
        Write-Host "`n!!! Off-Hours Login Activity Detected !!!" -ForegroundColor Red
        $advancedThreats.OffHourLogins | Format-Table
    }

    if ($advancedThreats.GeographicallyImpossible) {
        Write-Host "`n!!! Geographically Impossible Logins Detected !!!" -ForegroundColor Red
        $advancedThreats.GeographicallyImpossible | Format-Table
    }

    if ($advancedThreats.ServiceAccountMisuse) {
        Write-Host "`n!!! Service Account Misuse Detected !!!" -ForegroundColor Red
        $advancedThreats.ServiceAccountMisuse | Format-Table
    }

    if ($advancedThreats.AdminAccountMisuse) {
        Write-Host "`n!!! Admin Account Misuse Detected !!!" -ForegroundColor Red
        $advancedThreats.AdminAccountMisuse | Format-Table
    }

    if ($ExportPath) {
        try {
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $exportFileName = "ADThreatHunt_$timestamp"
            
            switch ($ExportFormat) {
                'CSV' {
                    $exportFile = Join-Path $ExportPath "$exportFileName.csv"
                    $exportData = @()
                    if ($results.DetailedFailedLogins) {
                        $exportData += $results.DetailedFailedLogins | Select-Object @{N='EventType';E={'FailedLogin'}}, *
                    }
                    if ($results.DetailedLockouts) {
                        $exportData += $results.DetailedLockouts | Select-Object @{N='EventType';E={'Lockout'}}, *
                    }
                    $exportData | Export-Csv -Path $exportFile -NoTypeInformation
                }
                'JSON' {
                    $exportFile = Join-Path $ExportPath "$exportFileName.json"
                    $results | ConvertTo-Json -Depth 10 | Out-File $exportFile
                }
                'HTML' {
                    $exportFile = Join-Path $ExportPath "$exportFileName.html"
                    $htmlReport = @"
                    <html>
                    <head>
                        <title>AD Threat Hunting Report - $timestamp</title>
                        <style>
                            body { font-family: Arial, sans-serif; margin: 20px; }
                            table { border-collapse: collapse; width: 100%; }
                            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                            th { background-color: #f2f2f2; }
                            .warning { color: red; }
                        </style>
                    </head>
                    <body>
                        <h1>AD Threat Hunting Report</h1>
                        <p>Time Range: $($results.TimeRange)</p>
                        <p>Total Failed Logins: $($results.TotalFailedLogins)</p>
                        <p>Total Lockouts: $($results.TotalLockouts)</p>
"@
                    if ($results.DetailedFailedLogins) {
                        $htmlReport += "<h2>Failed Logins</h2>"
                        $htmlReport += $results.DetailedFailedLogins | ConvertTo-Html -Fragment
                    }
                    if ($results.DetailedLockouts) {
                        $htmlReport += "<h2>Account Lockouts</h2>"
                        $htmlReport += $results.DetailedLockouts | ConvertTo-Html -Fragment
                    }
                    $htmlReport += "</body></html>"
                    $htmlReport | Out-File $exportFile
                }
            }
            Write-Host "`nReport exported to: $exportFile" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to export report: $($_.Exception.Message)"
        }
    }

    # Update the report display section to include timing analysis
    if ($results.TimingAnalysis) {
        Write-Host "`nTiming Analysis:" -ForegroundColor Yellow
        Write-Host "- Attack Duration: $($results.TimingAnalysis.TotalDuration) minutes"
        Write-Host "- Start Time: $($results.TimingAnalysis.StartTime)"
        Write-Host "- End Time: $($results.TimingAnalysis.EndTime)"
        Write-Host "- Attempts per Minute: $($results.TimingAnalysis.AttemptsPerMinute)"
        Write-Host "- Highest Activity: $($results.TimingAnalysis.HighestAttemptsIn5Min) attempts in 5 minutes"

        if ($results.TimingAnalysis.TimeWindowsWithHighActivity) {
            Write-Host "`nHigh Activity Windows:" -ForegroundColor Yellow
            Write-Host "Time Window         Attempts  Unique Accounts"
            Write-Host "-----------         --------  ---------------"
            $results.TimingAnalysis.TimeWindowsWithHighActivity | ForEach-Object {
                "{0,-18} {1,-9} {2,-5}" -f $_.TimeWindow, $_.Attempts, $_.UniqueAccounts
            }
        }
    }
}
catch {
    $errorDetails = @{
        Message = $_.Exception.Message
        ScriptLineNumber = $_.InvocationInfo.ScriptLineNumber
        Line = $_.InvocationInfo.Line
        ErrorRecord = $_
    }

    Write-Host "`nScript execution failed!" -ForegroundColor Red
    Write-Host "Error Message: $($errorDetails.Message)" -ForegroundColor Red
    Write-Host "Location: Line $($errorDetails.ScriptLineNumber)" -ForegroundColor Red
    
    # Provide troubleshooting guidance
    Write-Host "`nTroubleshooting steps:" -ForegroundColor Yellow
    Write-Host "1. Ensure you're running the script as a Domain Admin" -ForegroundColor Yellow
    Write-Host "2. Check network connectivity to the domain controller" -ForegroundColor Yellow
    Write-Host "3. Verify Windows Remote Management (WinRM) is running:" -ForegroundColor Yellow
    Write-Host "   Get-Service WinRM | Select Status" -ForegroundColor Yellow
    Write-Host "4. Try running with -Verbose flag for more details:" -ForegroundColor Yellow
    Write-Host "   .\Start-ADThreatHunt.ps1 -Verbose" -ForegroundColor Yellow
    Write-Host "5. Check if RPC service is running on the domain controller:" -ForegroundColor Yellow
    Write-Host "   Get-Service RpcSs | Select Status" -ForegroundColor Yellow
    
    # For verbose output
    if ($VerbosePreference -eq 'Continue') {
        Write-Host "`nDetailed Error Information:" -ForegroundColor Yellow
        $errorDetails.ErrorRecord | Format-List * -Force
    }
}