<#
.SYNOPSIS
Analyzes Active Directory security events to detect suspicious login activity and potential attacks.

.DESCRIPTION
This function examines security events from Active Directory Domain Controllers to identify patterns 
indicative of password spraying, brute force attempts, and other suspicious login behaviors.

Key capabilities:
- Detects potential password spraying attacks by analyzing failed logins across multiple accounts
- Identifies possible brute force attempts against individual accounts
- Performs timing analysis to detect coordinated attack patterns
- Analyzes login types and failure reasons
- Provides detailed timing metrics including attempts per minute and high activity windows

The function collects failed login events (4625) and account lockouts (4740) from the PDC Emulator
and performs correlation analysis to surface suspicious patterns.

.PARAMETER Hours
Number of hours to look back for events. Default is 24 hours.

.PARAMETER Identity
Optional username to filter events for a specific account.

.PARAMETER UseWinRM
Switch to force using WinRM instead of RPC for remote collection.

.EXAMPLE
Get-ADSuspiciousActivity -Hours 48
Returns suspicious activity analysis for the last 48 hours

.EXAMPLE
Get-ADSuspiciousActivity -Identity "jsmith" -UseWinRM
Analyzes suspicious activity for user jsmith using WinRM collection

.NOTES
Author: The Haag
Requires: Active Directory PowerShell module, appropriate audit policies
#>

function Get-ADSuspiciousActivity {
    [CmdletBinding()]
    param (
        [int]$Hours = 24,
        [string]$Identity,
        [switch]$UseWinRM
    )

    try {
        try {
            $PDCEmulator = (Get-ADDomain).PDCEmulator
        }
        catch {
            throw "Failed to get PDC Emulator. Error: $($_.Exception.Message)"
        }

        $startTime = (Get-Date).AddHours(-$Hours)
        Write-Verbose "Searching for events from $startTime to $(Get-Date)"

        if ($UseWinRM -or $env:COMPUTERNAME -eq $PDCEmulator) {
            Write-Verbose "Using WinRM or local access for event collection"
            $failedLogins = Get-ADFailedLogins -Hours $Hours -Identity $Identity -UseWinRM
            $lockouts = Get-ADAccountLockouts -Hours $Hours -Identity $Identity -UseWinRM
        }
        else {
            Write-Verbose "Using RPC for event collection"
            $failedLogins = Get-ADFailedLogins -Hours $Hours -Identity $Identity
            $lockouts = Get-ADAccountLockouts -Hours $Hours -Identity $Identity
        }

        $possibleSpray = @()
        $possibleBruteForce = @()

        if ($failedLogins) {
            Write-Verbose "Found $($failedLogins.Count) failed login events"
            
            $processedLogins = $failedLogins | ForEach-Object {
                try {
                    Write-Verbose "Processing event with TimeCreated: $($_.TimeCreated)"
                    
                    if (-not $_.Properties) {
                        Write-Warning "Event has no Properties collection"
                        return $null
                    }

                    if ($_.Properties.Count -lt 20) {
                        Write-Warning "Event Properties collection has insufficient elements: $($_.Properties.Count)"
                        return $null
                    }

                    @{
                        TargetAccount = "$($_.Properties[5].Value)"
                        LogonType = switch ($_.Properties[10].Value) {
                            2 { "Interactive" }
                            3 { "Network" }
                            4 { "Batch" }
                            5 { "Service" }
                            7 { "Unlock" }
                            8 { "NetworkCleartext" }
                            9 { "NewCredentials" }
                            10 { "RemoteInteractive" }
                            11 { "CachedInteractive" }
                            default { "Unknown" }
                        }
                        TimeStamp = $_.TimeCreated
                        CallingComputer = $_.Properties[13].Value ?? "Unknown"
                        IPAddress = $_.Properties[19].Value ?? "Unknown"
                        ProcessName = $_.Properties[18].Value ?? "Unknown"
                    }
                }
                catch {
                    Write-Warning "Failed to process event: $($_.Exception.Message)"
                    Write-Verbose "Event details: $($_ | ConvertTo-Json -Depth 1)"
                    return $null
                }
            } | Where-Object { $_ -ne $null }

            Write-Verbose "Successfully processed $($processedLogins.Count) events"

            if ($processedLogins) {
                $possibleSpray = $processedLogins | 
                    Group-Object { $_.TimeStamp.ToString("yyyy-MM-dd HH:mm") } | 
                    Where-Object { $_.Count -ge 3 } |
                    Select-Object @{
                        Name = "Count"
                        Expression = { $_.Count }
                    }, @{
                        Name = "Time"
                        Expression = { $_.Name }
                    }, @{
                        Name = "Accounts"
                        Expression = { 
                            ($_.Group | ForEach-Object { $_.TargetAccount } | Where-Object { $_ -ne '-' } | Sort-Object -Unique) -join ", "
                        }
                    }

                $possibleBruteForce = $processedLogins | 
                    Where-Object { $_.TargetAccount -ne '-' } | 
                    Group-Object TargetAccount | 
                    Where-Object { $_.Count -ge 3 } |
                    Select-Object @{
                        Name = "Count"
                        Expression = { $_.Count }
                    }, @{
                        Name = "Account"
                        Expression = { $_.Name }
                    }, @{
                        Name = "LogonTypes"
                        Expression = { 
                            ($_.Group | ForEach-Object { 
                                switch ($_.LogonType) {
                                    2 { "Interactive" }
                                    3 { "Network" }
                                    4 { "Batch" }
                                    5 { "Service" }
                                    7 { "Unlock" }
                                    8 { "NetworkCleartext" }
                                    9 { "NewCredentials" }
                                    10 { "RemoteInteractive" }
                                    11 { "CachedInteractive" }
                                    default { "Type $_" }
                                }
                            } | Sort-Object -Unique) -join ", "
                        }
                    }

                # Group by time windows (e.g., 5-minute intervals)
                $timeWindows = $processedLogins | Group-Object {
                    $_.TimeStamp.ToString("yyyy-MM-dd HH:mm")
                } | Sort-Object Name

                $timingAnalysis = @{
                    StartTime = ($timeWindows | Select-Object -First 1).Name
                    EndTime = ($timeWindows | Select-Object -Last 1).Name
                    TotalDuration = [math]::Round(($processedLogins[-1].TimeStamp - $processedLogins[0].TimeStamp).TotalMinutes, 2)
                    AttemptsPerMinute = [math]::Round($processedLogins.Count / ($processedLogins[-1].TimeStamp - $processedLogins[0].TimeStamp).TotalMinutes, 2)
                    HighestAttemptsIn5Min = ($timeWindows | Sort-Object Count -Descending | Select-Object -First 1).Count
                    TimeWindowsWithHighActivity = $timeWindows | 
                        Where-Object { $_.Count -ge 30 } |
                        Select-Object @{
                            Name = "TimeWindow"
                            Expression = { $_.Name }
                        }, @{
                            Name = "Attempts"
                            Expression = { $_.Count }
                        }, @{
                            Name = "UniqueAccounts"
                            Expression = { ($_.Group.TargetAccount | Sort-Object -Unique).Count }
                        }
                }
            }
            else {
                Write-Verbose "No events could be processed"
            }
        }
        else {
            Write-Verbose "No failed login events found in the specified time period"
        }

        if ($lockouts) {
            Write-Verbose "Found $($lockouts.Count) account lockout events"
        }
        else {
            Write-Verbose "No account lockout events found in the specified time period"
        }

        [PSCustomObject]@{
            TimeRange = "$startTime to $(Get-Date)"
            TotalFailedLogins = $failedLogins ? $failedLogins.Count : 0
            TotalLockouts = $lockouts ? $lockouts.Count : 0
            PossiblePasswordSpray = $possibleSpray
            PossibleBruteForce = $possibleBruteForce
            TimingAnalysis = $timingAnalysis
            FailedLoginSummary = $processedLogins | Group-Object LogonType | 
                Select-Object @{
                    Name = "LogonType"
                    Expression = {
                        switch ($_.Name) {
                            2 { "Interactive" }
                            3 { "Network" }
                            4 { "Batch" }
                            5 { "Service" }
                            7 { "Unlock" }
                            8 { "NetworkCleartext" }
                            9 { "NewCredentials" }
                            10 { "RemoteInteractive" }
                            11 { "CachedInteractive" }
                            default { "Type $($_.Name)" }
                        }
                    }
                }, @{
                    Name = "Count"
                    Expression = { $_.Count }
                }
            DetailedFailedLogins = $processedLogins
            DetailedLockouts = $lockouts
            NoActivityFound = (-not $failedLogins) -and (-not $lockouts)
        }
    }
    catch {
        Write-Error "Error in Get-ADSuspiciousActivity: $($_.Exception.Message)"
        throw
    }
}