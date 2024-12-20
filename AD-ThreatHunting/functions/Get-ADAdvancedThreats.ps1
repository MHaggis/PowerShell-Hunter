<#
.SYNOPSIS
Detects advanced threats and suspicious activities in Active Directory environments.

.DESCRIPTION
This function analyzes Active Directory security events to identify advanced threats and suspicious patterns including:
- Off-hours login activity
- Geographically impossible login patterns 
- Service account misuse
- Administrative account abuse
- Suspicious password changes and account modifications

The analysis focuses on correlating events across time and location to detect anomalous behavior that may indicate 
compromise or insider threats. Events are collected from the PDC Emulator and analyzed against baseline thresholds
defined in the configuration.

.PARAMETER Hours 
Number of hours to look back for events. Default is 24 hours.

.PARAMETER UseWinRM
Use WinRM for event collection instead of RPC.

.EXAMPLE
Get-ADAdvancedThreats -Hours 48
Returns advanced threats detected in the last 48 hours

.NOTES
Author: The Haag
Requires: Active Directory PowerShell module, appropriate audit policies
#>


function Get-ADAdvancedThreats {
    [CmdletBinding()]
    param (
        [Parameter()]
        [int]$Hours = 24,
        
        [Parameter()]
        [switch]$UseWinRM
    )

    $config = Import-PowerShellDataFile -Path "$PSScriptRoot\..\config\config.psd1"
    $PDCEmulator = (Get-ADDomain).PDCEmulator
    $startTime = (Get-Date).AddHours(-$Hours)

    # Build filter hashtable
    $filterParams = @{
        LogName = 'Security'
        ID = @(
            $config.EventIDs.SuccessfulLogin,
            $config.EventIDs.PasswordChange,
            $config.EventIDs.AccountModification
        )
        StartTime = $startTime
    }

    try {
        if ($UseWinRM -or $env:COMPUTERNAME -eq $PDCEmulator) {
            if ($env:COMPUTERNAME -eq $PDCEmulator) {
                Write-Verbose "Using local event collection for advanced threats"
                $events = Get-WinEvent -FilterHashtable $filterParams -ErrorAction Stop
            }
            else {
                Write-Verbose "Using WinRM for advanced threat collection"
                $events = Invoke-Command -ComputerName $PDCEmulator -ScriptBlock {
                    param($filter)
                    Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
                } -ArgumentList $filterParams
            }
        }
        else {
            Write-Verbose "Using RPC for advanced threat collection"
            $events = Get-WinEvent -ComputerName $PDCEmulator -FilterHashtable $filterParams -ErrorAction Stop
        }

        $threats = @{
            OffHourLogins = @()
            GeographicallyImpossible = @()
            ServiceAccountMisuse = @()
            AdminAccountMisuse = @()
            SuspiciousPasswordChanges = @()
        }

        $successfulLogins = $events | Where-Object { $_.Id -eq $config.EventIDs.SuccessfulLogin } | 
            Group-Object { $_.Properties[5].Value }

        foreach ($userLogins in $successfulLogins) {
            $loginEvents = $userLogins.Group | Sort-Object TimeCreated

            $offHourLogins = $loginEvents | Where-Object { 
                $_.TimeCreated.Hour -in $config.Thresholds.UnusualLoginHours 
            }
            if ($offHourLogins) {
                $threats.OffHourLogins += [PSCustomObject]@{
                    User = $userLogins.Name
                    Times = $offHourLogins.TimeCreated
                    Workstations = $offHourLogins | ForEach-Object { $_.Properties[11].Value }
                }
            }

            for ($i = 0; $i -lt ($loginEvents.Count - 1); $i++) {
                $timeDiff = ($loginEvents[$i + 1].TimeCreated - $loginEvents[$i].TimeCreated).TotalSeconds
                $location1 = $loginEvents[$i].Properties[11].Value
                $location2 = $loginEvents[$i + 1].Properties[11].Value

                if ($timeDiff -lt $config.Thresholds.GeographicallyImpossibleLoginSeconds -and 
                    $location1 -ne $location2) {
                    $threats.GeographicallyImpossible += [PSCustomObject]@{
                        User = $userLogins.Name
                        Location1 = $location1
                        Location2 = $location2
                        TimeDifference = $timeDiff
                        Time = $loginEvents[$i + 1].TimeCreated
                    }
                }
            }

            if ($config.Patterns.ServiceAccounts | Where-Object { $userLogins.Name -like $_ }) {
                $interactiveLogins = $loginEvents | Where-Object { 
                    $_.Properties[8].Value -in @('2', '10') # Interactive or RemoteInteractive
                }
                if ($interactiveLogins) {
                    $threats.ServiceAccountMisuse += [PSCustomObject]@{
                        Account = $userLogins.Name
                        LoginType = $config.LogonTypes[$interactiveLogins[0].Properties[8].Value]
                        Time = $interactiveLogins[0].TimeCreated
                        Workstation = $interactiveLogins[0].Properties[11].Value
                    }
                }
            }

            if ($config.Patterns.AdminAccounts | Where-Object { $userLogins.Name -like $_ }) {
                $nonITLogins = $loginEvents | Where-Object {
                    $workstation = $_.Properties[11].Value
                    -not ($config.Thresholds.ITWorkstations | Where-Object { $workstation -like $_ })
                }
                if ($nonITLogins -and $config.Thresholds.AdminAccountUsageOutsideIT) {
                    $threats.AdminAccountMisuse += [PSCustomObject]@{
                        Account = $userLogins.Name
                        Workstation = $nonITLogins[0].Properties[11].Value
                        Time = $nonITLogins[0].TimeCreated
                    }
                }
            }
        }

        [PSCustomObject]$threats
    }
    catch {
        Write-Error "An error occurred while collecting events: $_"
    }
} 