<#
.SYNOPSIS
Retrieves account lockout events from Active Directory Domain Controllers.

.DESCRIPTION
This function queries the Security Event Log on the PDC Emulator for account lockout events (Event ID 4740).
It supports both WinRM and RPC-based collection methods and can filter for specific users.

Key features:
- Flexible time window for event collection
- Optional user targeting
- Choice of WinRM or RPC collection
- Configurable via external config file
- Handles both local and remote collection

.PARAMETER Hours
Number of hours to look back for lockout events. Default is 24 hours.

.PARAMETER Identity 
Optional username to filter lockout events for a specific account.

.PARAMETER UseWinRM
Switch to use WinRM instead of RPC for remote event collection.

.EXAMPLE
Get-ADAccountLockouts -Hours 48
Returns all account lockouts from the last 48 hours

.EXAMPLE
Get-ADAccountLockouts -Identity "jsmith" -UseWinRM
Returns lockouts for user "jsmith" using WinRM collection

.NOTES
Author: The Haag
Requires: Active Directory PowerShell module
#>


function Get-ADAccountLockouts {
    [CmdletBinding()]
    param (
        [Parameter()]
        [int]$Hours = 24,
        
        [Parameter()]
        [string]$Identity,

        [Parameter()]
        [switch]$UseWinRM
    )

    $config = Import-PowerShellDataFile -Path "$PSScriptRoot\..\config\config.psd1"
    $PDCEmulator = (Get-ADDomain).PDCEmulator
    $startTime = (Get-Date).AddHours(-$Hours)

    $filterParams = @{
        LogName = 'Security'
        ID = $config.EventIDs.AccountLockout
        StartTime = $startTime
    }

    try {
        if ($UseWinRM -or $env:COMPUTERNAME -eq $PDCEmulator) {
            if ($env:COMPUTERNAME -eq $PDCEmulator) {
                Write-Verbose "Using local event collection for lockouts"
                $events = Get-WinEvent -FilterHashtable $filterParams -ErrorAction Stop
            }
            else {
                Write-Verbose "Using WinRM for lockout event collection"
                $events = Invoke-Command -ComputerName $PDCEmulator -ScriptBlock {
                    param($filter)
                    Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
                } -ArgumentList $filterParams
            }
        }
        else {
            Write-Verbose "Using RPC for lockout event collection"
            $events = Get-WinEvent -ComputerName $PDCEmulator -FilterHashtable $filterParams -ErrorAction Stop
        }

        if ($Identity) {
            $events = $events | Where-Object { $_.Properties[0].Value -eq $Identity }
        }

        $events | ForEach-Object {
            [PSCustomObject]@{
                UserName = $_.Properties[0].Value
                CallerComputer = $_.Properties[1].Value
                TimeStamp = $_.TimeCreated
                DomainController = $PDCEmulator
            }
        }
    }
    catch {
        if ($_.Exception.Message -match "No events were found") {
            Write-Verbose "No account lockout events found in the specified time period"
            return $null
        }
        Write-Error "Failed to get account lockout events: $($_.Exception.Message)"
        return $null
    }
} 