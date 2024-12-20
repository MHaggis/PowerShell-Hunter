<#
.SYNOPSIS
Retrieves failed login events from Active Directory Domain Controllers.

.DESCRIPTION
This function queries the Security Event Log on the PDC Emulator for failed login events (Event ID 4625).
It supports both WinRM and RPC-based collection methods and can filter for specific users.

Key features:
- Flexible time window for event collection (default 24 hours)
- Optional user targeting via -Identity parameter
- Choice of WinRM or RPC collection via -UseWinRM switch
- Detailed event property collection including:
  * User information (target and subject)
  * Login type and process
  * Failure reason and status
  * Source IP and workstation
  * Authentication details

.PARAMETER Hours
Number of hours to look back for events. Default is 24 hours.

.PARAMETER Identity 
Optional username to filter events for a specific account.

.PARAMETER UseWinRM
Switch to force using WinRM instead of RPC for remote collection.

.EXAMPLE
Get-ADFailedLogins -Hours 48
Returns all failed logins from the last 48 hours

.EXAMPLE
Get-ADFailedLogins -Identity "jsmith" -UseWinRM
Returns failed logins for user jsmith using WinRM collection

.NOTES
Author: The Haag
Requires: Active Directory PowerShell module
#>

function Get-ADFailedLogins {
    [CmdletBinding()]
    param (
        [Parameter()]
        [int]$Hours = 24,
        
        [Parameter()]
        [string]$Identity,

        [Parameter()]
        [switch]$UseWinRM
    )

    # Fix to use config later
    $filterParams = @{
        LogName = 'Security'
        ID = 4625  # Failed login event ID
        StartTime = (Get-Date).AddHours(-$Hours)
    }

    try {
        $PDCEmulator = (Get-ADDomain).PDCEmulator
        Write-Verbose "PDC Emulator: $PDCEmulator"

        if ($UseWinRM -or $env:COMPUTERNAME -eq $PDCEmulator) {
            if ($env:COMPUTERNAME -eq $PDCEmulator) {
                Write-Verbose "Using local event collection"
                $rawEvents = Get-WinEvent -FilterHashtable $filterParams -ErrorAction Stop
                # Format local events the same way
                $events = $rawEvents | ForEach-Object {
                    $event = $_
                    [PSCustomObject]@{
                        TimeCreated = $event.TimeCreated
                        Id = $event.Id
                        Properties = @(
                            [PSCustomObject]@{ Value = $event.Properties[0].Value },  # SubjectUserSid
                            [PSCustomObject]@{ Value = $event.Properties[1].Value },  # SubjectUserName
                            [PSCustomObject]@{ Value = $event.Properties[2].Value },  # SubjectDomainName
                            [PSCustomObject]@{ Value = $event.Properties[3].Value },  # SubjectLogonId
                            [PSCustomObject]@{ Value = $event.Properties[4].Value },  # TargetUserSid
                            [PSCustomObject]@{ Value = $event.Properties[5].Value },  # TargetUserName
                            [PSCustomObject]@{ Value = $event.Properties[6].Value },  # TargetDomainName
                            [PSCustomObject]@{ Value = $event.Properties[7].Value },  # Status
                            [PSCustomObject]@{ Value = $event.Properties[8].Value },  # FailureReason
                            [PSCustomObject]@{ Value = $event.Properties[9].Value },  # SubStatus
                            [PSCustomObject]@{ Value = $event.Properties[10].Value }, # LogonType
                            [PSCustomObject]@{ Value = $event.Properties[11].Value }, # LogonProcessName
                            [PSCustomObject]@{ Value = $event.Properties[12].Value }, # AuthenticationPackageName
                            [PSCustomObject]@{ Value = $event.Properties[13].Value }, # WorkstationName
                            [PSCustomObject]@{ Value = $event.Properties[14].Value }, # TransmittedServices
                            [PSCustomObject]@{ Value = $event.Properties[15].Value }, # LmPackageName
                            [PSCustomObject]@{ Value = $event.Properties[16].Value }, # KeyLength
                            [PSCustomObject]@{ Value = $event.Properties[17].Value }, # ProcessId
                            [PSCustomObject]@{ Value = $event.Properties[18].Value }, # ProcessName
                            [PSCustomObject]@{ Value = $event.Properties[19].Value }, # IpAddress
                            [PSCustomObject]@{ Value = $event.Properties[20].Value }  # IpPort
                        )
                    }
                }
            }
            else {
                Write-Verbose "Using WinRM for event collection"
                $events = Invoke-Command -ComputerName $PDCEmulator -ScriptBlock {
                    param($filter)
                    
                    $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
                    
                    $events | ForEach-Object {
                        $event = $_
                        
                        [PSCustomObject]@{
                            TimeCreated = $event.TimeCreated
                            Id = $event.Id
                            Properties = @(
                                [PSCustomObject]@{ Value = $event.Properties[0].Value },  # SubjectUserSid
                                [PSCustomObject]@{ Value = $event.Properties[1].Value },  # SubjectUserName
                                [PSCustomObject]@{ Value = $event.Properties[2].Value },  # SubjectDomainName
                                [PSCustomObject]@{ Value = $event.Properties[3].Value },  # SubjectLogonId
                                [PSCustomObject]@{ Value = $event.Properties[4].Value },  # TargetUserSid
                                [PSCustomObject]@{ Value = $event.Properties[5].Value },  # TargetUserName
                                [PSCustomObject]@{ Value = $event.Properties[6].Value },  # TargetDomainName
                                [PSCustomObject]@{ Value = $event.Properties[7].Value },  # Status
                                [PSCustomObject]@{ Value = $event.Properties[8].Value },  # FailureReason
                                [PSCustomObject]@{ Value = $event.Properties[9].Value },  # SubStatus
                                [PSCustomObject]@{ Value = $event.Properties[10].Value }, # LogonType
                                [PSCustomObject]@{ Value = $event.Properties[11].Value }, # LogonProcessName
                                [PSCustomObject]@{ Value = $event.Properties[12].Value }, # AuthenticationPackageName
                                [PSCustomObject]@{ Value = $event.Properties[13].Value }, # WorkstationName
                                [PSCustomObject]@{ Value = $event.Properties[14].Value }, # TransmittedServices
                                [PSCustomObject]@{ Value = $event.Properties[15].Value }, # LmPackageName
                                [PSCustomObject]@{ Value = $event.Properties[16].Value }, # KeyLength
                                [PSCustomObject]@{ Value = $event.Properties[17].Value }, # ProcessId
                                [PSCustomObject]@{ Value = $event.Properties[18].Value }, # ProcessName
                                [PSCustomObject]@{ Value = $event.Properties[19].Value }, # IpAddress
                                [PSCustomObject]@{ Value = $event.Properties[20].Value }  # IpPort
                            )
                        }
                    }
                } -ArgumentList $filterParams
            }
        }
        else {
            Write-Verbose "Using RPC for event collection"
            $rawEvents = Get-WinEvent -ComputerName $PDCEmulator -FilterHashtable $filterParams -ErrorAction Stop
            
            # Format RPC events the same way
            $events = $rawEvents | ForEach-Object {
                $event = $_
                [PSCustomObject]@{
                    TimeCreated = $event.TimeCreated
                    Id = $event.Id
                    Properties = @(
                        [PSCustomObject]@{ Value = $event.Properties[0].Value },  # SubjectUserSid
                        [PSCustomObject]@{ Value = $event.Properties[1].Value },  # SubjectUserName
                        [PSCustomObject]@{ Value = $event.Properties[2].Value },  # SubjectDomainName
                        [PSCustomObject]@{ Value = $event.Properties[3].Value },  # SubjectLogonId
                        [PSCustomObject]@{ Value = $event.Properties[4].Value },  # TargetUserSid
                        [PSCustomObject]@{ Value = $event.Properties[5].Value },  # TargetUserName
                        [PSCustomObject]@{ Value = $event.Properties[6].Value },  # TargetDomainName
                        [PSCustomObject]@{ Value = $event.Properties[7].Value },  # Status
                        [PSCustomObject]@{ Value = $event.Properties[8].Value },  # FailureReason
                        [PSCustomObject]@{ Value = $event.Properties[9].Value },  # SubStatus
                        [PSCustomObject]@{ Value = $event.Properties[10].Value }, # LogonType
                        [PSCustomObject]@{ Value = $event.Properties[11].Value }, # LogonProcessName
                        [PSCustomObject]@{ Value = $event.Properties[12].Value }, # AuthenticationPackageName
                        [PSCustomObject]@{ Value = $event.Properties[13].Value }, # WorkstationName
                        [PSCustomObject]@{ Value = $event.Properties[14].Value }, # TransmittedServices
                        [PSCustomObject]@{ Value = $event.Properties[15].Value }, # LmPackageName
                        [PSCustomObject]@{ Value = $event.Properties[16].Value }, # KeyLength
                        [PSCustomObject]@{ Value = $event.Properties[17].Value }, # ProcessId
                        [PSCustomObject]@{ Value = $event.Properties[18].Value }, # ProcessName
                        [PSCustomObject]@{ Value = $event.Properties[19].Value }, # IpAddress
                        [PSCustomObject]@{ Value = $event.Properties[20].Value }  # IpPort
                    )
                }
            }
        }

        Write-Verbose "First event properties:"
        $firstEvent = $events | Select-Object -First 1
        $firstEvent.Properties | ForEach-Object {
            Write-Verbose "Property Value: $($_.Value)"
        }

        if ($Identity -and $events) {
            Write-Verbose "Filtering for user: $Identity"
            $events = $events | Where-Object { 
                try { $_.Properties[5].Value -eq $Identity }
                catch { 
                    Write-Warning "Failed to access Properties for event"
                    $false 
                }
            }
        }

        return $events
    }
    catch {
        if ($_.Exception.Message -match "No events were found") {
            Write-Verbose "No failed login events found in the specified time period"
            return $null
        }
        Write-Error "Failed to get failed login events: $($_.Exception.Message)"
        return $null
    }
} 