<#
.SYNOPSIS
Tests prerequisites required for AD threat hunting.

.DESCRIPTION
This function performs a series of checks to verify that all prerequisites are met before running AD threat hunting operations.

Key checks include:
- Administrative privileges
- Active Directory PowerShell module availability 
- Domain connectivity
- PDC Emulator access
- Event log permissions
- Required ports and protocols

The function returns a results object containing:
- Success: Boolean indicating if all checks passed
- Messages: Detailed status messages for each check

.EXAMPLE
$prereqCheck = Test-ADPrerequisites
if (-not $prereqCheck.Success) {
    throw "Prerequisites check failed"
}

.NOTES
Author: The Haag
Requires: Administrative privileges, Active Directory PowerShell module
#>

function Test-ADPrerequisites {
    [CmdletBinding()]
    param()

    $results = @{
        Success = $true
        Messages = @()
    }

    # Check if running with admin privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        $results.Success = $false
        $results.Messages += "Script must be run with administrative privileges"
    }

    # Check AD PowerShell module
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $results.Messages += "✓ ActiveDirectory PowerShell module is available"
    }
    catch {
        $results.Success = $false
        $results.Messages += "✕ ActiveDirectory PowerShell module is not available: $($_.Exception.Message)"
    }

    # Test AD connectivity
    try {
        $domain = Get-ADDomain
        $results.Messages += "✓ Successfully connected to domain: $($domain.DNSRoot)"
        
        # Test PDC Emulator connectivity
        $pdcEmulator = $domain.PDCEmulator
        $results.Messages += "✓ PDC Emulator identified: $pdcEmulator"
        
        # Test network connectivity to PDC
        $testConnection = Test-NetConnection -ComputerName $pdcEmulator -Port 445 -WarningAction SilentlyContinue
        if ($testConnection.TcpTestSucceeded) {
            $results.Messages += "✓ Network connectivity to PDC Emulator is working"
        } else {
            $results.Success = $false
            $results.Messages += "✕ Cannot connect to PDC Emulator on port 445 (SMB/RPC)"
        }

        # Test event log access
        try {
            # Try local access first if we're on the PDC
            if ($env:COMPUTERNAME -eq $pdcEmulator) {
                $events = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
                $results.Messages += "✓ Successfully queried events (local access)"
            }
            else {
                # Try different methods for remote access
                try {
                    # Method 1: Direct WinRM
                    $events = Invoke-Command -ComputerName $pdcEmulator -ScriptBlock {
                        Get-WinEvent -LogName Security -MaxEvents 1
                    } -ErrorAction Stop
                    $results.Messages += "✓ Successfully queried events via WinRM"
                }
                catch {
                    # Method 2: Traditional RPC
                    $events = Get-WinEvent -ComputerName $pdcEmulator -LogName Security -MaxEvents 1 -ErrorAction Stop
                    $results.Messages += "✓ Successfully queried events via RPC"
                }
            }
        }
        catch {
            $results.Success = $false
            $results.Messages += "✕ Failed to query events: $($_.Exception.Message)"
            $results.Messages += "  Ensure the following:"
            $results.Messages += "  - Windows Firewall allows RPC (TCP 135) and Dynamic RPC ports"
            $results.Messages += "  - WinRM is configured (Run: winrm quickconfig)"
            $results.Messages += "  - Event Log Readers group membership"
        }
    }
    catch {
        $results.Success = $false
        $results.Messages += "✕ Failed to connect to Active Directory: $($_.Exception.Message)"
    }

    return [PSCustomObject]$results
} 