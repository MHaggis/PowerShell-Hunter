<#
.SYNOPSIS
    Analyzes Background Activity Moderator (BAM) data collected from Windows systems.

.DESCRIPTION
    This script analyzes BAM data exported from the Windows registry to identify application 
    execution patterns, suspicious activities, and generate forensic reports. It processes
    registry exports containing BAM data and produces detailed HTML and CSV reports.

.PARAMETER BAMDirectory
    Directory containing the exported BAM registry files to analyze.

.PARAMETER ExportAll
    Switch to export all data formats (HTML, CSV, JSON). Default is True.

.NOTES
    File Name      : analyze-BAM.ps1
    Prerequisite   : PowerShell 5.1 or later
    Copyright      : PowerShell-Hunter Project
    Author         : The Haag
    
.EXAMPLE
    .\analyze-BAM.ps1 -BAMDirectory .\BAM_Collection
    Analyzes BAM data in the specified directory and generates reports.

.LINK
    https://github.com/MHaggis/PowerShell-Hunter
#>


param(
    [Parameter(Mandatory=$true)]
    [string]$BAMDirectory,
    [switch]$ExportAll = $true
)


$AsciiArt = @"
    +-+-+-+ 
    |B|A|M| 
    +-+-+-+ 
                                                                           
 +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+
 |P|o|w|e|r|S|h|e|l|l| |H|U|N|T|E|R|
 +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+

        [ Hunt smarter, Hunt harder ]
"@

Write-Host $AsciiArt -ForegroundColor Cyan
Write-Host "`nBAM Data Analysis Tool" -ForegroundColor Green
Write-Host "------------------------`n" -ForegroundColor DarkGray


$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script requires Administrator privileges. Please run as Administrator." -ForegroundColor Red
    exit
}

if (-not (Test-Path $BAMDirectory)) {
    Write-Host "BAM directory not found: $BAMDirectory" -ForegroundColor Red
    exit
}

function Convert-FiletimeToDateTime {
    param([int64]$Filetime)
    try {
        [datetime]::FromFileTime($Filetime)
    } catch {
        return "Invalid timestamp"
    }
}

function Convert-SIDtoUsername {
    param([string]$SID)
    
    try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
        $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
        return $objUser.Value
    } catch {
        try {
            $query = "SELECT * FROM Win32_UserAccount WHERE SID='$SID'"
            $wmiFetch = Get-WmiObject -Query $query
            if ($wmiFetch) {
                return "$($wmiFetch.Domain)\$($wmiFetch.Name)"
            }
        } catch {}
        
        try {
            $userPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID"
            if (Test-Path $userPath) {
                $profilePath = (Get-ItemProperty -Path $userPath -Name ProfileImagePath).ProfileImagePath
                if ($profilePath -match "\\([^\\]+)$") {
                    return "$env:COMPUTERNAME\$($Matches[1])"
                }
            }
        } catch {}
        
        $wellKnownSIDs = @{
            "S-1-5-18" = "NT AUTHORITY\SYSTEM"
            "S-1-5-19" = "NT AUTHORITY\LOCAL SERVICE"
            "S-1-5-20" = "NT AUTHORITY\NETWORK SERVICE"
        }
        
        foreach ($knownSID in $wellKnownSIDs.Keys) {
            if ($SID -eq $knownSID) {
                return $wellKnownSIDs[$knownSID]
            }
        }
        
        return "Unknown User ($SID)"
    }
}

function Get-FileSignature {
    param([string]$FilePath)
    try {
        if ($FilePath -match "^\\Device\\HarddiskVolume\d+\\(.+)$") {
            $FilePath = $Matches[1]
            if ($FilePath -match "^[A-Za-z]:\\") {
                $FilePath = $FilePath.Substring(2)
            }
            $FilePath = Join-Path $env:SystemDrive $FilePath
        }
        
        if (Test-Path $FilePath) {
            $sig = Get-AuthenticodeSignature $FilePath
            return [PSCustomObject]@{
                'IsSigned' = $sig.Status -eq 'Valid'
                'SignatureStatus' = $sig.Status
                'Publisher' = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "Unknown" }
            }
        }
        return [PSCustomObject]@{
            'IsSigned' = $false
            'SignatureStatus' = 'File Not Found'
            'Publisher' = 'Unknown'
        }
    } catch {
        return [PSCustomObject]@{
            'IsSigned' = $false
            'SignatureStatus' = 'Error'
            'Publisher' = 'Error: ' + $_.Exception.Message
        }
    }
}

function Get-AppType {
    param([string]$Path)
    $knownApps = @{
        "\\Windows\\System32\\svchost.exe" = "Critical System Process"
        "\\Windows\\explorer.exe" = "Windows Shell"
        "\\Program Files\\Windows Defender\\" = "Security Software"
        "\\AppData\\Local\\Temp\\" = "Temporary Application"
    }

    foreach ($pattern in $knownApps.Keys) {
        if ($Path -match [regex]::Escape($pattern)) {
            return $knownApps[$pattern]
        }
    }

    if ($Path -match "_[a-z0-9]+$") {
        return "Windows Store App"
    } elseif ($Path -match "\\Windows\\") {
        return "System Binary"
    } elseif ($Path -match "\\Program Files\\") {
        return "Installed Application"
    } elseif ($Path -match "\\AppData\\") {
        return "User Application"
    } elseif ($Path -match "^\\\\") {
        return "Network Path"
    } else {
        return "Other"
    }
}

function Get-SuspiciousIndicators {
    param(
        [string]$Path,
        [datetime]$ExecutionTime,
        [string]$Username
    )
    $indicators = @()

    # Suspicious paths
    if ($Path -match "\\Temp\\") { $indicators += "Executed from Temp" }
    if ($Path -match "\\Downloads\\") { $indicators += "Executed from Downloads" }
    if ($Path -match "^\\\\") { $indicators += "Network Path Execution" }
    # Suspicious file extensions
    if ($Path -match "\.(exe|dll|ps1|vbs|bat|cmd|hta|js|wsf)$") { $indicators += "Script/Executable File" }
    
    # Common malware paths
    if ($Path -match "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\") { $indicators += "Startup Folder Execution" }
    if ($Path -match "\\AppData\\Local\\Temp\\7z[A-Z0-9]{6}") { $indicators += "7zip Temp Extraction" }
    if ($Path -match "\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\") { $indicators += "System Startup Folder" }
    
    # Living off the land binaries (LOLBins)
    if ($Path -match "\\certutil\.exe|\\regsvr32\.exe|\\mshta\.exe|\\rundll32\.exe") { $indicators += "Potential LOLBin Usage" }
    
    # Unusual locations
    if ($Path -match "\\Public\\") { $indicators += "Public Directory Execution" }
    if ($Path -match "\\Recycle") { $indicators += "Recycle Bin Execution" }
    if ($Path -match "\\Users\\Public\\") { $indicators += "Public User Space Execution" }
    
    # Masquerading attempts
    if ($Path -match "svchost\.exe$" -and -not ($Path -match "\\Windows\\System32\\")) { $indicators += "Suspicious svchost Location" }
    if ($Path -match "\\Windows\\Fonts\\.*\.exe$") { $indicators += "Suspicious Fonts Directory Execution" }
    
    # Obfuscation indicators
    if ($Path -match "\s{2,}") { $indicators += "Multiple Spaces in Path" }
    if ($Path -match "[`\u0000-`\u0019]") { $indicators += "Control Characters in Path" }
    if ($Path -match "\.{2,}") { $indicators += "Multiple Dots in Path" }
    
    # Uncommon paths
    if ($Path -match "\\Windows\\Debug\\") { $indicators += "Debug Directory Execution" }
    if ($Path -match "\\Windows\\Tasks\\") { $indicators += "Tasks Directory Execution" }
    if ($Path -match "\\Windows\\Temp\\") { $indicators += "Windows Temp Execution" }
    if ($Path -match "\\Perflogs\\") { $indicators += "Perflogs Directory Execution" }
    if ($Path -match "\\Windows\\tracing\\") { $indicators += "Tracing Directory Execution" }
    if ($Path -match "\\Windows\\PLA\\(Reports|Rules|Templates)\\") { $indicators += "PLA Directory Execution" }
    if ($Path -match "\\Windows\\Registration\\CRMLog\\") { $indicators += "CRM Log Directory Execution" }
    if ($Path -match "\\Windows\\System32\\Com\\dmp\\") { $indicators += "COM Dump Directory Execution" }
    if ($Path -match "\\Windows\\System32\\LogFiles\\WMI\\") { $indicators += "WMI Log Directory Execution" }
    if ($Path -match "\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\") { $indicators += "Machine Keys Directory Execution" }
    if ($Path -match "\\Windows\\System32\\spool\\(PRINTERS|SERVERS|drivers)\\") { $indicators += "Printer Spool Directory Execution" }
    if ($Path -match "\\Windows\\(System32|SysWOW64)\\Tasks\\") { $indicators += "System Tasks Directory Execution" }
    if ($Path -match "\\Windows\\(System32|SysWOW64)\\Tasks\\Microsoft\\Windows\\RemoteApp") { $indicators += "RemoteApp Tasks Execution" }
    
    # Suspicious timing
    $hour = $ExecutionTime.Hour
    if ($hour -ge 23 -or $hour -le 4) { $indicators += "After Hours Execution" }
    
    # System accounts
    if ($Username -match "SYSTEM|Administrator") { $indicators += "System Account Usage" }

    # Suspicious names
    if ($Path -match "cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe") {
        $indicators += "Script Host Execution"
    }

    return $indicators
}

function Get-SequenceGroups {
    param([array]$Results)
    
    # Group by sequence number, only include groups with multiple entries
    $groups = $Results | 
        Where-Object { $_.SequenceNumber -ne $null } |
        Group-Object -Property SequenceNumber |
        Where-Object { $_.Count -gt 1 }
    
    return $groups
}

function Export-ResultsToFormats {
    param(
        [array]$Results,
        [string]$BaseName
    )
    
    $CSVPath = "$BaseName.csv"
    $Results | Export-Csv -Path $CSVPath -NoTypeInformation
    Write-Host "Exported to CSV: $CSVPath" -ForegroundColor Green

    $JSONPath = "$BaseName.json"
    $Results | ConvertTo-Json -Depth 10 | Out-File $JSONPath
    Write-Host "Exported to JSON: $JSONPath" -ForegroundColor Green

    $HTMLPath = "$BaseName.html"
    $HTMLHeader = @"
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #4CAF50; color: white; }
            tr:nth-child(even) { background-color: #f2f2f2; }
            .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
            h2 { color: #2c3e50; }
            .suspicious { color: red; font-weight: bold; }
            .warning { background-color: #fff3cd; }
            .safe { background-color: #d4edda; }
            .relationship-table { 
                width: 100%;
                margin-top: 10px;
                border-collapse: collapse;
            }
            .relationship-table th {
                background-color: #4CAF50;
                color: white;
                padding: 8px;
            }
            .relationship-table td {
                padding: 8px;
                border: 1px solid #ddd;
            }
            .relationship-table tr:nth-child(even) {
                background-color: #f9f9f9;
            }
        </style>
    </head>
    <body>
"@

    $HTMLContent = $HTMLHeader
    $HTMLContent += "<h1>BAM Analysis Report - $(Get-Date)</h1>"
    
    $HTMLContent += "<div class='section'>"
    $HTMLContent += "<h2>Summary</h2>"
    $HTMLContent += "<ul>"
    $HTMLContent += "<li>Total Entries: $($Results.Count)</li>"

    $EarliestDate = ($Results | Sort-Object {$_.LastExecuted} | Select-Object -First 1).LastExecuted
    $LatestDate = ($Results | Sort-Object {$_.LastExecuted} | Select-Object -Last 1).LastExecuted
    $HTMLContent += "<li>Date Range: $($EarliestDate) to $($LatestDate)</li>"

    $HTMLContent += "<li>Unique Applications: $($Results | Select-Object -Unique ExecutablePath | Measure-Object | Select-Object -ExpandProperty Count)</li>"
    $HTMLContent += "<li>Suspicious Activities: $($Results | Where-Object {$_.SuspiciousIndicators} | Measure-Object | Select-Object -ExpandProperty Count)</li>"
    $HTMLContent += "</ul>"
    $HTMLContent += "</div>"

    $SuspiciousResults = $Results | Where-Object {$_.SuspiciousIndicators}
    if ($SuspiciousResults) {
        $HTMLContent += "<div class='section warning'>"
        $HTMLContent += "<h2>&#9888; Suspicious Activities</h2>"
        $HTMLContent += $SuspiciousResults | 
            Select-Object ExecutablePath, LastExecuted, Username, SuspiciousIndicators, SignatureStatus |
            ConvertTo-Html -Fragment
        $HTMLContent += "</div>"
    }

    $HTMLContent += "<div class='section'>"
    $HTMLContent += "<h2>Most Recent Executions</h2>"
    $HTMLContent += $Results | Sort-Object LastExecuted -Descending | 
        Select-Object -First 10 | 
        ConvertTo-Html -Fragment
    $HTMLContent += "</div>"

    $NetworkPaths = $Results | Where-Object {$_.ExecutablePath -match "^\\\\"}
    if ($NetworkPaths) {
        $HTMLContent += "<div class='section warning'>"
        $HTMLContent += "<h2>&#127760; Network Path Executions</h2>"
        $HTMLContent += $NetworkPaths | ConvertTo-Html -Fragment
        $HTMLContent += "</div>"
    }

    $UnsignedApps = $Results | Where-Object {-not $_.IsSigned}
    if ($UnsignedApps) {
        $HTMLContent += "<div class='section warning'>"
        $HTMLContent += "<h2>&#10060; Unsigned Applications</h2>"
        $HTMLContent += $UnsignedApps | ConvertTo-Html -Fragment
        $HTMLContent += "</div>"
    }

    $SequenceGroups = Get-SequenceGroups -Results $Results
    if ($SequenceGroups) {
        $HTMLContent += "<div class='section'>"
        $HTMLContent += "<h2>&#128279; Related Activities by Sequence</h2>"
        
        foreach ($group in $SequenceGroups) {
            $HTMLContent += "<h3>Sequence ID: $($group.Name)</h3>"
            $HTMLContent += "<table class='relationship-table'>"
            $HTMLContent += "<tr><th>Executable Path</th><th>Last Executed</th><th>Username</th></tr>"
            
            foreach ($entry in $group.Group | Sort-Object LastExecuted) {
                $HTMLContent += "<tr>"
                $HTMLContent += "<td>$($entry.ExecutablePath)</td>"
                $HTMLContent += "<td>$($entry.LastExecuted)</td>"
                $HTMLContent += "<td>$($entry.Username)</td>"
                $HTMLContent += "</tr>"
            }
            
            $HTMLContent += "</table>"
        }
        
        $HTMLContent += "</div>"
    }

    $HTMLContent += "</body></html>"
    $HTMLContent | Out-File $HTMLPath
    Write-Host "Exported to HTML: $HTMLPath" -ForegroundColor Green

    $TimelinePath = "$BaseName`_timeline.csv"
    $Results | Select-Object LastExecuted, ExecutablePath, Username, AppType, SuspiciousIndicators, SignatureStatus | 
        Sort-Object LastExecuted | 
        Export-Csv -Path $TimelinePath -NoTypeInformation
    Write-Host "Exported timeline to: $TimelinePath" -ForegroundColor Green
}

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutputDir = Join-Path $BAMDirectory "Analysis_$Timestamp"
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$Results = @()

$RegFile = Get-ChildItem -Path $BAMDirectory -Filter "bam_*.reg" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

if ($RegFile) {
    Write-Host "Processing $($RegFile.Name)..." -ForegroundColor Yellow
    
    try {
        $Content = Get-Content $RegFile.FullName -Raw
        $Lines = $Content -split "`r`n"
        $CurrentSID = $null
        
        foreach ($Line in $Lines) {
            if ($Line -match '^\[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\(.+?)\]$') {
                $CurrentSID = $Matches[1]
            }
            elseif ($Line -match '^"(.+?)"=hex:(.+)$' -and $CurrentSID) {
                $Path = $Matches[1]
                $HexString = $Matches[2] -replace ',',''
                
                Write-Verbose "Debug: Path: $Path"
                Write-Verbose "Debug: Hex string length: $($HexString.Length)"
                Write-Verbose "Debug: Full hex string: $HexString"
                Write-Verbose "---"

                try {
                    if ($HexString.Length -ge 16) {
                        $TimestampHex = $HexString.Substring(0, 16)
                        $Bytes = [byte[]]::new(8)
                        for ($i = 0; $i -lt 16; $i += 2) {
                            $Bytes[$i/2] = [Convert]::ToByte($TimestampHex.Substring($i, 2), 16)
                        }
                        
                        $Timestamp = [BitConverter]::ToInt64($Bytes, 0)
                        $LastExecuted = Convert-FiletimeToDateTime $Timestamp
                        $Username = Convert-SIDtoUsername $CurrentSID
                        $Signature = Get-FileSignature $Path
                        $AppType = Get-AppType $Path
                        $SuspiciousIndicators = Get-SuspiciousIndicators -Path $Path -ExecutionTime $LastExecuted -Username $Username
                        
                        # Update the sequence number extraction
                        $SequenceNumber = if ($HexString) {  # As long as we have any hex data
                            try {
                                # Clean the hex string and get meaningful bytes
                                $cleanHex = $HexString.Trim().TrimEnd('\').TrimEnd('0')
                                
                                if ($cleanHex.Length -gt 0) {
                                    # Take whatever meaningful bytes we have
                                    $seqBytes = $cleanHex.Substring([Math]::Max(0, $cleanHex.Length - 8))
                                    Write-Verbose "Debug: Clean hex: $cleanHex -> Sequence bytes: $seqBytes"
                                    
                                    # Convert to uint32, handling both short and long formats
                                    if ($seqBytes.Length -ge 8) {
                                        [uint32]"0x$seqBytes"
                                    } elseif ($seqBytes.Length -gt 0) {
                                        # For shorter sequences, pad with zeros
                                        $paddedSeq = $seqBytes.PadLeft(8, '0')
                                        Write-Verbose "Debug: Padded sequence: $paddedSeq"
                                        [uint32]"0x$paddedSeq"
                                    } else {
                                        Write-Verbose "Debug: No valid sequence bytes found"
                                        $null
                                    }
                                } else {
                                    Write-Verbose "Debug: No meaningful bytes found in hex string for $Path"
                                    $null
                                }
                            } catch {
                                Write-Verbose "Debug: Could not parse hex data for $Path : $($_.Exception.Message)"
                                $null
                            }
                        } else {
                            Write-Verbose "Debug: No hex data found for $Path"
                            $null
                        }

                        $Results += [PSCustomObject]@{
                            'UserSID' = $CurrentSID
                            'Username' = $Username
                            'ExecutablePath' = $Path
                            'LastExecuted' = $LastExecuted
                            'AppType' = $AppType
                            'IsSigned' = $Signature.IsSigned
                            'SignatureStatus' = $Signature.SignatureStatus
                            'Publisher' = $Signature.Publisher
                            'SuspiciousIndicators' = if ($SuspiciousIndicators) { $SuspiciousIndicators -join '; ' } else { $null }
                            'HexData' = $HexString
                            'SequenceNumber' = $SequenceNumber
                        }
                    }
                } catch {
                    Write-Host "Error processing entry $Path`: $_" -ForegroundColor Red
                }
            }
        }
    } catch {
        Write-Host "Error processing registry file: $_" -ForegroundColor Red
    }
}

Export-ResultsToFormats -Results $Results -BaseName (Join-Path $OutputDir "BAM_Analysis")

Write-Host "`nAnalysis complete! Found $($Results.Count) executable entries" -ForegroundColor Green

if ($Results.Count -gt 0) {
    Write-Host "`nMost recent executions:" -ForegroundColor Cyan
    $Results | Where-Object { $_.LastExecuted -ne "Invalid timestamp" } |
        Sort-Object LastExecuted -Descending | 
        Select-Object ExecutablePath, LastExecuted, Username, AppType, SignatureStatus, SequenceNumber |
        Format-Table -AutoSize

    Write-Host "`nApplication Types:" -ForegroundColor Cyan
    $Results | Group-Object AppType | 
        Sort-Object Count -Descending | 
        Format-Table @{L='Type';E={$_.Name}}, Count -AutoSize

    Write-Host "`nSuspicious Activities:" -ForegroundColor Red
    $Results | Where-Object {$_.SuspiciousIndicators} |
        Select-Object ExecutablePath, LastExecuted, Username, SuspiciousIndicators |
        Format-Table -AutoSize

    Write-Host "`nExecution Sequence Analysis:" -ForegroundColor Cyan
    $Results | Where-Object { $_.SequenceNumber -ne $null } |
        Sort-Object SequenceNumber | 
        Select-Object ExecutablePath, LastExecuted, SequenceNumber |
        Format-Table -AutoSize

    Write-Host "`nOpening HTML report..." -ForegroundColor Cyan
    Start-Process (Join-Path $OutputDir "BAM_Analysis.html")
}

Write-Host "`nReports have been generated in: $OutputDir" -ForegroundColor Green 