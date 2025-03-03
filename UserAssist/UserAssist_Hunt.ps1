<#
.SYNOPSIS
    UserAssist Registry Forensics Tool

.DESCRIPTION
    This PowerShell script extracts UserAssist registry data, decodes ROT13 entries,
    and parses binary data to reveal application execution history. Results are exported
    to CSV, JSON, and HTML formats for analysis and reporting.

.NOTES
    Name: UserAssist_Hunt.ps1
    Author: The Haag
    Version: 1.0
    Created: 2025-03-03
    
.EXAMPLE
    .\UserAssist_Hunt.ps1
    Extracts UserAssist registry data and exports to multiple formats, then opens HTML report.

.LINK
    https://github.com/MHaggis/PowerShell-Hunter
#>
#>

$AsciiArt = @"
    +-+-+-+-+-+-+-+-+-+-+-+ 
    |U|s|e|r|A|s|s|i|s|t| 
    +-+-+-+-+-+-+-+-+-+-+-+ 
                                                                           
 +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+
 |P|o|w|e|r|S|h|e|l|l| |H|U|N|T|E|R|
 +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+

        [ Hunt smarter, Hunt harder ]
"@

Write-Host $AsciiArt -ForegroundColor Cyan
Write-Host "`nUserAssist Registry Extraction Tool" -ForegroundColor Green
Write-Host "--------------------------------`n" -ForegroundColor DarkGray

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script requires Administrator privileges. Please run as Administrator." -ForegroundColor Red
    exit
}

$OutputPath = ".\UserAssist_Collection"

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath
}

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutputPrefix = "UserAssist_$Timestamp"
$JsonFile = Join-Path $OutputPath "$OutputPrefix.json"
$CsvFile = Join-Path $OutputPath "$OutputPrefix.csv"
$HtmlFile = Join-Path $OutputPath "$OutputPrefix.html"

Write-Host "Extracting UserAssist Registry Keys..." -ForegroundColor Yellow

$userAssistPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
$UserAssistResults = @()

try {
    $guidKeys = Get-ChildItem -Path $userAssistPath -ErrorAction Stop
    
    foreach ($guidKey in $guidKeys) {
        $guidName = Split-Path -Leaf $guidKey.Name
        $countPath = Join-Path -Path $guidKey.PSPath -ChildPath "Count"
        
        if (Test-Path $countPath) {
            $entries = Get-ItemProperty -Path $countPath
            
            foreach ($entry in $entries.PSObject.Properties) {
                if ($entry.Name -ne "PSPath" -and $entry.Name -ne "PSParentPath" -and 
                    $entry.Name -ne "PSChildName" -and $entry.Name -ne "PSDrive" -and 
                    $entry.Name -ne "PSProvider") {
                    
                    $decodedName = [regex]::Replace($entry.Name, '[A-Za-z]', {
                        param($match)
                        $char = [char]$match.Value
                        if (($char -ge 'A' -and $char -le 'Z') -or ($char -ge 'a' -and $char -le 'z')) {
                            $baseChar = if ($char -ge 'A' -and $char -le 'Z') { [byte][char]'A' } else { [byte][char]'a' }
                            $rotChar = [char](($baseChar + (([byte][char]$char - $baseChar + 13) % 26)))
                            return $rotChar
                        }
                        return $char
                    })
                    
                    $entryData = $null
                    $runCount = 0
                    $lastRunTime = $null
                    $focusCount = 0
                    $focusTime = $null
                    
                    if ($entry.Value -is [byte[]]) {
                        if ($entry.Value.Length -ge 16) {
                            $runCount = [BitConverter]::ToUInt32($entry.Value, 4)
                            
                            $fileTime = [BitConverter]::ToInt64($entry.Value, 8)
                            if ($fileTime -gt 0) {
                                $lastRunTime = [DateTime]::FromFileTime($fileTime)
                            }
                            
                            if ($entry.Value.Length -ge 72) {
                                $focusCount = [BitConverter]::ToUInt32($entry.Value, 16)
                                $focusFileTime = [BitConverter]::ToInt64($entry.Value, 60)
                                if ($focusFileTime -gt 0) {
                                    $focusTime = [DateTime]::FromFileTime($focusFileTime)
                                }
                            }
                        }
                    }
                    
                    $resultObject = [PSCustomObject]@{
                        GUID = $guidName
                        EncodedName = $entry.Name
                        DecodedName = $decodedName
                        RunCount = $runCount
                        LastRunTime = if ($lastRunTime) { $lastRunTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                        FocusCount = $focusCount
                        FocusTime = if ($focusTime) { $focusTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                        RawData = if ($entry.Value -is [byte[]]) { [Convert]::ToBase64String($entry.Value) } else { "N/A" }
                    }
                    
                    $UserAssistResults += $resultObject
                    
                    Write-Host "Decoded Entry: $decodedName" -ForegroundColor Cyan
                    Write-Host "  Run Count: $runCount" -ForegroundColor White
                    Write-Host "  Last Run Time: $($resultObject.LastRunTime)" -ForegroundColor White
                    Write-Host "  GUID: $guidName" -ForegroundColor Gray
                    Write-Host "--------------------------------" -ForegroundColor DarkGray
                }
            }
        }
    }
    
    if ($UserAssistResults.Count -gt 0) {
        Write-Host "`nExporting data to multiple formats..." -ForegroundColor Yellow
        
        $UserAssistResults | ConvertTo-Json -Depth 3 | Out-File -FilePath $JsonFile -Encoding UTF8
        Write-Host "JSON data exported to: $JsonFile" -ForegroundColor Green
        
        $UserAssistResults | Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8
        Write-Host "CSV data exported to: $CsvFile" -ForegroundColor Green
        
        $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>UserAssist Registry Analysis</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th { background-color: #2c3e50; color: white; text-align: left; padding: 12px; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        tr:hover { background-color: #ddd; }
        .timestamp { color: #7f8c8d; font-size: 0.8em; }
    </style>
</head>
<body>
    <h1>UserAssist Registry Analysis</h1>
    <p class="timestamp">Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    <table>
        <tr>
            <th>GUID</th>
            <th>Decoded Name</th>
            <th>Run Count</th>
            <th>Last Run Time</th>
            <th>Focus Count</th>
            <th>Focus Time</th>
        </tr>
"@

        $htmlRows = ""
        foreach ($result in $UserAssistResults) {
            $htmlRows += @"
        <tr>
            <td>$($result.GUID)</td>
            <td>$($result.DecodedName)</td>
            <td>$($result.RunCount)</td>
            <td>$($result.LastRunTime)</td>
            <td>$($result.FocusCount)</td>
            <td>$($result.FocusTime)</td>
        </tr>
"@
        }

        $htmlFooter = @"
    </table>
    <p>Total Entries: $($UserAssistResults.Count)</p>
</body>
</html>
"@

        $htmlContent = $htmlHeader + $htmlRows + $htmlFooter
        $htmlContent | Out-File -FilePath $HtmlFile -Encoding UTF8
        Write-Host "HTML report generated at: $HtmlFile" -ForegroundColor Green
        
        Write-Host "`nTotal UserAssist entries found: $($UserAssistResults.Count)" -ForegroundColor Cyan
    } else {
        Write-Host "No UserAssist entries found." -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "Error accessing UserAssist registry keys: $_" -ForegroundColor Red
}

Write-Host "`nUserAssist extraction completed." -ForegroundColor Green

Invoke-Item $HtmlFile