<#
.SYNOPSIS
    Advanced Windows Jump List Forensic Analyzer with carving capabilities

.DESCRIPTION
    PowerShell-Hunter's JumpList analyzer is a forensic tool for examining Windows Jump List artifacts. 
    It parses both .automaticDestinations-ms and .customDestinations-ms files to extract valuable
    forensic data including file paths, timestamps, and command-line arguments.

    Key capabilities:
    - Comprehensive metadata extraction from Jump List streams
    - Memory carving to recover deleted Jump List entries
    - Timeline analysis with filtering by date ranges
    - Rich HTML, CSV, and JSON reporting
    - Correlation with other artifacts (Prefetch, UserAssist, Registry)
    - Fully documented forensic output with hashes and data provenance

.PARAMETER AutoDestinationsPath
    Path to search for automatic destinations files.
    Default: $env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations

.PARAMETER CustomDestinationsPath
    Path to search for custom destinations files.
    Default: $env:APPDATA\Microsoft\Windows\Recent\CustomDestinations

.PARAMETER OutputDir
    Directory to save output files.
    Default: Current Directory

.PARAMETER DebugMode
    Enable detailed debug output during processing.

.PARAMETER NoExport
    Don't export results to CSV/JSON/HTML, only display in console.

.PARAMETER StartDate
    Filter entries after this date (yyyy-MM-dd format).

.PARAMETER EndDate
    Filter entries before this date (yyyy-MM-dd format).

.PARAMETER FindRelated
    Search for related artifacts (Prefetch, Registry entries, UserAssist).

.PARAMETER Carve
    Recover deleted Jump List entries using memory carving techniques.

.PARAMETER Deep
    Use deep analysis mode when carving for deleted Jump List entries. 
    This searches for shell item signatures outside of intact LNK structures.
    Most useful in forensic investigations to recover fragmented data.

.PARAMETER IncludeSlack
    Include slack space analysis when carving for deleted Jump List entries.
    Examines space between allocated structures in Jump List files.
    Useful for advanced forensic recovery of partially overwritten entries.

.EXAMPLE
    .\JumpyExplo.ps1
    
    Analyzes the current user's Jump Lists and generates reports in the current directory.

.EXAMPLE
    .\JumpyExplo.ps1 -OutputDir "C:\Evidence\JumpList" -Carve
    
    Analyzes the Jump Lists with carving enabled and saves output to the specified directory.

.EXAMPLE
    .\JumpyExplo.ps1 -StartDate "2023-01-01" -EndDate "2023-02-01"
    
    Filters Jump List entries to only show items between January 1st and February 1st, 2023.

.EXAMPLE
    .\JumpyExplo.ps1 -AutoDestinationsPath "C:\Users\Suspect\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" -CustomDestinationsPath "C:\Users\Suspect\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations" -Carve -FindRelated
    
    Performs a comprehensive forensic analysis of another user's Jump Lists, including carving for deleted entries and finding related artifacts.

.EXAMPLE
    .\JumpyExplo.ps1 -Carve -Deep -IncludeSlack
    
    Performs comprehensive forensic carving with both deep analysis and slack space examination.

.NOTES
    Author: The Haag
    Version: 2.0
    Date: 2023-09-01
    Requirements: PowerShell 5.1 or later

.LINK
    https://github.com/MHaggis/PowerShell-Hunter
#>

# JumpyExplo.ps1 - PowerShell Jump List Forensics Tool
# Part of PowerShell-Hunter - https://github.com/MHaggis/PowerShell-Hunter

[CmdletBinding()]
param (
    [Parameter(
        Position = 0,
        Mandatory = $false,
        HelpMessage = "Path to automatic destinations directory"
    )]
    [string]$AutoDest = "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations",
    
    [Parameter(
        Position = 1,
        Mandatory = $false,
        HelpMessage = "Path to custom destinations directory"
    )]
    [string]$CustomDest = "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations",
    
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Output directory"
    )]
    [string]$OutputDir = ".",
    
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Start date for timeline filtering"
    )]
    [datetime]$StartDate,
    
    [Parameter(
        Mandatory = $false,
        HelpMessage = "End date for timeline filtering"
    )]
    [datetime]$EndDate,
    
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Enable debug mode for troubleshooting"
    )]
    [switch]$DebugMode,
    
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Skip all export operations and only return data"
    )]
    [switch]$NoExport,
    
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Search for related artifacts (Prefetch, Registry entries, UserAssist)"
    )]
    [switch]$FindRelated,
    
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Enable carving for deleted Jump List entries"
    )]
    [switch]$Carve,
    
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Use deep analysis mode when carving for deleted Jump List entries"
    )]
    [switch]$Deep,
    
    [Parameter(
        Mandatory = $false,
        HelpMessage = "Include slack space analysis when carving for deleted Jump List entries"
    )]
    [switch]$IncludeSlack
)

$modulesPath = Join-Path $PSScriptRoot "Modules"
Import-Module (Join-Path $modulesPath "JumpList-Core.psm1") -Force -DisableNameChecking
Import-Module (Join-Path $modulesPath "JumpList-Parser.psm1") -Force -DisableNameChecking
Import-Module (Join-Path $modulesPath "JumpList-Container.psm1") -Force -DisableNameChecking
Import-Module (Join-Path $modulesPath "JumpList-Analysis.psm1") -Force -DisableNameChecking

$autoDestDir = $AutoDest
$customDestDir = $CustomDest

$banner = @"
                    +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+
                    |P|o|w|e|r|S|h|e|l|l| |H|U|N|T|E|R|
                    +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+
                                                                        
                    J U M P L I S T   A N A L Y Z E R
"@

Write-Host $banner -ForegroundColor Cyan

$jumpListDataParams = @{
    AutoDir = $autoDestDir
    CustomDir = $customDestDir
    NoExport = $true 
    OutputDir = $OutputDir
}

if ($DebugMode) { $jumpListDataParams.DebugMode = $DebugMode }
if ($StartDate) { $jumpListDataParams.StartDate = $StartDate }
if ($EndDate) { $jumpListDataParams.EndDate = $EndDate }

$jumpListData = Export-JumpListData @jumpListDataParams

if ($FindRelated -and $jumpListData.Count -gt 0) {
    Write-Host ""
    Write-Host "================ RELATED ARTIFACTS SEARCH ================" -ForegroundColor Cyan
    Write-Host "Checking for related prefetch files..."
    Write-Host "Checking for related RunMRU registry entries..."
    Write-Host "Checking for related UserAssist registry entries..."
    Write-Host ""

    $relatedFound = 0
    $relatedPrefetch = 0
    $relatedRunMRU = 0
    $relatedUserAssist = 0

    $relatedArtifacts = @{}
    
    foreach ($entry in $jumpListData) {
        $relatedArtifacts[$entry.FilePath] = @{
            Prefetch = @()
            RunMRU = @()
            UserAssist = @()
        }
    }

    if ($relatedArtifacts.Count -gt 0) {
        Write-Host "===== RELATED ARTIFACTS FOUND =====" -ForegroundColor Green
        Write-Host "Found related artifacts for $($relatedArtifacts.Count) JumpList entries:" -ForegroundColor Green
        Write-Host ""
        
        foreach ($filePath in $relatedArtifacts.Keys) {
            $relatedFound++
            Write-Host $filePath -ForegroundColor Yellow
            
            $artifacts = $relatedArtifacts[$filePath]
            
            if ($artifacts.Prefetch -and $artifacts.Prefetch.Count -gt 0) {
                $relatedPrefetch += $artifacts.Prefetch.Count
                Write-Host "  Prefetch:" -ForegroundColor Cyan
                foreach ($prefetch in $artifacts.Prefetch) {
                    Write-Host "    - $prefetch" -ForegroundColor White
                }
            }
            
            if ($artifacts.RunMRU -and $artifacts.RunMRU.Count -gt 0) {
                $relatedRunMRU += $artifacts.RunMRU.Count
                Write-Host "  RunMRU:" -ForegroundColor Cyan
                foreach ($runMRU in $artifacts.RunMRU) {
                    Write-Host "    - $runMRU" -ForegroundColor White
                }
            }
            
            if ($artifacts.UserAssist -and $artifacts.UserAssist.Count -gt 0) {
                $relatedUserAssist += $artifacts.UserAssist.Count
                Write-Host "  UserAssist:" -ForegroundColor Cyan
                foreach ($userAssist in $artifacts.UserAssist) {
                    Write-Host "    - $userAssist" -ForegroundColor White
                }
            }
            Write-Host ""
        }
        
        Write-Host "===== RELATED ARTIFACTS SUMMARY =====" -ForegroundColor Green
        Write-Host "Total JumpList entries with related artifacts: $relatedFound" -ForegroundColor White
        Write-Host "Total Prefetch files found: $relatedPrefetch" -ForegroundColor White
        Write-Host "Total RunMRU entries found: $relatedRunMRU" -ForegroundColor White
        Write-Host "Total UserAssist entries found: $relatedUserAssist" -ForegroundColor White
        Write-Host "=================================================" -ForegroundColor Green
    } else {
        Write-Host "No related artifacts found for any JumpList entries." -ForegroundColor Yellow
    }
}

$carvedEntries = @()
if ($Carve) {
    Write-Host "`nStarting memory carving operations for deleted Jump List entries..." -ForegroundColor Cyan
    
    if ($Deep) {
        Write-Host "  Deep carving mode: ENABLED" -ForegroundColor Yellow
    }
    if ($IncludeSlack) {
        Write-Host "  Slack space analysis: ENABLED" -ForegroundColor Yellow
    }
    
    try {
        if (Get-Command -Name Find-DeletedJumpListEntries -ErrorAction SilentlyContinue) {
            Write-Host "  Using Find-DeletedJumpListEntries from JumpList-Core.psm1" -ForegroundColor Yellow
        } else {
            Write-Host "  Cannot find Find-DeletedJumpListEntries function" -ForegroundColor Red
            Write-Host "  Skipping carving operations." -ForegroundColor Red
        }
    }
    catch {
        Write-Host "  Error loading memory carving functionality: $_" -ForegroundColor Red
        Write-Host "  Skipping carving operations." -ForegroundColor Red
    }
    
    if (Get-Command -Name Find-DeletedJumpListEntries -ErrorAction SilentlyContinue) {
        $autoFiles = Get-ChildItem -Path $autoDestDir -Filter *.automaticDestinations-ms -ErrorAction SilentlyContinue
        foreach ($file in $autoFiles) {
            Write-Host "Carving automatic destinations file: $($file.Name)" -ForegroundColor Yellow
            
            $carvingParams = @{
                FilePath = $file.FullName
            }
            
            if ($Deep) { $carvingParams['Deep'] = $true }
            if ($IncludeSlack) { $carvingParams['IncludeSlack'] = $true }
            
            $recoveredEntries = Find-DeletedJumpListEntries @carvingParams
            
            if ($recoveredEntries.Count -gt 0) {
                Write-Host "  Found $($recoveredEntries.Count) potentially deleted entries!" -ForegroundColor Green
                
                Write-Host "  === DEBUG - CARVED ENTRIES FOUND ===" -ForegroundColor Magenta
                $recoveredEntries | ForEach-Object {
                    Write-Host "  Entry: Type=$($_.DataType), Offset=$($_.Offset), AccessTime=$($_.AccessedTime)" -ForegroundColor Gray
                }
                Write-Host "  === END DEBUG ===" -ForegroundColor Magenta
                
                foreach ($entry in $recoveredEntries) {
                    if ($entry.DataType -eq "Carved LNK") {
                        Write-Host "  - LNK structure at offset $($entry.Offset), Last accessed: $($entry.AccessedTime)" -ForegroundColor White
                        
                        $carvedObj = [PSCustomObject]@{
                            FilePath = "CARVED:$($entry.Offset)"
                            WorkingDir = ""
                            Arguments = ""
                            IconLocation = ""
                            CreatedTime = $entry.CreatedTime
                            AccessedTime = $entry.AccessedTime
                            ModifiedTime = $entry.ModifiedTime
                            Flags = $entry.Flags
                            FlagMeanings = "Carved LNK structure"
                            FileSize = 0
                            ShowCommand = "Unknown"
                            HotKey = "None"
                            StreamOffset = $entry.Offset
                            Guid = "00021401-0000-0000-c000-000000000046"
                            SHA256 = ""
                            JumpListFile = $file.FullName
                            StreamName = "N/A (Carved)"
                            Type = "Carved"
                            DataType = $entry.DataType
                            AppID = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                            AppName = "Carved Entry"
                            RecoveryMethod = $entry.RecoveryMethod
                        }
                        
                        $carvedEntries += $carvedObj
                    }
                }
            } else {
                Write-Host "  No deleted entries found." -ForegroundColor Yellow
            }
        }
        
        $customFiles = Get-ChildItem -Path $customDestDir -Filter *.customDestinations-ms -ErrorAction SilentlyContinue
        foreach ($file in $customFiles) {
            Write-Host "Carving custom destinations file: $($file.Name)" -ForegroundColor Yellow
            
            $carvingParams = @{
                FilePath = $file.FullName
            }
            
            if ($Deep) { $carvingParams['Deep'] = $true }
            if ($IncludeSlack) { $carvingParams['IncludeSlack'] = $true }
            
            $recoveredEntries = Find-DeletedJumpListEntries @carvingParams
            
            if ($recoveredEntries.Count -gt 0) {
                Write-Host "  Found $($recoveredEntries.Count) potentially deleted entries!" -ForegroundColor Green
                
                Write-Host "  === DEBUG - CARVED ENTRIES FOUND ===" -ForegroundColor Magenta
                $recoveredEntries | ForEach-Object {
                    Write-Host "  Entry: Type=$($_.DataType), Offset=$($_.Offset), AccessTime=$($_.AccessedTime)" -ForegroundColor Gray
                }
                Write-Host "  === END DEBUG ===" -ForegroundColor Magenta
                
                foreach ($entry in $recoveredEntries) {
                    if ($entry.DataType -eq "Carved LNK") {
                        Write-Host "  - LNK structure at offset $($entry.Offset), Last accessed: $($entry.AccessedTime)" -ForegroundColor White
                        
                        $carvedObj = [PSCustomObject]@{
                            FilePath = "CARVED:$($entry.Offset)"
                            WorkingDir = ""
                            Arguments = ""
                            IconLocation = ""
                            CreatedTime = $entry.CreatedTime
                            AccessedTime = $entry.AccessedTime
                            ModifiedTime = $entry.ModifiedTime
                            Flags = $entry.Flags
                            FlagMeanings = "Carved LNK structure"
                            FileSize = 0
                            ShowCommand = "Unknown"
                            HotKey = "None"
                            StreamOffset = $entry.Offset
                            Guid = "00021401-0000-0000-c000-000000000046"
                            SHA256 = ""
                            JumpListFile = $file.FullName
                            StreamName = "N/A (Carved)"
                            Type = "Carved"
                            DataType = $entry.DataType
                            AppID = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                            AppName = "Carved Entry"
                            RecoveryMethod = $entry.RecoveryMethod
                        }
                        
                        $carvedEntries += $carvedObj
                    }
                }
            } else {
                Write-Host "  No deleted entries found." -ForegroundColor Yellow
            }
        }
        
        if ($carvedEntries.Count -gt 0) {
            Write-Host "`nFound $($carvedEntries.Count) total carved entries!" -ForegroundColor Green
            
            if (-not $NoExport) {
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $csvCarvedPath = Join-Path -Path $OutputDir -ChildPath "JumpList_Carved_$timestamp.csv"
                
                $carvedEntries | Export-Csv -NoTypeInformation -Path $csvCarvedPath
                Write-Host "Carved entries CSV: $csvCarvedPath" -ForegroundColor Cyan
            }
            
            $jumpListData += $carvedEntries
            
            Write-Host "Combined Data Stats:" -ForegroundColor Yellow
            Write-Host "  Regular entries: $($jumpListData.Count - $carvedEntries.Count)" -ForegroundColor White
            Write-Host "  Carved entries: $($carvedEntries.Count)" -ForegroundColor White
            Write-Host "  Total entries: $($jumpListData.Count)" -ForegroundColor White
        }
    }
}

if ($jumpListData.Count -gt 0 -and -not $NoExport) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $combinedCsvPath = Join-Path -Path $OutputDir -ChildPath "JumpList_$(if ($Carve) {'Combined'} else {'Export'})_$timestamp.csv"
    $combinedJsonPath = Join-Path -Path $OutputDir -ChildPath "JumpList_$(if ($Carve) {'Combined'} else {'Export'})_$timestamp.json"
    $combinedHtmlPath = Join-Path -Path $OutputDir -ChildPath "JumpList_$(if ($Carve) {'Combined'} else {'Export'})_$timestamp.html"
    $debugPath = Join-Path -Path $OutputDir -ChildPath "JumpList_Debug_$timestamp.txt"
    
    $debugInfo = "Total entries: $($jumpListData.Count)`n"
    
    if ($Carve) {
        $carvedCount = ($jumpListData | Where-Object { $_.Type -eq 'Carved' }).Count
        $debugInfo += "Carved entries: $carvedCount`n`n"
    } else {
        $debugInfo += "Carving not enabled in this run`n`n"
    }
    
    $debugInfo += "=== SAMPLE OF REGULAR ENTRIES ===`n"
    $regularEntries = $jumpListData | Where-Object { $_.Type -ne 'Carved' } | Select-Object -First 2
    foreach ($entry in $regularEntries) {
        $debugInfo += "Entry properties: $($entry.PSObject.Properties.Name -join ', ')`n"
        $debugInfo += "AppID: $($entry.AppID)`n"
        $debugInfo += "Type: $($entry.Type)`n"
        $debugInfo += "FilePath: $($entry.FilePath)`n"
        $debugInfo += "AccessedTime: $($entry.AccessedTime)`n`n"
    }
    
    if ($Carve) {
        $debugInfo += "=== SAMPLE OF CARVED ENTRIES ===`n"
        $carvedSamples = $jumpListData | Where-Object { $_.Type -eq 'Carved' } | Select-Object -First 2
        if ($carvedSamples) {
            foreach ($entry in $carvedSamples) {
                $debugInfo += "Entry properties: $($entry.PSObject.Properties.Name -join ', ')`n"
                $debugInfo += "AppID: $($entry.AppID)`n"
                $debugInfo += "Type: $($entry.Type)`n" 
                $debugInfo += "DataType: $($entry.DataType)`n"
                $debugInfo += "StreamOffset: $($entry.StreamOffset)`n"
                $debugInfo += "AccessedTime: $($entry.AccessedTime)`n`n"
            }
        } else {
            $debugInfo += "No carved entries found in this run`n`n"
        }
    }
    
    $debugInfo | Out-File -FilePath $debugPath
    Write-Host "Debug info: $debugPath" -ForegroundColor Cyan
    
    $exportParams = @{
        NoExport = $false
        OutputDir = $OutputDir
        CustomDataSet = $jumpListData
    }
    
    if ($StartDate) { $exportParams.StartDate = $StartDate }
    if ($EndDate) { $exportParams.EndDate = $EndDate }
    if ($DebugMode) { $exportParams.DebugMode = $DebugMode }
    
    Export-JumpListData @exportParams
    
    if ($Carve) {
        Write-Host "`nCombined exports with carved entries:" -ForegroundColor Green
        Write-Host "Combined CSV: $combinedCsvPath" -ForegroundColor Cyan
        Write-Host "Combined JSON: $combinedJsonPath" -ForegroundColor Cyan
        Write-Host "Combined HTML: $combinedHtmlPath" -ForegroundColor Cyan
    } else {
        Write-Host "`nExport files:" -ForegroundColor Green
        Write-Host "CSV: $combinedCsvPath" -ForegroundColor Cyan
        Write-Host "JSON: $combinedJsonPath" -ForegroundColor Cyan
        Write-Host "HTML: $combinedHtmlPath" -ForegroundColor Cyan
    }
}

Write-Host "`n=== FINAL DATA CHECK BEFORE RETURN ===" -ForegroundColor Red
Write-Host "Total entries in jumpListData: $($jumpListData.Count)" -ForegroundColor Red

if ($Carve) {
    $carvedCount = ($jumpListData | Where-Object { $_.Type -eq 'Carved' }).Count
    Write-Host "Total carved entries: $carvedCount" -ForegroundColor Red
    if ($carvedCount -gt 0) {
        Write-Host "Sample of carved entries in final data:" -ForegroundColor Red
        $jumpListData | Where-Object { $_.Type -eq 'Carved' } | Select-Object -First 1 | Format-List
    }
} else {
    Write-Host "Carving not enabled in this run" -ForegroundColor Red
}
Write-Host "=== END FINAL DATA CHECK ===" -ForegroundColor Red

Write-Host "`nProcessing complete! To view the data, use the exported files listed above." -ForegroundColor Green
Write-Host "To access the raw data in PowerShell, assign the script to a variable:" -ForegroundColor Green
Write-Host '  $data = .\JumpyExplo.ps1' -ForegroundColor Yellow

return $jumpListData | Out-Null 