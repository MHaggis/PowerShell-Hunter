<#
.SYNOPSIS
    Collects Background Activity Moderator (BAM) data from Windows systems.

.DESCRIPTION
    This script extracts BAM data from the Windows registry, which contains information about
    application execution history and background activity. The data is exported to a registry
    file for further analysis.

.NOTES
    File Name      : get-BAM.ps1
    Prerequisite   : PowerShell 5.1 or later
    Copyright      : PowerShell-Hunter Project
    Author         : The Haag
    
.EXAMPLE
    .\get-BAM.ps1
    Exports BAM data to the BAM_Collection directory with timestamp.

.LINK
    https://github.com/MHaggis/PowerShell-Hunter
#>


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
Write-Host "`nBAM Data Collection Tool" -ForegroundColor Green
Write-Host "------------------------`n" -ForegroundColor DarkGray

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script requires Administrator privileges. Please run as Administrator." -ForegroundColor Red
    exit
}

$OutputPath = ".\BAM_Collection"

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath
}
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
Write-Host "Exporting BAM registry key..." -ForegroundColor Yellow

try {
    $RegFile = Join-Path $OutputPath "bam_$Timestamp.reg"
    $Result = reg export "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" $RegFile /y
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Successfully exported BAM data to $RegFile" -ForegroundColor Green
    } else {
        Write-Host "Failed to export BAM data. Error code: $LASTEXITCODE" -ForegroundColor Red
    }
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
}
