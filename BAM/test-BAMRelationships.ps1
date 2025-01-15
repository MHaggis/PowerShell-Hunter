<#
.SYNOPSIS
    Test script to generate and analyze BAM parent-child process relationships.

.DESCRIPTION
    This script creates test scenarios to generate BAM (Background Activity Moderator) data
    by spawning various processes in parent-child relationships. It then collects and analyzes
    the BAM data to verify relationship tracking.

.NOTES
    Author: PowerShell-Hunter Team
    Version: 1.0
    Requires: PowerShell 5.1+, Administrator privileges
#>
$bamService = Get-Service "bam"
if ($bamService.Status -ne "Running") {
    Write-Host "BAM service is not running. Starting it..." -ForegroundColor Yellow
    Start-Service "bam"
    Start-Sleep -Seconds 5
}

$testScript = @'
# First sequence
Write-Host "Running first sequence..."
Start-Process cmd.exe -ArgumentList "/c ping localhost && rundll32.exe user32.dll,LockWorkStation" -Wait
Start-Sleep -Seconds 2

# Second sequence
Write-Host "Running second sequence..."
Start-Process powershell.exe -ArgumentList "-Command Get-Process" -PassThru -Wait
Start-Sleep -Seconds 2

# Third sequence
Write-Host "Running third sequence..."
wmic.exe process get name
Start-Sleep -Seconds 2

# Fourth sequence - fixed syntax
Write-Host "Running fourth sequence..."
Start-Process cmd.exe -ArgumentList '/c "powershell.exe -Command {Start-Process notepad.exe; Start-Sleep -Seconds 1; Stop-Process -Name notepad}"' -Wait
'@


$testScript | Out-File ".\test-bam.ps1"
Write-Host "Executing test commands to generate BAM data..." -ForegroundColor Yellow


powershell.exe -File ".\test-bam.ps1"


Write-Host "Waiting for BAM to register activities..." -ForegroundColor Yellow
Start-Sleep -Seconds 10


Write-Host "`nCollecting BAM data..." -ForegroundColor Yellow
.\get-BAM.ps1

Write-Host "`nAnalyzing BAM data..." -ForegroundColor Yellow
.\analyze-BAM.ps1 -BAMDirectory .\BAM_Collection


Remove-Item ".\test-bam.ps1" 