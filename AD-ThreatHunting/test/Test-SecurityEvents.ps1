[CmdletBinding()]
param()

Write-Host "`nChecking Security Event Log Access..." -ForegroundColor Cyan

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Running as Administrator: $isAdmin"

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = @(4625, 4740)
        StartTime = (Get-Date).AddHours(-1)
    } -MaxEvents 1 -ErrorAction Stop
    Write-Host "Can read Security log: Yes"
}
catch {
    Write-Host "Can read Security log: No - $_" -ForegroundColor Red
}

$secLog = Get-WinEvent -ListLog Security
Write-Host "`nSecurity Log Details:"
Write-Host "Log Size: $([math]::Round($secLog.FileSize / 1MB, 2)) MB"
Write-Host "Maximum Size: $([math]::Round($secLog.MaximumSizeInBytes / 1MB, 2)) MB"
Write-Host "Is Enabled: $($secLog.IsEnabled)"
Write-Host "Log Mode: $($secLog.LogMode)"
Write-Host "Records Count: $($secLog.RecordCount)"

Write-Host "`nMost Recent Security Events (Last Hour):"
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    StartTime = (Get-Date).AddHours(-1)
} -MaxEvents 5 | Format-Table TimeCreated, Id, LevelDisplayName, Message -Wrap

Write-Host "`nCurrent Audit Policy:"
auditpol /get /category:"Account Logon","Account Management","Logon/Logoff" /r | ConvertFrom-Csv | 
    Format-Table "Subcategory", "Inclusion Setting" -AutoSize 