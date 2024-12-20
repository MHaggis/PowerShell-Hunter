[CmdletBinding()]
param()

Write-Host "`nTesting AD Event Logging..." -ForegroundColor Cyan

$testUser = "ADEventTest"
$testPass = ConvertTo-SecureString "TestPass123!" -AsPlainText -Force

Write-Host "`nCreating test user..."
New-ADUser -Name $testUser `
    -SamAccountName $testUser `
    -UserPrincipalName "$testUser@$env:USERDNSDOMAIN" `
    -AccountPassword $testPass `
    -Enabled $true `
    -PasswordNeverExpires $true

Start-Sleep -Seconds 5

Write-Host "`nAttempting failed login..."
$wrongPass = "WrongPass123!"

cmdkey /add:$env:COMPUTERNAME /user:$env:USERDOMAIN\$testUser /pass:$wrongPass
runas /user:$env:USERDOMAIN\$testUser "cmd.exe /c whoami"
cmdkey /delete:$env:COMPUTERNAME

net use \\$env:COMPUTERNAME\admin$ /user:$env:USERDOMAIN\$testUser $wrongPass 2>&1
net use \\$env:COMPUTERNAME\admin$ /delete /y 2>&1 | Out-Null

Start-Sleep -Seconds 5

Write-Host "`nChecking for events..."
$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = @(4625, 4740)
    StartTime = (Get-Date).AddMinutes(-5)
} -ErrorAction SilentlyContinue

if ($events) {
    Write-Host "Found $($events.Count) events:" -ForegroundColor Green
    $events | Format-Table TimeCreated, Id, 
        @{N='EventType';E={if($_.Id -eq 4625){'Failed Login'}else{'Account Lockout'}}},
        @{N='Username';E={
            if($_.Id -eq 4625) {
                $_.Properties[5].Value
            } else {
                $_.Properties[0].Value
            }
        }} -AutoSize
} else {
    Write-Host "No events found!" -ForegroundColor Red
    
    Write-Host "`nChecking Security Log settings..."
    $log = Get-WinEvent -ListLog Security
    $log | Select-Object LogName, IsEnabled, LogMode, MaximumSizeInBytes
    
    Write-Host "`nChecking recent Security events..."
    Get-WinEvent -LogName Security -MaxEvents 5 | 
        Format-Table TimeCreated, Id, LevelDisplayName, Message -Wrap
}

Write-Host "`nCleaning up..."
Remove-ADUser -Identity $testUser -Confirm:$false 