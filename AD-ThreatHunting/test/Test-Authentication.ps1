[CmdletBinding()]
param()

Write-Host "`nTesting Authentication Methods..." -ForegroundColor Cyan

$testUser = "AuthTest"
$correctPass = "TestPass123!"
$wrongPass = "WrongPass123!"

try {
    Write-Host "`nCreating test user..."
    New-ADUser -Name $testUser `
        -SamAccountName $testUser `
        -UserPrincipalName "$testUser@$env:USERDNSDOMAIN" `
        -AccountPassword (ConvertTo-SecureString $correctPass -AsPlainText -Force) `
        -Enabled $true `
        -Path "CN=Users,$((Get-ADDomain).DistinguishedName)" `
        -Server $env:LOGONSERVER.TrimStart("\\")

    Start-Sleep -Seconds 5

    Write-Host "`nTesting successful authentication..."
    net use \\$env:COMPUTERNAME\IPC$ /user:$env:USERDOMAIN\$testUser $correctPass
    net use \\$env:COMPUTERNAME\IPC$ /delete /y

    Start-Sleep -Seconds 2

    Write-Host "`nTesting failed authentication..."
    net use \\$env:COMPUTERNAME\IPC$ /user:$env:USERDOMAIN\$testUser $wrongPass
    net use \\$env:COMPUTERNAME\IPC$ /delete /y

    Start-Sleep -Seconds 5

    Write-Host "`nChecking events..."
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = @(4624, 4625)
        StartTime = (Get-Date).AddMinutes(-5)
    } -ErrorAction SilentlyContinue

    if ($events) {
        Write-Host "Found $($events.Count) events:" -ForegroundColor Green
        $events | Format-Table TimeCreated, Id,
            @{N='Type';E={if($_.Id -eq 4624){'Success'}else{'Failure'}}},
            @{N='Username';E={$_.Properties[5].Value}},
            @{N='LogonType';E={$_.Properties[8].Value}} -AutoSize
    }
    else {
        Write-Host "No events found!" -ForegroundColor Red
    }
}
finally {
    Remove-ADUser -Identity $testUser -Confirm:$false -ErrorAction SilentlyContinue
} 