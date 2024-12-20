[CmdletBinding()]
param()

Write-Host "`nTesting Event Collection..." -ForegroundColor Cyan

Write-Host "`nChecking WinRM Configuration:"
Test-WSMan -ErrorAction SilentlyContinue
Get-Service WinRM | Select-Object Name, Status, StartType

Write-Host "`nChecking Event Log Service:"
Get-Service EventLog | Select-Object Name, Status, StartType

Write-Host "`nChecking Security Log Configuration:"
$secLog = Get-WinEvent -ListLog Security
$secLog | Select-Object LogName, IsEnabled, IsClassicLog, LogFilePath, 
    @{N='MaxSizeMB';E={$_.MaximumSizeInBytes/1MB}},
    @{N='CurrentSizeMB';E={$_.FileSize/1MB}},
    RecordCount

Write-Host "`nChecking Detailed Audit Policy:"
$auditPolicy = auditpol /get /category:* /r | ConvertFrom-Csv
$auditPolicy | Where-Object {
    $_.Subcategory -match 'Logon|Logoff|Account Lockout|Credential Validation'
} | Format-Table Subcategory, "Inclusion Setting" -AutoSize

Write-Host "`nTesting Event Generation:"
$testUser = "EventTest"
$testPass = ConvertTo-SecureString "TestPass123!" -AsPlainText -Force

try {
    New-ADUser -Name $testUser `
        -SamAccountName $testUser `
        -UserPrincipalName "$testUser@$env:USERDNSDOMAIN" `
        -AccountPassword $testPass `
        -Enabled $true `
        -Path "CN=Users,$((Get-ADDomain).DistinguishedName)" `
        -Server $env:LOGONSERVER.TrimStart("\\")

    Start-Sleep -Seconds 5

    $wrongPass = "WrongPass123!"

    # 1. Network logon
    Write-Host "`nTesting network logon..."
    net use \\$env:COMPUTERNAME\IPC$ /user:$env:USERDOMAIN\$testUser $wrongPass 2>&1
    net use \\$env:COMPUTERNAME\IPC$ /delete /y 2>&1 | Out-Null

    # 2. Interactive logon
    Write-Host "`nTesting interactive logon..."
    $command = "echo $wrongPass | runas /user:$env:USERDOMAIN\$testUser cmd.exe /c whoami"
    cmd /c $command 2>&1

    # 3. PowerShell remoting
    Write-Host "`nTesting PowerShell remoting..."
    $cred = New-Object System.Management.Automation.PSCredential("$env:USERDOMAIN\$testUser", 
        (ConvertTo-SecureString $wrongPass -AsPlainText -Force))
    Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $cred -ScriptBlock { whoami } -ErrorAction SilentlyContinue

    Start-Sleep -Seconds 5

    Write-Host "`nChecking for generated events..."
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = @(4625, 4740)
        StartTime = (Get-Date).AddMinutes(-5)
    } -ErrorAction SilentlyContinue

    if ($events) {
        Write-Host "Found $($events.Count) events:" -ForegroundColor Green
        $events | Format-Table TimeCreated, Id, 
            @{N='EventType';E={if($_.Id -eq 4625){'Failed Login'}else{'Account Lockout'}}},
            @{N='Username';E={$_.Properties[5].Value}},
            @{N='LogonType';E={$_.Properties[10].Value}} -AutoSize
    }
    else {
        Write-Host "No events found!" -ForegroundColor Red
        Write-Host "`nChecking audit policy..."
        auditpol /get /category:"Logon/Logoff","Account Logon" /r | ConvertFrom-Csv | 
            Format-Table Subcategory,"Inclusion Setting" -AutoSize
    }
}
finally {
    Remove-ADUser -Identity $testUser -Confirm:$false -ErrorAction SilentlyContinue
}

Write-Host "`nChecking Recent Security Events (Last 5 minutes):"
$events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    StartTime = (Get-Date).AddMinutes(-5)
} -MaxEvents 5 -ErrorAction SilentlyContinue

if ($events) {
    $events | Format-Table TimeCreated, Id, LevelDisplayName, Message -Wrap
}
else {
    Write-Host "No recent security events found" -ForegroundColor Yellow
}

Write-Host "`nChecking Event Channel Access:"
$channels = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | 
    Where-Object { $_.LogName -like "*Security*" -or $_.LogName -like "*Auth*" }
$channels | Format-Table LogName, IsEnabled, RecordCount

Write-Host "`nSystem Information:"
$os = Get-WmiObject Win32_OperatingSystem
Write-Host "OS: $($os.Caption)"
Write-Host "Version: $($os.Version)"
Write-Host "Architecture: $($os.OSArchitecture)"
Write-Host "Domain Role: $((Get-WmiObject Win32_ComputerSystem).DomainRole)" 