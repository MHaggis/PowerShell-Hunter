Add-Type @'
using System;
using System.Runtime.InteropServices;

public class LogonAPI {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LogonUser(
        string lpszUsername,
        string lpszDomain,
        string lpszPassword,
        int dwLogonType,
        int dwLogonProvider,
        out IntPtr phToken
    );
}
'@

function Get-NextAvailableUsername {
    param(
        [string]$BaseUsername
    )
    
    $counter = 1
    $username = $BaseUsername
    
    while ($true) {
        try {
            Get-ADUser -Identity $username -ErrorAction Stop
            $username = "${BaseUsername}${counter}"
            $counter++
        }
        catch {
            return $username
        }
    }
}

$namingPatterns = @{
    Prefixes = @(
        'admin', 'dev', 'svc', 'test', 'temp', 'usr',
        'app', 'sys', 'svc', 'srv', 'support',
        'helpdesk', 'service', 'backup', 'monitor', 'scan'
    )
    Suffixes = @(
        'user', 'admin', 'dev', 'test', 'temp', 'app',
        'sys', 'svc', 'srv', 'support', 'acct',
        'prod', 'qa', 'uat', 'dev', 'test', 'stage'
    )
    Separators = @('-', '_', '.', '')
    Numbers = @('', '1', '01', '001', (Get-Date).ToString('yy'))
}

function New-RandomUsername {
    $prefix = $namingPatterns.Prefixes | Get-Random
    $suffix = $namingPatterns.Suffixes | Get-Random 
    $separator = $namingPatterns.Separators | Get-Random
    $number = $namingPatterns.Numbers | Get-Random
    return "$prefix$separator$suffix$number"
}

function Invoke-ADThreatSimulation {
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$PasswordSpray,

        [Parameter()]
        [switch]$BruteForce,

        [Parameter()]
        [switch]$AccountLockout,

        [Parameter()]
        [int]$EventCount = 10,

        [Parameter()]
        [string]$TestUserPrefix = "THTest",

        [Parameter()]
        [string]$TargetUser,

        [Parameter()]
        [switch]$NoCleanup,

        [Parameter()]
        [switch]$Random,
        
        [Parameter()]
        [switch]$IncludeAdvancedThreats
    )

    Import-Module ActiveDirectory

    function Attempt-FailedLogin {
        param(
            [string]$Username,
            [string]$WrongPassword,
            [int]$LogonType = 2  # Default to interactive logon
        )
        
        Write-Verbose "Attempting failed login for: $Username (LogonType: $LogonType)"
        
        $tokenHandle = [IntPtr]::Zero
        $result = [LogonAPI]::LogonUser(
            $Username,
            $env:USERDOMAIN,
            $WrongPassword,
            $LogonType,  # Use the specified logon type
            0,  # LOGON32_PROVIDER_DEFAULT
            [ref]$tokenHandle
        )
        Write-Verbose "Logon attempt result: $result"
        Start-Sleep -Seconds 1
    }

    function Get-RandomUsername {
        param(
            [int]$Length = 2
        )
        
        do {
            $prefix = $namingPatterns.Prefixes | Get-Random
            $suffix = $namingPatterns.Suffixes | Get-Random
            $separator = '-'
            $number = Get-Random -Minimum 1 -Maximum 999
            $username = "${prefix}${separator}${suffix}${number}"
            $exists = $false
            try {
                Get-ADUser -Identity $username -ErrorAction Stop | Out-Null
                $exists = $true
            } catch {
                $exists = $false
            }
        } while ($exists)
        return $username
    }

    function Start-RandomSimulation {
        $script:usedNames = @{}
        $userCount = Get-Random -Minimum 3 -Maximum 10
        Write-Verbose "Creating $userCount random users"
        $users = @()
        1..$userCount | ForEach-Object {
            $username = Get-RandomUsername
            Write-Verbose "Creating user: $username"
            
            try {
                New-ADUser -Name $username `
                    -SamAccountName $username `
                    -UserPrincipalName "$username@$env:USERDNSDOMAIN" `
                    -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
                    -Enabled $true `
                    -Path "CN=Users,$((Get-ADDomain).DistinguishedName)" `
                    -ErrorAction Stop
                
                $users += $username
            }
            catch {
                Write-Warning "Failed to create user $username : $($_.Exception.Message)"
            }
        }
        if ($users.Count -eq 0) {
            throw "No users were created successfully"
        }

        Start-Sleep -Seconds 5

        $patterns = @(
            # Password spray
            {
                param($users)
                Write-Host "Random Pattern: Password Spray" -ForegroundColor Yellow
                foreach ($user in $users) {
                    Attempt-FailedLogin -Username $user -WrongPassword "Spring2024!"
                    Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 1000)
                }
            },
            # Brute force
            {
                param($users)
                Write-Host "Random Pattern: Brute Force" -ForegroundColor Yellow
                $target = $users | Get-Random
                1..(Get-Random -Minimum 5 -Maximum 15) | ForEach-Object {
                    Attempt-FailedLogin -Username $target -WrongPassword "BadPass$_"
                    Start-Sleep -Milliseconds (Get-Random -Minimum 50 -Maximum 500)
                }
            },
            # Mixed pattern
            {
                param($users)
                Write-Host "Random Pattern: Mixed Attack" -ForegroundColor Yellow
                $attempts = Get-Random -Minimum 10 -Maximum 20
                1..$attempts | ForEach-Object {
                    $target = $users | Get-Random
                    Attempt-FailedLogin -Username $target -WrongPassword "Random$_!"
                    Start-Sleep -Milliseconds (Get-Random -Minimum 200 -Maximum 800)
                }
            }
        )

        # Execute 2-4 random patterns
        $numPatterns = Get-Random -Minimum 2 -Maximum 4
        1..$numPatterns | ForEach-Object {
            $pattern = $patterns | Get-Random
            & $pattern $users
            Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 5)
        }

        return $users
    }

    Write-Host "`nStarting AD Threat Simulation..." -ForegroundColor Cyan

    try {
        Write-Verbose "Domain Configuration:"
        Write-Verbose "Domain: $env:USERDOMAIN"
        Write-Verbose "Domain DNS: $env:USERDNSDOMAIN"
        Write-Verbose "Logon Server: $env:LOGONSERVER"
        Write-Verbose "Computer Name: $env:COMPUTERNAME"

        $dc = Get-ADDomainController -Discover -Service PrimaryDC
        Write-Verbose "Primary DC: $($dc.HostName)"

        Write-Verbose "Verifying audit policy..."
        $auditPolicy = auditpol /get /category:"Logon/Logoff" /r | ConvertFrom-Csv
        $auditPolicy | ForEach-Object {
            Write-Verbose "  $($_.Subcategory): $($_.'Inclusion Setting')"
        }

        if ($PasswordSpray) {
            Write-Host "Simulating Password Spray Attack..." -ForegroundColor Yellow

            $users = @()
            1..5 | ForEach-Object {
                $baseUsername = "$TestUserPrefix$_"
                $username = Get-NextAvailableUsername -BaseUsername $baseUsername
                Write-Verbose "Creating domain user: $username"
                
                try {
                    New-ADUser -Name $username `
                        -SamAccountName $username `
                        -UserPrincipalName "$username@$env:USERDNSDOMAIN" `
                        -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
                        -Enabled $true `
                        -Path "CN=Users,$((Get-ADDomain).DistinguishedName)" `
                        -Server $env:LOGONSERVER.TrimStart("\\") `
                        -ErrorAction Stop
                    
                    $users += $username
                }
                catch {
                    Write-Warning "Failed to create user $username : $($_.Exception.Message)"
                    continue
                }
            }

            Write-Verbose "Waiting for AD replication..."
            Start-Sleep -Seconds 5

            # Verify users were created
            foreach ($user in $users) {
                $adUser = Get-ADUser -Identity $user -ErrorAction SilentlyContinue
                if ($adUser) {
                    Write-Verbose "Verified user $user exists in AD"
                } else {
                    Write-Warning "User $user was not found in AD!"
                }
            }

            # Attempt failed logins
            foreach ($user in $users) {
                Attempt-FailedLogin -Username $user -WrongPassword "WrongPassword123!"
            }
        }

        if ($BruteForce) {
            Write-Host "Simulating Brute Force Attack..." -ForegroundColor Yellow
            
            if ($TargetUser) {
                $username = $TargetUser
                Write-Verbose "Using existing user: $username"
            }
            else {
                # Create single test user for brute force
                $baseUsername = "$TestUserPrefix"
                $username = Get-NextAvailableUsername -BaseUsername $baseUsername
                Write-Verbose "Creating domain user: $username"
                
                try {
                    New-ADUser -Name $username `
                        -SamAccountName $username `
                        -UserPrincipalName "$username@$env:USERDNSDOMAIN" `
                        -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
                        -Enabled $true `
                        -Path "CN=Users,$((Get-ADDomain).DistinguishedName)" `
                        -ErrorAction Stop
                    
                    Start-Sleep -Seconds 5
                }
                catch {
                    Write-Warning "Failed to create user $username : $($_.Exception.Message)"
                    return
                }
            }
            
            Write-Verbose "Making $EventCount attempts against $username"
            1..$EventCount | ForEach-Object {
                Write-Verbose "Brute force attempt $_ for $username"
                Attempt-FailedLogin -Username $username -WrongPassword "WrongPass$_"
                Start-Sleep -Milliseconds 500
            }
        }

        if ($AccountLockout) {
            Write-Host "Simulating Account Lockout..." -ForegroundColor Yellow
            
            if ($TargetUser) {
                $username = $TargetUser
                Write-Verbose "Using existing user: $username"
            }
            else {
                $baseUsername = "$TestUserPrefix"
                $username = Get-NextAvailableUsername -BaseUsername $baseUsername
                Write-Verbose "Creating domain user: $username"
                
                try {
                    New-ADUser -Name $username `
                        -SamAccountName $username `
                        -UserPrincipalName "$username@$env:USERDNSDOMAIN" `
                        -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
                        -Enabled $true `
                        -Path "CN=Users,$((Get-ADDomain).DistinguishedName)" `
                        -ErrorAction Stop
                    
                    Start-Sleep -Seconds 5
                }
                catch {
                    Write-Warning "Failed to create user $username : $($_.Exception.Message)"
                    return
                }
            }
            
            # Many rapid attempts using EventCount
            Write-Verbose "Making $EventCount rapid attempts against $username"
            1..$EventCount | ForEach-Object {
                Write-Verbose "Lockout attempt $_ for $username"
                Attempt-FailedLogin -Username $username -WrongPassword "WrongPass123!"
                Start-Sleep -Milliseconds 100
            }
        }

        if ($Random) {
            Write-Host "Starting Random Attack Simulation..." -ForegroundColor Cyan
            
            Write-Host "Verifying audit policy..." -ForegroundColor Yellow
            $requiredPolicies = @(
                'Logon', 'Logoff', 'Account Lockout',
                'Credential Validation', 'Other Logon/Logoff Events'
            )
            
            $auditPol = auditpol /get /category:* /r | ConvertFrom-Csv
            $missingPolicies = @()
            
            foreach ($policy in $requiredPolicies) {
                $setting = $auditPol | Where-Object { $_.Subcategory -like "*$policy*" }
                if (-not $setting -or $setting.'Inclusion Setting' -notlike "*Success and Failure*") {
                    $missingPolicies += $policy
                }
            }
            
            if ($missingPolicies) {
                Write-Warning "Missing required audit policies: $($missingPolicies -join ', ')"
                Write-Host "Enabling required audit policies..." -ForegroundColor Yellow
                foreach ($policy in $missingPolicies) {
                    auditpol /set /subcategory:"$policy" /success:enable /failure:enable
                }

                Start-Sleep -Seconds 5
            }
            
            $userCount = Get-Random -Minimum 3 -Maximum 7
            Write-Verbose "Creating $userCount random users"
            
            $randomUsers = @()
            1..$userCount | ForEach-Object {
                $username = Get-RandomUsername
                Write-Verbose "Creating user: $username"
                
                try {
                    New-ADUser -Name $username `
                              -SamAccountName $username `
                              -UserPrincipalName "$username@$env:USERDNSDOMAIN" `
                              -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
                              -Enabled $true `
                              -Path "CN=Users,$((Get-ADDomain).DistinguishedName)" `
                              -ErrorAction Stop
                    $randomUsers += $username
                    Write-Verbose "Successfully created user: $username"
                } catch {
                    Write-Warning "Failed to create user $username : $($_.Exception.Message)"
                    continue
                }
            }

            if ($randomUsers.Count -eq 0) {
                throw "No users were created successfully"
            }

            $configPath = "$PSScriptRoot\..\config\config.psd1"
            $config = Import-PowerShellDataFile -Path $configPath
            $logonTypes = $config.LogonTypes

            Write-Host "Simulating random attack patterns..." -ForegroundColor Cyan
            
            foreach ($user in $randomUsers) {
                $attempts = Get-Random -Minimum 3 -Maximum 8
                Write-Verbose "Making $attempts failed login attempts for $user"
                
                1..$attempts | ForEach-Object {
                    $wrongPass = "WrongPass$_!"
                    Write-Verbose "Attempt $_ for $user"
                    
                    $numTypes = Get-Random -Minimum 1 -Maximum 4
                    $selectedTypes = $logonTypes.Keys | Get-Random -Count $numTypes
                    
                    foreach ($logonType in $selectedTypes) {
                        Write-Verbose "Attempting logon type: $($logonTypes[$logonType])"
                        Attempt-FailedLogin -Username $user `
                            -WrongPassword $wrongPass `
                            -LogonType ([int]$logonType)
                        Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 1000)
                    }
                    
                    Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 3)
                }
                
                Start-Sleep -Seconds (Get-Random -Minimum 3 -Maximum 7)
            }
            
            Write-Host "`nVerifying event generation..." -ForegroundColor Cyan
            $events = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = @(4625, 4740)
                StartTime = (Get-Date).AddMinutes(-15)
            } -ErrorAction SilentlyContinue
            
            if (-not $events) {
                Write-Warning "No events were found. Checking event log settings..."
                Get-WinEvent -ListLog Security | 
                    Select-Object LogName, IsEnabled, LogMode, MaximumSizeInBytes
            }

            Write-Host "Simulating advanced threats..." -ForegroundColor Cyan
            
            # 1. Off-Hours Login Simulation
            Write-Verbose "Simulating off-hours logins..."
            $offHoursUser = Get-RandomUsername
            New-ADUser -Name $offHoursUser `
                      -SamAccountName $offHoursUser `
                      -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
                      -Enabled $true
            $randomUsers += $offHoursUser
            
            # Set system time temporarily to 3 AM for off-hours simulation
            $currentTime = Get-Date
            Write-Host $currentTime
            try {
                Set-Date -Date (Get-Date).Date.AddHours(3)  # 3 AM
                Attempt-FailedLogin -Username $offHoursUser -WrongPassword "WrongPass!" -LogonType 2
                Start-Sleep -Seconds 1
                
                # Also try a late evening login
                Set-Date -Date (Get-Date).Date.AddHours(22)  # 10 PM
                Attempt-FailedLogin -Username $offHoursUser -WrongPassword "WrongPass!" -LogonType 2
            }
            finally {
                Set-Date -Date $currentTime
            }
            Write-Host $currentTime

            # 2. Service Account Misuse
            Write-Verbose "Simulating service account misuse..."
            $servicePattern = $config.Patterns.ServiceAccounts | Get-Random
            $serviceAccount = $servicePattern.Replace('*', "test$(Get-Random -Minimum 100 -Maximum 999)")
            New-ADUser -Name $serviceAccount `
                      -SamAccountName $serviceAccount `
                      -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
                      -Enabled $true
            $randomUsers += $serviceAccount
            
            # Try interactive logon with service account
            Attempt-FailedLogin -Username $serviceAccount -WrongPassword "WrongPass!" -LogonType 2
            Attempt-FailedLogin -Username $serviceAccount -WrongPassword "WrongPass!" -LogonType 10  # RemoteInteractive

            # 3. Admin Account Misuse
            Write-Verbose "Simulating admin account misuse..."
            $adminPattern = $config.Patterns.AdminAccounts | Get-Random
            $adminAccount = $adminPattern.Replace('*', "test$(Get-Random -Minimum 100 -Maximum 999)")
            New-ADUser -Name $adminAccount `
                      -SamAccountName $adminAccount `
                      -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
                      -Enabled $true
            Add-ADGroupMember -Identity "Domain Admins" -Members $adminAccount
            $randomUsers += $adminAccount
            
            # Try network logon with admin account from unusual source
            Attempt-FailedLogin -Username $adminAccount -WrongPassword "WrongPass!" -LogonType 3
            
            # 4. Geographically Impossible Logins
            Write-Verbose "Simulating geographically impossible logins..."
            $geoUser = Get-RandomUsername
            New-ADUser -Name $geoUser `
                      -SamAccountName $geoUser `
                      -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
                      -Enabled $true
            $randomUsers += $geoUser
            
            # Simulate logins from different locations in short time
            Attempt-FailedLogin -Username $geoUser -WrongPassword "WrongPass!" -LogonType 2
            Start-Sleep -Seconds 2
            Attempt-FailedLogin -Username $geoUser -WrongPassword "WrongPass!" -LogonType 3

            Write-Host "Advanced threat simulation complete!" -ForegroundColor Green
        }

        Write-Host "`nSimulation Complete!" -ForegroundColor Green
        Write-Host "Run the threat hunting script to detect the simulated activities:" -ForegroundColor Yellow
        Write-Host ".\Start-ADThreatHunt.ps1 -Hours 1 -UseWinRM" -ForegroundColor Yellow

        Write-Host "`nChecking for generated events..." -ForegroundColor Cyan
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = @(4625, 4740)
            StartTime = (Get-Date).AddMinutes(-5)
        } -ErrorAction SilentlyContinue 

        if ($events) {
            Write-Host "Found $($events.Count) events:" -ForegroundColor Green
            
            $logonTypes = $events | Where-Object {$_.Id -eq 4625} | Group-Object {
                $_.Properties[10].Value # This is the logon type
            }
            
            Write-Host "`nFailed Login Summary:"
            Write-Host "LogonType Count"
            Write-Host "--------- -----"
            $logonTypes | ForEach-Object {
                $type = switch ($_.Name) {
                    2 {"Interactive"}
                    3 {"Network"}
                    4 {"Batch"}
                    5 {"Service"}
                    7 {"Unlock"}
                    8 {"NetworkCleartext"}
                    9 {"NewCredentials"}
                    10 {"RemoteInteractive"}
                    11 {"CachedInteractive"}
                    default {$_}
                }
                "{0,-10} {1,5}" -f $type,$_.Count
            }

            Write-Host "`nDetailed Events:"
            $events | Format-Table TimeCreated, 
                @{N='EventType';E={if($_.Id -eq 4625){'Failed Login'}else{'Account Lockout'}}},
                @{N='Username';E={$_.Properties[5].Value}},
                @{N='LogonType';E={$_.Properties[10].Value}},
                @{N='Status';E={$_.Properties[8].Value}} -AutoSize
        }
        else {
            Write-Host "No events found!" -ForegroundColor Red
            Write-Host "`nChecking Security Log directly..."
            Get-WinEvent -LogName Security -MaxEvents 5 | Format-Table TimeCreated, Id, 
                @{N='Username';E={$_.Properties[5].Value}},
                @{N='Message';E={$_.Message.Split("`n")[0]}} -Wrap
        }
    }
    catch {
        Write-Error "Simulation failed: $_"
    }
    finally {
        if (-not $TargetUser -and -not $NoCleanup) {
            Write-Host "`nCleaning up test users..." -ForegroundColor Yellow
            Get-ADUser -Filter "Name -like '$TestUserPrefix*'" | Remove-ADUser -Confirm:$false
        }
    }
}

Invoke-ADThreatSimulation @args