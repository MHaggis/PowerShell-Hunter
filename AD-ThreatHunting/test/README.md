# AD Threat Hunting Test Scripts

This folder contains scripts to simulate various suspicious activities for testing the AD Threat Hunting tool.

## Prerequisites

### Required Audit Policies

Before running the simulation scripts, ensure these audit policies are enabled on your Domain Controller:

```powershell
# Enable required audit policies
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Verify settings
auditpol /get /category:"Logon/Logoff"
```

You should see "Success and Failure" for:
- Logon/Logoff
- Account Lockout
- Logon Events

If you see "No Auditing", the simulation events won't be captured in the Security Event Log.

## Usage

Run these commands on your Domain Controller to simulate different attack scenarios:

### Simulate Password Spray Attack
```powershell
.\Invoke-ADThreatSimulation.ps1 -PasswordSpray
```

### Simulate Brute Force Attack
```powershell
.\Invoke-ADThreatSimulation.ps1 -BruteForce -TargetUser "administrator" -EventCount 15
```

### Simulate Account Lockout
```powershell
.\Invoke-ADThreatSimulation.ps1 -AccountLockout -TargetUser "testuser"
```

### Simulate Multiple Scenarios
```powershell
.\Invoke-ADThreatSimulation.ps1 -PasswordSpray -BruteForce -AccountLockout
```

## Important Notes

1. These scripts must be run on a Domain Controller
2. Administrative privileges are required
3. The simulated events will appear in the Security Event Log
4. Use only in test environments
5. Events are marked with source "ADThreatSimulation" for easy identification
6. Proper audit policies must be enabled (see Prerequisites section)

## Testing Workflow

1. Verify audit policies are enabled (see Prerequisites)
2. Run the simulation script with desired parameters
3. Wait a few seconds for events to be written
4. Run the threat hunting script:
   ```powershell
   ..\Start-ADThreatHunt.ps1 -Hours 1 -UseWinRM
   ```
5. Verify that the simulated threats are detected

## Cleanup

To remove the test events, clear the Security Event Log (requires admin privileges):
```powershell
Clear-EventLog -LogName Security
```

## Example Commands

```powershell
# Test against specific user
.\Invoke-ADThreatSimulation.ps1 -AccountLockout -TargetUser "testuser"

# Test against specific user with brute force
.\Invoke-ADThreatSimulation.ps1 -BruteForce -TargetUser "testuser"

# Use test accounts but don't clean them up
.\Invoke-ADThreatSimulation.ps1 -AccountLockout -NoCleanup

# 15 brute force attempts
.\Invoke-ADThreatSimulation.ps1 -BruteForce -TargetUser "administrator" -EventCount 15

# 20 rapid attempts for lockout
.\Invoke-ADThreatSimulation.ps1 -AccountLockout -TargetUser "testuser" -EventCount 20

# Default 10 attempts if not specified
.\Invoke-ADThreatSimulation.ps1 -BruteForce -TargetUser "administrator"

# Just random chaos
.\Invoke-ADThreatSimulation.ps1 -Random -Verbose

# Random with no cleanup
.\Invoke-ADThreatSimulation.ps1 -Random -NoCleanup

# Combine with other patterns
.\Invoke-ADThreatSimulation.ps1 -Random -PasswordSpray
```

## Troubleshooting

If you're not seeing events in the Security Log:

1. Verify audit policies are enabled:
```powershell
auditpol /get /category:"Logon/Logoff"
```

2. Check Event Log service is running:
```powershell
Get-Service EventLog | Select-Object Name, Status, StartType
```

3. Verify Security Log configuration:
```powershell
Get-WinEvent -ListLog Security | Select-Object LogName, IsEnabled, LogMode
```

**Warning**: Only clear the event log in test environments! 

---

<p align="center">
Made with ❤️ by defenders for defenders
</p>
