#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Hunt-HiddenScheduledTasks.ps1 - Detect Tarrask-style hidden scheduled task abuse
    
.DESCRIPTION
    Correlates multiple event sources to detect sophisticated scheduled task abuse:
    - Event 4698: Task creation
    - Sysmon Event 13: Registry TaskCache manipulation  
    - Event 4688: Suspicious process execution from hidden tasks
    - Missing Event 4699: Tasks that never get "properly" deleted
    
    This technique detects advanced persistence where attackers create tasks then
    manipulate the registry to hide them from standard tools.

.PARAMETER ComputerName
    Target computers to analyze (default: localhost)
    
.PARAMETER StartTime
    How far back to look for events (default: 24 hours)
    
.PARAMETER CorrelationWindowMinutes
    Time window for correlating related events (default: 5 minutes)
    
.PARAMETER OutputPath
    Directory to save results (default: .\HiddenTaskHunt_Results)

.EXAMPLE
    .\Hunt-HiddenScheduledTasks.ps1
    
.EXAMPLE
    .\Hunt-HiddenScheduledTasks.ps1 -ComputerName "SERVER01","SERVER02" -StartTime (Get-Date).AddDays(-7)

.NOTES
    Author: Michael Haag
    Requires: Administrative privileges, Sysmon for registry monitoring
    MITRE ATT&CK: T1053.005 (Scheduled Task/Job)
#>

[CmdletBinding()]
param(
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [datetime]$StartTime = (Get-Date).AddHours(-24),
    [int]$CorrelationWindowMinutes = 5,
    [string]$OutputPath = ".\HiddenTaskHunt_Results"
)

function Get-RegistryTaskCacheEvents {
    param([string]$Computer, [datetime]$Since)
    
    Write-HuntLog "Collecting TaskCache registry hiding events from $Computer..." "Info"
    
    try {
        $sysmonLogExists = Test-EventLogAvailability -Computer $Computer -LogName 'Microsoft-Windows-Sysmon/Operational'
        if (-not $sysmonLogExists) {
            Write-HuntLog "Sysmon log not available on $Computer - registry hiding detection limited" "Warning"
            return @()
        }
        
        $RegistryEvents = @()
        try {
            $events = Get-WinEvent -ComputerName $Computer -FilterHashTable @{
                LogName = 'Microsoft-Windows-Sysmon/Operational'
                Id = 13
                StartTime = $Since
            } -ErrorAction Stop
            
            $RegistryEvents = $events | Where-Object {
                $_.Message -match "TargetObject.*TaskCache" -and 
                ($_.Message -match "SD|SecurityDescriptor" -or 
                 $_.Message -match "Index" -or
                 $_.Message -match "DynamicInfo" -or
                 $_.Message -match "URI" -or
                 $_.Message -match "Source" -or
                 $_.Message -match "Author" -or
                 $_.Message -match "Date")
            } | ForEach-Object {
                $xml = [xml]$_.ToXml()
                $targetObject = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetObject"}).'#text'
                $valueName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "ValueName"}).'#text'
                $details = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "Details"}).'#text'
                $processName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "Image"}).'#text'
                
                $isSuspicious = $false
                $suspiciousReasons = @()
                
                if ($_.Message -match "SD.*DETAILS:\s*(EMPTY|\(Empty\))" -or 
                    $_.Message -match "SecurityDescriptor.*DETAILS:\s*(EMPTY|\(Empty\))") {
                    $isSuspicious = $true
                    $suspiciousReasons += "Security Descriptor removed/emptied"
                }
                
                if ($_.Message -match "Index.*DETAILS:\s*(EMPTY|\(Empty\))") {
                    $isSuspicious = $true
                    $suspiciousReasons += "Index value removed/emptied"
                }
                
                if ($valueName -eq "URI" -and ($details -eq "" -or $details -match "^\s*$")) {
                    $isSuspicious = $true
                    $suspiciousReasons += "URI reference removed"
                }
                
                if ($processName -and $processName -notmatch "svchost\.exe|taskhost\.exe|schtasks\.exe|mmc\.exe") {
                    if ($processName -match "powershell\.exe|cmd\.exe|python\.exe|rundll32\.exe|regsvr32\.exe") {
                        $isSuspicious = $true
                        $suspiciousReasons += "Non-system process manipulating TaskCache"
                    }
                }
                
                # Check for timestamp manipulation
                if ($valueName -eq "Date" -and $details) {
                    try {
                        $taskDate = [DateTime]::Parse($details)
                        $timeDiff = [Math]::Abs(($taskDate - $_.TimeCreated).TotalDays)
                        if ($timeDiff -gt 365) {  # More than a year difference
                            $isSuspicious = $true
                            $suspiciousReasons += "Suspicious timestamp manipulation"
                        }
                    } catch { }
                }
                $taskRelative = $null
                if ($targetObject) {
                    $taskRelative = ($targetObject -replace '^.*TaskCache\\Tree\\', '')
                    if ($taskRelative -match '\\') { $taskRelative = $taskRelative -replace '\\[^\\]+$', '' }
                }
                
                [PSCustomObject]@{
                    EventType = "RegistryModification"
                    Computer = $Computer
                    TimeCreated = $_.TimeCreated
                    EventId = $_.Id
                    TargetObject = $targetObject
                    ValueName = $valueName
                    Details = $details
                    ProcessName = $processName
                    ProcessId = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "ProcessId"}).'#text'
                    TaskPath = if ($taskRelative) { "\" + $taskRelative } else { "Unknown" }
                    IsSuspicious = $isSuspicious
                    SuspiciousReasons = $suspiciousReasons
                    RawEvent = $_
                }
            }
        } catch {
            if ($_.Exception.Message -match "No events were found") {
                Write-HuntLog "No Sysmon registry events found in specified time window" "Info"
            } else {
                Write-HuntLog "Error querying Sysmon events: $($_.Exception.Message)" "Warning"
            }
        }
        
        Write-HuntLog "Found $($RegistryEvents.Count) TaskCache registry hiding modifications" "Info"
        return $RegistryEvents
        
    } catch {
        Write-HuntLog "Failed to collect registry hiding events from $Computer`: $($_.Exception.Message)" "Error"
        return @()
    }
}

function Get-TaskCacheStateFromRegistry {
    param([string]$Computer)
    
    Write-HuntLog "Sysmon logs not found. Falling back to direct registry query for hidden tasks on $Computer..." "Warning"
    
    $hiddenTasks = @()
    $basePath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
    
    try {
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $Computer)
        $treeKey = $reg.OpenSubKey($basePath)
        
        $taskQueue = [System.Collections.Generic.Queue[object]]::new()
        $taskQueue.Enqueue($treeKey)
        
        while ($taskQueue.Count -gt 0) {
            $currentKey = $taskQueue.Dequeue()
            
            foreach ($subKeyName in $currentKey.GetSubKeyNames()) {
                try {
                    $subKey = $currentKey.OpenSubKey($subKeyName)
                    if ($subKey -eq $null) { continue }
                    
                    $taskQueue.Enqueue($subKey)
                    
    $sdValue = $subKey.GetValue("SD")
    $idValue = $subKey.GetValue("Id")
    $indexValue = $subKey.GetValue("Index")
    $authorValue = $subKey.GetValue("Author")
    $uriValue = $subKey.GetValue("URI")
    
    $hidingIndicators = @()
    $suspicionLevel = 0
    
    $fullPathForName = $subKey.Name -replace "HKEY_LOCAL_MACHINE\\", ""
    $taskName = $fullPathForName -replace [regex]::Escape("$basePath\"), ""
    
    if ($idValue -and $sdValue -eq $null) {
        $hidingIndicators += "Missing Security Descriptor (SD)"
        $suspicionLevel += 50
    }
    
    if ($sdValue -and ($sdValue.Length -eq 0 -or $sdValue.Length -lt 20)) {
        $hidingIndicators += "Empty or corrupted Security Descriptor"
        $suspicionLevel += 40
    }
    
    if ($idValue -and $indexValue -eq $null) {
        $hidingIndicators += "Missing Index value"
        $suspicionLevel += 30
    }
    
    if ($taskName -match "^[A-F0-9-]{36}$|^[a-f0-9]{8,}$|^\\.+$") {
        $hidingIndicators += "Suspicious task naming pattern"
        $suspicionLevel += 20
    }
    
    if ($idValue -and $uriValue -eq $null) {
        $hidingIndicators += "Missing URI reference"
        $suspicionLevel += 25
    }
    
    if ($hidingIndicators.Count -gt 0 -and $suspicionLevel -ge 30) {
        $fullPath = $subKey.Name -replace "HKEY_LOCAL_MACHINE\\", ""
        $taskName = $fullPath -replace [regex]::Escape("$basePath\"), ""
        
        $lastWriteTime = try { $subKey.GetValue("Date") } catch { $null }
        $creationTime = if ($lastWriteTime) { [DateTime]::Parse($lastWriteTime) } else { (Get-Date) }
        
        $hiddenTasks += [PSCustomObject]@{
            EventType             = "HiddenTask_DirectRegistry"
            Computer              = $Computer
            TimeCreated           = $creationTime
            TaskName              = $taskName
            Evidence              = "Task registry anomalies detected: $($hidingIndicators -join ', ')"
            DetectionMethod       = "Enhanced Registry Analysis"
            SuspicionLevel        = $suspicionLevel
            HidingIndicators      = $hidingIndicators
            RegistryPath          = $fullPath
        }
    }
                }
                catch {
                }
            }
        }
        Write-HuntLog "Direct registry scan found $($hiddenTasks.Count) tasks with registry anomalies." "Success"
    }
    catch {
        Write-HuntLog "Failed to perform direct registry query on $Computer`: $($_.Exception.Message)" "Error"
    }
    
    return $hiddenTasks
}

function Get-ScheduledTaskDetails {
    param(
        [string]$Computer,
        [string]$TaskPath
    )

    try {
        $job = Start-Job -ScriptBlock {
            param($c, $p)
            if ($c -eq $env:COMPUTERNAME -or $c -eq "localhost" -or $c -eq ".") {
                try {
                    Get-ScheduledTask -TaskPath $p -ErrorAction SilentlyContinue | Select-Object -Property TaskPath, State, Description, Actions, Principal
                } catch {
                    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -eq $p -or $_.TaskName -eq ($p -replace '^\\', '') } | Select-Object -First 1 -Property TaskPath, State, Description, Actions, Principal
                }
            } else {
                Invoke-Command -ComputerName $c -ScriptBlock {
                    param($taskPath)
                    try {
                        Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue | Select-Object -Property TaskPath, State, Description, Actions, Principal
                    } catch {
                        Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -eq $taskPath -or $_.TaskName -eq ($taskPath -replace '^\\', '') } | Select-Object -First 1 -Property TaskPath, State, Description, Actions, Principal
                    }
                } -ArgumentList $p -ErrorAction SilentlyContinue
            }
        } -ArgumentList $Computer, $TaskPath

        if (Wait-Job $job -Timeout 15) {
            $task = Receive-Job $job
            if ($task) {
                $actionStrings = $task.Actions | ForEach-Object {
                    if ($_.Execute) {
                        return "'$($_.Execute)' '$($_.Arguments)'"
                    }
                    return $_.ToString()
                }

                return [PSCustomObject]@{
                    Path        = $task.TaskPath
                    State       = $task.State.ToString()
                    Description = $task.Description
                    User        = $task.Principal.UserId
                    Actions     = $actionStrings -join "; "
                }
            }
        } else {
            Write-HuntLog "Timed out trying to get details for task '$TaskPath' on $Computer." "Warning"
        }

        Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-HuntLog "Failed to get task details for '$TaskPath' on $Computer`: $($_.Exception.Message)" "Warning"
    }
    return $null
}

function Write-HuntLog {
    param([string]$Message, [string]$Level = "Info")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch($Level) {
        "Error" { "Red" }
        "Warning" { "Yellow" }
        "Success" { "Green" }
        "Critical" { "Magenta" }
        default { "White" }
    }
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

function Test-EventLogAvailability {
    param([string]$Computer, [string]$LogName)
    
    try {
        $testLog = Get-WinEvent -ComputerName $Computer -ListLog $LogName -ErrorAction Stop
        return $testLog.IsEnabled
    } catch {
        return $false
    }
}

function Get-SuspiciousTaskPatterns {
    return @(
        'powershell.*-enc',
        'powershell.*-WindowStyle.*Hidden',
        'powershell.*-ExecutionPolicy.*Bypass',
        'cmd.*\/c.*del ',
        'rundll32.*javascript:',
        'regsvr32.*\/s.*\/n.*\/u.*\/i:',
        'mshta.*vbscript:',
        'certutil.*-decode',
        'bitsadmin.*\/transfer',
        'Invoke-WebRequest|iwr|wget|curl',
        'DownloadString|DownloadFile',
        'Start-Process.*-WindowStyle.*Hidden',
        'IEX|Invoke-Expression',
        'wscript.*\.vbs|cscript.*\.vbs',
        'regsvr32.*\/u.*\/s.*scrobj\.dll',
        'msiexec.*\/q.*\/i.*http',
        'schtasks.*\/create.*\/f',
        'net.*user.*\/add',
        'wmic.*process.*call.*create'
    )
}

function Get-LegitimateWindowsTasks {
    return @(
        # Windows Update and Maintenance
        'Microsoft\\Windows\\UpdateOrchestrator\\*',
        'Microsoft\\Windows\\WindowsUpdate\\*',
        'Microsoft\\Windows\\Maintenance\\*',
        'Microsoft\\Windows\\Defrag\\*',
        'Microsoft\\Windows\\DiskCleanup\\*',
        'Microsoft\\Windows\\SystemRestore\\*',
        'Microsoft\\Windows\\Diagnosis\\*',
        'Microsoft\\Windows\\MemoryDiagnostic\\*',
        
        # Security and Windows Defender
        'Microsoft\\Windows\\Windows Defender\\*',
        'Microsoft\\Windows\\Windows Security\\*',
        'Microsoft\\Windows\\AppID\\*',
        'Microsoft\\Windows\\CertificateServicesClient\\*',
        
        # System Services
        'Microsoft\\Windows\\Time Synchronization\\*',
        'Microsoft\\Windows\\Registry\\*',
        'Microsoft\\Windows\\WS\\*',
        'Microsoft\\Windows\\Wininet\\*',
        'Microsoft\\Windows\\WCM\\*',
        'Microsoft\\Windows\\WLAN\\*',
        
        # Application Framework
        'Microsoft\\Windows\\.NET Framework\\*',
        'Microsoft\\Windows\\Application Experience\\*',
        'Microsoft\\Windows\\ApplicationData\\*',
        'Microsoft\\Windows\\Clip\\*',
        'Microsoft\\Windows\\Customer Experience Improvement Program\\*',
        
        # Hardware and Power
        'Microsoft\\Windows\\Power Efficiency Diagnostics\\*',
        'Microsoft\\Windows\\Plug and Play\\*',
        'Microsoft\\Windows\\TPM\\*',
        'Microsoft\\Windows\\BitLocker\\*',
        
        # Common legitimate patterns
        '*\\Microsoft\\*',
        '*\\Adobe\\*',
        '*\\Google\\*',
        '*\\Intel\\*',
        '*\\NVIDIA\\*',
        '*\\AMD\\*'
    )
}

function Test-LegitimateTask {
    param([string]$TaskName)
    
    $legitimateTasks = Get-LegitimateWindowsTasks
    
    foreach ($pattern in $legitimateTasks) {
        if ($TaskName -like $pattern) {
            return $true
        }
    }
    
    return $false
}

function Get-ScheduledTaskEvents {
    param([string]$Computer, [datetime]$Since)
    
    Write-HuntLog "Collecting scheduled task events from $Computer..." "Info"
    
    try {
        $SecurityTaskCreated = Get-WinEvent -ComputerName $Computer -FilterHashTable @{
            LogName = 'Security'
            Id = 4698
            StartTime = $Since
        } -ErrorAction SilentlyContinue | ForEach-Object {
            $xml = [xml]$_.ToXml()
            [PSCustomObject]@{
                EventType = "TaskCreated_Security"
                Computer = $Computer
                TimeCreated = $_.TimeCreated
                EventId = $_.Id
                LogSource = "Security"
                TaskName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "TaskName"}).'#text'
                TaskContent = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "TaskContent"}).'#text'
                UserContext = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "SubjectUserName"}).'#text'
                ProcessId = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "ProcessId"}).'#text'
                CreationMethod = "Standard (schtasks/GUI)"
                RawEvent = $_
            }
        }
        
        $OperationalTaskCreated = Get-WinEvent -ComputerName $Computer -FilterHashTable @{
            LogName = 'Microsoft-Windows-TaskScheduler/Operational'
            Id = 106
            StartTime = $Since
        } -ErrorAction SilentlyContinue | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $taskName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "TaskName"}).'#text'
            $userContext = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "UserContext"}).'#text'
            
            [PSCustomObject]@{
                EventType = "TaskCreated_Operational"
                Computer = $Computer
                TimeCreated = $_.TimeCreated
                EventId = $_.Id
                LogSource = "TaskScheduler/Operational"
                TaskName = $taskName
                TaskContent = $_.Message
                UserContext = $userContext
                ProcessId = $_.ProcessId
                CreationMethod = "Programmatic (WinAPI/.NET/WMI/PowerShell)"
                RawEvent = $_
            }
        }
        
        $TaskActionEvents = Get-WinEvent -ComputerName $Computer -FilterHashTable @{
            LogName = 'Microsoft-Windows-TaskScheduler/Operational'
            Id = 200
            StartTime = $Since
        } -ErrorAction SilentlyContinue | ForEach-Object {
            $xml = [xml]$_.ToXml()
            [PSCustomObject]@{
                EventType = "TaskAction"
                Computer = $Computer
                TimeCreated = $_.TimeCreated
                EventId = $_.Id
                LogSource = "TaskScheduler/Operational"
                TaskName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "TaskName"}).'#text'
                ActionName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "ActionName"}).'#text'
                TaskInstanceId = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "TaskInstanceId"}).'#text'
                EnginePID = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "EnginePID"}).'#text'
                RawEvent = $_
            }
        }
        
        $AllTaskCreated = @()
        $AllTaskCreated += $SecurityTaskCreated
        $AllTaskCreated += $OperationalTaskCreated
        
        $TaskUpdated = Get-WinEvent -ComputerName $Computer -FilterHashTable @{
            LogName = 'Security'
            Id = 4702
            StartTime = $Since
        } -ErrorAction SilentlyContinue | ForEach-Object {
            $xml = [xml]$_.ToXml()
            [PSCustomObject]@{
                EventType = "TaskUpdated"
                Computer = $Computer
                TimeCreated = $_.TimeCreated
                EventId = $_.Id
                LogSource = "Security"
                TaskName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "TaskName"}).'#text'
                TaskContentNew = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "TaskContentNew"}).'#text'
                TaskContentOld = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "TaskContentOld"}).'#text'
                UserContext = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "SubjectUserName"}).'#text'
                ProcessId = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "ProcessId"}).'#text'
                RawEvent = $_
            }
        }
        
        $TaskEnabled = Get-WinEvent -ComputerName $Computer -FilterHashTable @{
            LogName = 'Security'
            Id = 4700
            StartTime = $Since
        } -ErrorAction SilentlyContinue | ForEach-Object {
            $xml = [xml]$_.ToXml()
            [PSCustomObject]@{
                EventType = "TaskEnabled"
                Computer = $Computer
                TimeCreated = $_.TimeCreated
                EventId = $_.Id
                LogSource = "Security"
                TaskName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "TaskName"}).'#text'
                UserContext = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "SubjectUserName"}).'#text'
                ProcessId = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "ProcessId"}).'#text'
                RawEvent = $_
            }
        }
        
        $TaskDisabled = Get-WinEvent -ComputerName $Computer -FilterHashTable @{
            LogName = 'Security'
            Id = 4701
            StartTime = $Since
        } -ErrorAction SilentlyContinue | ForEach-Object {
            $xml = [xml]$_.ToXml()
            [PSCustomObject]@{
                EventType = "TaskDisabled"
                Computer = $Computer
                TimeCreated = $_.TimeCreated
                EventId = $_.Id
                LogSource = "Security"
                TaskName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "TaskName"}).'#text'
                UserContext = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "SubjectUserName"}).'#text'
                ProcessId = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "ProcessId"}).'#text'
                RawEvent = $_
            }
        }
        $TaskDeleted = Get-WinEvent -ComputerName $Computer -FilterHashTable @{
            LogName = 'Security'
            Id = 4699
            StartTime = $Since
        } -ErrorAction SilentlyContinue | ForEach-Object {
            $xml = [xml]$_.ToXml()
            [PSCustomObject]@{
                EventType = "TaskDeleted"
                Computer = $Computer
                TimeCreated = $_.TimeCreated
                EventId = $_.Id
                LogSource = "Security"
                TaskName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "TaskName"}).'#text'
                UserContext = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "SubjectUserName"}).'#text'
                ProcessId = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "ProcessId"}).'#text'
                RawEvent = $_
            }
        }
        
        Write-HuntLog "Found $($SecurityTaskCreated.Count) Security log tasks, $($OperationalTaskCreated.Count) Operational log tasks, $($TaskActionEvents.Count) action events, $($TaskUpdated.Count) updates, $($TaskDeleted.Count) deletions" "Info"
        
        return @{
            Created = if ($AllTaskCreated) { $AllTaskCreated } else { @() }
            Updated = if ($TaskUpdated) { $TaskUpdated } else { @() }
            Enabled = if ($TaskEnabled) { $TaskEnabled } else { @() }
            Disabled = if ($TaskDisabled) { $TaskDisabled } else { @() }
            Deleted = if ($TaskDeleted) { $TaskDeleted } else { @() }
            Actions = if ($TaskActionEvents) { $TaskActionEvents } else { @() }
            SecurityCreated = if ($SecurityTaskCreated) { $SecurityTaskCreated } else { @() }
            OperationalCreated = if ($OperationalTaskCreated) { $OperationalTaskCreated } else { @() }
        }
        
    } catch {
        Write-HuntLog "Failed to collect task events from $Computer`: $($_.Exception.Message)" "Error"
        return @{
            Created = @()
            Updated = @()
            Enabled = @()
            Disabled = @()
            Deleted = @()
            Actions = @()
            SecurityCreated = @()
            OperationalCreated = @()
        }
    }
}

function Get-DirectRegistryTaskCreation {
    param([string]$Computer, [datetime]$Since)
    
    Write-HuntLog "Detecting direct registry task creation on $Computer..." "Info"
    
    try {
        $sysmonLogExists = Test-EventLogAvailability -Computer $Computer -LogName 'Microsoft-Windows-Sysmon/Operational'
        if (-not $sysmonLogExists) {
            Write-HuntLog "Sysmon log not available on $Computer - direct registry detection limited" "Warning"
            return @()
        }
        
        $DirectRegistryCreation = @()
        $RegistryObjectEvents = @()
        
        try {
            $events13 = Get-WinEvent -ComputerName $Computer -FilterHashTable @{
                LogName = 'Microsoft-Windows-Sysmon/Operational'
                Id = 13
                StartTime = $Since
            } -ErrorAction Stop
            
            $DirectRegistryCreation = $events13 | Where-Object {
                $_.Message -match "TargetObject.*TaskCache\\Tree\\" -and
                ($_.Message -match "ValueName.*Author|Actions|Triggers|Path" -or
                 $_.Message -match "DETAILS.*CREATE")
            } | ForEach-Object {
                $xml = [xml]$_.ToXml()
                $targetObject = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetObject"}).'#text'
                $processName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "Image"}).'#text'
                
                $taskName = "Unknown"
                if ($targetObject) {
                    $relative = ($targetObject -replace '^.*TaskCache\\Tree\\', '')
                    if ($relative -match '\\') { $relative = $relative -replace '\\[^\\]+$', '' }
                    $taskName = "\" + $relative
                }
                
                [PSCustomObject]@{
                    EventType = "DirectRegistryCreation"
                    Computer = $Computer
                    TimeCreated = $_.TimeCreated
                    EventId = $_.Id
                    LogSource = "Sysmon"
                    TaskName = $taskName
                    TargetObject = $targetObject
                    ValueName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "ValueName"}).'#text'
                    ProcessName = $processName
                    ProcessId = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "ProcessId"}).'#text'
                    CreationMethod = "Direct Registry Manipulation"
                    IsSuspicious = $processName -notmatch "svchost\.exe|taskhost\.exe|schtasks\.exe" -and
                                  $processName -match "powershell\.exe|cmd\.exe|python\.exe|rundll32\.exe"
                    RawEvent = $_
                }
            }
        } catch {
            if ($_.Exception.Message -notmatch "No events were found") {
                Write-HuntLog "Error querying Sysmon Event 13: $($_.Exception.Message)" "Warning"
            }
        }
        
        try {
            $events12 = Get-WinEvent -ComputerName $Computer -FilterHashTable @{
                LogName = 'Microsoft-Windows-Sysmon/Operational'
                Id = 12
                StartTime = $Since
            } -ErrorAction Stop
            
            $RegistryObjectEvents = $events12 | Where-Object {
                $_.Message -match "TargetObject.*TaskCache\\Tree\\" -and
                $_.Message -match "EventType.*CreateKey"
            } | ForEach-Object {
                $xml = [xml]$_.ToXml()
                $targetObject = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetObject"}).'#text'
                
                # Extract task name from registry path and normalize
                $taskName = "Unknown"
                if ($targetObject) {
                    $relative = ($targetObject -replace '^.*TaskCache\\Tree\\', '')
                    $taskName = "\" + $relative
                }
                
                [PSCustomObject]@{
                    EventType = "RegistryKeyCreation"
                    Computer = $Computer
                    TimeCreated = $_.TimeCreated
                    EventId = $_.Id
                    LogSource = "Sysmon"
                    TaskName = $taskName
                    TargetObject = $targetObject
                    ProcessName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "Image"}).'#text'
                    ProcessId = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "ProcessId"}).'#text'
                    CreationMethod = "Registry Key Creation"
                    RawEvent = $_
                }
            }
        } catch {
            if ($_.Exception.Message -notmatch "No events were found") {
                Write-HuntLog "Error querying Sysmon Event 12: $($_.Exception.Message)" "Warning"
            }
        }
        
        $AllDirectCreation = @()
        $AllDirectCreation += $DirectRegistryCreation
        $AllDirectCreation += $RegistryObjectEvents
        
        Write-HuntLog "Found $($DirectRegistryCreation.Count) direct registry value modifications, $($RegistryObjectEvents.Count) registry key creations" "Info"
        
        return $AllDirectCreation
        
    } catch {
        Write-HuntLog "Failed to collect direct registry events from $Computer`: $($_.Exception.Message)" "Error"
        return @()
    }
}

function Get-SuspiciousProcessEvents {
    param([string]$Computer, [datetime]$Since, [string[]]$SuspiciousPatterns)
    
    Write-HuntLog "Collecting suspicious process events from $Computer..." "Info"
    
    try {
        $ProcessEvents = @()
        try {
            $events = Get-WinEvent -ComputerName $Computer -FilterHashTable @{
                LogName = 'Security'
                Id = 4688
                StartTime = $Since
            } -ErrorAction Stop
            
            $ProcessEvents = $events | Where-Object {
                $message = $_.Message
                $SuspiciousPatterns | Where-Object { $message -match $_ }
            } | ForEach-Object {
                $xml = [xml]$_.ToXml()
                [PSCustomObject]@{
                    EventType = "SuspiciousProcess"
                    Computer = $Computer
                    TimeCreated = $_.TimeCreated
                    EventId = $_.Id
                    ProcessName = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "NewProcessName"}).'#text'
                    CommandLine = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "CommandLine"}).'#text'
                    ParentProcess = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "ParentProcessName"}).'#text'
                    ProcessId = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "NewProcessId"}).'#text'
                    UserContext = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq "SubjectUserName"}).'#text'
                    RawEvent = $_
                }
            }
        } catch {
            if ($_.Exception.Message -match "No events were found") {
                Write-HuntLog "No suspicious process events found in specified time window" "Info"
            } elseif ($_.Exception.Message -match "There is no event log on the") {
                Write-HuntLog "Security log not available on $Computer - process correlation limited" "Warning"
            } else {
                Write-HuntLog "Error querying process creation events: $($_.Exception.Message)" "Warning"
            }
        }
        
        Write-HuntLog "Found $($ProcessEvents.Count) suspicious process executions" "Info"
        return $ProcessEvents
        
    } catch {
        Write-HuntLog "Failed to collect process events from $Computer`: $($_.Exception.Message)" "Error"
        return @()
    }
}

function Find-HiddenTaskAbuseCorrelations {
    param($TaskEvents, $RegistryEvents, $ProcessEvents, $DirectRegistryEvents, [int]$WindowMinutes)
    
    Write-HuntLog "Correlating events to detect hidden task abuse..." "Info"
    
    $CorrelatedThreats = @()
    $WindowTicks = [TimeSpan]::TicksPerMinute * $WindowMinutes
    
    $safeTaskEvents = if ($TaskEvents -and $TaskEvents.Created) { $TaskEvents.Created } else { @() }
    $safeRegistryEvents = if ($RegistryEvents) { $RegistryEvents } else { @() }
    $safeProcessEvents = if ($ProcessEvents) { $ProcessEvents } else { @() }
    $safeDirectRegistryEvents = if ($DirectRegistryEvents) { $DirectRegistryEvents } else { @() }
    
    Write-HuntLog "Event counts - Tasks: $($safeTaskEvents.Count), Registry Hiding: $($safeRegistryEvents.Count), Processes: $($safeProcessEvents.Count), Direct Registry: $($safeDirectRegistryEvents.Count)" "Info"
    
    foreach ($createdTask in $safeTaskEvents) {
        if (Test-LegitimateTask -TaskName $createdTask.TaskName) {
            Write-HuntLog "Skipping legitimate Windows task: $($createdTask.TaskName)" "Info"
            continue
        }
        
        $threat = [PSCustomObject]@{
            ThreatType = "Potential Hidden Scheduled Task"
            TaskName = $createdTask.TaskName
            Computer = $createdTask.Computer
            InitialCreation = $createdTask.TimeCreated
            ThreatScore = 0
            Evidence = @()
            CorrelatedEvents = @{
                TaskCreated = $createdTask
                TaskUpdated = @()
                TaskEnabled = @()
                TaskDisabled = @()
                RegistryModifications = @()
                SuspiciousProcesses = @()
                TaskDeleted = $null
                DirectRegistryCreation = @()
                TaskActions = @()
            }
            Indicators = @()
            MissingLogs = @()
            CreationMethod = $createdTask.CreationMethod
            ThreatLevel = "INFO"
            TaskDetails = $null
            IsLegitimate = $false
        }
        
        $threat.TaskDetails = Get-ScheduledTaskDetails -Computer $createdTask.Computer -TaskPath $createdTask.TaskName
    
        switch ($createdTask.LogSource) {
            "Security" { 
                $threat.ThreatScore += 5
                $threat.Evidence += "Task created via standard Windows interface (schtasks/GUI)"
            }
            "TaskScheduler/Operational" { 
                $threat.ThreatScore += 15
                $threat.Evidence += "Task created programmatically (WinAPI/.NET/WMI/PowerShell)"
            }
        }
    
    if ($safeRegistryEvents.Count -gt 0) {
        $relatedRegistryEvents = $safeRegistryEvents | Where-Object {
            $_.TaskPath -eq $createdTask.TaskName -and
            [Math]::Abs(($_.TimeCreated.Ticks - $createdTask.TimeCreated.Ticks)) -le $WindowTicks
        }
        
        if ($relatedRegistryEvents) {
            $threat.CorrelatedEvents.RegistryModifications = $relatedRegistryEvents
            $threat.ThreatScore += 30
            
            $sdDeletion = $relatedRegistryEvents | Where-Object { $_.IsSuspicious }
            if ($sdDeletion) {
                $threat.ThreatScore += 50
                $threat.Indicators += "Security Descriptor manipulation detected"
                $threat.Evidence += "Registry modification removed TaskCache Security Descriptor - task likely hidden from schtasks.exe"
            }
        }
    } else {
        $threat.MissingLogs += "Sysmon Registry Events (Event 13)"
        $threat.Evidence += "WARNING: Sysmon registry logging not available - cannot detect registry-based hiding"
    }
    
    if ($safeDirectRegistryEvents.Count -gt 0) {
        $relatedDirectRegistry = $safeDirectRegistryEvents | Where-Object {
            $_.TaskName -eq $createdTask.TaskName -and
            [Math]::Abs(($_.TimeCreated.Ticks - $createdTask.TimeCreated.Ticks)) -le $WindowTicks
        }
        
        if ($relatedDirectRegistry) {
            $threat.CorrelatedEvents.DirectRegistryCreation = $relatedDirectRegistry
            $threat.ThreatScore += 40
            $threat.Indicators += "Direct registry manipulation detected"
            $threat.Evidence += "Task created via direct registry modification (bypassing normal Task Scheduler APIs)"
            
            $suspiciousDirectCreation = $relatedDirectRegistry | Where-Object { $_.IsSuspicious }
            if ($suspiciousDirectCreation) {
                $threat.ThreatScore += 30
                $threat.Indicators += "Suspicious process performed direct registry creation"
                $threat.Evidence += "Non-system process performed direct registry manipulation: $($suspiciousDirectCreation.ProcessName -join ', ')"
            }
        }
    }
    
    if ($TaskEvents -and ($TaskEvents.Updated -or $TaskEvents.Enabled -or $TaskEvents.Disabled)) {
        $relatedUpdates = $TaskEvents.Updated | Where-Object {
            $_.TaskName -eq $createdTask.TaskName -and
            $_.TimeCreated -gt $createdTask.TimeCreated
        }
        
        if ($relatedUpdates) {
            $threat.CorrelatedEvents.TaskUpdated = $relatedUpdates
            $threat.ThreatScore += 35
            $threat.Indicators += "Task modified after creation"
            $threat.Evidence += "Scheduled task was modified after initial creation (common persistence technique)"
            
            foreach ($update in $relatedUpdates) {
                if ($update.TaskContentNew -and $update.TaskContentOld) {
                    $suspiciousChanges = @()
                    
                    if ($update.TaskContentNew -notmatch [regex]::Escape($update.TaskContentOld)) {
                        $suspiciousChanges += "Command/Action modified"
                    }
                    
                    $suspiciousUpdatePatterns = Get-SuspiciousTaskPatterns
                    
                    $newSuspiciousPatterns = $suspiciousUpdatePatterns | Where-Object { 
                        $update.TaskContentNew -match $_ -and $update.TaskContentOld -notmatch $_ 
                    }
                    
                    if ($newSuspiciousPatterns) {
                        $threat.ThreatScore += 45
                        $threat.Indicators += "Suspicious patterns added during modification"
                        $threat.Evidence += "Task modification added suspicious command patterns: $($newSuspiciousPatterns -join ', ')"
                    }
                    
                    if ($update.TaskContentNew -match "LogonType.*Password" -and $update.TaskContentOld -notmatch "LogonType.*Password") {
                        $threat.ThreatScore += 30
                        $threat.Indicators += "Credential storage added to task"
                        $threat.Evidence += "Task modification added password-based logon (potential credential abuse)"
                    }
                }
            }
        }
        
        $relatedEnables = $TaskEvents.Enabled | Where-Object {
            $_.TaskName -eq $createdTask.TaskName -and
            $_.TimeCreated -gt $createdTask.TimeCreated
        }
        
        $relatedDisables = $TaskEvents.Disabled | Where-Object {
            $_.TaskName -eq $createdTask.TaskName -and
            $_.TimeCreated -gt $createdTask.TimeCreated
        }
        
        if ($relatedEnables) {
            $threat.CorrelatedEvents.TaskEnabled = $relatedEnables
            if (-not ($threat.Indicators -contains "Task enabled after creation")) {
                $threat.ThreatScore += 15
                $threat.Indicators += "Task enabled after creation"
                $threat.Evidence += "Task was enabled after creation (potential activation of dormant persistence)"
            }
        }
        
        if ($relatedDisables) {
            $threat.CorrelatedEvents.TaskDisabled = $relatedDisables
            if (-not ($threat.Indicators -contains "Task disabled after creation")) {
                $threat.ThreatScore += 10
                $threat.Indicators += "Task disabled after creation"
                $threat.Evidence += "Task was disabled after creation (potential evasion technique)"
            }
        }
        
        if ($relatedEnables.Count -gt 0 -and $relatedDisables.Count -gt 0) {
            if (-not ($threat.Indicators -contains "Enable/disable toggle pattern detected")) {
                $threat.ThreatScore += 25
                $threat.Indicators += "Enable/disable toggle pattern detected"
                $threat.Evidence += "Task shows enable/disable toggle pattern (advanced evasion technique)"
            }
        }
    }
    if ($TaskEvents -and $TaskEvents.Deleted) {
        $correspondingDeletion = $TaskEvents.Deleted | Where-Object {
            $_.TaskName -eq $createdTask.TaskName -and
            $_.TimeCreated -gt $createdTask.TimeCreated
        }
        
        if (-not $correspondingDeletion) {
            $threat.ThreatScore += 20
            $threat.Indicators += "Task created but never properly deleted"
            $threat.Evidence += "Scheduled task was created but no corresponding deletion event found"
        } else {
            $threat.CorrelatedEvents.TaskDeleted = $correspondingDeletion
        }
    } else {
        $threat.ThreatScore += 10
        $threat.Evidence += "Note: Task deletion events not available for correlation"
    }
    
    if ($TaskEvents -and $TaskEvents.Actions) {
        $relatedActions = $TaskEvents.Actions | Where-Object {
            $_.TaskName -like "*$($createdTask.TaskName)*" -and
            $_.TimeCreated -gt $createdTask.TimeCreated
        }
        
        if ($relatedActions) {
            $threat.CorrelatedEvents.TaskActions = $relatedActions
            $threat.ThreatScore += 15
            $threat.Indicators += "Task execution detected"
            $threat.Evidence += "Task action events detected - task has been executed"
        }
    }
    
    if ($safeProcessEvents.Count -gt 0) {
        $relatedProcesses = $safeProcessEvents | Where-Object {
            $_.TimeCreated -gt $createdTask.TimeCreated -and
            ($_.CommandLine -match [regex]::Escape($createdTask.TaskName) -or
             $_.ParentProcess -match "taskeng|svchost")
        }
        
        if ($relatedProcesses) {
            $threat.CorrelatedEvents.SuspiciousProcesses = $relatedProcesses
            $threat.ThreatScore += 25
            $threat.Indicators += "Suspicious processes potentially spawned by task"
            $threat.Evidence += "Detected suspicious process execution potentially triggered by scheduled task"
        }
    } else {
        $threat.MissingLogs += "Process Creation Events (Event 4688)"
        $threat.Evidence += "WARNING: Process creation logging not available - cannot correlate task execution"
    }
    
    if ($createdTask.TaskContent) {
        $suspiciousTaskPatterns = Get-SuspiciousTaskPatterns
        $matchedPatterns = $suspiciousTaskPatterns | Where-Object { $createdTask.TaskContent -match $_ }
        if ($matchedPatterns) {
            $threat.ThreatScore += 40
            $threat.Indicators += "Suspicious command patterns in task content"
            $threat.Evidence += "Task contains suspicious command patterns: $($matchedPatterns -join ', ')"
        }
    }
    
    if ($TaskEvents.SecurityCreated -and $TaskEvents.OperationalCreated) {
        $dualCreation = ($TaskEvents.SecurityCreated | Where-Object { $_.TaskName -eq $createdTask.TaskName }) -and
                       ($TaskEvents.OperationalCreated | Where-Object { $_.TaskName -eq $createdTask.TaskName })
        
        if (-not $dualCreation -and $createdTask.LogSource -eq "TaskScheduler/Operational") {
            $threat.ThreatScore += 25
            $threat.Indicators += "Programmatic creation without Security log entry"
            $threat.Evidence += "Task created programmatically but missing corresponding Security event (potential audit log evasion)"
        }
    }
    
    $availableLogSources = 0
    if ($safeRegistryEvents.Count -gt 0) { $availableLogSources++ }
    if ($safeDirectRegistryEvents.Count -gt 0) { $availableLogSources++ }
    if ($TaskEvents -and $TaskEvents.Deleted) { $availableLogSources++ }
    if ($safeProcessEvents.Count -gt 0) { $availableLogSources++ }
    
    if ($threat.ThreatScore -gt 0 -and $availableLogSources -lt 2) {
        $threat.ThreatScore += 15
        $threat.Evidence += "Threat detected with limited log sources - consider enabling additional logging"
    }
    
    $threat.ThreatLevel = if ($threat.ThreatScore -ge 100) { "CRITICAL" }
                        elseif ($threat.ThreatScore -ge 80) { "HIGH" }
                        elseif ($threat.ThreatScore -ge 60) { "MEDIUM" }
                        elseif ($threat.ThreatScore -ge 40) { "LOW" }
                        else { "INFO" }
    
    $includeThreat = ($threat.ThreatScore -gt 0) -or 
                    ($threat.MissingLogs.Count -gt 0 -and $createdTask.TaskContent -match "powershell|cmd")
    
    if ($includeThreat) {
        $CorrelatedThreats += $threat
    }
}

    $standaloneDirectCreation = $safeDirectRegistryEvents | Where-Object {
        $directTask = $_
        -not ($safeTaskEvents | Where-Object { 
            $_.TaskName -eq $directTask.TaskName -and
            [Math]::Abs(($_.TimeCreated.Ticks - $directTask.TimeCreated.Ticks)) -le $WindowTicks
        })
    }
    
    foreach ($directTask in $standaloneDirectCreation) {
        $threat = [PSCustomObject]@{
            ThreatType = "Direct Registry Task Creation"
            TaskName = $directTask.TaskName
            Computer = $directTask.Computer
            InitialCreation = $directTask.TimeCreated
            ThreatScore = 70
            Evidence = @("Task created entirely via direct registry manipulation", "No corresponding Task Scheduler API calls detected")
            CorrelatedEvents = @{
                TaskCreated = $null
                RegistryModifications = @()
                SuspiciousProcesses = @()
                TaskDeleted = $null
                DirectRegistryCreation = @($directTask)
                TaskActions = @()
            }
            Indicators = @("Direct registry manipulation", "Bypassed Task Scheduler APIs")
            MissingLogs = @()
            CreationMethod = "Pure Registry Manipulation"
            ThreatLevel = "HIGH"
            TaskDetails = Get-ScheduledTaskDetails -Computer $directTask.Computer -TaskPath $directTask.TaskName
        }
        
        if ($directTask.IsSuspicious) {
            $threat.ThreatScore += 20
            $threat.ThreatLevel = "CRITICAL"
            $threat.Indicators += "Suspicious process performed registry creation"
        }
        
        $CorrelatedThreats += $threat
    }
    
    if ($TaskEvents -and $TaskEvents.Updated) {
        $standaloneUpdates = $TaskEvents.Updated | Where-Object {
            $updateEvent = $_
            -not ($safeTaskEvents | Where-Object { 
                $_.TaskName -eq $updateEvent.TaskName -and
                $_.TimeCreated -le $updateEvent.TimeCreated
            })
        }
        
        foreach ($updateEvent in $standaloneUpdates) {
            $threat = [PSCustomObject]@{
                ThreatType = "Suspicious Task Modification"
                TaskName = $updateEvent.TaskName
                Computer = $updateEvent.Computer
                InitialCreation = $updateEvent.TimeCreated
                ThreatScore = 40
                Evidence = @("Task modified without corresponding creation in analysis window", "May indicate modification of existing legitimate task for persistence")
                CorrelatedEvents = @{
                    TaskCreated = $null
                    TaskUpdated = @($updateEvent)
                    TaskEnabled = @()
                    TaskDisabled = @()
                    RegistryModifications = @()
                    SuspiciousProcesses = @()
                    TaskDeleted = $null
                    DirectRegistryCreation = @()
                    TaskActions = @()
                }
                Indicators = @("Standalone task modification", "Advanced persistence technique")
                MissingLogs = @()
                CreationMethod = "Modification of Existing Task"
                ThreatLevel = "MEDIUM"
                TaskDetails = Get-ScheduledTaskDetails -Computer $updateEvent.Computer -TaskPath $updateEvent.TaskName
            }
            
            if ($updateEvent.TaskContentNew) {
                $suspiciousModificationPatterns = Get-SuspiciousTaskPatterns
                
                $matchedModificationPatterns = $suspiciousModificationPatterns | Where-Object { $updateEvent.TaskContentNew -match $_ }
                if ($matchedModificationPatterns) {
                    $threat.ThreatScore += 50
                    $threat.ThreatLevel = "HIGH"
                    $threat.Indicators += "Suspicious command patterns in modification"
                    $threat.Evidence += "Task modification contains suspicious patterns: $($matchedModificationPatterns -join ', ')"
                }
                
                if ($updateEvent.TaskContentNew -match "LogonType.*Password") {
                    $threat.ThreatScore += 30
                    $threat.Indicators += "Credential storage in modified task"
                    $threat.Evidence += "Modified task includes password-based authentication (credential abuse risk)"
                }
                
                if ($updateEvent.TaskName -match "^\\[^\\]+$") {
                    $threat.ThreatScore += 25
                    $threat.Indicators += "Root-level task modification"
                    $threat.Evidence += "Modified task located in Task Scheduler root (common malware location)"
                }
            }
            
            if ($threat.ThreatScore -ge 100) { $threat.ThreatLevel = "CRITICAL" }
            elseif ($threat.ThreatScore -ge 80) { $threat.ThreatLevel = "HIGH" }
            elseif ($threat.ThreatScore -ge 60) { $threat.ThreatLevel = "MEDIUM" }
            
            $CorrelatedThreats += $threat
        }
    }

    return $CorrelatedThreats | Sort-Object ThreatScore -Descending
}

function Export-HuntResults {
    param($Results, [string]$OutputDir)
    
    if (-not (Test-Path $OutputDir)) {
        New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    $summaryPath = Join-Path $OutputDir "HiddenTask_Summary_$timestamp.txt"
    $summary = @"
HIDDEN SCHEDULED TASK HUNT RESULTS
==================================
Analysis Time: $(Get-Date)
Total Threats Detected: $($Results.Count)

THREAT BREAKDOWN:
Critical: $(($Results | Where-Object {$_.ThreatLevel -eq "CRITICAL"}).Count)
High:     $(($Results | Where-Object {$_.ThreatLevel -eq "HIGH"}).Count)  
Medium:   $(($Results | Where-Object {$_.ThreatLevel -eq "MEDIUM"}).Count)
Low:      $(($Results | Where-Object {$_.ThreatLevel -eq "LOW"}).Count)

TOP THREATS:
$(($Results | Select-Object -First 5 | ForEach-Object {
    "[$($_.ThreatLevel)] $($_.TaskName) on $($_.Computer) - Score: $($_.ThreatScore)"
    "  Indicators: $($_.Indicators -join '; ')"
}) -join "`n")

"@
    
    $summary | Out-File $summaryPath
    
    $detailPath = Join-Path $OutputDir "HiddenTask_Detailed_$timestamp.xml"
    $Results | Export-Clixml $detailPath
    
    $csvPath = Join-Path $OutputDir "HiddenTask_Analysis_$timestamp.csv"
    $Results | Select-Object ThreatType, TaskName, Computer, ThreatLevel, ThreatScore, 
                            @{N="Indicators";E={$_.Indicators -join "; "}},
                            @{N="Evidence";E={$_.Evidence -join "; "}},
                            @{N="Task_Action";E={$_.TaskDetails.Actions}},
                            @{N="Task_User";E={$_.TaskDetails.User}},
                            @{N="Task_State";E={$_.TaskDetails.State}},
                            @{N="Task_Description";E={$_.TaskDetails.Description}} |
        Export-Csv $csvPath -NoTypeInformation
    
    return @{
        Summary = $summaryPath
        Detailed = $detailPath
        CSV = $csvPath
    }
}

try {
    Write-HuntLog "Starting Hidden Scheduled Task Hunt" "Success"
    Write-HuntLog "Targets: $($ComputerName -join ', ')" "Info"
    Write-HuntLog "Lookback: $((Get-Date) - $StartTime)" "Info"
    
    $AllResults = @()
    
    $SuspiciousPatterns = @(
        'powershell.*-windowstyle.*hidden',
        'powershell.*-enc',
        'cmd.*\/c.*del.*temp',
        'rundll32.*javascript:',
        'regsvr32.*\/s.*\/n',
        'mshta.*vbscript:',
        'certutil.*-decode',
        'bitsadmin.*\/transfer'
    )
    
    foreach ($Computer in $ComputerName) {
        Write-HuntLog "Analyzing $Computer..." "Info"
        
        $taskEvents = Get-ScheduledTaskEvents -Computer $Computer -Since $StartTime
        $registryEvents = Get-RegistryTaskCacheEvents -Computer $Computer -Since $StartTime
        $processEvents = Get-SuspiciousProcessEvents -Computer $Computer -Since $StartTime -SuspiciousPatterns $SuspiciousPatterns
        $directRegistryEvents = Get-DirectRegistryTaskCreation -Computer $Computer -Since $StartTime
        
        if ($registryEvents.Count -eq 0) {
            Write-HuntLog "Sysmon registry events not available, performing direct registry scan for hidden tasks..." "Info"
            $directHiddenTasks = Get-TaskCacheStateFromRegistry -Computer $Computer
            foreach($hiddenTask in $directHiddenTasks) {
                 $AllResults += [PSCustomObject]@{
                    ThreatType = "Hidden Task (Direct Registry Check)"
                    TaskName = $hiddenTask.TaskName
                    Computer = $hiddenTask.Computer
                    InitialCreation = $hiddenTask.TimeCreated
                    ThreatScore = 85 # High score for confirmed hidden task
                    Evidence = @($hiddenTask.Evidence)
                    Indicators = @("Task hidden via Security Descriptor removal", "Direct Registry Detection")
                    ThreatLevel = "HIGH"
                    CorrelatedEvents = @{
                        TaskCreated = $null
                        TaskUpdated = @()
                        TaskEnabled = @()
                        TaskDisabled = @()
                        RegistryModifications = @()
                        SuspiciousProcesses = @()
                        TaskDeleted = $null
                        DirectRegistryCreation = @()
                        TaskActions = @()
                    }
                    MissingLogs = @("Sysmon Registry Events (Event 13)")
                    CreationMethod = "Unknown (Registry Scan Detection)"
                    TaskDetails = Get-ScheduledTaskDetails -Computer $Computer -TaskPath $hiddenTask.TaskName
                }
            }
        }
        
        if ($taskEvents) {
            $correlatedThreats = Find-HiddenTaskAbuseCorrelations -TaskEvents $taskEvents -RegistryEvents $registryEvents -ProcessEvents $processEvents -DirectRegistryEvents $directRegistryEvents -WindowMinutes $CorrelationWindowMinutes
            $AllResults += $correlatedThreats
        }
    }
    
    Write-HuntLog "Analysis complete. Found $($AllResults.Count) potential threats" "Success"
    
    if ($AllResults.Count -gt 0) {
        $exportResults = Export-HuntResults -Results $AllResults -OutputDir $OutputPath
        
        Write-HuntLog "Results exported to:" "Success"
        Write-HuntLog "  Summary: $($exportResults.Summary)" "Info"
        Write-HuntLog "  Detailed: $($exportResults.Detailed)" "Info"
        Write-HuntLog "  CSV: $($exportResults.CSV)" "Info"
        
        Write-HuntLog "`nTHREAT SUMMARY - $($AllResults.Count) TOTAL" "Critical"
        Write-HuntLog "=================================" "Critical"
 
        $GroupedThreats = $AllResults | Group-Object -Property ThreatLevel | Sort-Object @{Expression={@('CRITICAL','HIGH','MEDIUM','LOW').IndexOf($_.Name)}; Ascending=$true}
 
        foreach ($group in $GroupedThreats) {
            Write-HuntLog "`n$($group.Name) ($($group.Count) Threats)" "Yellow"
            Write-HuntLog "---------------------------------" "Yellow"
             
            foreach ($threat in $group.Group) {
                Write-HuntLog "  [Task] $($threat.TaskName) on $($threat.Computer) (Score: $($threat.ThreatScore))" "White"
                if ($threat.TaskDetails.Actions) {
                    Write-HuntLog "    Action:     $($threat.TaskDetails.Actions)" "Gray"
                }
                Write-HuntLog "    Indicators: $($threat.Indicators -join '; ')" "Cyan"
                $topEvidence = $threat.Evidence | Where-Object { $_ -notmatch "standard Windows interface|programmatically" } | Select-Object -First 2
                if ($topEvidence) {
                    Write-HuntLog "    Evidence:   $($topEvidence -join ' | ')" "Gray"
                }
            }
        }
        Write-HuntLog "`n=================================" "Critical"
 
        $logSummary = @"

LOG SOURCE AVAILABILITY SUMMARY:
Security Events (4698/4699): $((($AllResults | Where-Object {$_.CorrelatedEvents.TaskCreated}).Count -gt 0))
Sysmon Registry (Event 13): $(($AllResults | Where-Object {$_.MissingLogs -notcontains "Sysmon Registry Events (Event 13)"}).Count -gt 0)
Process Creation (Event 4688): $(($AllResults | Where-Object {$_.MissingLogs -notcontains "Process Creation Events (Event 4688)"}).Count -gt 0)

RECOMMENDATIONS:
$(if (($AllResults | Where-Object {$_.MissingLogs -contains "Sysmon Registry Events (Event 13)"}).Count -gt 0) {
    "- Enable Sysmon with registry monitoring (Event 13) to detect TaskCache manipulation"
})
$(if (($AllResults | Where-Object {$_.MissingLogs -contains "Process Creation Events (Event 4688)"}).Count -gt 0) {
    "- Enable process creation auditing (4688) to correlate task execution"
})
$(if ($AllResults.Count -eq 0) {
    "- Consider expanding time window or checking if scheduled task auditing is enabled"
})
"@
        Write-HuntLog $logSummary "Info"
    } else {
        Write-HuntLog "No hidden task abuse detected during analysis period" "Success"
    }
    
} catch {
    Write-HuntLog "Hunt failed: $($_.Exception.Message)" "Error"
    throw
}