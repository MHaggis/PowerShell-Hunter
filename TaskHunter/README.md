## Task Hunter: Hidden Scheduled Tasks

**Task Hunting** for detecting advanced scheduled task abuse and hiding techniques (e.g., Tarrask) by correlating multiple Windows event sources with intelligent false positive reduction.

### What this tool does

- **Detects hiding techniques** including Tarrask, Index manipulation, URI tampering, and timestamp attacks
- **Correlates events** across 4 log sources to raise fidelity and reduce false positives  
- **Filters common legitimate Windows and vendor tasks** to minimize noise in enterprise environments
- **Advanced registry analysis** with multi-indicator scoring for sophisticated attacks
- **Process context awareness** to identify suspicious registry manipulation
- **Scores findings** with intelligent ThreatScore and classifies by ThreatLevel
- **Exports comprehensive reports** (summary TXT, detailed CLIXML, and CSV for analysis)

### Prerequisites

- Windows host(s) with administrative rights to query logs
- PowerShell >= 5.1
- Run PowerShell as Administrator
- Logging requirements:
  - **Security log**: 4688 (Process Creation), 4698 (Task Created), 4699 (Task Deleted), 4700 (Task Enabled), 4701 (Task Disabled), 4702 (Task Updated)
  - **Task Scheduler Operational log**: 106 (Task Registered), 200 (Action Started)
  - **Sysmon** (recommended): 12 (Registry object create/delete), 13 (Registry value set)
    - Sysmon must include registry monitoring for `TaskCache` paths

If some logs are missing, the script still runs and clearly marks missing sources; scoring adapts accordingly.

### Scripts

- `Hunt-HiddenScheduledTasks.ps1` - Main hunting script
- `Test-HiddenTaskAbuse.ps1` - Test/validation script
- `Enable-TaskHuntingLogs.ps1` - One-time setup to enable required logging

### Parameters

- **ComputerName**: One or more target computers. Default: current host (`$env:COMPUTERNAME`).
- **StartTime**: Lookback start time for analysis. Default: last 24 hours.
- **CorrelationWindowMinutes**: Time window to correlate related events. Default: 5.
- **OutputPath**: Directory for exported reports. Default: `./HiddenTaskHunt_Results`.

Example defaults (effective when you run without parameters):

```powershell
.\n+Hunt-HiddenScheduledTasks.ps1
```

### 🔍 Advanced Detection Capabilities

**Registry Hiding Techniques Detected:**
- **Tarrask Technique**: Security Descriptor removal/emptying (primary focus)
- **Index Manipulation**: Tampering with TaskCache Index values  
- **URI Reference Attacks**: Breaking task visibility by removing URI links
- **Timestamp Manipulation**: Suspicious date/time modifications to evade detection
- **Process Context Analysis**: Non-system processes manipulating TaskCache registry

**Suspicious Command Pattern Detection:**
```powershell
# 22+ malicious patterns including:
'powershell.*-enc'                    # Encoded PowerShell commands
'regsvr32.*\/u.*\/s.*scrobj\.dll'    # Squiblydoo technique  
'msiexec.*\/q.*\/i.*http'            # Remote MSI execution
'wmic.*process.*call.*create'        # WMI process creation
'net.*user.*\/add'                   # User account creation
```

### How it works (high level)

1. **Multi-Source Event Collection**:
   - **Security log**: 4698/4699/4700/4701/4702 and 4688 (task lifecycle + process creation)
   - **Task Scheduler Operational**: 106 and 200 (programmatic creation + execution)
   - **Sysmon**: 12 and 13 (registry object/value manipulation in TaskCache)
   - **Direct Registry Scanning**: Fallback detection when Sysmon unavailable

2. **Intelligent Correlation**: Task name, time proximity, process lineage, and registry context within configurable windows

3. **False Positive Reduction**: Common Windows/vendor tasks filtered out (Microsoft, Adobe, Google, Intel, NVIDIA, etc.)

4. **Advanced Scoring**: Multi-factor threat scoring based on creation method, hiding indicators, suspicious commands, and attack context

5. **Enterprise Reporting**: Consolidated results with actionable indicators, evidence chains, and threat classification

### 🚀 Quick Start

**🔬 Lab/Testing (validate detection capabilities):**
```powershell
.\Enable-TaskHuntingLogs.ps1    # Enable logging (one-time setup)
.\Test-HiddenTaskAbuse.ps1      # Create test tasks
.\Hunt-HiddenScheduledTasks.ps1 # Hunt and validate detection
```

**🔍 DFIR/Incident Response (investigate with existing logs):**
```powershell
# Just run the hunt - works with whatever logging exists
.\Hunt-HiddenScheduledTasks.ps1 -ComputerName "SUSPECT-PC" -StartTime (Get-Date).AddDays(-30)

# No events found = either no suspicious activity OR logging wasn't enabled
# Check the MissingLogs field in results to see what telemetry is unavailable
```

**🎯 Enterprise Threat Hunting:**
```powershell
.\Hunt-HiddenScheduledTasks.ps1 -ComputerName @("DC01","FILE01","WEB01") -StartTime (Get-Date).AddDays(-7)
```

### Usage Scenarios

**🔬 Lab/Testing Environment:**

If you're testing or validating detection capabilities in a lab, enable logging first:

```powershell
# 1. Enable required event logs (run as Administrator)
.\Enable-TaskHuntingLogs.ps1

# 2. Create test tasks to simulate attacks
.\Test-HiddenTaskAbuse.ps1

# 3. Run the hunt to validate detection
.\Hunt-HiddenScheduledTasks.ps1 -StartTime (Get-Date).AddHours(-2)
```

**🔍 Production DFIR/Incident Response:**

In real investigations, just run the hunt against existing logs. **No setup required.**

```powershell
# Hunt on local system
.\Hunt-HiddenScheduledTasks.ps1

# Hunt on remote compromised host
.\Hunt-HiddenScheduledTasks.ps1 -ComputerName "SUSPECT-PC" -StartTime (Get-Date).AddDays(-30)

# Enterprise sweep across multiple hosts
.\Hunt-HiddenScheduledTasks.ps1 -ComputerName @("DC01","FILE01","WEB01") -StartTime (Get-Date).AddDays(-7)
```

**What to expect:**
- If logging was enabled: You'll get detailed threat detection with scoring
- If logging wasn't enabled: The hunt will report missing log sources in the output
- Zero results = Either no suspicious activity OR logging gaps (check `MissingLogs` field)

The tool works with whatever telemetry is available and clearly marks gaps.

---

### Testing Options (Lab Use)

```powershell
# Create basic test task
.\Test-HiddenTaskAbuse.ps1

# Create advanced test task with encoded commands
.\Test-HiddenTaskAbuse.ps1 -TestType Advanced

# Create full test with network activity simulation
.\Test-HiddenTaskAbuse.ps1 -TestType Full

# Skip execution, just create and hide
.\Test-HiddenTaskAbuse.ps1 -SkipExecution
```

**Note for remote targets:** Ensure required remoting/permissions and that the target logs are enabled and accessible. The script uses `Get-WinEvent -ComputerName`.

### Output

Exports to the specified `OutputPath` (created if it does not exist):

- Summary TXT: `HiddenTask_Summary_<timestamp>.txt`
- Detailed CLIXML: `HiddenTask_Detailed_<timestamp>.xml`
- CSV: `HiddenTask_Analysis_<timestamp>.csv`

Each record includes:

- `ThreatType`, `TaskName`, `Computer`, `ThreatLevel`, `ThreatScore`
- `Indicators` (list) and `Evidence` (list)
- `CorrelatedEvents` (created/updated/enabled/disabled/deleted/actions/registry/process)
- `MissingLogs` for transparency when some telemetry is unavailable

### 📊 Interpreting Results

**Threat Classification System:**
- **ThreatScore**: Numerical score (0-150+) reflecting cumulative evidence strength
- **ThreatLevel**: Critical (100+) | High (80+) | Medium (60+) | Low (40+) | Info (<40)
- **Indicators**: Attack technique identifiers (e.g., "Security Descriptor manipulation detected")
- **Evidence**: Detailed technical findings supporting the threat score
- **MissingLogs**: Transparency about unavailable telemetry sources

**🎯 High-Value Detections to Investigate:**

| Finding | Threat Level | What It Means |
|---------|-------------|---------------|
| **Security Descriptor Removal** | 🔴 **Critical** | Classic Tarrask technique - task hidden from schtasks.exe |
| **Non-system Registry Manipulation** | 🟠 **High** | PowerShell/cmd manipulating TaskCache directly |
| **Programmatic Creation + No Audit** | 🟠 **High** | API-based creation bypassing Security event logs |
| **Encoded Command Patterns** | 🟠 **High** | Obfuscated malicious payloads in task content |
| **Enable/Disable Toggle Patterns** | 🟡 **Medium** | Advanced evasion technique to avoid detection |
| **Missing Deletion Events** | 🟡 **Medium** | Tasks created but never properly removed |

**🔍 Investigation Priority:**
1. **Critical/High findings** - Immediate investigation required
2. **Tasks with multiple indicators** - Higher confidence detections  
3. **Recent activity** - Active or ongoing threats
4. **Non-legitimate task paths** - Outside standard Windows/vendor locations

### Troubleshooting

- **Run PowerShell as Administrator**
- **If no events are found:** Run `.\Enable-TaskHuntingLogs.ps1` to enable logging, or check if logs are enabled:
  ```powershell
  auditpol /get /subcategory:"Other Object Access Events"
  auditpol /get /subcategory:"Process Creation"
  ```
- **Manual log enablement:**
  - Security auditing for process and task events
  - Task Scheduler Operational log: `Microsoft-Windows-TaskScheduler/Operational`
  - Sysmon with registry monitoring for `TaskCache` (Events 12/13)
- If remote queries fail, verify:
  - Network connectivity and firewall rules for Event Log RPC
  - Credentials have rights to read remote event logs
  - WinRM/EventLog service is running on targets
- If no results are returned:
  - Extend `-StartTime` further back
  - Widen `-CorrelationWindowMinutes`
  - Confirm scheduled task auditing is enabled
- If Sysmon queries fail with "The parameter is incorrect":
  - Install Sysmon: `sysmon.exe -i -accepteula`
  - Configure Sysmon to monitor registry: Include `<RegistryEvent>` rules for `TaskCache` paths
  - Example Sysmon config snippet:
    ```xml
    <RegistryEvent onmatch="include">
        <TargetObject name="technique_id:T1053.005,technique_name:Scheduled Task" condition="contains">TaskCache</TargetObject>
    </RegistryEvent>
    ```



