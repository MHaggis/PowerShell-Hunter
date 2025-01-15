# BAM (Background Activity Moderator) Analysis Tool

<img src="../images/logo.png" alt="PowerShell-Hunter Logo" width="400" align="center">

<p align="center">
  <br>
  <em>Hunt smarter, Hunt harder</em>
</p>

## Overview
The BAM Analysis Tool is a PowerShell-based forensics utility designed to extract and analyze Windows Background Activity Moderator (BAM) data. BAM is a Windows service introduced in Windows 10 that tracks application execution times and helps Windows manage background applications' resource consumption.

## Forensic Value
BAM data provides crucial forensic artifacts that can help investigators:
- Track application execution history
- Establish user activity timelines
- Identify after-hours activity
- Detect potentially suspicious executions
- Verify user statements about application usage
- Correlate activity across multiple evidence sources

## Features
- **Data Collection**
  - Extracts BAM data from registry
  - Supports multiple Windows versions
  - Handles both .dat files and registry entries

- **Advanced Analysis**
  - Process signature verification
  - User SID resolution
  - Application categorization
  - Suspicious activity detection
  - Network path analysis
  - Timeline reconstruction

- **Multiple Export Formats**
  - CSV for spreadsheet analysis
  - JSON for programmatic processing
  - HTML for interactive viewing
  - Timeline for chronological review

## Usage

### Data Collection
```powershell
.\get-BAM.ps1
```
This script will collect BAM data from the system and store it in the `BAM_Collection` directory.

### Analysis
```powershell
.\analyze-BAM.ps1 -BAMDirectory .\BAM_Collection
```
This will analyze the collected data and generate comprehensive reports.


## Output Files
- `BAM_Analysis.csv` - Detailed data in CSV format
- `BAM_Analysis.json` - Complete data structure in JSON
- `BAM_Analysis.html` - Interactive report with visualizations
- `BAM_Analysis_timeline.csv` - Chronological activity timeline

## Technical Details

### BAM Data Location
Windows stores BAM data in:
- Registry: `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`
- Legacy: `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\BAM`

### Data Structure
BAM entries contain:
- Executable path
- Last execution timestamp
- User SID
- Additional metadata

## Use Cases

### For Incident Response
- Establish timeline of compromise
- Identify unauthorized access
- Track malware execution
- Verify system access times

### For Forensic Analysis
- Document user activity
- Validate timestamps
- Support or refute alibis
- Correlate cross-system activity

### For Threat Hunting
- Detect unusual patterns
- Identify suspicious executables
- Monitor after-hours activity
- Track network-based execution

## Why This Tool?
1. **Accessibility**: Native Windows tools don't provide easy access to BAM data
2. **Analysis Depth**: Raw BAM data requires significant processing for meaningful analysis
3. **Correlation**: Helps connect user activities across time periods
4. **Automation**: Streamlines the forensic analysis process
5. **Reporting**: Generates court-ready reports in multiple formats

## Requirements
- Windows 10/11
- PowerShell 5.1 or later
- Administrator privileges

## Limitations
- Some Windows Store apps may show as "File Not Found"
- SID resolution requires access to the system where the user exists
- Historical data limited by Windows' retention policies

## Contributing
Contributions are welcome! Please feel free to submit pull requests or open issues for:
- Bug fixes
- Feature additions
- Documentation improvements
- Analysis enhancements

## What BAM Actually Tracks

BAM (Background Activity Moderator) specifically monitors:
- Background applications and services
- Windows Store/UWP applications
- Apps that register for background tasks
- Applications using Windows power management
- Programs that declare background activity

BAM does NOT track:
- Regular program executions
- Command-line tools that run and exit
- Programs without background activity registration
- Short-lived processes

### When to Use BAM Analysis
BAM is most useful for:
1. Tracking persistent background activity
2. Monitoring Windows Store app usage
3. Identifying apps that run during system idle
4. Analyzing background task patterns
5. Investigating long-running application behavior

### Example Applications That Typically Appear:
- Windows Store apps
- System background services
- Update services
- Notification providers
- Background task hosts

## Future Enhancements
Planned features and improvements:

### Remote Collection Support
- Multi-system collection capabilities
- Credential management for remote access
- WinRM/PSRemoting configuration handling
- Per-system output organization


Contributions and suggestions for additional features are welcome!

## References
- [Tracking Parent-Child Process Relationship Via BAM](https://github.com/nasbench/Misc-Research/blob/main/Other/Tracking-Parent-Child-Process-Relationship-Via-BAM.md) - Research on extracting parent-child process relationships from BAM data

---

<p align="center">
Made with ❤️ by defenders for defenders
</p>
