 # PCA Analyzer

<img src="../images/logo.png" alt="PowerShell-Hunter Logo" width="400" align="center">

<p align="center">
  <br>
  <em>Hunt smarter, hunt harder</em>
</p>

A PowerShell script that parses and analyzes Program Compatibility Assistant (PCA) logs from Windows systems. This tool helps forensic analysts and threat hunters investigate application execution history and identify potential compatibility issues.

## Description

PCA_Analyzer.ps1 extracts and displays data from the following Windows PCA log files:

```powershell
C:\Windows\appcompat\pca\
├── PcaAppLaunchDic.txt      # Application execution history with timestamps
└── PcaGeneralDb0.txt        # Process events and abnormal program exits
```

The Program Compatibility Assistant (PCA) is a Windows feature that detects compatibility issues when applications run. The logs provide valuable forensic artifacts for tracking application execution and identifying problematic software.

## Features

- Parses application execution history with accurate timestamps
- Identifies recorded process events and abnormal program exits
- Generates visually appealing HTML reports with interactive elements
- Exports data in multiple formats (HTML, CSV, JSON)
- Provides quick summary statistics of PCA activity
- Automatically opens generated reports for immediate analysis
- Color-coded console output for better readability

## Usage

```powershell
# Basic usage - generates all report formats (HTML, CSV, JSON)
.\PCA_Analyzer.ps1

# Generate only HTML report
.\PCA_Analyzer.ps1 -ExportFormat HTML

# Generate only CSV report
.\PCA_Analyzer.ps1 -ExportFormat CSV

# Generate only JSON report
.\PCA_Analyzer.ps1 -ExportFormat JSON
```

## Example Output

Console output displays application execution history and process events:

```
PCA Application Execution Log (PcaAppLaunchDic.txt):

ExecutablePath                                                                LastExecutionTime
--------------                                                                -----------------
C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2412.16.0_x64_...\   2/26/2025 7:23:23 PM
C:\Program Files\WindowsApps\Microsoft.WDAC.WDACWizard_2.4.4.0_x64_...\       2/26/2025 7:21:27 PM
C:\Windows\Temp\{A8F897DA-2306-444F-9304-98ABC56BBC34}\.be\...\               2/12/2025 3:05:36 AM
```

## Why This Matters

PCA logs are valuable artifacts for:
- **Digital Forensics**: Reconstruct application execution timelines
- **Incident Response**: Identify potentially malicious applications
- **Threat Hunting**: Detect unusual program behavior patterns
- **Malware Analysis**: Find evidence of program crashes or compatibility issues

The Windows PCA logs provide key information about:
- When applications were executed on the system
- Which applications experienced abnormal exits or crashes
- Compatibility issues that might indicate malicious behavior
- Historical evidence of application execution not found elsewhere

## Reports and Visualization

The script generates three types of reports:

1. **HTML Report**: Interactive and visually appealing dashboard with statistics
2. **CSV Report**: Comma-separated values for easy import into other tools
3. **JSON Report**: Structured data format for programmatic analysis

The HTML report includes:
- Summary statistics with key metrics
- Formatted tables of application execution history
- Details about process events and abnormal exits
- Professional styling for easy analysis

## Requirements

- Windows Operating System
- PowerShell 3.0 or later
- Access to C:\Windows\appcompat\pca\ directory

## References
- [Diving into the Windows 11 Forensics PCA Artifact](https://www.sygnia.co/blog/new-windows-11-pca-artifact/)


## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

---

<p align="center">
Made with ❤️ by defenders for defenders
</p>