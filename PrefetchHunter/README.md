# Prefetch Hunter

<img src="../images/logo.png" alt="PowerShell-Hunter Logo" width="400" align="center">

<p align="center">
  <br>
  <em>Hunt smarter, hunt harder</em>
</p>

![PowerShell Hunter](https://img.shields.io/badge/PowerShell-Hunter-blue)

## Overview

Prefetch Hunter is a powerful PowerShell tool that analyzes Windows Prefetch files to identify program execution history, frequency, and patterns. Windows Prefetch files are valuable forensic artifacts that contain information about executed programs, including execution timestamps and run counts, making them essential for digital forensics and incident response (DFIR).

## Features

- **Comprehensive Prefetch Analysis**: Extracts execution history, timestamps, and run frequency from Prefetch files
- **LOLBAS Integration**: Automatically identifies "Living Off The Land Binaries and Scripts" that could be abused by attackers
- **Time-Based Analysis**: Detects unusual execution patterns during off-hours and weekends
- **Statistical Analysis**: Identifies outliers based on execution frequency and system baselines
- **Beautiful HTML Reports**: Generates interactive HTML reports with charts, tables, and color-coded categories
- **Multiple Export Formats**: Outputs to HTML, CSV, and JSON for integration with other tools
- **Filtering Options**: Analyze only recent executions or the most frequently run programs
- **No External Dependencies**: Uses only native PowerShell and .NET capabilities

## What's New

- **LOLBAS Project Integration**: Automatically detects and links to known abusable binaries
- **Forensic Categories**: Programs are now classified into specific categories like "System Utility Anomaly" or "Off-Hours Activity"
- **Behavioral Analysis**: Identifies suspicious patterns based on when and how programs are executed
- **Context-Aware Detection**: Understands system baselines to reduce false positives
- **Enhanced Visualization**: Beautiful HTML reports with interactive charts and color-coded categories

## Requirements

- PowerShell 5.1 or later
- Administrator rights (required to access Prefetch files)
- Windows operating system (Windows 7 or later)
- Internet connection (optional, for LOLBAS data retrieval)

## Usage

### Basic Usage

```powershell
# Run with default settings (generates all report formats)
.\Prefetch_Hunter.ps1
```

### Command-Line Parameters

```powershell
# Generate only HTML report
.\Prefetch_Hunter.ps1 -ExportFormat HTML

# Show only programs executed in the last 24 hours
.\Prefetch_Hunter.ps1 -ExecutedInLast24Hours

# Show the top 10 most frequently executed programs
.\Prefetch_Hunter.ps1 -TopExecuted 10

# Show the top 10 most recently executed programs
.\Prefetch_Hunter.ps1 -TopExecuted 10 -SortByLastExecution

# Analyze Prefetch files from an alternative location (like a mounted forensic image)
.\Prefetch_Hunter.ps1 -PrefetchPath "D:\Windows\Prefetch"
```

## Understanding Notable Execution Detection

Prefetch Hunter employs a sophisticated detection mechanism to identify potentially interesting program executions:

1. **LOLBAS Binary Detection**: Identifies Windows binaries documented in the LOLBAS project that can be abused by attackers
2. **Security Tool Detection**: Recognizes known security/hacking tools (e.g., Mimikatz, PsExec)
3. **Time-Based Analysis**: Flags system utilities executed during unusual hours (10PM-5AM)
4. **Statistical Outliers**: Identifies programs with execution frequencies significantly above system baseline
5. **Context Analysis**: Evaluates execution timing patterns (weekends, off-hours) for business software
6. **Recently Introduced Programs**: Highlights new programs with abnormally high usage in their first week

## Understanding Windows Prefetch Files

Windows Prefetch is a performance feature that helps applications start faster by monitoring and storing information about executed programs. For each program execution, Windows creates or updates a Prefetch file (with a `.pf` extension) in the `C:\Windows\Prefetch` directory.

Prefetch filenames follow the format `PROGRAMNAME-HASH.pf`, where:
- `PROGRAMNAME` is the name of the executed program
- `HASH` is a hash value based on the application's path and command-line arguments

Key forensic insights from Prefetch files:
- **Execution Evidence**: Confirms a program was executed on the system
- **Timestamps**: Last modification time indicates the last execution time
- **Run Count**: File size correlates with the number of executions
- **Program Location**: May reveal the original location of executed programs

## How Prefetch Hunter Works

1. **Access Prefetch Directory**: Scans the Windows Prefetch directory for `.pf` files
2. **Extract Metadata**: Analyzes file metadata including timestamps and size
3. **Fetch LOLBAS Data**: Retrieves the latest LOLBAS binaries information
4. **Statistical Analysis**: Establishes baselines for normal system activity
5. **Notable Detection**: Applies heuristics and statistical models to identify notable executions
6. **Report Generation**: Creates comprehensive reports with categorized findings

## Example Output

The HTML report includes:
- Summary statistics (total programs, recent executions, notable count, LOLBAS binaries)
- Interactive chart of most frequently executed programs
- Dedicated sections for LOLBAS binaries and other notable executions
- Color-coded categories and analysis insights
- Complete table of all detected Prefetch files with links to LOLBAS documentation

## Integration with Other Tools

The CSV and JSON outputs can be easily integrated with other forensic tools, SIEM systems, or custom analysis scripts.

## Limitations

- Prefetch must be enabled on the target system (enabled by default on Windows)
- Administrator privileges are required to access the Prefetch directory
- Run count estimation is approximate and not based on the actual Prefetch file format parsing
- LOLBAS integration requires internet connectivity for first-time use

---

<p align="center">
Made with ❤️ by defenders for defenders
</p>