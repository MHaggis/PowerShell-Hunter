# Get-MRU

<img src="../images/logo.png" alt="PowerShell-Hunter Logo" width="400" align="center">

<p align="center">
  <br>
  <em>Hunt smarter, hunt harder</em>
</p>

A PowerShell script that extracts Most Recently Used (MRU) entries from the Windows Registry. This tool helps forensic analysts and threat hunters investigate user activity by revealing recently accessed files and applications.

## Description

Get-MRU.ps1 decodes and displays MRU entries from the following registry locations:

```powershell
HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\
├── OpenSavePidlMRU      # Recent files accessed through Open/Save dialogs
├── LastVisitedPidlMRU   # Recent applications that showed Open/Save dialogs
└── CIDSizeMRU           # Recent applications with window size information
```

## Features

- Decodes both Unicode strings and binary PIDL (Pointer IDentifier List) data
- Shows items in chronological order (most recent first)
- Displays full paths to accessed files when available
- Lists applications that were recently used to open or save files
- Dynamic file extension detection (no hardcoded extension filtering)
- Handles complex PIDL structures and various encoding formats
- Color-coded output for better readability

## Usage

```powershell
.\Get-MRU.ps1
```

## Example Output

```
=== Windows MRU (Most Recently Used) Data ===
================================================

Registry Key: CIDSizeMRU
Last Modified: 2025-01-14 20:54:21

Most Recent Items:
  [0] PowerShell_ISE.exe
  [1] devenv.exe

All Stored Items:
  1: devenv.exe
  0: PowerShell_ISE.exe

================================================

Registry Key: LastVisitedPidlMRU
Last Modified: 2025-01-14 20:54:21

Most Recent Items:
  [0] PowerShell_ISE.exe
  [1] devenv.exe

All Stored Items:
  1: devenv.exe
  0: PowerShell_ISE.exe

================================================
```

## Why This Matters

MRU entries are valuable artifacts for:
- Digital Forensics: Reconstructing user activity
- Incident Response: Identifying potentially malicious file access
- Threat Hunting: Detecting unusual application usage patterns

The Windows Registry's ComDlg32 keys maintain records of:
- Files opened or saved through standard Windows dialogs
- Applications that displayed these dialogs
- The order in which these actions occurred
- File types and extensions commonly used

## Advanced Features

- Intelligent PIDL parsing for complex file path structures
- Robust Unicode and ASCII string decoding
- Automatic detection of valid filenames and paths
- Comprehensive error handling and verbose logging options
- Support for various file types and extensions

## Requirements

- Windows Operating System
- PowerShell
- Administrative privileges (recommended)

## Diagnostic Tools

The repository includes `Analyze-MRURegistry.ps1`, a diagnostic script that provides detailed analysis of MRU registry entries, including:
- Hex dumps of binary data
- Multiple encoding attempts (Unicode, ASCII)
- PIDL structure analysis
- Detailed logging for troubleshooting

## References

- [SANS - OpenSaveMRU and LastVisitedMRU](https://www.sans.org/blog/opensavemru-and-lastvisitedmru/)
- [Windows Registry Forensics](https://www.sciencedirect.com/book/9780128032916/windows-registry-forensics)

## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

---

<p align="center">
Made with ❤️ by defenders for defenders
</p>
