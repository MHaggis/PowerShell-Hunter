# ShellBag Hunter

<img src="../images/logo.png" alt="PowerShell-Hunter Logo" width="400" align="center">

<p align="center">
  <br>
  <em>Hunt smarter, hunt harder</em>
</p>


![PowerShell Hunter](https://img.shields.io/badge/PowerShell-Hunter-blue)

## Overview

ShellBag Hunter is a powerful PowerShell tool that extracts and analyzes Windows ShellBag data from the registry. ShellBags are registry artifacts that store information about folder views and can reveal user browsing history, including evidence of deleted folders that were previously accessed.

## Features

- **Comprehensive ShellBag Analysis**: Extracts folder access history from Windows registry
- **Deleted Folder Detection**: Identifies evidence of deleted folders that were previously accessed
- **Timestamp Analysis**: Extracts and analyzes last modified times for folders
- **Multiple User Support**: Can analyze ShellBags from any user profile via their SID
- **Beautiful Reports**: Generates interactive HTML reports with folder hierarchies and tables
- **Multiple Export Formats**: Outputs to HTML, CSV, and JSON for integration with other tools
- **Flexible Filtering**: Filter by date range, path, or only recent entries
- **Windows 11 Support**: Fallback to Quick Access and Recent Items on Windows 11
- **No External Dependencies**: Uses only native PowerShell and .NET capabilities

## Requirements

- PowerShell 5.1 or later
- Windows operating system
- Access to the Windows Registry

## Usage

### Basic Usage

```powershell
# Run with default settings (generates all report formats)
.\shellBagHunter.ps1
```

### Command-Line Parameters

```powershell
# Generate only HTML report
.\shellBagHunter.ps1 -OutputFormat HTML

# Include potentially deleted folders in the analysis
.\shellBagHunter.ps1 -IncludeDeleted

# Show only ShellBag entries from the last 7 days
.\shellBagHunter.ps1 -DaysBack 7

# Filter results by path
.\shellBagHunter.ps1 -FilterPath "Documents"

# Set a specific date range for analysis
.\shellBagHunter.ps1 -StartDate (Get-Date).AddDays(-30) -EndDate (Get-Date)

# Analyze ShellBags for a specific user SID
.\shellBagHunter.ps1 -UserSID "S-1-5-21-1234567890-1234567890-1234567890-1001"

# Process all available user profiles
.\shellBagHunter.ps1 -ProcessAllUsers
```

## Understanding Windows ShellBags

ShellBags are registry artifacts that store information about how folders are displayed in Windows Explorer. They record folder view settings such as icon size, position, and folder layout. These registry entries are created and updated when a user accesses a folder through Windows Explorer.

ShellBag data is stored in two main registry locations:
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\BagMRU`: Contains the folder paths
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Bags`: Contains view preferences

Key forensic insights from ShellBags:
- **User Activity**: Reveals folders accessed by a user, even if they've been deleted
- **Timestamps**: Can indicate when folders were last accessed
- **Deleted Evidence**: May contain references to folders that no longer exist on the filesystem
- **Folder Navigation**: Shows the hierarchy of folders a user navigated through

## How ShellBag Hunter Works

1. **Access Registry**: Navigates to the ShellBag registry keys
2. **Extract Binary Data**: Decodes binary data in registry values to extract folder paths
3. **Build Folder Hierarchy**: Reconstructs the folder structure from the ShellBag entries
4. **Identify Deleted Folders**: Compares extracted paths against the filesystem to identify deleted folders
5. **Extract Timestamps**: Parses LastWriteTime values to determine when folders were accessed
6. **Windows 11 Support**: Falls back to Quick Access and Recent Items on Windows 11 systems
7. **Report Generation**: Creates comprehensive reports in the selected formats

## Example Output

The HTML report includes:
- Summary statistics (total entries, recent accesses, deleted folder count)
- Recent folder activity from the last 7 days
- Highlighted section for potentially deleted folders
- Visual representation of the folder hierarchy
- Complete table of all detected ShellBag entries

## Forensic Value

ShellBags are extremely valuable for digital forensics and incident response because:
- They persist even after folders are deleted
- They can reveal sensitive folder access even if files were removed
- They can establish a timeline of user folder interaction
- They may reveal external media connections (USB drives, network shares)

## Limitations

- ShellBag entries only reflect folders accessed through Windows Explorer
- Some binary data in ShellBags can be complex to decode
- Timestamps may not always represent the actual folder access time
- Windows 11 has changed how ShellBag data is stored, shifting more data to Quick Access

## References
- [Forensic Analysis of Windows Shellbags](https://www.magnetforensics.com/blog/forensic-analysis-of-windows-shellbags/)
---

<p align="center">
Made with ❤️ by defenders for defenders
</p>