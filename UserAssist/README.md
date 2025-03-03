# UserAssist Registry Analyzer

<img src="../images/logo.png" alt="PowerShell-Hunter Logo" width="400" align="center">

<p align="center">
  <br>
  <em>Hunt smarter, hunt harder</em>
</p>


## Overview

The UserAssist Registry Analyzer is a powerful PowerShell forensic tool designed to extract, decode, and analyze UserAssist registry keys in Windows systems. These keys maintain a record of application executions and user interactions, making them invaluable for digital forensics, incident response, and user activity tracking.

## Forensic Significance

UserAssist registry keys are a critical artifact in Windows forensics for several reasons:

- **Evidence of Program Execution**: Provides conclusive evidence that specific applications were launched by a user
- **Execution Timeline**: Records timestamps of application launches, allowing for temporal analysis
- **Frequency Analysis**: Tracks the number of times applications were executed
- **User Behavior Insights**: Reveals patterns of software usage and user activities
- **Anti-Forensics Detection**: Modifications to these keys may indicate attempts to conceal activity

These registry keys persist even after temporary files are deleted, making them valuable for reconstructing user activities during investigations.

## Technical Details

### Registry Locations

UserAssist keys are stored in the following registry path:

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
```

The GUIDs typically correspond to:

- **CEBFF5CD-ACE2-4F4F-9178-9926F41749EA**: Executable file execution
- **F4E57C4B-2036-45F0-A9AB-443BCFE33D9F**: Shortcut file execution

### Data Structure

Each UserAssist entry contains binary data with the following structure:

- **Bytes 0-3**: Session ID
- **Bytes 4-7**: Run count (32-bit integer)
- **Bytes 8-15**: Last execution time (64-bit FILETIME)
- **Bytes 16-19**: Focus count (32-bit integer) 
- **Bytes 60-67**: Focus time (64-bit FILETIME)

The entry names are obfuscated using ROT13 encoding (a simple character rotation cipher).

### Windows Version Compatibility

The tool supports extracting UserAssist data from:
- Windows 7
- Windows 8/8.1
- Windows 10
- Windows 11

The binary data structure may vary slightly between Windows versions, which the tool handles automatically.

## Installation

No installation is required. Simply download the script to your forensic workstation.

### Requirements

- PowerShell 5.1 or later
- Administrator privileges (to access registry)
- Windows operating system

## Usage

```powershell
# Basic usage (exports to current directory)
.\UserAssist_Hunt.ps1

# Output files will be saved to .\UserAssist_Collection\ with timestamped filenames
```

The script automatically creates a "UserAssist_Collection" directory to store all output files.

### Output Formats

The tool exports data in three formats:

1. **JSON** (UserAssist_[timestamp].json)
   - Complete structured data with all metadata
   - Ideal for programmatic analysis or importing into analysis platforms
   
2. **CSV** (UserAssist_[timestamp].csv)
   - Tabular format for spreadsheet analysis
   - Compatible with Excel, Google Sheets, etc.
   
3. **HTML** (UserAssist_[timestamp].html)
   - Interactive, styled report with sortable columns
   - Provides an immediate visual representation of findings
   - Can be opened in any modern web browser

## Data Interpretation

### Decoded Fields

The tool extracts and presents the following data for each UserAssist entry:

- **GUID**: The category identifier for the entry
- **EncodedName**: The original ROT13-encoded name from the registry
- **DecodedName**: The properly decoded application name/path
- **RunCount**: Number of times the application was executed
- **LastRunTime**: The last time the application was executed
- **FocusCount**: Number of times the application received focus
- **FocusTime**: Duration the application had focus
- **RawData**: Base64-encoded binary data for further analysis

### Path Prefixes

Decoded paths often include special prefixes that indicate the type of execution:

- **UEME_RUNPATH**: Program execution via direct path
- **UEME_RUNPIDL**: Program execution via Windows shell object
- **UEME_RUNCPL**: Control Panel applet execution
- **UEME_UITOOLBAR**: Toolbar button interaction
- **UEME_UIHOTKEY**: Application launched via hotkey
- **UEME_UISCUT**: Application launched via shortcut

### Common Analysis Scenarios

1. **Timeline Reconstruction**:
   - Sort entries by LastRunTime to recreate a timeline of user activities
   
2. **Application Usage Patterns**:
   - Identify frequently used applications by analyzing RunCount values
   
3. **Unusual Activity Detection**:
   - Identify applications executed at unusual times or with anomalous patterns
   
4. **Anti-Forensics Identification**:
   - Look for inconsistencies in timestamps or missing entries that might indicate tampering

## Integration with Other Tools

UserAssist data can be effectively combined with other forensic artifacts:

- **Prefetch Files**: Cross-reference execution times
- **Windows Event Logs**: Correlate with logon/logoff events
- **Jump Lists**: Compare with recently accessed documents
- **Browser History**: Build comprehensive user activity timelines
- **BAM/DAM Data**: Compare with other application execution records

## Troubleshooting

If you encounter issues:

1. **Ensure Administrator Privileges**: The script requires elevated permissions to access registry keys
2. **Registry Access Errors**: Some security tools may restrict registry access
3. **Empty Results**: Some systems may have UserAssist tracking disabled via Group Policy
4. **Corrupted Data**: Malware or system issues can occasionally corrupt registry entries

## Part of PowerShell-Hunter Project

This tool is designed to aid in forensic analysis by extracting and presenting UserAssist data in an easily analyzable format. It is part of the broader PowerShell-Hunter toolkit for Windows forensic artifact collection and analysis.

## References and Further Reading

- https://www.magnetforensics.com/blog/artifact-profile-userassist/
- https://docs.velociraptor.app/artifact_references/pages/windows.registry.userassist

---

<p align="center">
Made with ❤️ by defenders for defenders
</p>