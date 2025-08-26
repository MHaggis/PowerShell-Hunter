# JumpList Analyzer

<img src="./images/jumpyexplo.png" alt="PowerShell-Hunter Logo" width="400" align="center">

<p align="center">
  <br>
  <em>Hunt smarter, hunt harder</em>
</p>

PowerShell-Hunter's JumpList analyzer is a forensic tool for examining Windows Jump List artifacts. It parses both .automaticDestinations-ms and .customDestinations-ms files to extract valuable forensic data including file paths, timestamps, and command-line arguments.

## Key Features

- **Comprehensive metadata extraction** from Jump List streams
- **Memory carving** to recover deleted Jump List entries
- **Timeline analysis** with filtering by date ranges
- **Rich reporting** in HTML, CSV, and JSON formats
- **Correlation with other artifacts** (Prefetch, UserAssist, Registry)
- **Fully documented forensic output** with hashes and data provenance

## What are Jump Lists?

Jump Lists are a Windows feature introduced in Windows 7 that track recently and frequently used applications and files. They serve as an artifact source for digital forensics, containing:

- Recently opened files
- Application execution history
- Timestamps of file access
- Evidence of deleted files (through carving)

The feature persists even after files are deleted from the file system, making it valuable for forensic investigations.

## Usage

```powershell
# Basic analysis of current user's Jump Lists
.\JumpyExplo.ps1

# Analysis with carving for deleted entries
.\JumpyExplo.ps1 -Carve

# Analysis with date filtering
.\JumpyExplo.ps1 -StartDate "2023-01-01" -EndDate "2023-12-31"

# Advanced forensic carving with deep analysis and slack space examination
.\JumpyExplo.ps1 -Carve -Deep -IncludeSlack

# Analysis of another user's Jump Lists with carving and related artifact discovery
.\JumpyExplo.ps1 -AutoDestinationsPath "C:\Users\Suspect\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" -CustomDestinationsPath "C:\Users\Suspect\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations" -Carve -FindRelated
```

### Parameters

- `-AutoDestinationsPath`: Path to automatic destinations files (default: current user's profile)
- `-CustomDestinationsPath`: Path to custom destinations files (default: current user's profile)
- `-OutputDir`: Directory to save reports (default: current directory)
- `-DebugMode`: Enable detailed debug output
- `-NoExport`: Don't export results, only display in console
- `-StartDate`: Filter entries after this date (yyyy-MM-dd format)
- `-EndDate`: Filter entries before this date (yyyy-MM-dd format)
- `-FindRelated`: Search for related artifacts (Prefetch, Registry entries, UserAssist)
- `-Carve`: Recover deleted Jump List entries using memory carving techniques
- `-Deep`: Use deep analysis mode when carving (finds shell items outside of LNK structures)
- `-IncludeSlack`: Examine file slack space for additional recoverable data
- `-Help`: Display the help message with examples

## Carving for Deleted Entries

The JumpList analyzer can recover deleted Jump List entries through memory carving. This capability allows forensic investigators to uncover evidence that would otherwise be unavailable.

To enable carving, use the `-Carve` parameter:

```powershell
.\JumpyExplo.ps1 -Carve
```

Note that carving operations are resource-intensive and will only run when explicitly requested. Carved entries will be included in the exported reports and clearly marked as recovered artifacts.

### Advanced Carving Options

PowerShell-Hunter offers advanced carving options for more comprehensive forensic recovery:

- **Basic Carving** (`-Carve`): Searches for complete LNK file structures in Jump List files by looking for the standard LNK file header signature (`4C 00 00 00`) followed by the Shell Link CLSID. This mode recovers intact LNK entries that have been deleted but not yet overwritten.
  ```powershell
  .\JumpyExplo.ps1 -Carve
  ```

- **Deep Mode** (`-Carve -Deep`): Goes beyond looking for complete LNK files and also searches for shell item signatures, which are components inside LNK files. Shell items contain information about folders, files, drives, and network locations. This can recover partial evidence even when full LNK structures are damaged or fragmented.
  ```powershell
  .\JumpyExplo.ps1 -Carve -Deep
  ```
  *What you'll recover*: File and folder names, drive letters, and partial paths that may not be associated with intact LNK structures.

- **Slack Space Analysis** (`-Carve -IncludeSlack`): Examines the "file slack" - the unused space between the logical end of the file and the end of the allocated disk cluster. When files are deleted, remnants of their data can persist in this slack space. This technique can recover data from previously deleted files that existed in the same disk location.
  ```powershell
  .\JumpyExplo.ps1 -Carve -IncludeSlack
  ```
  *What you'll recover*: Fragments of Jump List data that may have been partially overwritten or that existed in previous versions of the file.

- **Combined Analysis** (`-Carve -Deep -IncludeSlack`): Provides the most thorough recovery by combining all carving techniques. This is the most comprehensive but also the most resource-intensive option.
  ```powershell
  .\JumpyExplo.ps1 -Carve -Deep -IncludeSlack
  ```
  *What you'll recover*: Maximum possible data recovery, including complete LNK structures, partial shell items, and fragments from slack space.

#### Technical Details of Recovery Methods

| Carving Mode | Target Data | Search Method | Best Used When | Limitations |
|--------------|-------------|---------------|----------------|-------------|
| Basic `-Carve` | Complete LNK structures | LNK header signatures | Initial investigation | Only finds intact entries |
| Deep `-Deep` | Shell items within and outside LNK files | Shell item type identifiers | Main evidence is fragmented | May produce false positives |
| Slack `-IncludeSlack` | Data in unused space at end of clusters | Analysis of file tail and slack space | Critical to recover every fragment | Resource-intensive |
| Combined | All of the above | Comprehensive scanning | Forensic investigations where recovery is critical | Slowest performance |

Each method has different forensic implications and reliability:

1. **Basic carving** provides high confidence results - when a complete LNK structure is found, it's almost certainly a real deleted Jump List entry.

2. **Deep mode** may find fragments that basic carving misses, but with lower confidence - some shell items might be legitimate file system structures that aren't from Jump Lists.

3. **Slack space analysis** provides the lowest confidence but potentially the most interesting results - it can recover data that has been partially overwritten, which might be the only remaining evidence of certain activities.

These options are particularly valuable in forensic investigations where maximizing data recovery is critical.

## Reports and Visualization

The tool provides comprehensive reporting capabilities:

- **HTML Reports**: Interactive reports with collapsible sections and filtering capabilities
- **CSV Export**: For easy import into spreadsheet applications or other analysis tools
- **JSON Export**: For programmatic analysis or integration with other tools

All reports include detailed metadata about each Jump List entry, file paths, timestamps, and additional context when available.

## Module Structure

The analyzer is modular by design:

- `JumpList-Core.psm1`: Core functionality and helpers
- `JumpList-Parser.psm1`: Parsing logic for Jump List file formats
- `JumpList-Container.psm1`: Container file handling (Compound files)
- `JumpList-Analysis.psm1`: Analysis and reporting functions

## Requirements

- PowerShell 5.1 or higher
- Windows operating system
- No external dependencies required

## References

- https://github.com/EricZimmerman/JLECmd
- https://www.huntress.com/blog/brute-force-or-something-more-ransomware-initial-access-brokers-exposed

## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

---

<p align="center">
Made with ❤️ by defenders for defenders
</p> 