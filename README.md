# PowerShell-Hunter 🎯

<img src="images/logo.png" alt="PowerShell-Hunter Logo" width="400" align="center">

<p align="center">
  <br>
  <em>Hunt smarter, hunt harder</em>
</p>

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-%3E%3D5.1-blue)](https://github.com/PowerShell/PowerShell)

## About PowerShell-Hunter

PowerShell-Hunter is a growing collection of PowerShell-based threat hunting tools designed to help defenders investigate and detect malicious activity in Windows environments. This project aims to provide security analysts with powerful, flexible tools that leverage PowerShell's native capabilities for threat hunting.

### Current Tools

#### 🔍 PowerShell 4104 Event Analysis
PowerShell is both a powerful administrative tool and a favorite weapon for attackers. While its extensive logging capabilities are great for security, the sheer volume of logs can be overwhelming. The PowerShell 4104 Event Analyzer helps defenders cut through the noise and focus on what matters.

Key Benefits:
- 🔍 **Smart Pattern Detection**: Pre-configured patterns catch common attack techniques
- 📊 **Risk Scoring**: Prioritize investigation with weighted scoring system
- 🚀 **Performance Optimized**: Efficiently process thousands of events
- 📝 **Flexible Output**: Export to CSV or JSON for further analysis
- 🛠 **Extensible**: Easy to add custom detection patterns

➡️ [Learn more about PowerShell 4104 Event Analysis](PowerShell%204104/README.md) ⬅️

#### 🛡️ Active Directory Threat Hunting
A comprehensive tool for detecting and analyzing suspicious activities in Active Directory environments. Features real-time detection of password sprays, brute force attempts, and account lockouts with advanced timing analysis.

Key Features:
- 🚨 **Attack Detection**: Identify password sprays, brute force, and suspicious patterns
- ⚡ **Smart Analysis**: Timing-based detection and pattern recognition
- 📊 **Visual Reporting**: Detailed timelines and attack pattern visualization
- 🧪 **Test Framework**: Built-in simulation tools for testing and validation
- 🔄 **Flexible Collection**: Support for WinRM and RPC-based event collection

➡️ [Learn more about AD Threat Hunting](AD-ThreatHunting/README.md) ⬅️

#### 🔄 MRU (Most Recently Used) Analysis
A powerful tool for extracting and analyzing Windows Registry MRU entries to reveal user activity patterns and potentially suspicious file access. Provides deep visibility into recently accessed files and applications.

Key Features:
- 🔍 **Deep Registry Analysis**: Extract MRU data from multiple registry locations
- 📂 **PIDL Decoding**: Parse complex binary structures for full file paths
- ⏱️ **Chronological Tracking**: Order events by access time
- 🎯 **Smart Detection**: Identify suspicious file access patterns
- 📊 **Multiple Output Formats**: Export findings in various formats
- 🔄 **Comprehensive Coverage**: Track both files and applications

➡️ [Learn more about MRU Analysis](MRUHunt/README.md) ⬅️

#### 📊 BAM (Background Activity Moderator) Analysis
A forensics utility that extracts and analyzes Windows BAM data to track application execution history and establish user activity timelines. Essential for incident response and digital forensics.

Key Features:
- 🕒 **Timeline Analysis**: Track application execution times
- 👤 **User Activity Mapping**: Correlate actions with users
- 🔍 **Signature Verification**: Validate process authenticity
- 📊 **Multiple Export Options**: CSV, JSON, and HTML reports
- 🎯 **Pattern Detection**: Identify suspicious execution patterns
- 🔄 **Cross-System Correlation**: Link activities across systems

➡️ [Learn more about BAM Analysis](BAM/README.md) ⬅️


## Project Vision

PowerShell-Hunter will continue to expand with new tools and capabilities focused on Windows-based threat hunting. Planned areas include:

- 🔍 Further Windows Event Log Analysis
- 🔧 Other random things

### Getting Started

Each tool in the PowerShell-Hunter collection has its own documentation and usage instructions. See the respective README files in each directory for detailed information.

### Prerequisites

- PowerShell 5.1 or higher
- Administrator access (for certain operations)
- Windows environment
- Tool-specific requirements detailed in individual READMEs

### Contributing

We welcome contributions! Whether it's:
- Adding new hunting tools
- Improving existing detection patterns
- Enhancing documentation
- Reporting bugs
- Suggesting features

## Roadmap 🗺️

- [x] PowerShell 4104 Event Analysis
- [x] Active Directory Threat Hunting
- [ ] Integration with SIEM systems
- [ ] Machine Learning-based anomaly detection
- [ ] Other random things, why not?

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by the need for efficient Windows-based threat hunting
- Built on the experience of security practitioners
- Leverages community-contributed detection patterns
- Pattern [database](https://research.splunk.com/endpoint/d6f2b006-0041-11ec-8885-acde48001122/)

---

<p align="center">
Made with ❤️ by defenders for defenders
</p>
