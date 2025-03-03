#requires -version 3.0

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("HTML", "CSV", "JSON", "ALL")]
    [string]$ExportFormat = "ALL"
)

$PcaLogPath = "C:\Windows\appcompat\pca"

$PcaAppLaunchDic = Join-Path -Path $PcaLogPath -ChildPath "PcaAppLaunchDic.txt"
$PcaGeneralDb0 = Join-Path -Path $PcaLogPath -ChildPath "PcaGeneralDb0.txt"

<#
.SYNOPSIS
    Analyzes Program Compatibility Assistant (PCA) logs from Windows systems.

.DESCRIPTION
    This script analyzes PCA logs to identify application execution history, 
    compatibility issues, and generate detailed reports in HTML, CSV, and JSON formats.

.PARAMETER ExportFormat
    The format to export results. Accepts: HTML, CSV, JSON, or ALL. Default is ALL.

.NOTES
    File Name      : PCA_Analyzer.ps1
    Prerequisite   : PowerShell 5.1 or later
    Author         : The Haag
    
.EXAMPLE
    .\PCA_Analyzer.ps1 -ExportFormat HTML
    Analyzes PCA data and generates only an HTML report.

.EXAMPLE
    .\PCA_Analyzer.ps1
    Analyzes PCA data and generates all report formats (HTML, CSV, JSON).

.LINK
    https://github.com/MHaggis/PowerShell-Hunter
#>

$AsciiArt = @"
    +-+-+-+ 
    |P|C|A| 
    +-+-+-+ 
                                                                           
 +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+
 |P|o|w|e|r|S|h|e|l|l| |H|U|N|T|E|R|
 +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+

        [ Hunt smarter, Hunt harder ]
"@

Write-Host $AsciiArt -ForegroundColor Cyan
Write-Host "`nPCA Data Analysis Tool" -ForegroundColor Green
Write-Host "------------------------`n" -ForegroundColor DarkGray

# Function to parse PcaAppLaunchDic.txt (Application Execution Log)
function Parse-PcaAppLaunchDic {
    if (Test-Path $PcaAppLaunchDic) {
        Get-Content $PcaAppLaunchDic | ForEach-Object {
            $parts = $_ -split "\|"
            if ($parts.Length -eq 2) {
                [PSCustomObject]@{
                    ExecutablePath    = $parts[0]
                    LastExecutionTime = [datetime]$parts[1]
                }
            }
        }
    } else {
        Write-Warning "$PcaAppLaunchDic not found."
    }
}

# Function to parse PcaGeneralDb0.txt (Abnormal Process Exits & Compatibility Logs)
function Parse-PcaGeneralDb0 {
    if (Test-Path $PcaGeneralDb0) {
        Get-Content $PcaGeneralDb0 -Encoding Unicode | ForEach-Object {
            $parts = $_ -split "\|"
            if ($parts.Length -ge 7) {
                [PSCustomObject]@{
                    Timestamp      = [datetime]$parts[0]
                    RecordType     = $parts[1]
                    ExecutablePath = $parts[2]
                    ProductName    = $parts[3]
                    CompanyName    = $parts[4]
                    ProductVersion = $parts[5]
                    ProgramID      = $parts[6]
                    Message        = $parts[7]
                }
            }
        }
    } else {
        Write-Warning "$PcaGeneralDb0 not found."
    }
}

function Export-ResultsToFormats {
    param(
        [array]$AppLaunchData,
        [array]$GeneralDbData,
        [string]$ExportFormat,
        [string]$BasePath
    )
    
    $Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $ExportBaseName = "$BasePath`_$Timestamp"
    $AllData = $AppLaunchData + $GeneralDbData
    $HtmlPath = "$ExportBaseName.html"
    
    if ($AllData) {
        if ($ExportFormat -eq "CSV" -or $ExportFormat -eq "ALL") {
            $CSVPath = "$ExportBaseName.csv"
            $AllData | Export-Csv -Path $CSVPath -NoTypeInformation
            Write-Host "`nData exported to CSV: $CSVPath" -ForegroundColor Green
        }
        
        if ($ExportFormat -eq "JSON" -or $ExportFormat -eq "ALL") {
            $JSONPath = "$ExportBaseName.json"
            $AllData | ConvertTo-Json -Depth 4 | Out-File $JSONPath
            Write-Host "Data exported to JSON: $JSONPath" -ForegroundColor Green
        }
        
        Create-HtmlReport -AppLaunchData $AppLaunchData -GeneralDbData $GeneralDbData -HtmlPath $HtmlPath
        Write-Host "HTML report generated: $HtmlPath" -ForegroundColor Green
        
        return $HtmlPath
    } else {
        Write-Host "No data to export." -ForegroundColor Yellow
        return $null
    }
}

function Create-HtmlReport {
    param(
        [array]$AppLaunchData,
        [array]$GeneralDbData,
        [string]$HtmlPath
    )
    
    $Css = @"
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #0078D7;
        }
        h1 {
            text-align: center;
            padding-bottom: 10px;
            border-bottom: 2px solid #0078D7;
            margin-bottom: 30px;
        }
        .section {
            margin-bottom: 30px;
            padding: 15px;
            background-color: #f9f9f9;
            border-radius: 5px;
            border-left: 5px solid #0078D7;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th {
            background-color: #0078D7;
            color: white;
            padding: 12px;
            text-align: left;
        }
        td {
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        tr:hover {
            background-color: #e6f3ff;
        }
        .summary {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            margin-bottom: 20px;
        }
        .stat-box {
            flex: 1;
            min-width: 200px;
            margin: 10px;
            padding: 15px;
            background-color: #e6f3ff;
            border-radius: 5px;
            text-align: center;
            box-shadow: 0 0 5px rgba(0,0,0,0.05);
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #0078D7;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            font-size: 12px;
            color: #777;
        }
        .path-column {
            max-width: 500px;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
    </style>
"@

    $ChartJs = @"
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
"@

    $HtmlContent = @"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PCA Analysis Report - $(Get-Date -Format 'yyyyMMdd_HHmmss')</title>
        $Css
        $ChartJs
    </head>
    <body>
        <div class="container">
            <h1>Program Compatibility Assistant (PCA) Analysis Report</h1>
            <p>Report generated on $(Get-Date -Format 'dddd, MMMM dd, yyyy HH:mm:ss')</p>
            
            <div class="summary">
"@

    if ($AppLaunchData) {
        $AppCount = ($AppLaunchData | Measure-Object).Count
        $RecentExecution = ($AppLaunchData | Sort-Object LastExecutionTime -Descending | Select-Object -First 1).LastExecutionTime
        
        $HtmlContent += @"
                <div class="stat-box">
                    <div>Total Applications</div>
                    <div class="stat-value">$AppCount</div>
                </div>
                <div class="stat-box">
                    <div>Most Recent Execution</div>
                    <div class="stat-value">$($RecentExecution.ToString("MM/dd/yyyy"))</div>
                </div>
"@
    }

    if ($GeneralDbData) {
        $EventCount = ($GeneralDbData | Measure-Object).Count
        $RecordTypes = $GeneralDbData | Group-Object RecordType | Select-Object Name, Count
        
        $HtmlContent += @"
                <div class="stat-box">
                    <div>Total PCA Events</div>
                    <div class="stat-value">$EventCount</div>
                </div>
"@
    }

    $HtmlContent += @"
            </div>
"@

    $HtmlContent += @"
            <div class="section">
                <h2>PCA Application Execution Log</h2>
"@

    if ($AppLaunchData) {
        $AppLaunchHtml = $AppLaunchData | Sort-Object LastExecutionTime -Descending | ConvertTo-Html -Fragment -Property ExecutablePath, LastExecutionTime
        $AppLaunchHtml = $AppLaunchHtml -replace "<td>([^<]*)</td>", "<td class=`"path-column`">`$1</td>"
        $HtmlContent += $AppLaunchHtml
    } else {
        $HtmlContent += "<p>No execution data found.</p>"
    }

    $HtmlContent += @"
            </div>

            <div class="section">
                <h2>PCA Process Events & Abnormal Exits</h2>
"@

    if ($GeneralDbData) {
        $GeneralDbHtml = $GeneralDbData | Sort-Object Timestamp -Descending | ConvertTo-Html -Fragment
        $GeneralDbHtml = $GeneralDbHtml -replace "<td>([^<]*)</td>", "<td class=`"path-column`">`$1</td>"
        $HtmlContent += $GeneralDbHtml
    } else {
        $HtmlContent += "<p>No process event data found.</p>"
    }

    $HtmlContent += @"
            </div>

            <div class="footer">
                <p>Generated by PCA_Analyzer.ps1 - PowerShell Hunter Project</p>
                <p>$(Get-Date -Format 'dddd, MMMM dd, yyyy HH:mm:ss')</p>
            </div>
        </div>
"@

    $HtmlContent += @"
    </body>
    </html>
"@

    $HtmlContent | Out-File -FilePath $HtmlPath -Encoding UTF8
}

Write-Host "Parsing PCA logs..." -ForegroundColor Yellow

$AppLaunchData = Parse-PcaAppLaunchDic
$GeneralDbData = Parse-PcaGeneralDb0

Write-Host "`nPCA Application Execution Log (PcaAppLaunchDic.txt):" -ForegroundColor Cyan
if ($AppLaunchData) {
    $AppLaunchData | Sort-Object LastExecutionTime -Descending | Format-Table -AutoSize -Wrap
} else {
    Write-Host "No execution data found." -ForegroundColor Yellow
}

Write-Host "`nPCA Process Events & Abnormal Exits (PcaGeneralDb0.txt):" -ForegroundColor Cyan
if ($GeneralDbData) {
    $GeneralDbData | Sort-Object Timestamp -Descending | Format-Table -AutoSize -Wrap
} else {
    Write-Host "No process event data found." -ForegroundColor Yellow
}

$HtmlReportPath = Export-ResultsToFormats `
    -AppLaunchData $AppLaunchData `
    -GeneralDbData $GeneralDbData `
    -ExportFormat $ExportFormat `
    -BasePath "$env:USERPROFILE\Desktop\PCA_Analysis"

if ($HtmlReportPath -and (Test-Path $HtmlReportPath)) {
    Write-Host "`nOpening HTML report..." -ForegroundColor Cyan
    Start-Process $HtmlReportPath
}

Write-Host "`nPCA Analysis complete!" -ForegroundColor Green