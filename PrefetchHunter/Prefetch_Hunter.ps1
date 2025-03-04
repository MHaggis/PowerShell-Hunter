param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("HTML", "CSV", "JSON", "ALL")]
    [string]$ExportFormat = "ALL",

    [Parameter(Mandatory=$false)]
    [string]$PrefetchPath = "C:\Windows\Prefetch",

    [Parameter(Mandatory=$false)]
    [switch]$SortByLastExecution,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExecutedInLast24Hours,
    
    [Parameter(Mandatory=$false)]
    [int]$TopExecuted = 0
)

<#
.SYNOPSIS
    Analyzes Windows Prefetch files to identify program execution history.

.DESCRIPTION
    This script extracts and analyzes Windows Prefetch files to identify application execution
    history, frequency, and patterns. It can generate detailed reports in HTML, CSV, and JSON formats.

.PARAMETER ExportFormat
    The format to export results. Accepts: HTML, CSV, JSON, or ALL. Default is ALL.

.PARAMETER PrefetchPath
    The path to the Prefetch directory. Default is "C:\Windows\Prefetch".

.PARAMETER SortByLastExecution
    If specified, results will be sorted by last execution time instead of execution count.

.PARAMETER ExecutedInLast24Hours
    If specified, only shows programs executed in the last 24 hours.

.PARAMETER TopExecuted
    If specified, only shows the top N most executed programs. Default is 0 (show all).

.NOTES
    File Name      : Prefetch_Hunter.ps1
    Prerequisite   : PowerShell 5.1 or later, Administrator rights
    Author         : The Haag
    
.EXAMPLE
    .\Prefetch_Hunter.ps1 -ExportFormat HTML
    Analyzes Prefetch data and generates only an HTML report.

.EXAMPLE
    .\Prefetch_Hunter.ps1 -TopExecuted 10 -SortByLastExecution
    Shows the top 10 most recently executed programs and generates all report formats.

.EXAMPLE
    .\Prefetch_Hunter.ps1 -ExecutedInLast24Hours
    Shows only programs executed in the last 24 hours and generates all report formats.

.LINK
    https://github.com/MHaggis/PowerShell-Hunter
#>

$AsciiArt = @"
    +-+-+-+-+-+-+-+-+ 
    |P|r|e|f|e|t|c|h| 
    +-+-+-+-+-+-+-+-+ 
                                                                           
 +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+
 |P|o|w|e|r|S|h|e|l|l| |H|U|N|T|E|R|
 +-+-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+

        [ Hunt smarter, Hunt harder ]
"@

Write-Host $AsciiArt -ForegroundColor Cyan
Write-Host "`nPrefetch Data Analysis Tool" -ForegroundColor Green
Write-Host "----------------------------`n" -ForegroundColor DarkGray

function Test-Administrator {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($user)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Warning "This script requires Administrator privileges to access Prefetch files!"
    exit
}

# parse prefetch files
function Parse-PrefetchFiles {
    param(
        [string]$PrefetchPath,
        [switch]$SortByLastExecution,
        [switch]$ExecutedInLast24Hours,
        [int]$TopExecuted = 0
    )
    
    Write-Host "Analyzing Prefetch files from $PrefetchPath..." -ForegroundColor Yellow

    if (-not (Test-Path -Path $PrefetchPath)) {
        Write-Warning "Prefetch directory not found at $PrefetchPath"
        return @()
    }
    
    $prefetchFiles = Get-ChildItem -Path $PrefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue
    
    if ($prefetchFiles.Count -eq 0) {
        Write-Warning "No prefetch files found in $PrefetchPath"
        return @()
    }
    
    Write-Host "Found $($prefetchFiles.Count) prefetch files. Extracting data..." -ForegroundColor Green
    
    $results = @()
    
    foreach ($file in $prefetchFiles) {
        try {
            $programName = ($file.Name -split '-')[0]
            $fileInfo = Get-ItemProperty -Path $file.FullName
            
            $prefetchInfo = [PSCustomObject]@{
                ProgramName      = $programName
                LastExecution    = $fileInfo.LastWriteTime
                CreationTime     = $fileInfo.CreationTime
                PrefetchFile     = $file.Name
                PrefetchSize     = "{0:N2} KB" -f ($file.Length / 1KB)
                FilePath         = $file.FullName
                SizeInBytes      = $file.Length
                AccessTime       = $fileInfo.LastAccessTime
                HashValue        = ($file.Name -split '-')[1] -replace ".pf", ""
                RunCount         = $null
                DaysSinceCreated = [math]::Round(((Get-Date) - $fileInfo.CreationTime).TotalDays, 1)
                DaysSinceLastRun = [math]::Round(((Get-Date) - $fileInfo.LastWriteTime).TotalDays, 1)
                RunsPerDay       = $null
            }
            
            $baseSize = 2KB  # Minimum size for a prefetch file
            $estimatedRunCount = [math]::Max(1, [math]::Round(($file.Length - $baseSize) / 512) + 1)
            $prefetchInfo.RunCount = $estimatedRunCount
            
            if ($prefetchInfo.DaysSinceCreated -gt 0) {
                $prefetchInfo.RunsPerDay = [math]::Round($estimatedRunCount / $prefetchInfo.DaysSinceCreated, 2)
            } else {
                $prefetchInfo.RunsPerDay = $estimatedRunCount
            }
            
            $results += $prefetchInfo
        }
        catch {
            Write-Warning "Error processing $($file.Name): $_"
        }
    }
    
    if ($ExecutedInLast24Hours) {
        $cutoffTime = (Get-Date).AddDays(-1)
        $results = $results | Where-Object { $_.LastExecution -gt $cutoffTime }
        Write-Host "Filtered to $($results.Count) programs executed in the last 24 hours." -ForegroundColor Yellow
    }
    
    if ($SortByLastExecution) {
        $results = $results | Sort-Object -Property LastExecution -Descending
    } else {
        $results = $results | Sort-Object -Property RunCount -Descending
    }
    
    if ($TopExecuted -gt 0 -and $results.Count -gt $TopExecuted) {
        $results = $results | Select-Object -First $TopExecuted
        Write-Host "Showing top $TopExecuted programs." -ForegroundColor Yellow
    }
    
    return $results
}

function Get-NotableExecutions {
    param(
        [array]$PrefetchData
    )
    
    $notable = @()
    
    # Get baseline statistics
    $avgRunsPerDay = ($PrefetchData | Measure-Object -Property RunsPerDay -Average).Average
    $stdDevRunsPerDay = [Math]::Sqrt(($PrefetchData | ForEach-Object { [Math]::Pow(($_.RunsPerDay - $avgRunsPerDay), 2) } | Measure-Object -Average).Average)
    
    # Calculate time-based statistics
    $executionsByHour = @{}
    foreach ($item in $PrefetchData) {
        $hour = $item.LastExecution.Hour
        if (-not $executionsByHour.ContainsKey($hour)) {
            $executionsByHour[$hour] = 0
        }
        $executionsByHour[$hour]++
    }
    
    # Calculate average executions per hour
    $avgExecPerHour = ($executionsByHour.Values | Measure-Object -Average).Average
    $stdDevExecPerHour = [Math]::Sqrt(($executionsByHour.Values | ForEach-Object { [Math]::Pow(($_ - $avgExecPerHour), 2) } | Measure-Object -Average).Average)
    
    # Identify off-hours with unusual activity (2+ standard deviations)
    $unusualHours = @()
    foreach ($hour in $executionsByHour.Keys) {
        if (($hour -ge 22 -or $hour -le 5) -and ($executionsByHour[$hour] -gt ($avgExecPerHour + (2 * $stdDevExecPerHour)))) {
            $unusualHours += $hour
        }
    }
    
    # Get first-seen dates for all programs
    $firstSeenDates = @{}
    foreach ($item in $PrefetchData) {
        if (-not $firstSeenDates.ContainsKey($item.ProgramName)) {
            $firstSeenDates[$item.ProgramName] = $item.CreationTime
        } elseif ($item.CreationTime -lt $firstSeenDates[$item.ProgramName]) {
            $firstSeenDates[$item.ProgramName] = $item.CreationTime
        }
    }
    
    # Fetch LOLBAS data
    Write-Host "Fetching LOLBAS data to identify potentially abusable binaries..." -ForegroundColor Yellow
    $lolbasData = $null
    try {
        $lolbasUrl = "https://lolbas-project.github.io/api/lolbas.json"
        $webClient = New-Object System.Net.WebClient
        $lolbasJson = $webClient.DownloadString($lolbasUrl)
        $lolbasData = ConvertFrom-Json -InputObject $lolbasJson
        Write-Host "Successfully loaded LOLBAS data with $($lolbasData.Count) entries" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to fetch LOLBAS data: $_"
        Write-Host "Continuing without LOLBAS integration..." -ForegroundColor Yellow
    }
    
    $lolbasBinaries = @{}
    $lolbasDescriptions = @{}
    $lolbasCategoryMap = @{}
    $lolbasUrls = @{}
    
    if ($lolbasData) {
        foreach ($entry in $lolbasData) {
            $filename = $entry.Name
            $lolbasBinaries[$filename.ToUpper()] = $true
            $lolbasBinaries[$filename.ToLower()] = $true
            
            $lolbasDescriptions[$filename.ToUpper()] = $entry.Description
            $lolbasUrls[$filename.ToUpper()] = $entry.url
            
            $categories = $entry.Commands | ForEach-Object { $_.Category } | Select-Object -Unique
            $lolbasCategoryMap[$filename.ToUpper()] = $categories -join ", "
        }
        Write-Host "Processed $($lolbasBinaries.Count / 2) unique LOLBAS binaries" -ForegroundColor Green
    }
    
    $systemDirs = @(
        "$env:SystemRoot\System32",
        "$env:SystemRoot\SysWOW64", 
        "$env:SystemRoot\WinSxS",
        "$env:SystemRoot"
    )
    
    $securityTools = @(
        '^MIMIKATZ\.EXE$',
        '^PSEXEC\.EXE$',
        '^PSEXESVC\.EXE$',
        '^NETCAT\.EXE$',
        '^NC\.EXE$',
        '^NMAP\.EXE$',
        '^LAZAGNE\.EXE$',
        '^PWDUMP\d*\.EXE$',
        '^PROCDUMP\.EXE$',
        '^RUBEUS\.EXE$',
        '^BLOODHOUND\.EXE$',
        '^SHARPHOUND\.EXE$',
        '^WCESERVICE\.EXE$',
        '^WINPCAP\.EXE$',
        '^ETTERCAP\.EXE$',
        '^RESPONDER\.EXE$',
        '^HASHCAT\.EXE$',
        '^JOHN\.EXE$',
        '^CAIN\.EXE$',
        '^HYDRA\.EXE$',
        '^WIRESHARK\.EXE$',
        '^TCPDUMP\.EXE$'
    )
    
    foreach ($item in $PrefetchData) {
        $isNotable = $false
        $categories = @()
        $insights = @()
        
        $isLolbas = $false
        $lolbasDetails = ""
        $lolbasUrl = ""
        $binaryCategoriesString = ""
        
        if ($lolbasBinaries -and $lolbasBinaries.ContainsKey($item.ProgramName.ToUpper())) {
            $isLolbas = $true
            $isNotable = $true
            $categories += "LOLBAS Binary"
            
            $lolbasDetails = $lolbasDescriptions[$item.ProgramName.ToUpper()]
            if ($lolbasCategoryMap.ContainsKey($item.ProgramName.ToUpper())) {
                $binaryCategoriesString = $lolbasCategoryMap[$item.ProgramName.ToUpper()]
            } else {
                $binaryCategoriesString = "Unknown"
            }
            $lolbasUrl = $lolbasUrls[$item.ProgramName.ToUpper()]
            
            $insights += "Known LOLBAS binary that could be abused for $binaryCategoriesString - $lolbasDetails"
        }
        
        $isSecurityTool = $false
        foreach ($pattern in $securityTools) {
            if ($item.ProgramName -match $pattern) {
                $isSecurityTool = $true
                $isNotable = $true
                $categories += "Security Tool Usage"
                $insights += "Known penetration testing or security tool detected"
                break
            }
        }
        
        # Check for system utilities executed in unusual contexts
        if (-not $isSecurityTool -and $item.ProgramName -match '(?i)(powershell|cmd|wmic|reg|schtasks|bitsadmin)\.exe$') {
            # Check context - high frequency or unusual hours
            $hourOfDay = $item.LastExecution.Hour
            $unusualHours = ($hourOfDay -ge 22 -or $hourOfDay -le 5)
            $highFrequency = ($item.RunsPerDay -gt ($avgRunsPerDay + $stdDevRunsPerDay * 2))
            
            if ($unusualHours -or $highFrequency) {
                $isNotable = $true
                $categories += "System Utility Anomaly"
                if ($unusualHours) { $insights += "Executed during non-business hours (10PM-5AM)" }
                if ($highFrequency) { $insights += "Unusually high execution frequency compared to system baseline" }
            }
        }
        
        # Statistical outliers - only consider significant deviations
        if ($item.RunsPerDay -gt ($avgRunsPerDay + $stdDevRunsPerDay * 3)) {
            $isNotable = $true
            $categories += "Statistical Outlier"
            $insights += "Execution frequency significantly above normal system baseline"
        }
        
        # New or recently introduced programs with significant usage
        $firstSeen = $firstSeenDates[$item.ProgramName]
        $daysSinceFirstSeen = [math]::Round(((Get-Date) - $firstSeen).TotalDays, 1)
        if ($daysSinceFirstSeen -le 7 -and $item.RunCount -gt 20) {
            $isNotable = $true
            $categories += "Recently Introduced Program"
            $insights += "Program first appeared $daysSinceFirstSeen days ago with significant usage"
        }
        
        # Time-based unusual execution patterns
        $hourOfDay = $item.LastExecution.Hour
        if ($unusualHours -contains $hourOfDay -and $item.RunCount -gt 5) {
            $isNotable = $true
            $categories += "Off-Hours Activity"
            $insights += "Unusual execution during off-hours (10PM-5AM) with significant activity"
        }
        
        $dayOfWeek = $item.LastExecution.DayOfWeek
        if (($dayOfWeek -eq 'Saturday' -or $dayOfWeek -eq 'Sunday') -and 
            $item.ProgramName -match '(?i)(excel|word|powerpoint|outlook|teams|skype|zoom)') {
            $isNotable = $true
            $categories += "Weekend Business Activity"
            $insights += "Business software executed during weekend"
        }
        
        if ($item.RunCount -eq 1 -and $item.DaysSinceLastRun -lt 2 -and 
            -not ($item.ProgramName -match '(?i)(install|setup|update|config|uninstall)')) {
            $likelySystemBinary = $false
            foreach ($dir in $systemDirs) {
                $potentialPath = Join-Path -Path $dir -ChildPath $item.ProgramName
                if (Test-Path -Path $potentialPath -ErrorAction SilentlyContinue) {
                    $likelySystemBinary = $true
                    break
                }
            }
            
            if (-not $likelySystemBinary) {
                $isNotable = $true
                $categories += "One-time Execution"
                $insights += "Single execution of program that doesn't appear to be an installer/updater"
            }
        }
        
        if ($isNotable) {
            $notableItem = $item.PSObject.Copy()
            $notableItem | Add-Member -MemberType NoteProperty -Name "Categories" -Value ($categories -join "; ")
            $notableItem | Add-Member -MemberType NoteProperty -Name "AnalysisInsights" -Value ($insights -join "; ")
            $notableItem | Add-Member -MemberType NoteProperty -Name "FirstSeen" -Value $firstSeen
            
            if ($isLolbas) {
                $notableItem | Add-Member -MemberType NoteProperty -Name "IsLolbas" -Value $true
                $notableItem | Add-Member -MemberType NoteProperty -Name "LolbasUrl" -Value $lolbasUrl
            } else {
                $notableItem | Add-Member -MemberType NoteProperty -Name "IsLolbas" -Value $false
            }
            
            $notable += $notableItem
        }
    }
    
    return $notable
}

function Create-HtmlReport {
    param(
        [array]$PrefetchData,
        [array]$NotableData,
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
        .notable-section {
            border-left: 5px solid #FF8C00;
        }
        .lolbas-section {
            border-left: 5px solid #9C27B0;
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
        .notable-table th {
            background-color: #FF8C00;
        }
        .lolbas-table th {
            background-color: #9C27B0;
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
        tr.lolbas-row {
            background-color: #f3e5f5;
        }
        tr.lolbas-row:hover {
            background-color: #e1bee7;
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
        .notable-stat {
            background-color: #FFF3E0;
        }
        .notable-value {
            color: #FF8C00;
        }
        .lolbas-stat {
            background-color: #f3e5f5;
        }
        .lolbas-value {
            color: #9C27B0;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            font-size: 12px;
            color: #777;
        }
        .program-name {
            max-width: 300px;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        .chart-container {
            width: 100%;
            height: 400px;
            margin: 20px 0;
        }
        .insight-cell {
            max-width: 500px;
        }
        .lolbas-link {
            display: inline-block;
            padding: 2px 8px;
            background-color: #9C27B0;
            color: white;
            text-decoration: none;
            border-radius: 3px;
            font-size: 12px;
            margin-left: 5px;
        }
        .lolbas-link:hover {
            background-color: #7B1FA2;
        }
        .infobox {
            padding: 10px 15px;
            margin: 10px 0;
            border-radius: 5px;
            background-color: #E3F2FD;
            border-left: 5px solid #2196F3;
        }
        .legend {
            margin: 15px 0;
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }
        .legend-item {
            display: flex;
            align-items: center;
            margin-right: 15px;
        }
        .legend-color {
            width: 15px;
            height: 15px;
            margin-right: 5px;
            border-radius: 3px;
        }
        .legend-color.notable {
            background-color: #FF8C00;
        }
        .legend-color.lolbas {
            background-color: #9C27B0;
        }
        .legend-text {
            font-size: 14px;
        }
        .category-tag {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 11px;
            margin-right: 3px;
            color: white;
            background-color: #607D8B;
        }
        .category-tag.security-tool {
            background-color: #F44336;
        }
        .category-tag.lolbas {
            background-color: #9C27B0;
        }
        .category-tag.anomaly {
            background-color: #FF9800;
        }
        .category-tag.outlier {
            background-color: #2196F3;
        }
        .category-tag.naming {
            background-color: #009688;
        }
    </style>
"@

    $ChartJs = @"
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
"@

    $totalPrograms = $PrefetchData.Count
    $last24Hours = ($PrefetchData | Where-Object { $_.LastExecution -gt (Get-Date).AddDays(-1) }).Count
    $last7Days = ($PrefetchData | Where-Object { $_.LastExecution -gt (Get-Date).AddDays(-7) }).Count
    $notableCount = $NotableData.Count
    $lolbasCount = ($NotableData | Where-Object { $_.IsLolbas -eq $true }).Count
    $mostExecuted = $PrefetchData | Sort-Object -Property RunCount -Descending | Select-Object -First 1
    $mostRecent = $PrefetchData | Sort-Object -Property LastExecution -Descending | Select-Object -First 1

    $top10Executed = $PrefetchData | Sort-Object -Property RunCount -Descending | Select-Object -First 10

    $chartLabels = $top10Executed.ProgramName | ForEach-Object { 
        $name = $_
        if ($name.Length -gt 20) { $name = $name.Substring(0, 17) + "..." }
        "`"$name`""
    }
    $chartData = $top10Executed.RunCount
    
    $HtmlContent = @"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Prefetch Analysis Report - $(Get-Date -Format 'yyyyMMdd_HHmmss')</title>
        $Css
        $ChartJs
    </head>
    <body>
        <div class="container">
            <h1>Windows Prefetch Analysis Report</h1>
            <p>Report generated on $(Get-Date -Format 'dddd, MMMM dd, yyyy HH:mm:ss')</p>
            
            <div class="infobox">
                <p><strong>About Prefetch Analysis:</strong> Prefetch files are created by Windows to speed up application launching. They contain metadata about program executions including launch times and frequency. Analyzing these files provides insights into system usage patterns and can help identify potentially unusual activity.</p>
            </div>
            
            <div class="summary">
                <div class="stat-box">
                    <div>Total Programs</div>
                    <div class="stat-value">$totalPrograms</div>
                </div>
                <div class="stat-box">
                    <div>Executed in Last 24h</div>
                    <div class="stat-value">$last24Hours</div>
                </div>
                <div class="stat-box">
                    <div>Executed in Last 7d</div>
                    <div class="stat-value">$last7Days</div>
                </div>
                <div class="stat-box notable-stat">
                    <div>Notable Executions</div>
                    <div class="stat-value notable-value">$notableCount</div>
                </div>
                <div class="stat-box lolbas-stat">
                    <div>LOLBAS Binaries</div>
                    <div class="stat-value lolbas-value">$lolbasCount</div>
                </div>
            </div>
            
            <div class="legend">
                <div class="legend-item">
                    <div class="legend-color notable"></div>
                    <div class="legend-text">Notable Execution</div>
                </div>
                <div class="legend-item">
                    <div class="legend-color lolbas"></div>
                    <div class="legend-text">LOLBAS Binary</div>
                </div>
            </div>
            
            <div class="section">
                <h2>Most Frequently Executed Programs</h2>
                <div class="chart-container">
                    <canvas id="executionChart"></canvas>
                </div>
                <script>
                    var ctx = document.getElementById('executionChart').getContext('2d');
                    var executionChart = new Chart(ctx, {
                        type: 'bar',
                        data: {
                            labels: [$($chartLabels -join ', ')],
                            datasets: [{
                                label: 'Execution Count',
                                data: [$($chartData -join ', ')],
                                backgroundColor: 'rgba(0, 120, 215, 0.7)',
                                borderColor: 'rgba(0, 120, 215, 1)',
                                borderWidth: 1
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            scales: {
                                y: {
                                    beginAtZero: true
                                }
                            }
                        }
                    });
                </script>
            </div>
"@

    $lolbasBinaries = $NotableData | Where-Object { $_.IsLolbas -eq $true }
    if ($lolbasBinaries.Count -gt 0) {
        $lolbasTable = "<table class='lolbas-table'><thead><tr><th>Program Name</th><th>Last Execution</th><th>Run Count</th><th>Runs Per Day</th><th>Categories</th><th>Analysis Insights</th><th>LOLBAS</th></tr></thead><tbody>"
        
        foreach ($item in $lolbasBinaries) {
            $categoryTags = ($item.Categories -split ';') | ForEach-Object { 
                $class = "category-tag"
                if ($_ -match 'Security Tool') { $class += " security-tool" }
                elseif ($_ -match 'LOLBAS') { $class += " lolbas" }
                elseif ($_ -match 'Anomaly') { $class += " anomaly" }
                elseif ($_ -match 'Outlier') { $class += " outlier" }
                elseif ($_ -match 'Naming') { $class += " naming" }
                
                "<span class='$class'>$($_.Trim())</span>" 
            }
            $formattedCategories = $categoryTags -join " "
            
            $lolbasTable += "<tr class='lolbas-row'>
                <td class='program-name'>$($item.ProgramName)</td>
                <td>$($item.LastExecution)</td>
                <td>$($item.RunCount)</td>
                <td>$($item.RunsPerDay)</td>
                <td>$formattedCategories</td>
                <td class='insight-cell'>$($item.AnalysisInsights)</td>
                <td><a href='$($item.LolbasUrl)' target='_blank' class='lolbas-link'>LOLBAS Info</a></td>
            </tr>"
        }
        
        $lolbasTable += "</tbody></table>"
        
        $HtmlContent += @"
            <div class="section lolbas-section">
                <h2>LOLBAS (Living Off The Land Binaries and Scripts)</h2>
                <p>The following $($lolbasBinaries.Count) programs are known LOLBAS binaries that could potentially be abused for various purposes:</p>
                <div class="infobox">
                    <p><strong>What is LOLBAS?</strong> The LOLBAS project documents Windows binaries, scripts, and libraries that can be used for legitimate purposes but may also be abused by attackers for malicious activities like execution, persistence, or data exfiltration while evading security tools.</p>
                </div>
                $lolbasTable
            </div>
"@
    }

    $otherNotable = $NotableData | Where-Object { $_.IsLolbas -ne $true }
    if ($otherNotable.Count -gt 0) {
        $notableTable = "<table class='notable-table'><thead><tr><th>Program Name</th><th>Last Execution</th><th>Run Count</th><th>Runs Per Day</th><th>First Seen</th><th>Categories</th><th>Analysis Insights</th></tr></thead><tbody>"
        
        foreach ($item in $otherNotable) {
            $categoryTags = ($item.Categories -split ';') | ForEach-Object { 
                $class = "category-tag"
                if ($_ -match 'Security Tool') { $class += " security-tool" }
                elseif ($_ -match 'System Utility') { $class += " anomaly" }
                elseif ($_ -match 'Statistical Outlier') { $class += " outlier" }
                elseif ($_ -match 'Naming') { $class += " naming" }
                
                "<span class='$class'>$($_.Trim())</span>" 
            }
            $formattedCategories = $categoryTags -join " "
            
            $notableTable += "<tr>
                <td class='program-name'>$($item.ProgramName)</td>
                <td>$($item.LastExecution)</td>
                <td>$($item.RunCount)</td>
                <td>$($item.RunsPerDay)</td>
                <td>$($item.FirstSeen)</td>
                <td>$formattedCategories</td>
                <td class='insight-cell'>$($item.AnalysisInsights)</td>
            </tr>"
        }
        
        $notableTable += "</tbody></table>"
        
        $HtmlContent += @"
            <div class="section notable-section">
                <h2>Other Notable Program Executions</h2>
                <p>The following $($otherNotable.Count) programs exhibited potentially interesting execution patterns:</p>
                $notableTable
            </div>
"@
    }

    $prefetchTable = "<table><thead><tr><th>Program Name</th><th>Last Execution</th><th>Run Count</th><th>Runs Per Day</th><th>Days Since Last Run</th><th>Prefetch File</th></tr></thead><tbody>"
    
    foreach ($item in $PrefetchData) {
        $rowClass = ""
        $lolbasLink = ""
        
        $matchedItem = $NotableData | Where-Object { $_.ProgramName -eq $item.ProgramName } | Select-Object -First 1
        if ($matchedItem) {
            if ($matchedItem.IsLolbas -eq $true) {
                $rowClass = "class='lolbas-row'"
                $lolbasLink = " <a href='$($matchedItem.LolbasUrl)' target='_blank' class='lolbas-link'>LOLBAS</a>"
            }
        }
        
        $prefetchTable += "<tr $rowClass>
            <td class='program-name'>$($item.ProgramName)$lolbasLink</td>
            <td>$($item.LastExecution)</td>
            <td>$($item.RunCount)</td>
            <td>$($item.RunsPerDay)</td>
            <td>$($item.DaysSinceLastRun)</td>
            <td>$($item.PrefetchFile)</td>
        </tr>"
    }
    
    $prefetchTable += "</tbody></table>"
    
    $HtmlContent += @"
            <div class="section">
                <h2>All Prefetch Files</h2>
                <p>Total of $($PrefetchData.Count) prefetch files analyzed:</p>
                $prefetchTable
            </div>
            
            <div class="footer">
                <p>Generated by Prefetch Hunter - PowerShell Hunter Toolkit</p>
                <p>Enhanced with <a href="https://lolbas-project.github.io/" target="_blank">LOLBAS Project</a> integration</p>
                <p>https://github.com/MHaggis/PowerShell-Hunter</p>
            </div>
        </div>
    </body>
    </html>
"@

    $HtmlContent | Out-File -FilePath $HtmlPath
}

function Export-ResultsToFormats {
    param(
        [array]$PrefetchData,
        [array]$NotableData,
        [string]$ExportFormat,
        [string]$BasePath
    )
    
    $Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $ExportBaseName = "$($BasePath)_$($Timestamp)"
    $HtmlPath = "$ExportBaseName.html"
    
    if ($PrefetchData) {
        if ($ExportFormat -eq "CSV" -or $ExportFormat -eq "ALL") {
            $CSVPath = "$ExportBaseName.csv"
            $PrefetchData | Export-Csv -Path $CSVPath -NoTypeInformation
            Write-Host "`nData exported to CSV: $CSVPath" -ForegroundColor Green
        }
        
        if ($ExportFormat -eq "JSON" -or $ExportFormat -eq "ALL") {
            $JSONPath = "$ExportBaseName.json"
            $PrefetchData | ConvertTo-Json -Depth 4 | Out-File $JSONPath
            Write-Host "Data exported to JSON: $JSONPath" -ForegroundColor Green
        }
        
        if ($ExportFormat -eq "HTML" -or $ExportFormat -eq "ALL") {
            Create-HtmlReport -PrefetchData $PrefetchData -NotableData $NotableData -HtmlPath $HtmlPath
            Write-Host "HTML report generated: $HtmlPath" -ForegroundColor Green
            
            return $HtmlPath
        }
    } else {
        Write-Host "No data to export." -ForegroundColor Yellow
        return $null
    }
}

$prefetchData = Parse-PrefetchFiles -PrefetchPath $PrefetchPath -SortByLastExecution:$SortByLastExecution -ExecutedInLast24Hours:$ExecutedInLast24Hours -TopExecuted $TopExecuted
$notableData = Get-NotableExecutions -PrefetchData $prefetchData

if ($prefetchData.Count -gt 0) {
    Write-Host "`nAnalyzed $($prefetchData.Count) prefetch files." -ForegroundColor Green
    
    if ($notableData.Count -gt 0) {
        Write-Host "Found $($notableData.Count) potentially interesting executions!" -ForegroundColor Yellow
    }
    
    $reportPath = Export-ResultsToFormats -PrefetchData $prefetchData -NotableData $notableData -ExportFormat $ExportFormat -BasePath "PrefetchHunter"
    
    if ($reportPath) {
        Write-Host "`nAnalysis complete. Open $reportPath to view the full report." -ForegroundColor Green
        
        try {
            Write-Host "Launching HTML report in default browser..." -ForegroundColor Cyan
            Invoke-Item $reportPath
        } catch {
            Write-Warning "Unable to automatically open the HTML report: $_"
            Write-Host "Please open the report manually: $reportPath" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "No Prefetch data found to analyze." -ForegroundColor Yellow
} 