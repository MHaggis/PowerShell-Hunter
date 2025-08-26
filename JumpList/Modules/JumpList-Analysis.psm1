# JumpList-Analysis.psm1 - Analysis and reporting functions
# Part of PowerShell-Hunter - https://github.com/MHaggis/PowerShell-Hunter

Import-Module (Join-Path $PSScriptRoot 'JumpList-Container.psm1')
Import-Module (Join-Path $PSScriptRoot 'JumpList-Core.psm1')

function Get-AppIDFriendlyName {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AppID,
        
        [Parameter(Mandatory=$false)]
        [switch]$LogUnresolved
    )

    if (-not (Get-Variable -Name 'script:appNameCache' -ErrorAction SilentlyContinue)) {
        $script:appNameCache = @{}
    }
    
    $normalizedAppID = $AppID.ToUpper().Replace("-","")
    
    if ($script:appNameCache.ContainsKey($normalizedAppID)) {
        return $script:appNameCache[$normalizedAppID]
    }

    $knownAppIDs = @{
        # Microsoft Applications
        '1AC14E77-02E7-4E5D-B744-2EB1AE5198B7' = 'Windows Explorer'
        '9C7CC110-85C7-401A-B742-03CD91D3B54C' = 'Microsoft Edge'
        '26A5FB95-A861-4ECC-A155-DC5797E3C4C5' = 'Microsoft Outlook'
        '416D2F6B-573F-4BFA-9B13-F8F79A4BF839' = 'Microsoft Word'
        'BC03160F-2225-4FC6-ADE1-529EB3A6D497' = 'Microsoft PowerPoint'
        'CF49FE73-E3B2-4D8E-B58A-6A44F459CF6C' = 'Microsoft Excel'
        'FEE00455-F577-477C-9AB6-73DB443CD3DC' = 'Microsoft OneDrive'
        '308046B0-8044-454F-8A58-F36D780195EF' = 'Microsoft Teams'
        'E7E0224B-FEB7-4B1D-A004-945A8230CE8E' = 'Microsoft Visual Studio'
        '9ACDD262-5CEB-40C4-A1DF-447780F6ECBC' = 'Microsoft To Do'
        '6CF8659F-5204-489B-92D9-FC111395C70F' = 'Microsoft OneNote'
        '1C6D0E9C-2438-4833-BE2E-2623EA94163D' = 'Microsoft Paint'
        'E3C9668A-32AF-4392-8F3A-42F315B205B4' = 'Microsoft Notepad'
        '7E53A2A5-1A69-4680-9DE4-2FAE1F67FF49' = 'Windows Media Player'
        'A0953C92-50DC-43BF-BE83-3742FED03C9C' = 'Microsoft Photos'
        'AD705855-5152-4C0F-A72C-776F5D56B65D' = 'Windows Calculator'
        
        # PowerShell and Terminal
        '590AEE7BDD69B59B' = 'Windows PowerShell'
        '3C3871276E149215' = 'PowerShell 7'
        '16F2F0042DDBE0E8' = 'Windows Terminal'
        
        # Browsers
        'CCBA5A5986C77E43' = 'Microsoft Edge'
        '40371339AD31A7E6' = 'Mozilla Firefox'
        '2A2E0412B8AD04A2' = 'Microsoft EdgeWebView'
        '4F99164D-2A68-4974-8D21-51C966EE9C3F' = 'Google Chrome'
        'A9BD1B11-8273-43A5-B1EE-0E4E1375EF7D' = 'Brave Browser'
        '4B3A8026-47B0-443C-9B72-09182CEA2DFF' = 'Opera Browser'
        
        # Adobe
        'ACDA53CB-5A84-43D3-8089-AE21F79E1C43' = 'Adobe Acrobat Reader'
        '75D0847C-B829-41DB-86E5-09FB92FD75CA' = 'Adobe Photoshop'
        'BD7A8F3A-9C9B-4AC8-A68F-D83EE11D82A0' = 'Adobe Illustrator'
        '0E45FCFD-AA3D-409D-9723-AA839C2D6037' = 'Adobe Premiere Pro'
        
        # Development Tools
        'DF36ADDA-E2CA-4F46-9290-F1F782E705D9' = 'Visual Studio Code'
        '4F11DBCE-81CE-4017-88C2-E2CA2D3983F6' = 'GitHub Desktop'
        '8B27A7EF-86C9-4D57-A279-2A44058B0D71' = 'Sublime Text'
        'F485BFF7-2C5E-4A38-BD67-1A2E32D4C827' = 'JetBrains IntelliJ IDEA'
        
        # Utilities
        '7D93547A-5AB9-47DC-9D1B-D5DEDAD0883D' = 'WinRAR'
        '3BAFD9C1-6123-45BA-8287-E6E058E20838' = '7-Zip'
        'B8D3765A-DB01-45DD-A6DC-954D1992FCCF' = 'Notepad++'
        '3DD3456C-1580-4BF2-8987-BB3982C3FF17' = 'VLC Media Player'
        'F4283CB5-1687-4680-93DD-4F0F22278DC1' = 'PuTTY'
        
        # Communication
        'C8B400FB-91C1-4D5B-A789-C45398D17E48' = 'Discord'
        'B2A2750C-2A6F-4F07-A0F7-6CD4E3D2F353' = 'Zoom'
        '881DB366-F398-4143-9D1A-01CEC1D5D275' = 'Slack'
        'E3A6F20B-AD67-4D6F-B89B-BFDF3372C582' = 'Skype'
        'BF5F1CAD-8A5D-46FD-9D2A-A37D59A202C7' = 'Telegram'
        '1F1D9A9C-4F92-4C14-B7E3-3C2B7D75E19A' = 'WhatsApp'
        
        # Gaming
        'E3D7889D-0D39-4A61-9781-2D4C6A7E0DB0' = 'Steam'
        'B59E1D01-4221-4A49-8E0E-BE1B3C67F763' = 'Epic Games Launcher'
        '75D2541D-BAAF-4222-90A8-1A0E3F3B2026' = 'GOG Galaxy'
        'BAD046BA-7932-4365-B273-F972BFAAAFB9' = 'Origin'
        'A67D30C3-2F10-4C4F-B7CF-626BB2F1D223' = 'Ubisoft Connect'
        
        # Streaming
        '31DAA6EA-2226-4D9D-A012-D2C917F025AE' = 'Spotify'
        'C71D61D7-4B97-4DE7-A166-235FDD4E31B3' = 'Netflix'
        'E6E5BCBD-75A3-46C3-8FEF-0D44B06BE7C9' = 'Amazon Prime Video'
        'FC93051A-5AD1-4D77-A563-BB4682B8934B' = 'Disney+'
    }

    if ($knownAppIDs.ContainsKey($normalizedAppID)) {
        $friendlyName = $knownAppIDs[$normalizedAppID]
        $script:appNameCache[$normalizedAppID] = $friendlyName
        return $friendlyName
    }

    try {
        $appDataPaths = @(
            "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\$AppID.automaticDestinations-ms",
            "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\$AppID.customDestinations-ms",
            "$env:LOCALAPPDATA\Microsoft\Windows\Recent\AutomaticDestinations\$AppID.automaticDestinations-ms", 
            "$env:LOCALAPPDATA\Microsoft\Windows\Recent\CustomDestinations\$AppID.customDestinations-ms"
        )
        
        $userProfilesPath = [System.IO.Path]::GetDirectoryName($env:USERPROFILE)
        if (Test-Path $userProfilesPath) {
            $userProfiles = Get-ChildItem -Path $userProfilesPath -Directory | Where-Object { $_.Name -ne 'Public' -and $_.Name -ne 'Default' -and $_.Name -ne 'Default User' }
            foreach ($profile in $userProfiles) {
                $profileAppDataPath = "$($profile.FullName)\AppData"
                if (Test-Path $profileAppDataPath) {
                    $appDataPaths += "$profileAppDataPath\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\$AppID.automaticDestinations-ms"
                    $appDataPaths += "$profileAppDataPath\Roaming\Microsoft\Windows\Recent\CustomDestinations\$AppID.customDestinations-ms"
                    $appDataPaths += "$profileAppDataPath\Local\Microsoft\Windows\Recent\AutomaticDestinations\$AppID.automaticDestinations-ms"
                    $appDataPaths += "$profileAppDataPath\Local\Microsoft\Windows\Recent\CustomDestinations\$AppID.customDestinations-ms"
                }
            }
        }

        foreach ($path in $appDataPaths) {
            if (Test-Path $path) {
                $jumpListData = if ($path -like "*.automaticDestinations-ms") { 
                    Get-AutomaticJumpListLnkStreams -JumpListPath $path
                } else {
                    Parse-CustomDestinations -FilePath $path
                }
                
                if ($jumpListData -and $jumpListData.Count -gt 0) {
                    foreach ($item in $jumpListData) {
                        if ($item.FilePath) {
                            try {
                                $exeName = [System.IO.Path]::GetFileNameWithoutExtension($item.FilePath)
                                if ($exeName) {
                                    $appName = $exeName.Replace(".exe", "")
                                    
                                    $appName = $appName -replace "\.(x64|x86)$|64$", ""
                                    
                                    if ($appName -match "^[a-z]") { 
                                        $appName = (Get-Culture).TextInfo.ToTitleCase($appName)
                                    }
                                    
                                    $appName = $appName -replace "([a-z])([A-Z])", '$1 $2'  # Add spaces between camelCase
                                    
                                    $script:appNameCache[$normalizedAppID] = $appName
                                    return $appName
                                }
                            } catch {
                                Write-Debug "Error getting filename from $($item.FilePath): $_"
                            }
                        }
                    }
                }
            }
        }
        
        try {
            $registryPaths = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
                "HKLM:\SOFTWARE\Classes\Applications",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
                "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\JumplistData",
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                "HKLM:\SOFTWARE\RegisteredApplications",
                "HKCU:\SOFTWARE\RegisteredApplications"
            )
            
            foreach ($regPath in $registryPaths) {
                if (Test-Path $regPath) {
                    $keys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
                    foreach ($key in $keys) {
                        if ($key.Name -match $AppID -or 
                            $key.Name -match ($AppID -replace "-", "") -or 
                            (Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue | Out-String) -match $AppID) {
                            
                            $friendlyName = Split-Path $key.Name -Leaf
                            
                            $displayNameProp = Get-ItemProperty -Path $key.PSPath -Name "DisplayName" -ErrorAction SilentlyContinue
                            if ($displayNameProp -and $displayNameProp.DisplayName) {
                                $friendlyName = $displayNameProp.DisplayName
                            }
                            
                            if ($regPath -like "*MuiCache*") {
                                $muiProps = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
                                foreach ($prop in $muiProps.PSObject.Properties) {
                                    if ($prop.Name -match $AppID -or $prop.Name -match ".*\.exe") {
                                        $friendlyName = $prop.Value
                                        break
                                    }
                                }
                            }
                            
                            $friendlyName = $friendlyName -replace "\.(exe|lnk|url)$", ""
                            $friendlyName = $friendlyName -replace "\.(x64|x86)$|64$", ""
                            
                            $friendlyName = $friendlyName -replace "([a-z])([A-Z])", '$1 $2'
                            
                            $script:appNameCache[$normalizedAppID] = $friendlyName
                            return $friendlyName
                        }
                    }
                }
            }
            
            $startMenuPath = "$env:LOCALAPPDATA\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState"
            if (Test-Path $startMenuPath) {
                $startMenuFiles = Get-ChildItem -Path $startMenuPath -Filter "*.json" -Recurse -ErrorAction SilentlyContinue
                foreach ($file in $startMenuFiles) {
                    try {
                        $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
                        if ($content -match $AppID) {
                            $jsonData = $content | ConvertFrom-Json -ErrorAction SilentlyContinue
                            if ($jsonData) {
                                $possibleNames = @()
                                
                                $jsonData.PSObject.Properties | ForEach-Object {
                                    if ($_.Value -is [string] -and $_.Name -like "*Name*") {
                                        $possibleNames += $_.Value
                                    }
                                }
                                
                                if ($possibleNames.Count -gt 0) {
                                    $friendlyName = $possibleNames[0]
                                    $script:appNameCache[$normalizedAppID] = $friendlyName
                                    return $friendlyName
                                }
                            }
                        }
                    } catch {
                        Write-Debug "Error reading Start Menu file $($file.FullName): $_"
                    }
                }
            }
        } catch {
            Write-Debug "Error searching registry for AppID $AppID`: $_"
        }
    } catch {
        Write-Debug "Error resolving AppID $AppID`: $_"
    }
    
    if ($AppID -match '^[0-9a-fA-F]{16}$') {
        $commonAppHashes = @{
            "^5[0-9a-f]{15}$" = "Windows PowerShell"  # Matches pattern like 590aee7bdd69b59b
            "^4[0-9a-f]{15}$" = "Web Browser"          # Common pattern for browsers
            "^3[0-9a-f]{15}$" = "PowerShell Core"      # Matches pattern like 3c3871276e149215
            "^2[0-9a-f]{15}$" = "Terminal App"         # Matches patterns like 2a2e0412b8ad04a2
            "^1[0-9a-f]{15}$" = "Editor App"           # Common pattern for text editors
        }
        
        foreach ($pattern in $commonAppHashes.Keys) {
            if ($AppID -match $pattern) {
                $friendlyName = $commonAppHashes[$pattern]
                $script:appNameCache[$normalizedAppID] = $friendlyName
                return $friendlyName
            }
        }
    }
    
    if ($LogUnresolved) {
        $logPath = Join-Path -Path $PSScriptRoot -ChildPath "unresolved_appids.log"
        $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Unresolved AppID: $AppID"
        
        try {
            Add-Content -Path $logPath -Value $logEntry -ErrorAction SilentlyContinue
        } catch {
            Write-Debug "Could not log unresolved AppID: $_"
        }
    }

    $script:appNameCache[$normalizedAppID] = $AppID
    return $AppID
}

function Export-JumpListData {
    param (
        [string]$AutoDir,
        [string]$CustomDir,
        [switch]$DebugMode,
        [switch]$NoExport,
        [string]$OutputDir = "$env:USERPROFILE\Desktop",
        [Parameter(Mandatory=$false)]
        [DateTime]$StartDate,
        [Parameter(Mandatory=$false)]
        [DateTime]$EndDate,
        [Parameter(Mandatory=$false)]
        [array]$CustomDataSet
    )

    if ($DebugMode) {
        $DebugPreference = 'Continue'
    }

    $output = @()
    $startTime = Get-Date
    Write-Host "Starting JumpList analysis at $startTime" -ForegroundColor Cyan

    if ($CustomDataSet) {
        Write-Host "Using pre-processed dataset with $($CustomDataSet.Count) entries" -ForegroundColor Yellow
        $output = $CustomDataSet
    }
    else {
        if ($StartDate -ne $null) {
            Write-Host ("Filtering entries after: " + $StartDate.ToString('yyyy-MM-dd HH:mm:ss')) -ForegroundColor Yellow
        }
        if ($EndDate -ne $null) {
            Write-Host ("Filtering entries before: " + $EndDate.ToString('yyyy-MM-dd HH:mm:ss')) -ForegroundColor Yellow
        }

        Write-Host "Processing Automatic Destinations..." -ForegroundColor Yellow
        $autoFiles = Get-ChildItem -Path $AutoDir -Filter *.automaticDestinations-ms -ErrorAction SilentlyContinue
        $autoCount = $autoFiles.Count
        $currentAuto = 0
        
        foreach ($file in $autoFiles) {
            $currentAuto++
            Write-Progress -Activity "Processing Automatic Destinations" -Status "$currentAuto of $autoCount" -PercentComplete (($currentAuto / $autoCount) * 100)
            Write-Debug "Processing automatic file: $($file.FullName)"
            $output += Get-AutomaticJumpListLnkStreams -JumpListPath $file.FullName
        }

        Write-Host "Processing Custom Destinations..." -ForegroundColor Yellow
        $customFiles = Get-ChildItem -Path $CustomDir -Filter *.customDestinations-ms -ErrorAction SilentlyContinue
        $customCount = $customFiles.Count
        $currentCustom = 0
        
        foreach ($file in $customFiles) {
            $currentCustom++
            Write-Progress -Activity "Processing Custom Destinations" -Status "$currentCustom of $customCount" -PercentComplete (($currentCustom / $customCount) * 100)
            Write-Debug "Processing custom file: $($file.FullName)"
            $output += ConvertFrom-CustomDestinations -FilePath $file.FullName
        }
    }

    if ($StartDate -ne $null -or $EndDate -ne $null) {
        $preFilterCount = $output.Count
        $output = $output | Where-Object {
            $includeEntry = $true
            if ($StartDate -ne $null -and $_.Timestamp -ne $null) {
                if ($_.Timestamp -lt $StartDate) { $includeEntry = $false }
            }
            if ($EndDate -ne $null -and $_.Timestamp -ne $null) {
                if ($_.Timestamp -gt $EndDate) { $includeEntry = $false }
            }
            $includeEntry
        }
        $postFilterCount = $output.Count
        Write-Host "Date filtering removed $($preFilterCount - $postFilterCount) entries" -ForegroundColor Yellow
    }

    if ($NoExport) {
        Write-Host "Skipping export as requested" -ForegroundColor Yellow
        return $output
    }

    $outputPath = Join-Path -Path $OutputDir -ChildPath "JumpListAnalysis_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    if (-not (Test-Path $outputPath)) {
        New-Item -ItemType Directory -Path $outputPath | Out-Null
    }

    $csvPath = Join-Path -Path $outputPath -ChildPath "JumpListEntries.csv"

    if ($output.Count -gt 0) {
        Write-Host "Exporting $($output.Count) entries to $csvPath" -ForegroundColor Green
        $output | Export-Csv -Path $csvPath -NoTypeInformation

        Write-Host "Creating HTML report" -ForegroundColor Green
        if ($CustomDataSet) {
            Write-Host "Using custom dataset from parameter - some file statistics may not apply" -ForegroundColor Yellow
        }
        Export-JumpListReport -Data $output -OutputDir $outputPath

        Write-Host "Analysis complete. Results saved to: $outputPath" -ForegroundColor Green
    } else {
        Write-Warning "No data found to export"
    }

    return $output
}

function Export-JumpListReport {
    <#
    .SYNOPSIS
        Generates an HTML report from JumpList data.
    
    .DESCRIPTION
        Creates a detailed HTML report from JumpList data with filtering capabilities
        and multiple views of the data.
    
    .PARAMETER Data
        The JumpList data to include in the report.
    
    .PARAMETER OutputDir
        The directory where the HTML report will be saved.
    
    .EXAMPLE
        $jumpListData | Export-JumpListReport -OutputDir "C:\Reports"
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [PSObject[]]$Data,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputDir
    )
    
    Begin {
        $allData = @()
    }
    
    Process {
        foreach ($item in $Data) {
            $allData += $item
        }
    }
    
    End {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $htmlPath = Join-Path -Path $OutputDir -ChildPath "JumpList_Report_$timestamp.html"
        
        $regularEntries = ($allData | Where-Object { $_.Type -ne "Carved" } | Measure-Object).Count
        $carvedEntries = ($allData | Where-Object { $_.Type -eq "Carved" } | Measure-Object).Count
        
        $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>PowerShell-Hunter JumpList Analysis</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        h1, h2, h3 {
            color: #0078D7;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            border-radius: 5px;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 20px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #0078D7;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        .timestamp {
            color: #666;
        }
        .summary {
            background-color: #e8f0ff;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .filter {
            margin: 10px 0;
        }
        .carved {
            background-color: #fff2cc !important;
        }
        .tab {
            overflow: hidden;
            background-color: #f1f1f1;
            border-radius: 5px 5px 0 0;
        }
        .tab button {
            background-color: inherit;
            float: left;
            border: none;
            outline: none;
            cursor: pointer;
            padding: 10px 15px;
            transition: 0.3s;
            font-size: 15px;
        }
        .tab button:hover {
            background-color: #ddd;
        }
        .tab button.active {
            background-color: #0078D7;
            color: white;
        }
        .tabcontent {
            display: none;
            padding: 15px;
            border: 1px solid #ccc;
            border-top: none;
            border-radius: 0 0 5px 5px;
        }
    </style>
    <script>
        function filterTable() {
            // Get input values
            var input = document.getElementById("searchInput").value.toUpperCase();
            var startDate = document.getElementById("startDate").value;
            var endDate = document.getElementById("endDate").value;
            
            // Convert dates to comparable format
            var startDateObj = startDate ? new Date(startDate) : null;
            var endDateObj = endDate ? new Date(endDate) : null;
            
            // Get tables
            var tables = document.getElementsByClassName("data-table");
            
            for (var t = 0; t < tables.length; t++) {
                var table = tables[t];
                var tr = table.getElementsByTagName("tr");
                
                // Loop through all table rows
                for (var i = 1; i < tr.length; i++) { // Start at 1 to skip header row
                    var row = tr[i];
                    var showRow = true;
                    
                    // Text search
                    if (showRow && input) {
                        showRow = false;
                        var cells = row.getElementsByTagName("td");
                        for (var j = 0; j < cells.length; j++) {
                            var cell = cells[j];
                            if (cell) {
                                var txtValue = cell.textContent || cell.innerText;
                                if (txtValue.toUpperCase().indexOf(input) > -1) {
                                    showRow = true;
                                    break;
                                }
                            }
                        }
                    }
                    
                    // Date filtering
                    if (showRow && (startDateObj || endDateObj)) {
                        var dateCell = row.querySelector("[data-date]");
                        if (dateCell) {
                            var rowDate = new Date(dateCell.getAttribute("data-date"));
                            
                            if (startDateObj && rowDate < startDateObj) {
                                showRow = false;
                            }
                            
                            if (endDateObj && rowDate > endDateObj) {
                                showRow = false;
                            }
                        }
                    }
                    
                    // Show/hide the row
                    row.style.display = showRow ? "" : "none";
                }
            }
        }
        
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }
        
        // Default to opening the first tab
        window.onload = function() {
            document.getElementsByClassName("tablinks")[0].click();
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>PowerShell-Hunter JumpList Analysis</h1>
        <div class="summary">
            <h2>Analysis Summary</h2>
            <p><strong>Analysis Date:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p><strong>Total Entries Found:</strong> $($allData.Count)</p>
            <p><strong>Regular Entries:</strong> $regularEntries</p>
            <p><strong>Carved Entries:</strong> $carvedEntries</p>
        </div>
        
        <div class="filter">
            <h3>Filter Results</h3>
            <input type="text" id="searchInput" onkeyup="filterTable()" placeholder="Search for any text...">
            <label for="startDate">Start Date:</label>
            <input type="date" id="startDate" onchange="filterTable()">
            <label for="endDate">End Date:</label>
            <input type="date" id="endDate" onchange="filterTable()">
            <button onclick="filterTable()">Apply Filters</button>
        </div>
        
        <div class="tab">
            <button class="tablinks" onclick="openTab(event, 'AllEntries')">All Jump List Entries</button>
            <button class="tablinks" onclick="openTab(event, 'AppStats')">Application Statistics</button>
        </div>
        
        <div id="AllEntries" class="tabcontent">
            <h3>All Jump List Entries</h3>
            <table class="data-table">
                <tr>
                    <th>App Name</th>
                    <th>File Path</th>
                    <th>Arguments</th>
                    <th>Access Time</th>
                    <th>Modified Time</th>
                    <th>Created Time</th>
                    <th>Type</th>
                </tr>
"@

        foreach ($entry in $allData) {
            $rowClass = ""
            if ($entry.Type -eq "Carved") {
                $rowClass = "carved"
            }
            
            $accessTimeAttr = ""
            if ($entry.AccessedTime) {
                try {
                    $accessTimeIso = [datetime]::Parse($entry.AccessedTime).ToString("o")
                    $accessTimeAttr = "data-date='$accessTimeIso'"
                }
                catch {
                }
            }
            
            $htmlContent += @"
                <tr class="$rowClass">
                    <td>$($entry.AppName)</td>
                    <td>$($entry.FilePath)</td>
                    <td>$($entry.Arguments)</td>
                    <td $accessTimeAttr>$($entry.AccessedTime)</td>
                    <td>$($entry.ModifiedTime)</td>
                    <td>$($entry.CreatedTime)</td>
                    <td>$($entry.Type)</td>
                </tr>
"@
        }
        
        $htmlContent += @"
            </table>
        </div>
        
        <div id="AppStats" class="tabcontent">
            <h3>Jump List Statistics by Application</h3>
            <table class="data-table">
                <tr>
                    <th>Application</th>
                    <th>Regular Entries</th>
                    <th>Carved Entries</th>
                    <th>Total Entries</th>
                    <th>Date Range</th>
                </tr>
"@

        $appGroups = $allData | Group-Object -Property AppName
        
        foreach ($group in $appGroups) {
            $regularCount = ($group.Group | Where-Object { $_.Type -ne "Carved" } | Measure-Object).Count
            $carvedCount = ($group.Group | Where-Object { $_.Type -eq "Carved" } | Measure-Object).Count
            
            $dates = $group.Group.AccessedTime | Where-Object { $_ } | ForEach-Object { try { [datetime]::Parse($_) } catch { $null } } | Where-Object { $_ } | Sort-Object
            $dateRange = if ($dates -and $dates.Count -gt 0) {
                "$($dates[0].ToString('yyyy-MM-dd')) to $($dates[-1].ToString('yyyy-MM-dd'))"
            } else {
                "N/A"
            }
            
            $htmlContent += @"
                <tr>
                    <td>$($group.Name)</td>
                    <td>$regularCount</td>
                    <td>$carvedCount</td>
                    <td>$($group.Count)</td>
                    <td>$dateRange</td>
                </tr>
"@
        }
        
        $htmlContent += @"
            </table>
        </div>
        
        <div style="margin-top: 20px; color: #666; font-size: 0.8em; text-align: center;">
            <p>Generated by PowerShell-Hunter Jump List Analyzer</p>
            <p>https://github.com/MHaggis/PowerShell-Hunter</p>
        </div>
    </div>
</body>
</html>
"@

        $htmlContent | Out-File -FilePath $htmlPath
        Write-Host "HTML report generated: $htmlPath" -ForegroundColor Green
    }
}

function Find-RelatedArtifacts {
    param (
        [array]$JumpListData
    )
    
    $related = @{}
    
    $prefetchDir = "C:\Windows\Prefetch"
    if (Test-Path $prefetchDir) {
        Write-Host "Checking for related prefetch files..." -ForegroundColor Yellow
        foreach ($item in $JumpListData) {
            $exeName = [System.IO.Path]::GetFileName($item.FilePath)
            if (-not [string]::IsNullOrEmpty($exeName)) {
                $prefetchFiles = Get-ChildItem -Path $prefetchDir -Filter "$exeName*.pf" -ErrorAction SilentlyContinue
                if ($prefetchFiles.Count -gt 0) {
                    if (-not $related.ContainsKey($item.FilePath)) {
                        $related[$item.FilePath] = @{}
                    }
                    $related[$item.FilePath]["PrefetchFiles"] = $prefetchFiles.FullName
                }
            }
        }
    }
    
    try {
        Write-Host "Checking for related RunMRU registry entries..." -ForegroundColor Yellow
        $runMRU = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue
        if ($runMRU) {
            foreach ($item in $JumpListData) {
                $exeName = [System.IO.Path]::GetFileName($item.FilePath)
                if (-not [string]::IsNullOrEmpty($exeName)) {
                    foreach ($prop in $runMRU.PSObject.Properties) {
                        if ($prop.Name -ne "PSPath" -and $prop.Name -ne "PSParentPath" -and $prop.Value -match $exeName) {
                            if (-not $related.ContainsKey($item.FilePath)) {
                                $related[$item.FilePath] = @{}
                            }
                            $related[$item.FilePath]["RunMRU"] = $prop.Value
                        }
                    }
                }
            }
        }
    } catch {
        Write-Debug "Error accessing RunMRU registry key: $_"
    }
    
    try {
        Write-Host "Checking for related UserAssist registry entries..." -ForegroundColor Yellow
        $userAssistPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        if (Test-Path $userAssistPath) {
            $userAssistKeys = Get-ChildItem -Path $userAssistPath
            foreach ($key in $userAssistKeys) {
                $countKey = Join-Path -Path $key.PSPath -ChildPath "Count"
                if (Test-Path $countKey) {
                    $countEntries = Get-ItemProperty -Path $countKey
                    foreach ($entry in $countEntries.PSObject.Properties) {
                        if ($entry.Name -notlike "PS*") {
                            try {
                                $decoded = [regex]::Replace($entry.Name, '[A-Za-z]', {
                                    param($match)
                                    $char = [int][char]$match.Value
                                    if (($char -ge 65 -and $char -le 90)) {
                                        return [char]((($char - 65 + 13) % 26) + 65)
                                    } elseif (($char -ge 97 -and $char -le 122)) {
                                        return [char]((($char - 97 + 13) % 26) + 97)
                                    } else {
                                        return $match.Value
                                    }
                                })
                                
                                foreach ($item in $JumpListData) {
                                    $exeName = [System.IO.Path]::GetFileName($item.FilePath)
                                    if (-not [string]::IsNullOrEmpty($exeName) -and $decoded -match [regex]::Escape($exeName)) {
                                        if (-not $related.ContainsKey($item.FilePath)) {
                                            $related[$item.FilePath] = @{}
                                        }
                                        if (-not $related[$item.FilePath].ContainsKey("UserAssist")) {
                                            $related[$item.FilePath]["UserAssist"] = @()
                                        }
                                        $related[$item.FilePath]["UserAssist"] += $decoded
                                    }
                                }
                            } catch {
                                Write-Debug "Error processing UserAssist entry: $_"
                            }
                        }
                    }
                }
            }
        }
    } catch {
        Write-Debug "Error accessing UserAssist registry key: $_"
    }
    
    if ($related.Count -gt 0) {
        Write-Host ("`nFound related artifacts for " + $related.Count + " JumpList entries:") -ForegroundColor Green
        foreach ($path in $related.Keys) {
            Write-Host "`n$path" -ForegroundColor Cyan
            foreach ($artifactType in $related[$path].Keys) {
                Write-Host ("  " + $artifactType + ":") -ForegroundColor Yellow
                $artifactValue = $related[$path][$artifactType]
                if ($artifactValue -is [array]) {
                    foreach ($value in $artifactValue) {
                        Write-Host "    - $value" -ForegroundColor White
                    }
                } else {
                    Write-Host "    $artifactValue" -ForegroundColor White
                }
            }
        }
    } else {
        Write-Host "`nNo related artifacts found." -ForegroundColor Yellow
    }
    
    return $related
}



Export-ModuleMember -Function Export-JumpListData, Find-RelatedArtifacts, Get-AppIDFriendlyName