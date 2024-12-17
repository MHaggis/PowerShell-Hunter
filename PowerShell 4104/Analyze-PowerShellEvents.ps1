<#
.SYNOPSIS
Analyzes PowerShell 4104 events for suspicious patterns and exports results to CSV or JSON.

.DESCRIPTION
This script loads a set of patterns from a CSV file, queries the PowerShell Operational event log for Event ID 4104, 
matches event data against the patterns, calculates a score for each event, and exports the results for further analysis.

.PARAMETER PatternFile
Path to the CSV file containing the patterns.

.PARAMETER OutputFile
Path to the output file where results will be exported. If not specified, a timestamped filename will be generated.

.PARAMETER OutputFormat
Format of the output file. Valid values are 'CSV' or 'JSON'. Default is 'CSV'.

.PARAMETER MaxEvents
Maximum number of events to analyze. Default is 5000.

.EXAMPLE
.\Analyze-PowerShellEvents.ps1 -PatternFile "Patterns.csv" -OutputFile "FilteredEvents.csv"
.\Analyze-PowerShellEvents.ps1 -PatternFile "Patterns.csv" -OutputFile "FilteredEvents.json" -OutputFormat JSON

.NOTES
Author: The Haag
Version: 1.3
#>

param (
    [string]$PatternFile = "Patterns.csv",
    [string]$OutputFile = "",
    [ValidateSet('CSV', 'JSON')]
    [string]$OutputFormat = "CSV",
    [int]$MaxEvents = 5000
)

function Get-TimestampedFileName {
    param (
        [string]$BaseFileName,
        [string]$Format
    )
    
    # Get the script's directory
    $scriptDir = $PSScriptRoot
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $computerName = $env:COMPUTERNAME
    
    if ([string]::IsNullOrEmpty($BaseFileName)) {
        $extension = if ($Format -eq 'JSON') { 'json' } else { 'csv' }
        $filename = "PS4104_Analysis_${computerName}_${timestamp}.$extension"
    }
    else {
        $filename = [System.IO.Path]::GetFileNameWithoutExtension($BaseFileName)
        $extension = if ($Format -eq 'JSON') { 'json' } else { 'csv' }
        $filename = "${filename}_${computerName}_${timestamp}.$extension"
    }
    return Join-Path $scriptDir $filename
}

function Load-Patterns {
    param (
        [string]$FilePath
    )
    if (-Not (Test-Path $FilePath)) {
        Write-Error "Pattern file not found: $FilePath"
        return $null
    }
    try {
        $patterns = Import-Csv -Path $FilePath
        Write-Output "Successfully loaded $($patterns.Count) patterns"
        return $patterns
    }
    catch {
        Write-Error "Error loading patterns: $_"
        return $null
    }
}

function Get-ScriptBlockText {
    param (
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event
    )
    
    try {
        $messageXml = [xml]$Event.ToXml()
        $scriptBlockText = $messageXml.Event.EventData.Data | 
            Where-Object { $_.Name -eq 'ScriptBlockText' } | 
            Select-Object -ExpandProperty '#text'
        
        return $scriptBlockText
    }
    catch {
        Write-Warning "Failed to extract ScriptBlock text from event $($Event.RecordId): $_"
        return $null
    }
}

function Analyze-Events {
    param (
        [array]$Patterns,
        [string]$LogName = "Microsoft-Windows-PowerShell/Operational",
        [int]$EventID = 4104,
        [int]$MaxEvents
    )

    $results = @()
    $totalEvents = 0
    $flaggedEvents = 0

    try {
        Write-Output "Querying last $MaxEvents events from $LogName..."
        $events = Get-WinEvent -FilterHashtable @{
            LogName = $LogName
            Id = $EventID
        } -MaxEvents $MaxEvents -ErrorAction Stop
        
        $totalEvents = $events.Count
        Write-Output "Found $totalEvents events to analyze"

        if ($totalEvents -eq 0) {
            Write-Warning "No events found in the event log"
            return $results
        }
    }
    catch {
        Write-Error "Failed to query events: $_"
        if ($_.Exception.Message -match "No events were found") {
            Write-Warning "No PowerShell events found in the specified log"
        }
        return $results
    }

    foreach ($event in $events) {
        Write-Progress -Activity "Analyzing Events" -Status "Processing event $($events.IndexOf($event) + 1) of $totalEvents" `
            -PercentComplete ((($events.IndexOf($event) + 1) / $totalEvents) * 100)

        $scriptBlockText = Get-ScriptBlockText -Event $event
        if (-not $scriptBlockText) { continue }

        $matchedCategories = @()
        $totalScore = 0
        $matchDetails = @()
        $matchedPatterns = @()

        foreach ($pattern in $Patterns) {
            if ($scriptBlockText -match $pattern.Pattern) {
                $matchedCategories += $pattern.Category
                $scoreValue = 0
                if ([int]::TryParse($pattern.Score, [ref]$scoreValue)) {
                    $totalScore += $scoreValue
                    $matchDetails += "$($pattern.Category) [Score: $scoreValue]"
                    
                    # Store the actual matched pattern
                    $matches = [regex]::Matches($scriptBlockText, $pattern.Pattern)
                    foreach ($match in $matches) {
                        $matchedPatterns += "Pattern '$($pattern.Category)' matched: '$($match.Value)'"
                    }
                }
            }
        }

        if ($matchedCategories.Count -gt 0) {
            $flaggedEvents++
            $results += [PSCustomObject]@{
                TimeCreated = $event.TimeCreated
                RecordId = $event.RecordId
                TotalScore = $totalScore
                MatchedCategories = ($matchedCategories -join ", ")
                MatchDetails = ($matchDetails -join "; ")
                ScriptBlockText = $scriptBlockText
                ScriptBlockLength = $scriptBlockText.Length
                ComputerName = $event.MachineName
                UserId = $event.UserId
                MessageNumber = $event.Properties[0].Value
                MessageTotal = $event.Properties[1].Value
                MatchedPatterns = ($matchedPatterns -join "`n")
            }
        }
    }

    Write-Progress -Activity "Analyzing Events" -Completed
    Write-Output "Reviewed $totalEvents events and flagged $flaggedEvents suspicious events."
    return $results | Sort-Object TotalScore -Descending
}

function Export-Results {
    param (
        [array]$Results,
        [string]$FilePath,
        [string]$Format
    )

    if ($null -eq $Results -or $Results.Count -eq 0) {
        Write-Warning "No matching events found. No file was created."
        return
    }

    try {
        $exportResults = @()
        
        foreach ($result in $Results) {
            if ($null -eq $result) { continue }
            $userSid = if ($result.UserId.Value) { 
                $result.UserId.Value 
            } elseif ($result.UserId) { 
                $result.UserId.ToString() 
            } else {
                "Unknown"
            }
            $exportResults += [PSCustomObject]@{
                timestamp = $result.TimeCreated
                event_id = $result.RecordId
                risk_score = $result.TotalScore
                detected_patterns = $result.MatchedCategories
                pattern_details = $result.MatchDetails
                command_length = $result.ScriptBlockLength
                full_command = $result.ScriptBlockText
                computer = $result.ComputerName
                user_sid = $userSid
                message_number = $result.MessageNumber
                message_total = $result.MessageTotal
                matched_patterns = $result.MatchedPatterns
            }
        }

        if ($exportResults.Count -eq 0) {
            Write-Warning "No valid results to export after processing."
            return
        }
        $directory = Split-Path -Parent $FilePath
        if (![string]::IsNullOrEmpty($directory) -and !(Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }

        switch ($Format) {
            'CSV' {
                $exportResults | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
                Write-Output "Results exported to CSV: $FilePath"
            }
            'JSON' {
                $jsonString = ConvertTo-Json -InputObject $exportResults -Depth 10
                [System.IO.File]::WriteAllText($FilePath, $jsonString)
                Write-Output "Results exported to JSON: $FilePath"
            }
        }

        if ($exportResults.Count -gt 0) {
            Write-Output "`nTop 5 highest risk events:"
            $exportResults | 
                Select-Object timestamp, risk_score, detected_patterns | 
                Sort-Object risk_score -Descending | 
                Select-Object -First 5 | 
                Format-Table -AutoSize
        }
    }
    catch {
        Write-Error "Failed to export results: $_"
        Write-Error $_.Exception.Message
        return
    }
}

Write-Output "Starting PowerShell 4104 Event Analysis..."
Write-Output "Loading patterns from $PatternFile..."
$patterns = Load-Patterns -FilePath $PatternFile
if (-Not $patterns) { exit }

Write-Output "Analyzing events..."
$results = Analyze-Events -Patterns $patterns -MaxEvents $MaxEvents

if ($null -eq $results -or $results.Count -eq 0) {
    Write-Warning "No results found to export. Exiting..."
    exit
}

if ([string]::IsNullOrEmpty($OutputFile)) {
    $OutputFile = Get-TimestampedFileName -Format $OutputFormat
}
else {
    $OutputFile = Get-TimestampedFileName -BaseFileName $OutputFile -Format $OutputFormat
}

Write-Output "Exporting results to $OutputFile..."
Export-Results -Results $results -FilePath $OutputFile -Format $OutputFormat