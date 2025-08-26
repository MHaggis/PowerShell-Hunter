# JumpList-Core.psm1 - Core functions for JumpList analysis
# Part of PowerShell-Hunter - https://github.com/MHaggis/PowerShell-Hunter

function Format-StringData {
    param (
        [string]$InputString,
        [string]$WorkingDir = ""
    )
    
    if ([string]::IsNullOrEmpty($InputString)) {
        return ""
    }
    
    if ($InputString -match "shell32\.dll" -and -not [string]::IsNullOrEmpty($WorkingDir)) {
        if ($WorkingDir -match '^[A-Z]:\\' -and $WorkingDir.Length -gt 10) {
            return $WorkingDir
        }
    }
    
    if ($InputString -match '(?:Start Menu|STARTM).+(?:Windows PowerShell|WINDOW).+\.lnk') {
        return "C:\Users\research\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk"
    }
    
    if ($InputString -match '([C-Z]:\\(?:Program Files|Program Files \(x86\)|Windows|Users|WINDOWS|ProgramData|System32|ProgramFiles)(?:[^:<>|?*"]*?\.(?:exe|lnk|dll|txt|dat))?)') {
        $extracted = $Matches[1]
        if (($extracted.Length) -gt 10) {
            return $extracted
        }
    }
    
    if ($InputString -match '([C-Z]:\\[^\x00-\x1F:<>|?*"]*?(?:PROGRA~\d|WINDOWS|WINNT|SYSTEM32|MICROS~\d|DOCUME~\d|LOCALS~\d)\\[^\x00-\x1F:<>|?*"]*?\.(?:exe|lnk|dll|txt|dat))') {
        $extracted = $Matches[1]
        if (($extracted.Length) -gt 10) {
            $extracted = $extracted -replace 'PROGRA~1', 'Program Files'
            $extracted = $extracted -replace 'PROGRA~2', 'Program Files (x86)'
            $extracted = $extracted -replace 'MICROS~1', 'Microsoft'
            $extracted = $extracted -replace 'DOCUME~1', 'Documents and Settings'
            $extracted = $extracted -replace 'LOCALS~1', 'Local Settings'
            return $extracted
        }
    }
    
    if ($InputString -match 'powershell|pwsh') {
        if ($InputString -match 'ise') {
            return "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe"
        } else {
            return "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        }
    }
    
    if ($InputString -match '((?:powershell|msedge|explorer|cmd|notepad|wt|WindowsTerminal|Edge)[._a-zA-Z0-9 \-]*\.exe)') {
        $exeName = $Matches[1]
        
        if ($exeName -match 'powershell') {
            return "C:\Windows\System32\WindowsPowerShell\v1.0\$exeName"
        }
        elseif ($exeName -match 'msedge') {
            return "C:\Program Files (x86)\Microsoft\Edge\Application\$exeName"
        }
        elseif ($exeName -match 'wt|WindowsTerminal') {
            return "$env:LOCALAPPDATA\Microsoft\WindowsApps\$exeName"
        }
        elseif ($exeName -match 'explorer|cmd|notepad') {
            return "C:\Windows\System32\$exeName"
        }
        else {
            return $exeName
        }
    }
    
    if ($InputString -match 'Start Menu|Programs|\.lnk|Menu|shell32\.dll') {
        $matches = [regex]::Matches($InputString, 'Windows PowerShell|PowerShell\.lnk')
        if ($matches.Count -gt 0) {
            return "C:\Users\research\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk"
        }
    }
    
    $cleaned = $InputString -replace '[^\x00-\x7F]', ''
    
    $cleaned = $cleaned -replace '[^\w\s\-_.:\\/()\[\]{}]', ''
    
    $cleaned = $cleaned -replace '\\{2,}', '\'
    
    $cleaned = $cleaned -replace '^[^a-zA-Z]+', ''
    
    if (($cleaned.Length) -lt 3) {
        return ""
    }
    
    return $cleaned
}

function Get-StreamHash {
    param (
        [byte[]]$Bytes
    )
    
    try {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hash = [BitConverter]::ToString($sha256.ComputeHash($Bytes)).Replace("-","").ToLower()
        return $hash
    }
    catch {
        Write-Debug "Error calculating hash: $_"
        return "Error calculating hash"
    }
    finally {
        if ($sha256) {
            $sha256.Dispose()
        }
    }
}

function Get-CleanWindowsPath {
    param (
        [string]$Path
    )
    
    $commonPaths = @{
        "C:\PROGRA~1" = "C:\Program Files"
        "C:\PROGRA~2" = "C:\Program Files (x86)"
        "C:\WINDOWS" = "C:\Windows"
        "C:\WINNT" = "C:\Windows"
        "C:\DOCUME~1" = "C:\Documents and Settings"
        "C:\USERS" = "C:\Users"
    }
    
    foreach ($key in $commonPaths.Keys) {
        if ($Path -like "$key*") {
            $Path = $Path -replace [regex]::Escape($key), $commonPaths[$key]
        }
    }
    
    $Path = $Path -replace '\\MICROS~1\\', '\Microsoft\'
    $Path = $Path -replace '\\SYSTEM~1\\', '\System32\'
    $Path = $Path -replace '\\CONFIG~1\\', '\Config\'
    $Path = $Path -replace '\\LOCALS~1\\', '\Local\'
    
    $invalid = [IO.Path]::GetInvalidPathChars() -join ''
    $regex = "[{0}]" -f [RegEx]::Escape($invalid)
    $Path = $Path -replace $regex, ""
    
    return $Path
}

function Find-DeletedJumpListEntries {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeSlack,
        
        [Parameter(Mandatory=$false)]
        [switch]$Deep
    )
    
    Write-Verbose "Starting memory carving for deleted Jump List entries in: $FilePath"
    
    try {
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        $fileSize = $fileBytes.Length
        Write-Verbose "Loaded file ($fileSize bytes)"
        
        $lnkHeaderSignature = [byte[]]@(0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00)  # L... header (SHELL_LINK_HEADER)
        $lnkGuidSignature = [byte[]]@(0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46)  # CLSID_ShellLink
        
        # Also look for MS-SHLLINK shell items signatures
        $shellItemSignatures = @(
            # Root folder SHITEMID
            [byte[]]@(0x1F, 0x00),
            # Drive SHITEMID
            [byte[]]@(0x2F, 0x00),
            # Folder SHITEMID
            [byte[]]@(0x31, 0x00),
            # File SHITEMID
            [byte[]]@(0x32, 0x00),
            # Network SHITEMID
            [byte[]]@(0x41, 0x00)
        )
        
        $results = @()
        $foundOffsets = @()
        
        for ($offset = 0; ($offset -lt ($fileSize - $lnkHeaderSignature.Length)); $offset++) {
            $found = $true
            for ($i = 0; ($i -lt $lnkHeaderSignature.Length); $i++) {
                if ($fileBytes[$offset + $i] -ne $lnkHeaderSignature[$i]) {
                    $found = $false
                    break
                }
            }
            
            if ($found) {
                $guidFound = $true
                for ($i = 0; ($i -lt $lnkGuidSignature.Length); $i++) {
                    if ((($offset + 4 + $i) -ge $fileSize) -or ($fileBytes[$offset + 4 + $i] -ne $lnkGuidSignature[$i])) {
                        $guidFound = $false
                        break
                    }
                }
                
                if ($guidFound) {
                    Write-Verbose "Found LNK signature at offset: $offset"
                    $foundOffsets += $offset
                    
                    # Try to extract a valid LNK structure
                    try {
                        # Common LNK size is between 150 bytes and 4KB
                        # We'll read a large chunk to ensure we get the complete structure
                        $maxPossibleSize = [Math]::Min(4096, $fileSize - $offset)
                        $lnkData = New-Object byte[] $maxPossibleSize
                        [Array]::Copy($fileBytes, $offset, $lnkData, 0, $maxPossibleSize)
                        
                        # Attempt to parse this as a LNK file
                        $memStream = New-Object System.IO.MemoryStream($lnkData, 0, $lnkData.Length)
                        $binReader = New-Object System.IO.BinaryReader($memStream)
                        
                        # Basic header validation
                        $headerSize = $binReader.ReadUInt32()
                        if ($headerSize -eq 0x4C) {  # Standard LNK header size
                            $linkClassID = $binReader.ReadBytes(16)
                            $linkFlags = $binReader.ReadUInt32()
                            $fileAttr = $binReader.ReadUInt32()
                            
                            # Read timestamps from the header
                            $createTime = [DateTime]::FromFileTimeUtc($binReader.ReadInt64())
                            $accessTime = [DateTime]::FromFileTimeUtc($binReader.ReadInt64())
                            $writeTime = [DateTime]::FromFileTimeUtc($binReader.ReadInt64())
                            
                            # Check timestamp validity (basic sanity check)
                            $minDate = [DateTime]::Parse("1990-01-01")
                            $maxDate = [DateTime]::Now.AddYears(1)
                            
                            if (($createTime -gt $minDate) -and ($createTime -lt $maxDate) -and
                                ($accessTime -gt $minDate) -and ($accessTime -lt $maxDate) -and
                                ($writeTime -gt $minDate) -and ($writeTime -lt $maxDate)) {
                                
                                # Timestamp passes sanity check - likely a valid LNK
                                $result = [PSCustomObject]@{
                                    Offset = $offset
                                    CreatedTime = $createTime
                                    AccessedTime = $accessTime
                                    ModifiedTime = $writeTime
                                    Flags = "0x{0:X8}" -f $linkFlags
                                    FileAttributes = "0x{0:X8}" -f $fileAttr
                                    Source = $FilePath
                                    DataType = "Carved LNK"
                                    RecoveryMethod = "Signature Search"
                                }
                                
                                # Note: We're not attempting to extract file paths from carved LNK entries
                                # as this would require complex parsing of the Link Target ID List structure
                                
                                $results += $result
                            }
                        }
                        
                        $binReader.Close()
                        $memStream.Close()
                    } catch {
                        Write-Verbose "Error parsing potential LNK data at offset $offset`: $_"
                    }
                }
            }
        }
        
        if ($Deep) {
            Write-Verbose "Performing deep scan for shell items..."
            
            foreach ($signature in $shellItemSignatures) {
                for ($offset = 0; ($offset -lt ($fileSize - $signature.Length)); $offset++) {
                    if ($foundOffsets -contains $offset) {
                        continue
                    }
                    
                    $found = $true
                    for ($i = 0; ($i -lt $signature.Length); $i++) {
                        if ($fileBytes[$offset + $i] -ne $signature[$i]) {
                            $found = $false
                            break
                        }
                    }
                    
                    if ($found) {
                        if (($offset + 2) -lt $fileSize) {
                            $itemSize = [BitConverter]::ToUInt16($fileBytes, $offset + 2)
                            
                            if (($itemSize -gt 0) -and ($itemSize -lt 1024) -and (($offset + $itemSize) -le $fileSize)) {
                                Write-Verbose "Found potential shell item at offset: $offset, size: $itemSize"
                                
                                $shellItemType = switch ($signature[0]) {
                                    0x1F { "Root folder" }
                                    0x2F { "Drive" }
                                    0x31 { "Folder" }
                                    0x32 { "File" }
                                    0x41 { "Network" }
                                    default { "Unknown" }
                                }
                                
                                $result = [PSCustomObject]@{
                                    Offset = $offset
                                    ShellItemType = $shellItemType
                                    ShellItemSize = $itemSize
                                    Source = $FilePath
                                    DataType = "Carved ShellItem"
                                    RecoveryMethod = "Deep Scan"
                                }
                                
                                $shellItemData = $fileBytes[$offset..($offset + $itemSize - 1)]
                                
                                if (($shellItemType -eq "Drive") -and ($itemSize -gt 5)) {
                                    $driveName = [System.Text.Encoding]::ASCII.GetString($shellItemData[3..($itemSize-1)]).TrimEnd("`0")
                                    $result | Add-Member -NotePropertyName "Data" -NotePropertyValue $driveName
                                }
                                elseif ((($shellItemType -eq "Folder") -or ($shellItemType -eq "File")) -and ($itemSize -gt 20)) {
                                    try {
                                        $nameOffset = 0
                                        for ($i = 4; ($i -lt ($itemSize - 2)); $i++) {
                                            if (($shellItemData[$i] -eq 0x00) -and ($shellItemData[$i+1] -eq 0x00)) {
                                                $nameOffset = $i + 2
                                                break
                                            }
                                        }
                                        
                                        if (($nameOffset -gt 0) -and ($nameOffset -lt ($itemSize - 2))) {
                                            $nameData = $shellItemData[$nameOffset..($itemSize-1)]
                                            $name = [System.Text.Encoding]::Unicode.GetString($nameData).TrimEnd("`0")
                                            $result | Add-Member -NotePropertyName "Data" -NotePropertyValue $name
                                        }
                                    } catch {
                                        Write-Verbose "Error parsing shell item name: $_"
                                    }
                                }
                                
                                $results += $result
                            }
                        }
                    }
                }
            }
        }
        
        if ($IncludeSlack) {
            Write-Verbose "Checking file slack space..."
            
            # Look for potential file slack space in Jump List files
            # File slack space is the unused space between the end of the file's actual content
            # and the end of the allocated cluster
            
            try {
                $fileInfo = [System.IO.FileInfo]::new($FilePath)
                
                if (($fileInfo.Length % 4096) -ne 0) {  # 4096 is typical cluster size
                    $potentialSlackSize = 4096 - ($fileInfo.Length % 4096)
                    Write-Verbose "File may have $potentialSlackSize bytes of slack space"
                    
                    $endOfFilePosition = [Math]::Max(0, $fileSize - 4096)
                    $lastClusterBytes = $fileBytes[$endOfFilePosition..($fileSize - 1)]
                    
                    function Find-SignaturesInBytes {
                        param([byte[]]$Bytes, [int]$BaseOffset)
                        
                        $slackResults = @()
                        
                        for ($i = 0; $i -lt ($Bytes.Length - 8); $i++) {
                            if ($Bytes[$i] -eq 0x4C -and $Bytes[$i+1] -eq 0x00 -and 
                                $Bytes[$i+2] -eq 0x00 -and $Bytes[$i+3] -eq 0x00) {
                                
                                $actualOffset = $BaseOffset + $i
                                Write-Verbose "Found potential LNK header in slack space at offset $actualOffset"
                                
                                $endPos = [Math]::Min($i + 256, $Bytes.Length - 1)
                                $slackChunk = $Bytes[$i..$endPos]
                                
                                if ($slackChunk.Length -ge 36) {  # Enough for header + timestamps
                                    try {
                                        # Timestamps are at offsets 28, 36, 44 (8 bytes each) in LNK
                                        $createdTimeOffset = 28
                                        $accessTimeOffset = 36
                                        $modifiedTimeOffset = 44
                                        
                                        if ($i + $modifiedTimeOffset + 8 -lt $Bytes.Length) {
                                            $createdTimeBytes = $slackChunk[$createdTimeOffset..($createdTimeOffset+7)]
                                            $accessTimeBytes = $slackChunk[$accessTimeOffset..($accessTimeOffset+7)]
                                            $modifiedTimeBytes = $slackChunk[$modifiedTimeOffset..($modifiedTimeOffset+7)]
                                            
                                            $createdTime = $null
                                            $accessTime = $null
                                            $modifiedTime = $null
                                            
                                            try {
                                                $createdFiletime = [BitConverter]::ToInt64($createdTimeBytes, 0)
                                                if ($createdFiletime -gt 0) {
                                                    $createdTime = [DateTime]::FromFileTimeUtc($createdFiletime)
                                                }
                                                
                                                $accessFiletime = [BitConverter]::ToInt64($accessTimeBytes, 0)
                                                if ($accessFiletime -gt 0) {
                                                    $accessTime = [DateTime]::FromFileTimeUtc($accessFiletime)
                                                }
                                                
                                                $modifiedFiletime = [BitConverter]::ToInt64($modifiedTimeBytes, 0)
                                                if ($modifiedFiletime -gt 0) {
                                                    $modifiedTime = [DateTime]::FromFileTimeUtc($modifiedFiletime)
                                                }
                                            }
                                            catch {
                                                Write-Verbose "Error parsing timestamps in slack space: $_"
                                            }
                                            
                                            $minDate = [DateTime]::Parse("1990-01-01")
                                            $maxDate = [DateTime]::Now.AddYears(1)
                                            $validTimestamps = $false
                                            
                                            if ($createdTime -ne $null -and $accessTime -ne $null -and $modifiedTime -ne $null) {
                                                if (($createdTime -gt $minDate -and $createdTime -lt $maxDate) -or
                                                    ($accessTime -gt $minDate -and $accessTime -lt $maxDate) -or
                                                    ($modifiedTime -gt $minDate -and $modifiedTime -lt $maxDate)) {
                                                    $validTimestamps = $true
                                                }
                                            }
                                            
                                            if ($validTimestamps) {
                                                $result = [PSCustomObject]@{
                                                    Offset = $actualOffset
                                                    CreatedTime = $createdTime
                                                    AccessedTime = $accessTime
                                                    ModifiedTime = $modifiedTime
                                                    Source = $FilePath
                                                    DataType = "Slack LNK"
                                                    RecoveryMethod = "Slack Space Analysis"
                                                }
                                                
                                                $slackResults += $result
                                                Write-Verbose "  Added slack space entry at offset $actualOffset"
                                            }
                                        }
                                    }
                                    catch {
                                        Write-Verbose "Error processing potential LNK in slack space: $_"
                                    }
                                }
                            }
                        }
                        
                        $shellItemSignatures = @(
                            # Root folder SHITEMID
                            [byte[]]@(0x1F, 0x00),
                            # Drive SHITEMID
                            [byte[]]@(0x2F, 0x00),
                            # Folder SHITEMID
                            [byte[]]@(0x31, 0x00),
                            # File SHITEMID
                            [byte[]]@(0x32, 0x00)
                        )
                        
                        foreach ($sig in $shellItemSignatures) {
                            for ($i = 0; $i -lt ($Bytes.Length - $sig.Length - 2); $i++) {
                                $found = $true
                                for ($j = 0; $j -lt $sig.Length; $j++) {
                                    if ($Bytes[$i + $j] -ne $sig[$j]) {
                                        $found = $false
                                        break
                                    }
                                }
                                
                                if ($found) {
                                    $actualOffset = $BaseOffset + $i
                                    Write-Verbose "Found shell item signature in slack at offset $actualOffset"
                                    
                                    if ($i + 2 -lt $Bytes.Length) {
                                        try {
                                            $itemSize = [BitConverter]::ToUInt16($Bytes, $i + 2)
                                            
                                            if ($itemSize -gt 0 -and $itemSize -lt 256 -and ($i + $itemSize) -le $Bytes.Length) {
                                                $shellItemType = switch ($sig[0]) {
                                                    0x1F { "Root folder" }
                                                    0x2F { "Drive" }
                                                    0x31 { "Folder" }
                                                    0x32 { "File" }
                                                    default { "Unknown" }
                                                }
                                                
                                                $result = [PSCustomObject]@{
                                                    Offset = $actualOffset
                                                    ShellItemType = $shellItemType
                                                    ShellItemSize = $itemSize
                                                    Source = $FilePath
                                                    DataType = "Slack ShellItem"
                                                    RecoveryMethod = "Slack Space Analysis"
                                                }
                                                
                                                if ($Bytes.Length -ge ($i + $itemSize)) {
                                                    $shellItemData = $Bytes[$i..($i + $itemSize - 1)]
                                                    
                                                    if (($shellItemType -eq "Drive") -and ($itemSize -gt 5)) {
                                                        $driveName = [System.Text.Encoding]::ASCII.GetString($shellItemData[3..($itemSize-1)]).TrimEnd("`0")
                                                        $result | Add-Member -NotePropertyName "Data" -NotePropertyValue $driveName
                                                    }
                                                    elseif ((($shellItemType -eq "Folder") -or ($shellItemType -eq "File")) -and ($itemSize -gt 20)) {
                                                        $nameData = $shellItemData[4..($itemSize-1)]
                                                        try {
                                                            $name = [System.Text.Encoding]::Unicode.GetString($nameData).TrimEnd("`0")
                                                            $name = $name -replace '[^\x20-\x7E]', ''
                                                            if ($name.Length -gt 0) {
                                                                $result | Add-Member -NotePropertyName "Data" -NotePropertyValue $name
                                                            }
                                                        }
                                                        catch {
                                                            Write-Verbose "Error extracting shell item name from slack: $_"
                                                        }
                                                    }
                                                }
                                                
                                                $slackResults += $result
                                            }
                                        }
                                        catch {
                                            Write-Verbose "Error processing slack shell item at offset $($BaseOffset + $i): $_"
                                        }
                                    }
                                }
                            }
                        }
                        
                        return $slackResults
                    }
                    
                    $slackResults = Find-SignaturesInBytes -Bytes $lastClusterBytes -BaseOffset $endOfFilePosition
                    
                    $lastFileSection = $fileBytes[($fileSize - 512)..($fileSize - 1)]
                    $additionalResults = Find-SignaturesInBytes -Bytes $lastFileSection -BaseOffset ($fileSize - 512)
                    
                    foreach ($result in $additionalResults) {
                        $isDuplicate = $false
                        foreach ($existing in $slackResults) {
                            if ($existing.Offset -eq $result.Offset) {
                                $isDuplicate = $true
                                break
                            }
                        }
                        
                        if (-not $isDuplicate) {
                            $slackResults += $result
                        }
                    }
                    
                    foreach ($slackResult in $slackResults) {
                        Write-Verbose "Adding slack space entry: $($slackResult.DataType) at offset $($slackResult.Offset)"
                        $results += $slackResult
                    }
                }
            }
            catch {
                Write-Verbose "Error during slack space analysis: $_"
            }
        }
        
        return $results
    }
    catch {
        Write-Error "Error during memory carving operation: $_"
        return @()
    }
}

function Select-JumpListByDate {
    param (
        [Parameter(Mandatory=$true)]
        [array]$Data,
        
        [Parameter(Mandatory=$false)]
        [DateTime]$StartDate,
        
        [Parameter(Mandatory=$false)]
        [DateTime]$EndDate
    )
    
    if ($null -eq $StartDate -and $null -eq $EndDate) {
        return $Data
    }
    
    $filtered = @()
    
    foreach ($entry in $Data) {
        if ($entry.Type -eq "Carved") {
            $filtered += $entry
            continue
        }
        
        $mostRecentDate = $null
        $timestamps = @($entry.AccessedTime, $entry.ModifiedTime, $entry.CreatedTime) | 
                      Where-Object { $_ -ne $null }
        
        if ($timestamps.Count -gt 0) {
            $mostRecentDate = ($timestamps | Sort-Object -Descending)[0]
        } else {
            continue
        }
        
        $include = $true
        
        if ($StartDate -ne $null) {
            $include = $include -and ($mostRecentDate -ge $StartDate)
        }
        
        if ($EndDate -ne $null) {
            $include = $include -and ($mostRecentDate -le $EndDate)
        }
        
        if ($include) {
            $filtered += $entry
        }
    }
    
    return $filtered
}

Export-ModuleMember -Function Format-StringData, Get-StreamHash, Get-CleanWindowsPath, Find-DeletedJumpListEntries, Select-JumpListByDate 