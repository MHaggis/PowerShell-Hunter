# JumpList-Parser.psm1 - LNK and Shell Item parsing functions
# Part of PowerShell-Hunter - https://github.com/MHaggis/PowerShell-Hunter

Import-Module (Join-Path $PSScriptRoot 'JumpList-Core.psm1')

function ConvertFrom-Lnk {
    param (
        [byte[]]$Bytes,
        [int]$StreamOffset = 0
    )

    try {
        $reader = New-Object System.IO.BinaryReader([System.IO.MemoryStream]::new($Bytes))

        $streamHash = Get-StreamHash -Bytes $Bytes
        Write-Debug "Stream SHA256: $streamHash"

        $signature = $reader.ReadBytes(4)
        if ($signature[0] -ne 0x4C -or $signature[1] -ne 0x00 -or $signature[2] -ne 0x00 -or $signature[3] -ne 0x00) {
            Write-Debug "Invalid LNK signature"
            return $null
        }

        $reader.BaseStream.Seek(4, 'Begin') | Out-Null
        $guid = [Guid]::new($reader.ReadBytes(16))
        Write-Debug "LNK GUID: $guid"

        $reader.BaseStream.Seek(0x14, 'Begin') | Out-Null
        $flags = $reader.ReadUInt32()
        $flagsHex = '0x{0:X8}' -f $flags
        Write-Debug "LNK Flags: $flagsHex"

        $flagMeanings = @()
        if ($flags -band 0x00000001) { $flagMeanings += "HasLinkTargetIDList" }
        if ($flags -band 0x00000002) { $flagMeanings += "HasLinkInfo" }
        if ($flags -band 0x00000004) { $flagMeanings += "HasName" }
        if ($flags -band 0x00000008) { $flagMeanings += "HasRelativePath" }
        if ($flags -band 0x00000010) { $flagMeanings += "HasWorkingDir" }
        if ($flags -band 0x00000020) { $flagMeanings += "HasArguments" }
        if ($flags -band 0x00000040) { $flagMeanings += "HasIconLocation" }
        Write-Debug "Flag meanings: $($flagMeanings -join ', ')"

        $reader.BaseStream.Seek(0x18, 'Begin') | Out-Null
        $fileAttrs = $reader.ReadUInt32()
        $fileAttrsHex = '0x{0:X8}' -f $fileAttrs
        Write-Debug "File attributes: $fileAttrsHex"

        $reader.BaseStream.Seek(0x1C, 'Begin') | Out-Null
        $created = [DateTime]::FromFileTimeUtc($reader.ReadInt64())
        $accessed = [DateTime]::FromFileTimeUtc($reader.ReadInt64())
        $modified = [DateTime]::FromFileTimeUtc($reader.ReadInt64())
        Write-Debug "Created: $created, Accessed: $accessed, Modified: $modified"

        $reader.BaseStream.Seek(0x34, 'Begin') | Out-Null
        $fileSize = $reader.ReadUInt32()
        Write-Debug "File size: $fileSize"

        $reader.BaseStream.Seek(0x38, 'Begin') | Out-Null
        $iconIndex = $reader.ReadInt32()
        Write-Debug "Icon index: $iconIndex"

        $reader.BaseStream.Seek(0x3C, 'Begin') | Out-Null
        $showCommand = $reader.ReadUInt32()
        $showCommandStr = switch($showCommand) {
            1 { "Normal window" }
            3 { "Maximized" }
            7 { "Minimized" }
            default { "Unknown ($showCommand)" }
        }
        Write-Debug "Show command: $showCommandStr"

        $reader.BaseStream.Seek(0x40, 'Begin') | Out-Null
        $hotKey = $reader.ReadUInt16()
        $hotKeyStr = if ($hotKey -ne 0) {
            $key = $hotKey -band 0xFF
            $mod = ($hotKey -shr 8) -band 0xFF
            $keyStr = if ($key -ge 0x30 -and $key -le 0x39) { [char]$key } 
                      elseif ($key -ge 0x41 -and $key -le 0x5A) { [char]$key }
                      else { "VK 0x{0:X2}" -f $key }
            $modStr = @()
            if ($mod -band 1) { $modStr += "SHIFT" }
            if ($mod -band 2) { $modStr += "CTRL" }
            if ($mod -band 4) { $modStr += "ALT" }
            ($modStr -join '+') + '+' + $keyStr
        } else { "None" }
        Write-Debug "Hot key: $hotKeyStr"

        $shellItems = $null
        $reader.BaseStream.Position = 0x4C
        if ($flags -band 0x00000001) { # HasLinkTargetIDList
            $idListSize = $reader.ReadUInt16()
            if ($idListSize -gt 0) {
                $idListBytes = $reader.ReadBytes($idListSize)
                $shellItems = ConvertFrom-ShellItems -Bytes $idListBytes
                Write-Debug "Found $($shellItems.Count) shell items"
            }
            $reader.BaseStream.Position = 0x4C + 2 + $idListSize
        }

        $pathOffset = 0x4C
        if ($flags -band 0x00000001) { # HasLinkTargetIDList
            $idListSize = [BitConverter]::ToUInt16($Bytes, 0x4C)
            $pathOffset = 0x4C + 2 + $idListSize
        }
        
        $reader.BaseStream.Position = $pathOffset
        $pathSize = $reader.ReadUInt16()
        Write-Debug "Path size: $pathSize"
        
        $path = ""
        $workingDir = ""
        $args = ""
        $iconLocation = ""

        if ($pathSize -gt 0) {  # Sanity check on path size
            $rawPath = $reader.ReadChars($pathSize) -join ''
            $path = Format-StringData -InputString $rawPath
            Write-Debug "Found path: $path"

            # Additional metadata
            $reader.BaseStream.Position = $pathOffset + 2 + $pathSize
            $workingDirSize = $reader.ReadUInt16()
            Write-Debug "Working dir size: $workingDirSize"
            
            if ($workingDirSize -gt 0) { 
                $rawWorkingDir = ($reader.ReadChars($workingDirSize) -join '')
                $workingDir = Format-StringData -InputString $rawWorkingDir
                Write-Debug "Working dir: $workingDir"
            }
            
            $argsSize = 0
            if ($flags -band 0x00000020) { # HasArguments
                try {
                    $reader.BaseStream.Position = $pathOffset + 2 + $pathSize + 2 + $workingDirSize
                    $argsSize = $reader.ReadUInt16()
                    Write-Debug "Args size: $argsSize"
                    
                    if ($argsSize -gt 0) {
                        $rawArgs = ($reader.ReadChars($argsSize) -join '')
                        $args = Format-StringData -InputString $rawArgs
                        Write-Debug "Args: $args"
                    }
                } catch {
                    Write-Debug "Error reading args: $_"
                }
            }
            
            $iconLocationSize = 0
            if ($flags -band 0x00000040) { # HasIconLocation
                try {
                    $reader.BaseStream.Position = $pathOffset + 2 + $pathSize + 2 + $workingDirSize + 2 + $argsSize
                    $iconLocationSize = $reader.ReadUInt16()
                    Write-Debug "Icon location size: $iconLocationSize"
                    
                    if ($iconLocationSize -gt 0) {
                        $rawIconLocation = ($reader.ReadChars($iconLocationSize) -join '')
                        $iconLocation = Format-StringData -InputString $rawIconLocation
                        Write-Debug "Icon location: $iconLocation"
                    }
                } catch {
                    Write-Debug "Error reading icon location: $_"
                }
            }

            if ($path -match '[^\x20-\x7E]' -and -not [string]::IsNullOrEmpty($workingDir) -and $workingDir -notmatch '[^\x20-\x7E]') {
                $path = $workingDir
            }

            $result = [PSCustomObject]@{
                FilePath      = $path
                WorkingDir    = $workingDir
                Arguments     = $args
                IconLocation  = $iconLocation
                CreatedTime   = $created
                AccessedTime  = $accessed
                ModifiedTime  = $modified
                Flags         = $flagsHex
                FlagMeanings  = ($flagMeanings -join ', ')
                FileSize      = $fileSize
                ShowCommand   = $showCommandStr
                HotKey        = $hotKeyStr
                StreamOffset  = $StreamOffset
                Guid          = $guid.ToString()
                SHA256        = $streamHash
            }
            
            if ($shellItems -ne $null -and $shellItems.Count -gt 0) {
                $result | Add-Member -NotePropertyName "ShellItems" -NotePropertyValue $shellItems
                
                if ($path -match '[^\x20-\x7E]' -or $path -match '^[^A-Za-z]') {
                    $reconstructedPath = ""
                    foreach ($item in $shellItems) {
                        if (-not [string]::IsNullOrEmpty($item.Data)) {
                            if ($item.Type -eq "Drive") {
                                $reconstructedPath = "$($item.Data):\"
                            } else {
                                $reconstructedPath += "\$($item.Data)"
                            }
                        }
                    }
                    
                    if ($reconstructedPath.Length -gt 5) {
                        $result.FilePath = $reconstructedPath
                    }
                }
            }
            
            return $result
        } else {
            Write-Debug "Invalid path size: $pathSize"
            return $null
        }
    }
    catch {
        Write-Debug "Error parsing LNK: $_"
        return $null
    }
}

function ConvertFrom-ShellItems {
    param (
        [byte[]]$Bytes
    )
    
    $shellItems = @()
    $offset = 0
    
    try {
        if ($Bytes.Length -lt 2) {
            Write-Debug "Shell item data too small"
            return $shellItems
        }
        
        $idListSize = [BitConverter]::ToUInt16($Bytes, $offset)
        $offset += 2
        
        if ($idListSize -eq 0 -or $idListSize -gt $Bytes.Length) {
            Write-Debug "Invalid IDList size: $idListSize"
            return $shellItems
        }
        
        while ($offset -lt [Math]::Min($idListSize, $Bytes.Length - 2)) {
            $itemSize = [BitConverter]::ToUInt16($Bytes, $offset)
            if ($itemSize -eq 0 -or $offset + $itemSize -gt $Bytes.Length) { 
                Write-Debug "Invalid shell item size or end of data"
                break 
            }
            
            $itemData = $Bytes[$offset..($offset + $itemSize - 1)]
            
            $itemType = $itemData[0]
            
            $shellItem = @{
                "Size" = $itemSize
                "Type" = "Unknown"
                "Data" = ""
            }
            
            if ($itemType -eq 0x1F) {
                $shellItem.Type = "Drive"
                $driveName = ""
                for ($i = 3; $i -lt $itemSize; $i++) {
                    if ($itemData[$i] -eq 0) { break }
                    $driveName += [char]$itemData[$i]
                }
                $shellItem.Data = $driveName
            }
            elseif ($itemType -eq 0x31 -or $itemType -eq 0x32 -or $itemType -eq 0x3A) {
                $shellItem.Type = if ($itemType -eq 0x31 -or $itemType -eq 0x3A) { "Folder" } else { "File" }
                
                $nameOffset = 0
                
                for ($i = 4; $i -lt $itemSize - 2; $i++) {
                    if ($itemData[$i] -eq 0x00 -and $itemData[$i+1] -eq 0x00 -and $itemData[$i+2] -ne 0x00) {
                        $nameOffset = $i + 2
                        break
                    }
                }
                
                if ($nameOffset -gt 0 -and $nameOffset -lt $itemSize - 2) {
                    $nameBytes = $itemData[$nameOffset..($itemSize-1)]
                    if ($nameBytes.Length -gt 0) {
                        try {
                            if ($nameBytes.Length % 2 -eq 0) {
                                $shellItem.Data = [System.Text.Encoding]::Unicode.GetString($nameBytes).TrimEnd("`0")
                            }
                            
                            if ([string]::IsNullOrEmpty($shellItem.Data)) {
                                $shellItem.Data = [System.Text.Encoding]::ASCII.GetString($nameBytes).TrimEnd("`0")
                            }
                        } catch {
                            Write-Debug "Error extracting name from shell item: $_"
                        }
                    }
                }
                
                $shellItem.Data = $shellItem.Data -replace '[^\x20-\x7E]', ''
            }
            elseif ($itemType -eq 0x2F -or $itemType -eq 0x2E) {
                $shellItem.Type = "Network"
                
                $nameOffset = 0
                for ($i = 5; $i -lt $itemSize - 1; $i++) {
                    if ($itemData[$i] -eq 0x00 -and $itemData[$i+1] -ne 0x00) {
                        $nameOffset = $i + 1
                        break
                    }
                }
                
                if ($nameOffset -gt 0) {
                    try {
                        $shellItem.Data = [System.Text.Encoding]::ASCII.GetString($itemData[$nameOffset..($itemSize-1)]).TrimEnd("`0")
                    } catch {
                        Write-Debug "Error extracting network name: $_"
                    }
                }
            }
            
            $shellItems += $shellItem
            $offset += $itemSize
        }
    }
    catch {
        Write-Debug "Error parsing shell items: $_"
    }
    
    return $shellItems
}

Export-ModuleMember -Function ConvertFrom-Lnk, ConvertFrom-ShellItems 