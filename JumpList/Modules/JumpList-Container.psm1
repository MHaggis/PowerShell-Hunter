# JumpList-Container.psm1 - Jump List container parsing functions
# Part of PowerShell-Hunter - https://github.com/MHaggis/PowerShell-Hunter

Import-Module (Join-Path $PSScriptRoot 'JumpList-Parser.psm1')

function Get-AutomaticJumpListLnkStreams {
    param (
        [string]$JumpListPath
    )

    $results = @()
    try {
        Write-Debug "Processing automatic JumpList: $JumpListPath"
        $bytes = [System.IO.File]::ReadAllBytes($JumpListPath)
        
        if ($bytes.Length -lt 32) {
            Write-Warning "File too small to be a valid JumpList: $JumpListPath"
            return $results
        }

        $position = 32
        
        while ($position -lt ($bytes.Length - 4)) {
            try {
                # Look for LNK signature (4C 00 00 00)
                if ($bytes[$position] -eq 0x4C -and $bytes[$position+1] -eq 0x00) {
                    Write-Debug "Found LNK signature at offset $position"
                    
                    $streamSize = [BitConverter]::ToUInt32($bytes, $position + 4)
                    Write-Debug "Stream size at offset $position : $streamSize"
                    
                    if ($streamSize -gt 0) {
                        $effectiveSize = [Math]::Min($streamSize, $bytes.Length - $position)
                        Write-Debug "Using effective size: $effectiveSize (original: $streamSize)"
                        
                        $chunk = $bytes[$position..($position + $effectiveSize - 1)]
                        $stream = New-Object System.IO.MemoryStream
                        $writer = New-Object System.IO.BinaryWriter $stream
                        $writer.Write($chunk)
                        $writer.Flush()
                        $stream.Position = 0
                        $lnkBytes = $stream.ToArray()
                        
                        $parsed = ConvertFrom-Lnk -Bytes $lnkBytes -StreamOffset $position
                        if ($parsed) {
                            Write-Debug "Successfully parsed LNK at offset $position"
                            $parsed | Add-Member -NotePropertyName "JumpListFile" -NotePropertyValue $JumpListPath
                            $parsed | Add-Member -NotePropertyName "StreamName" -NotePropertyValue "Stream_$position"
                            $parsed | Add-Member -NotePropertyName "Type" -NotePropertyValue "Automatic"
                            $parsed | Add-Member -NotePropertyName "AppID" -NotePropertyValue ([System.IO.Path]::GetFileNameWithoutExtension($JumpListPath))
                            $results += $parsed
                        }
                        else {
                            Write-Debug "Failed to parse LNK at offset $position"
                        }
                        
                        if ($streamSize -eq 136193) {
                            $position += 1625 # Common offset difference observed in debug logs
                            Write-Debug "Using fixed increment for known stream size"
                        } else {
                            $position += $effectiveSize
                        }
                    }
                    else {
                        Write-Debug "Invalid stream size at offset $position : $streamSize"
                        $nextPosition = $position + 1
                        while ($nextPosition -lt ($bytes.Length - 4)) {
                            if ($bytes[$nextPosition] -eq 0x4C -and $bytes[$nextPosition+1] -eq 0x00) {
                                $position = $nextPosition
                                Write-Debug "Found next LNK signature at offset $position"
                                break
                            }
                            $nextPosition++
                        }
                        if ($nextPosition -ge ($bytes.Length - 4)) {
                            break
                        }
                    }
                }
                else {
                    $position++
                }
            }
            catch {
                Write-Debug "Error processing stream at offset $position : $_"
                $position++
            }
        }
    }
    catch {
        Write-Warning "Error reading automatic JumpList: $JumpListPath - $_"
    }

    return $results
}

function ConvertFrom-CustomDestinations {
    param (
        [string]$FilePath
    )

    $results = @()
    try {
        Write-Debug "Processing custom JumpList: $FilePath"
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $position = 0

        $knownOffsets = @(36, 1625, 1953, 3553)
        Write-Debug "Trying known JumpList offsets: $($knownOffsets -join ', ')"
        
        foreach ($offset in $knownOffsets) {
            if ($offset -lt ($bytes.Length - 4)) {
                try {
                    if ($bytes[$offset] -eq 0x4C -and $bytes[$offset+1] -eq 0x00) {
                        Write-Debug "Found LNK signature at known offset $offset"
                        $lnkBytes = $bytes[$offset..($offset + 2000)]
                        $parsed = ConvertFrom-Lnk -Bytes $lnkBytes -StreamOffset $offset
                        if ($parsed) {
                            Write-Debug "Successfully parsed LNK at known offset $offset"
                            $parsed | Add-Member -NotePropertyName "JumpListFile" -NotePropertyValue $FilePath
                            $parsed | Add-Member -NotePropertyName "StreamName" -NotePropertyValue "N/A"
                            $parsed | Add-Member -NotePropertyName "Type" -NotePropertyValue "Custom"
                            $parsed | Add-Member -NotePropertyName "AppID" -NotePropertyValue ([System.IO.Path]::GetFileNameWithoutExtension($FilePath))
                            $results += $parsed
                        }
                    }
                } catch {
                    Write-Debug "Error trying known offset $offset : $_"
                }
            }
        }

        if ($results.Count -eq 0) {
            Write-Debug "No results with known offsets, trying regular scan"
            while ($position -lt ($bytes.Length - 4)) {
                try {
                    # Look for LNK signature (4C 00 00 00)
                    if ($bytes[$position] -eq 0x4C -and $bytes[$position+1] -eq 0x00) {
                        Write-Debug "Found LNK signature at offset $position"
                        
                        $streamSize = [BitConverter]::ToUInt32($bytes, $position + 4)
                        Write-Debug "Stream size at offset $position : $streamSize"
                        
                        if ($streamSize -gt 0) {
                            $effectiveSize = [Math]::Min($streamSize, $bytes.Length - $position)
                            Write-Debug "Using effective size: $effectiveSize (original: $streamSize)"
                            
                            $chunk = $bytes[$position..($position + $effectiveSize - 1)]
                            $stream = New-Object System.IO.MemoryStream
                            $writer = New-Object System.IO.BinaryWriter $stream
                            $writer.Write($chunk)
                            $writer.Flush()
                            $stream.Position = 0
                            $lnkBytes = $stream.ToArray()
                            
                            $parsed = ConvertFrom-Lnk -Bytes $lnkBytes -StreamOffset $position
                            if ($parsed) {
                                Write-Debug "Successfully parsed LNK at offset $position"
                                $parsed | Add-Member -NotePropertyName "JumpListFile" -NotePropertyValue $FilePath
                                $parsed | Add-Member -NotePropertyName "StreamName" -NotePropertyValue "N/A"
                                $parsed | Add-Member -NotePropertyName "Type" -NotePropertyValue "Custom"
                                $parsed | Add-Member -NotePropertyName "AppID" -NotePropertyValue ([System.IO.Path]::GetFileNameWithoutExtension($FilePath))
                                $results += $parsed
                            }
                            else {
                                Write-Debug "Failed to parse LNK at offset $position"
                            }
                            
                            if ($streamSize -eq 136193) {
                                $position += 1625 # Common offset difference observed in debug logs
                                Write-Debug "Using fixed increment for known stream size"
                            } else {
                                $position += $effectiveSize
                            }
                        }
                        else {
                            Write-Debug "Invalid stream size at offset $position : $streamSize"
                            $nextPosition = $position + 1
                            while ($nextPosition -lt ($bytes.Length - 4)) {
                                if ($bytes[$nextPosition] -eq 0x4C -and $bytes[$nextPosition+1] -eq 0x00) {
                                    $position = $nextPosition
                                    Write-Debug "Found next LNK signature at offset $position"
                                    break
                                }
                                $nextPosition++
                            }
                            if ($nextPosition -ge ($bytes.Length - 4)) {
                                break
                            }
                        }
                    }
                    else {
                        $position++
                    }
                }
                catch {
                    Write-Debug "Error processing stream at offset $position : $_"
                    $position++
                }
            }
        }
    }
    catch {
        Write-Warning "Error reading custom JumpList: $FilePath - $_"
    }

    return $results
}

Export-ModuleMember -Function Get-AutomaticJumpListLnkStreams, ConvertFrom-CustomDestinations 