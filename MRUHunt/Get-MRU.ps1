<#
.SYNOPSIS
    Retrieves Most Recently Used (MRU) entries from Windows Registry
.DESCRIPTION
    Extracts and decodes MRU entries from ComDlg32 registry keys including:
    - OpenSavePidlMRU
    - LastVisitedPidlMRU
    - CIDSizeMRU
    Shows both recently used files and applications in chronological order.
.NOTES
    File Name      : Get-MRU.ps1
    Author        : The Haag
    Prerequisite  : PowerShell
.LINK
    https://github.com/MHaggis/PowerShell-Hunter
#>

function Convert-BinaryToString {
    param([byte[]]$Bytes)
    
    if ($null -eq $Bytes) { return "[null]" }
    

    try {
        $text = [System.Text.Encoding]::Unicode.GetString($Bytes).Split([char]0x00)[0]
        if ($text -match '[\w\-\.]+\.[a-zA-Z0-9]+$') {  # Match any extension
            return $text
        }
    }
    catch {
        Write-Verbose "Error decoding initial Unicode: $_"
    }
    
    # Handle PIDL structures (starts with 3A 00)
    if ($Bytes[0] -eq 0x3A -and $Bytes[1] -eq 0x00) {
        try {
            $offset = 2
            $itemIdList = New-Object System.Collections.ArrayList
            
            while ($offset -lt $Bytes.Length) {
                $itemSize = [BitConverter]::ToUInt16($Bytes, $offset)
                if ($itemSize -eq 0) { break }
                
                $itemData = $Bytes[($offset + 2)..($offset + $itemSize - 1)]
                $itemIdList.Add($itemData) | Out-Null
                $offset += $itemSize
            }
            
            if ($itemIdList.Count -gt 0) {
                foreach ($item in $itemIdList) {
                    try {
                        $text = [System.Text.Encoding]::Unicode.GetString($item).Split([char]0x00)[0]
                        if ($text -match '[\w\-\.]+\.[a-zA-Z0-9]+$') {
                            return $text
                        }
                    } catch {}
                    $asciiText = ""
                    for ($i = 0; $i -lt $item.Length; $i++) {
                        if ($item[$i] -ge 0x20 -and $item[$i] -le 0x7E) {
                            $asciiText += [char]$item[$i]
                        }
                    }
                    if ($asciiText -match '[\w\-\.]+\.[a-zA-Z0-9]+$') {
                        return $matches[0]
                    }
                }
            }
        }
        catch {
            Write-Verbose "Error parsing PIDL: $_"
        }
    }
    
    return "[Binary Data]"
}

function Format-KeyName {
    param([string]$KeyName)
    $shortName = $KeyName -replace '^.*\\', ''
    return $shortName
}

$basePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32"

# ASCII Art and Banner
$banner = @"

#     # ######  #     #    #     #                     
##   ## #     # #     #    #     # #    # #    # ##### 
# # # # #     # #     #    #     # #    # ##   #   #   
#  #  # ######  #     #    ####### #    # # #  #   #   
#     # #   #   #     #    #     # #    # #  # #   #   
#     # #    #  #     #    #     # #    # #   ##   #   
#     # #     #  #####     #     #  ####  #    #   #   
                                    
         [ Hunt smarter, hunt harder ]
         
"@

# Start of script
Write-Host $banner -ForegroundColor Cyan
Write-Host "=== Scanning Windows MRU Registry Keys ===`n" -ForegroundColor Yellow
Write-Host "Started at: $(Get-Date)`n" -ForegroundColor Gray

Get-ChildItem -Path $basePath -Recurse | Where-Object {
    # Filter out empty or system keys
    $_.PSChildName -notmatch '^PS' -and 
    (Get-ItemProperty -Path $_.PSPath) -and 
    $_.PSChildName -ne 'Count' -and 
    $_.PSChildName -ne 'Length'
} | ForEach-Object {
    $key = $_
    $keyName = Format-KeyName $key.Name
    Write-Host "Registry Key: " -NoNewline -ForegroundColor Yellow
    Write-Host $keyName
    
    if ($key.LastWriteTime) {
        Write-Host "Last Modified: " -NoNewline -ForegroundColor Gray
        Write-Host $key.LastWriteTime
    }
    
    $values = Get-ItemProperty -Path $key.PSPath
    
    $mruOrder = @()
    if ($values.MRUListEx) {
        for ($i = 0; $i -lt $values.MRUListEx.Length - 4; $i += 4) {
            $value = [BitConverter]::ToInt32($values.MRUListEx, $i)
            if ($value -ne -1) {
                $mruOrder += $value
            }
        }
        
        if ($mruOrder.Count -gt 0) {
            Write-Host "`nMost Recent Items:" -ForegroundColor Green
            foreach ($index in $mruOrder) {
                $value = $values.$index
                if ($value) {
                    $decoded = Convert-BinaryToString $value
                    if ($decoded -and $decoded -ne "[Binary Data]") {
                        Write-Host "  [$index] " -NoNewline -ForegroundColor Magenta
                        Write-Host $decoded
                    }
                }
            }
        }
    }
    
    $numericValues = $values.PSObject.Properties | Where-Object {
        $_.Name -match '^\d+$'
    }
    
    if ($numericValues) {
        Write-Host "`nAll Stored Items:" -ForegroundColor Green
        $numericValues | ForEach-Object {
            $decoded = Convert-BinaryToString $_.Value
            if ($decoded -and $decoded -ne "[Binary Data]") {
                Write-Host "  $($_.Name): " -NoNewline
                Write-Host $decoded
            }
        }
    }
    
    Write-Host "`n" + "=".PadRight(48, "=") + "`n"
}