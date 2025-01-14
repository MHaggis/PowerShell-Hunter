$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = Join-Path $PWD "MRU_Registry_Analysis_$timestamp.txt"

Start-Transcript -Path $outputFile -Force

function Format-ByteArrayAsHex {
    param([byte[]]$Bytes, $Width = 16)
    
    for($i = 0; $i -lt $Bytes.Length; $i += $Width) {
        $line = $Bytes[$i..([Math]::Min($i + $Width - 1, $Bytes.Length - 1))]
        $hex = ($line | ForEach-Object { $_.ToString('X2') }) -join ' '
        $ascii = ($line | ForEach-Object { if ($_ -ge 0x20 -and $_ -le 0x7E) { [char]$_ } else { '.' } }) -join ''
        
        '{0:X8}: {1,-48} {2}' -f $i, $hex, $ascii
    }
}

function Analyze-RegistryValue {
    param($Value)
    
    if ($Value -is [byte[]]) {
        Write-Host "As Hex dump:"
        Format-ByteArrayAsHex $Value
        
        Write-Host "`nAs Unicode string:"
        try { Write-Host ([System.Text.Encoding]::Unicode.GetString($Value)) } catch { Write-Host "Failed to decode as Unicode" }
        
        Write-Host "`nAs ASCII string:"
        try { Write-Host ([System.Text.Encoding]::ASCII.GetString($Value)) } catch { Write-Host "Failed to decode as ASCII" }
        
        if ($Value.Length -ge 2 -and $Value[0] -eq 0x3A -and $Value[1] -eq 0x00) {
            Write-Host "`nLooks like a PIDL structure. Analyzing..."
            $offset = 2
            while ($offset -lt $Value.Length) {
                $itemSize = [BitConverter]::ToUInt16($Value, $offset)
                if ($itemSize -eq 0) { break }
                
                Write-Host "ItemID at offset $offset, size: $itemSize bytes"
                $itemData = $Value[($offset + 2)..($offset + $itemSize - 1)]
                Format-ByteArrayAsHex $itemData
                
                $offset += $itemSize
            }
        }
    }
    else {
        Write-Host "Value: $Value"
    }
}

Write-Host "=== Registry MRU Analysis ===" -ForegroundColor Cyan
Write-Host "Analysis started at: $(Get-Date)" -ForegroundColor Cyan
Write-Host "Output saved to: $outputFile`n" -ForegroundColor Cyan

# Test the registry paths
$paths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\ps1",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\sln"
)

foreach ($path in $paths) {
    Write-Host "`n=== Analyzing $path ===`n" -ForegroundColor Cyan
    
    $values = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
    if ($values) {
        $values.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            Write-Host "Value Name: $($_.Name)" -ForegroundColor Yellow
            Analyze-RegistryValue $_.Value
            Write-Host "`n---`n"
        }
    }
}

Stop-Transcript