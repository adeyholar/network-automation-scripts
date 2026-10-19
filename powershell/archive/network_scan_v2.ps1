# PowerShell script to list open ports and active connections with destination details
# Output will be saved to a text file

# Define output file path
$outputFile = ".\network_scan_output.txt"

# Clear the output file if it exists
if (Test-Path $outputFile) { Clear-Content $outputFile }

# Function to get country from IP
function Get-CountryFromIP {
    param ($ip)
    try {
        $response = Invoke-RestMethod -Uri "http://ip-api.com/json/$ip" -TimeoutSec 5
        if ($response.status -eq "success") {
            return $response.country
        } else {
            return "Unknown"
        }
    } catch {
        return "Unknown"
    }
}

# Function to resolve DNS name
function Get-DNSName {
    param ($ip)
    try {
        $dns = [System.Net.Dns]::GetHostEntry($ip).HostName
        return $dns
    } catch {
        return "Unresolved"
    }
}

# Write to file and console
function Write-OutputAndFile {
    param ($message)
    Write-Host $message
    Add-Content -Path $outputFile -Value $message
}

Write-OutputAndFile "Scanning open ports and active connections..."

# Get open ports (listening)
$openPorts = Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess | Sort-Object LocalPort -Unique
Write-OutputAndFile "`n=== Open Ports ==="
Write-OutputAndFile "Port`tProcess"
foreach ($port in $openPorts) {
    $process = Get-Process -Id $port.OwningProcess -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    Write-OutputAndFile "$($port.LocalPort)`t$process"
}

# Get active established connections
$connections = Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
Write-OutputAndFile "`n=== Active Established Connections ==="
Write-OutputAndFile "Local Address`tLocal Port`tRemote Address`tRemote Port`tDNS Name`tCountry"
foreach ($conn in $connections) {
    $remoteIP = $conn.RemoteAddress
    if ($remoteIP -ne "0.0.0.0" -and $remoteIP -ne "127.0.0.1" -and $remoteIP -ne "::" -and $remoteIP -ne "::1") {
        $dnsName = Get-DNSName -ip $remoteIP
        $country = Get-CountryFromIP -ip $remoteIP
        Write-OutputAndFile "$($conn.LocalAddress)`t$($conn.LocalPort)`t$remoteIP`t$($conn.RemotePort)`t$dnsName`t$country"
    }
}

Write-OutputAndFile "`nScan complete."

# Optionally open the output file in Notepad++
# Replace 'notepad++.exe' path if it's different on your system
$notepadPlusPlus = "C:\Program Files\Notepad++\notepad++.exe"
if (Test-Path $notepadPlusPlus) {
    Start-Process -FilePath $notepadPlusPlus -ArgumentList $outputFile
} else {
    Write-Host "Notepad++ not found at $notepadPlusPlus. Please open $outputFile manually."
}