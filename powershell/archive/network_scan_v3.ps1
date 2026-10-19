# PowerShell script to list open ports and active connections with destination details
# Output will be saved to a CSV file

# Define output file path
$outputFile = ".\network_scan_output.csv"

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

# Write to console
Write-Host "Scanning open ports and active connections..."

# Initialize CSV content
$csvContent = @()

# Get open ports (listening)
$openPorts = Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess | Sort-Object LocalPort -Unique
Write-Host "`n=== Open Ports ==="
Write-Host "Port`tProcess"
$csvContent += '"Section","Port","Process"'
foreach ($port in $openPorts) {
    $process = Get-Process -Id $port.OwningProcess -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    Write-Host "$($port.LocalPort)`t$process"
    $csvContent += "`"Open Ports`",`"$($port.LocalPort)`",`"$process`""
}

# Get active established connections
$connections = Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
Write-Host "`n=== Active Established Connections ==="
Write-Host "Local Address`tLocal Port`tRemote Address`tRemote Port`tDNS Name`tCountry"
$csvContent += '"Section","Local Address","Local Port","Remote Address","Remote Port","DNS Name","Country"'
foreach ($conn in $connections) {
    $remoteIP = $conn.RemoteAddress
    if ($remoteIP -ne "0.0.0.0" -and $remoteIP -ne "127.0.0.1" -and $remoteIP -ne "::" -and $remoteIP -ne "::1") {
        $dnsName = Get-DNSName -ip $remoteIP
        $country = Get-CountryFromIP -ip $remoteIP
        Write-Host "$($conn.LocalAddress)`t$($conn.LocalPort)`t$remoteIP`t$($conn.RemotePort)`t$dnsName`t$country"
        $csvContent += "`"Connections`",`"$($conn.LocalAddress)`",`"$($conn.LocalPort)`",`"$remoteIP`",`"$($conn.RemotePort)`",`"$dnsName`",`"$country`""
    }
}

# Save to CSV file
$csvContent | Out-File -FilePath $outputFile -Encoding UTF8
Write-Host "`nScan complete. Output saved to $outputFile"

# Optionally open the output file in Notepad++
$notepadPlusPlus = "C:\Program Files\Notepad++\notepad++.exe"
if (Test-Path $notepadPlusPlus) {
    Start-Process -FilePath $notepadPlusPlus -ArgumentList $outputFile
} else {
    Write-Host "Notepad++ not found at $notepadPlusPlus. Please open $outputFile manually."
}