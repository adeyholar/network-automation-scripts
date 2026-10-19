# PowerShell script to list open ports and active connections with destination details
Write-Host "Scanning open ports and active connections..."

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

# Get open ports (listening)
$openPorts = Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess | Sort-Object LocalPort -Unique
Write-Host "`n=== Open Ports ==="
Write-Host "Port`tProcess"
foreach ($port in $openPorts) {
    $process = Get-Process -Id $port.OwningProcess -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    Write-Host "$($port.LocalPort)`t$process"
}

# Get active established connections
$connections = Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
Write-Host "`n=== Active Established Connections ==="
Write-Host "Local Address`tLocal Port`tRemote Address`tRemote Port`tDNS Name`tCountry"

foreach ($conn in $connections) {
    $remoteIP = $conn.RemoteAddress
    if ($remoteIP -ne "0.0.0.0" -and $remoteIP -ne "127.0.0.1" -and $remoteIP -ne "::" -and $remoteIP -ne "::1") {
        $dnsName = Get-DNSName -ip $remoteIP
        $country = Get-CountryFromIP -ip $remoteIP
        Write-Host "$($conn.LocalAddress)`t$($conn.LocalPort)`t$remoteIP`t$($conn.RemotePort)`t$dnsName`t$country"
    }
}

Write-Host "`nScan complete."