# PowerShell tools

## network_scan.ps1

**What:** Lists listening TCP ports with their owning process, and established connections with remote address, reverse DNS name and country (via the public ip-api.com service), then saves everything to `network_scan_output_<timestamp>.csv` and opens it in Notepad++ if installed.

**Requirements:** Windows with PowerShell 5.1+ (`Get-NetTCPConnection`). Internet access for the country lookup. No credentials needed.

**Usage:**
```powershell
.\network_scan.ps1                                   # output next to the script
$env:NETSCAN_OUTPUT_DIR = "D:\scans"; .\network_scan.ps1
```
Note: remote IPs are sent to ip-api.com for geolocation. Remove `Get-CountryFromIP` if that is not acceptable in your environment. `archive/` holds earlier versions.
