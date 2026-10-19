# VMware VeloCloud (SD-WAN) tools

**What:** Retrieves Non SD-WAN Destinations (`enterprise/getEnterpriseNetworkServices`) from the VeloCloud Orchestrator API and prints name and networks as a table.

- `non_sdwan_destinations.py` — authenticates with an API token.
- `non_sdwan_destinations_login.py` — logs in with username and password (`login/enterpriseLogin`) and uses the session.
- `archive/` — earlier version, not maintained.

**Requirements:** Python 3.9+, `requests`, `tabulate`. Set `VCO_URL` plus `VCO_API_TOKEN` (or `VCO_USERNAME`/`VCO_PASSWORD`); anything not set is prompted for, with secrets entered hidden.

**Usage:**
```bash
export VCO_URL=https://orchestrator.example.com
python non_sdwan_destinations.py
```
Adjust `enterprise_id` in the script if your account is not enterprise 1. The token script prints the raw API response for troubleshooting, so don't paste its output publicly.
