# Network Automation Scripts

A practical toolkit for automating day-to-day firewall and SD-WAN operations: **Palo Alto Networks PAN-OS** object and policy changes, configuration backup/restore, policy and routing exports, plus **VMware VeloCloud**, **FortiGate** and **Windows PowerShell** utilities. The tools grew out of real migration and change-management work and are written to be safe to run interactively by an engineer at a console.

## Highlights

| Area | What it does |
|---|---|
| **PAN-OS config change CLI** (`paloalto/config-change-cli`) | Menu-driven tool over the PAN-OS XML API: back up and restore the running config, bulk create / replace / delete address objects and address groups (from a file or interactively), validate IP / range / wildcard / FQDN / IPv6 values, and export security policies, routes and the default virtual router to CSV. Supports certificate-based API auth with a fallback to keygen. |
| **PAN-OS web UI** (`paloalto/config-change-webapp`) | Flask front end for the same object-migration workflow: upload a config backup, review objects, and push changes. |
| **PAN-OS policy API** (`paloalto/policy-api`) | FastAPI service that exports security rules (REST API with automatic XML API fallback), applies a policy from a JSON file and undoes it. Interactive docs at `/docs`. |
| **PAN-OS address-object updater** (`paloalto/address-object-updater`) | Small `pan-os-python` script to list and batch-update address objects on a firewall or Panorama. |
| **VeloCloud** (`velocloud`) | Pulls Non SD-WAN Destinations from the VeloCloud Orchestrator API and prints them as a table (API-token or username/password login). |
| **FortiGate** (`fortigate`) | Generates a staged FortiGate IPsec remote-access VPN implementation runbook (FortiManager + FortiAuthenticator RADIUS) as a Word document. |
| **PowerShell** (`powershell`) | Lists listening ports and established connections with process, reverse DNS and country lookup, saved to a timestamped CSV. |

## Repository layout

```
paloalto/
  config-change-cli/       palo_config_change.py (v1.5.19, latest), palo_config_change_stable.py (v1.5.13, known-good)
  config-change-webapp/    app.py + templates/index.html (Flask)
  policy-api/              policy_export_api.py (FastAPI)
  address-object-updater/  update_address_objects.py (pan-os-python)
velocloud/                 non_sdwan_destinations.py, non_sdwan_destinations_login.py
fortigate/                 ipsec_vpn_runbook_to_docx.py
powershell/                network_scan.ps1
```

Each folder has its own README with requirements and usage.

## Quick start

```bash
git clone https://github.com/adeyholar/network-automation-scripts.git
cd network-automation-scripts
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                # fill in your own values; never commit .env
```

Then, for example:

```bash
python paloalto/config-change-cli/palo_config_change.py          # interactive menu (Windows console)
cd paloalto/policy-api && uvicorn policy_export_api:app --reload # API docs at http://127.0.0.1:8000/docs
python velocloud/non_sdwan_destinations.py
```

## Credentials

No credentials are stored in this repository. Tools read them from environment variables (see `.env.example`) or prompt for them at run time with hidden input (`getpass`). PAN-OS tools prefer certificate-based API authentication where supported.

| Variable | Used by |
|---|---|
| `PANOS_HOST`, `PANOS_USERNAME`, `PANOS_PASSWORD` | `paloalto/policy-api` |
| `VCO_URL`, `VCO_API_TOKEN`, `VCO_USERNAME`, `VCO_PASSWORD` | `velocloud` |
| `FLASK_HOST`, `FLASK_PORT`, `FLASK_DEBUG` | `paloalto/config-change-webapp` |
| `NETSCAN_OUTPUT_DIR` | `powershell/network_scan.ps1` |
| `OUTPUT_DOCX` | `fortigate/ipsec_vpn_runbook_to_docx.py` |

## Safety notes

- **Test in a lab first.** Run against a lab or non-production device, and start with read-only actions (backup, list, export) before any change.
- **Back up before you change.** The config-change CLI offers a running-config backup before edits; keep it until the change is verified. Changes are not committed to the device until you commit them on the firewall.
- **TLS verification.** Several tools disable certificate verification to work with the self-signed certificates common on firewall management interfaces. Install a trusted management certificate and enable verification in production.
- **Keep data out of git.** `.gitignore` excludes config backups (`*.xml`), exports (`*.csv`, `*.xlsx`, `*.docx`), keys and certificates, `.env` and local cache files (`last_firewall.txt`, `last_host.txt`). Exports can contain real addresses and rule names; don't commit them.
- **Web UI and API bind to localhost by default** and have no authentication of their own. Don't expose them on a shared network.
- All IP addresses in examples are RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and all hostnames use `example.com`.

## Platform notes

- `palo_config_change*.py` uses `msvcrt` for timed console prompts, so it runs on **Windows**. The other Python tools are cross-platform.
- Python 3.9+ recommended. PowerShell scripts need Windows PowerShell 5.1 or PowerShell 7 on Windows (they use `Get-NetTCPConnection`).

## Versions

This repository contains the current version of each tool.

## License

MIT, see [LICENSE](LICENSE).
