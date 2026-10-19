# Palo Alto Networks (PAN-OS) tools

## config-change-cli

**What:** Interactive, menu-driven object and config management over the PAN-OS XML API.

Menu: 1 Backup running configuration · 2 Delete objects · 3 Replace objects · 4 Add new objects interactively · 5 Restore running configuration · 6 Exit · 7 Create or update objects in batch from file · 8 Export firewall policies to CSV · 9 Export routing configurations to CSV · 10 Export default virtual router configuration to CSV.

- `palo_config_change.py` — latest (v1.5.19).
- `palo_config_change_stable.py` — previous known-good release (v1.5.13), kept as a fallback.

**Requirements:** Windows (uses `msvcrt`), Python 3.9+, `requests`. HTTPS access to the firewall or Panorama management interface and an admin account (or an API certificate/key pair).

**Usage:**
```bash
python palo_config_change.py
```
You are prompted for the firewall/Panorama address, then for a client certificate and key (press Enter to use username/password keygen instead). Batch files use one entry per line: `name,value` for address objects and `group_name,member1;member2` for groups, for example `SRV-APP01,192.0.2.21/32`. The last reachable host is cached in `last_firewall.txt` (gitignored).

## config-change-webapp

**What:** Flask web UI for the object-migration workflow (upload a config backup such as `FW01_cfg_202401011200.xml`, review and push object changes).

**Requirements:** Python 3.9+, `flask`, `requests`.

**Usage:**
```bash
cd config-change-webapp
python app.py            # http://127.0.0.1:5000 ; set FLASK_DEBUG=1 only for local development
```

## policy-api

**What:** FastAPI service with three endpoints:
- `POST /export-security-policies/?output_file_path=...` exports security rules to JSON, using the PAN-OS REST API and falling back to the XML API.
- `POST /apply-policy/` applies a policy from a JSON config file.
- `POST /undo-policy/` reverts it.

**Requirements:** Python 3.9+, `fastapi`, `uvicorn`, `requests`. Credentials from `PANOS_HOST`, `PANOS_USERNAME`, `PANOS_PASSWORD` or prompted at start-up.

**Usage:**
```bash
cd policy-api
uvicorn policy_export_api:app --reload   # docs at http://127.0.0.1:8000/docs
```

## address-object-updater

**What:** Lists address objects on a firewall/Panorama, lets you pick some, enter new values and apply them in one batch, using `pan-os-python`.

**Requirements:** Python 3.9+, `pan-os-python`.

**Usage:** `python update_address_objects.py`
