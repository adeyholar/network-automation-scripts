# Palo Alto Networks (PAN-OS) tools

## config-change-cli

**What:** Interactive, menu-driven object and config management over the PAN-OS XML API.

Menu: 1 Backup running configuration · 2 Delete objects · 3 Replace objects · 4 Add new objects interactively · 5 Restore running configuration · 6 Exit · 7 Create or update objects in batch from file · 8 Export firewall policies to CSV · 9 Export routing configurations to CSV · 10 Export default virtual router configuration to CSV.

- `palo_config_change.py` (v1.5.21). Version history is in `CHANGELOG.md`; the older `palo_config_change_stable.py` was removed (it is in git history).

**Requirements:** Python 3.9+, `requests`, `defusedxml` (Windows, Linux or macOS). HTTPS access to the firewall or Panorama management interface and an admin account (or an API certificate/key pair).

**Usage:**
```bash
python palo_config_change.py --dry-run   # see what would change, no writes
python palo_config_change.py
```
You are prompted for the firewall/Panorama address, then for a client certificate and key (press Enter to use username/password keygen instead). Batch files use one entry per line: `name,value` for address objects and `group_name,member1;member2` for groups, for example `SRV-APP01,192.0.2.21/32`. The last reachable host is cached in `last_firewall.txt` (gitignored).

## config-change-webapp

**What:** Flask web UI for the object-migration workflow (upload a config backup such as `FW01_cfg_202401011200.xml`, review and push object changes).

**Requirements:** Python 3.9+, `flask`, `requests`.

**Usage:**
```bash
cd config-change-webapp
export FLASK_SECRET_KEY=...   # otherwise a random per-process key is used (with a warning)
python app.py                 # http://127.0.0.1:5000 ; debug is off unless FLASK_DEBUG=1
```

## policy-api

**What:** FastAPI service with three endpoints:
- `POST /export-security-policies/?output_file_path=...` exports security rules to JSON, using the PAN-OS REST API and falling back to the XML API.
- `POST /apply-policy/?config_file_path=...&target_file_path=...` creates one security rule in the candidate config (not committed) and saves a local copy. It fails closed: the JSON `policy` object must have `name`, `from`, `to`, `source`, `destination`, `application`, `service` (lists) and `action` (`allow`, `deny` or `drop`); any-to-any allow is refused.
- `POST /clear-local-policy-copy/?target_file_path=...` empties a local JSON copy. It does not change the firewall.

Every request needs the `X-API-Token` header matching `NET_SCRIPTS_API_TOKEN`; if that variable is unset, all requests are refused. File paths are relative to `NET_SCRIPTS_WORK_DIR` (default `./output`); paths outside it return HTTP 400. Logs contain status codes and counts only.

**Requirements:** Python 3.9+, `fastapi`, `uvicorn`, `requests`, `defusedxml`. Credentials come from `PANOS_HOST`, `PANOS_USERNAME`, `PANOS_PASSWORD` (environment only under uvicorn; `python policy_export_api.py` prompts for any that are missing).

Example `policy` file:
```json
{"policy": {"name": "allow-web", "from": ["trust"], "to": ["untrust"], "source": ["192.0.2.0/24"],
            "destination": ["198.51.100.10"], "application": ["web-browsing"],
            "service": ["application-default"], "action": "allow"}}
```

**Usage:**
```bash
cd policy-api
export NET_SCRIPTS_API_TOKEN=change-me-to-a-long-random-value
uvicorn policy_export_api:app   # docs at http://127.0.0.1:8000/docs
```

## address-object-updater

**What:** Lists address objects on a firewall/Panorama, lets you pick some, enter new values and apply them in one batch, using `pan-os-python`.

**Requirements:** Python 3.9+, `pan-os-python`.

**Usage:** `python update_address_objects.py`
