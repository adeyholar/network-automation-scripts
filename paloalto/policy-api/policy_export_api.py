"""PAN-OS policy API (FastAPI).

Endpoints export security rules, create one security rule from a JSON file, and
clear a local JSON copy. Every request needs the X-API-Token header.

Configuration is read from environment variables only (no prompts at import):
  NET_SCRIPTS_API_TOKEN  required; requests are rejected when it is unset
  PANOS_HOST, PANOS_USERNAME, PANOS_PASSWORD
  NET_SCRIPTS_WORK_DIR   folder for all file reads/writes (default ./output)
  NET_SCRIPTS_VERIFY_TLS / NET_SCRIPTS_CA_BUNDLE  (see README)

Run: uvicorn policy_export_api:app   (or `python policy_export_api.py` to be
prompted for any missing PAN-OS credentials before the server starts).
"""
import json
import os
import re
import secrets
import sys
from typing import Dict, List, Optional

import requests
from defusedxml.ElementTree import fromstring as safe_fromstring
from fastapi import Depends, FastAPI, Header, HTTPException

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
from panos_safety import configure_tls, tls_verify, xpath_literal  # noqa: E402

configure_tls()

VSYS_XPATH = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
ALLOWED_ACTIONS = {"allow", "deny", "drop"}
REQUIRED_LIST_FIELDS = ("from", "to", "source", "destination", "application", "service")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$")


# ---------- auth ----------
def require_token(x_api_token: Optional[str] = Header(default=None)) -> None:
    expected = os.environ.get("NET_SCRIPTS_API_TOKEN", "")
    if not expected:
        raise HTTPException(status_code=503, detail="Server has no NET_SCRIPTS_API_TOKEN set; all requests are refused.")
    if not x_api_token or not secrets.compare_digest(x_api_token.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Token header")


app = FastAPI(dependencies=[Depends(require_token)])


# ---------- settings and paths ----------
def firewall_settings():
    host = os.environ.get("PANOS_HOST", "").strip()
    user = os.environ.get("PANOS_USERNAME", "").strip()
    password = os.environ.get("PANOS_PASSWORD", "")
    if not (host and user and password):
        raise HTTPException(status_code=500, detail="PANOS_HOST, PANOS_USERNAME and PANOS_PASSWORD must be set")
    return host, user, password


def prompt_missing_credentials() -> None:
    """Interactive helper, used only when the file is run directly."""
    import getpass
    if not os.environ.get("PANOS_HOST"):
        os.environ["PANOS_HOST"] = input("Firewall IP or hostname (e.g., 192.0.2.1): ").strip()
    if not os.environ.get("PANOS_USERNAME"):
        os.environ["PANOS_USERNAME"] = input("Username: ").strip()
    if not os.environ.get("PANOS_PASSWORD"):
        os.environ["PANOS_PASSWORD"] = getpass.getpass("Password: ")


def work_dir() -> str:
    base = os.path.realpath(os.environ.get("NET_SCRIPTS_WORK_DIR") or os.path.join(os.getcwd(), "output"))
    os.makedirs(base, exist_ok=True)
    return base


def safe_path(user_path: str) -> str:
    """Resolve user_path inside WORK_DIR; HTTP 400 if it escapes (.., absolute paths, symlinks)."""
    if not user_path or "\x00" in user_path:
        raise HTTPException(status_code=400, detail="A file path is required")
    base = work_dir()
    full = os.path.realpath(os.path.join(base, user_path))
    if os.path.commonpath([base, full]) != base or full == base:
        raise HTTPException(status_code=400, detail="Path must be inside NET_SCRIPTS_WORK_DIR")
    return full


# ---------- PAN-OS ----------
def get_api_key() -> str:
    host, user, password = firewall_settings()
    try:
        # POST keeps the password out of the URL; the response (it holds the key) is never printed.
        response = requests.post(f"https://{host}/api/", data={"type": "keygen", "user": user, "password": password},
                                 verify=tls_verify(), timeout=10)
        response.raise_for_status()
        key = safe_fromstring(response.text).find(".//key")
    except requests.RequestException as e:
        status = getattr(getattr(e, "response", None), "status_code", None)
        print(f"Authentication failed ({type(e).__name__}, HTTP {status})")
        raise HTTPException(status_code=502, detail="Authentication to the firewall failed")
    except Exception:
        print("Authentication failed: unreadable firewall response")
        raise HTTPException(status_code=502, detail="Authentication to the firewall failed")
    if key is None or not key.text:
        print("Authentication failed: no API key in the firewall response")
        raise HTTPException(status_code=401, detail="Failed to retrieve API key")
    print("Authentication succeeded (API key not shown)")
    return key.text


def rules_from_xml(text: str) -> List[Dict]:
    rules = []
    for rule in safe_fromstring(text).findall(".//entry"):
        rule_dict = dict(rule.attrib)
        for child in rule:
            members = [m.text for m in child.findall("member")]
            rule_dict[child.tag] = members if members else child.text
        rules.append(rule_dict)
    return rules


def validate_policy(policy) -> Dict:
    """Fail closed: every field is required and any/any/allow is refused."""
    if not isinstance(policy, dict):
        raise HTTPException(status_code=400, detail="Config must contain a 'policy' object")
    name = policy.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="policy.name is required (letters, digits, space . _ -, max 63)")
    for field in REQUIRED_LIST_FIELDS:
        value = policy.get(field)
        if not isinstance(value, list) or not value or not all(isinstance(v, str) and v.strip() for v in value):
            raise HTTPException(status_code=400, detail=f"policy.{field} must be a non-empty list of names")
    action = policy.get("action")
    if action not in ALLOWED_ACTIONS:
        raise HTTPException(status_code=400, detail="policy.action must be allow, deny or drop")
    if action == "allow" and policy["source"] == ["any"] and policy["destination"] == ["any"]:
        raise HTTPException(status_code=400, detail="Refusing an any-to-any allow rule")
    return {"name": name, "action": action, **{f: policy[f] for f in REQUIRED_LIST_FIELDS}}


# ---------- endpoints ----------
@app.get("/")
async def root():
    return {"message": "PAN-OS policy API. Endpoints: /export-security-policies/, /apply-policy/, "
                       "/clear-local-policy-copy/. Docs at /docs."}


@app.post("/export-security-policies/")
async def export_security_policies(output_file_path: str) -> Dict:
    output_file_path = safe_path(output_file_path)
    host, _, _ = firewall_settings()
    api_key = get_api_key()
    headers = {"X-PAN-KEY": api_key}
    policies = []

    url = f"https://{host}/restapi/v11.1/Policies/SecurityRules"
    try:
        response = requests.get(url, headers=headers, params={"location": "vsys", "vsys": "vsys1"},
                                verify=tls_verify(), timeout=30)
        print(f"REST API request: HTTP {response.status_code}")
        if response.status_code == 200:
            policies = response.json().get("result", {}).get("entry", []) or []
    except (requests.RequestException, ValueError) as e:
        print(f"REST API request failed ({type(e).__name__})")

    if not policies:
        xpath = VSYS_XPATH + "/rulebase/security/rules"
        try:
            response = requests.get(f"https://{host}/api/", headers=headers,
                                    params={"type": "config", "action": "get", "xpath": xpath},
                                    verify=tls_verify(), timeout=30)
            print(f"XML API request: HTTP {response.status_code}")
            response.raise_for_status()
            policies = rules_from_xml(response.text)
        except requests.RequestException as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            print(f"XML API request failed ({type(e).__name__}, HTTP {status})")
            raise HTTPException(status_code=502, detail="Could not read security rules from the firewall")
        except Exception:
            print("XML API response could not be parsed")
            raise HTTPException(status_code=502, detail="Unreadable response from the firewall")

    print(f"Security rules retrieved: {len(policies)}")
    try:
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        with open(output_file_path, "w") as output_file:
            json.dump(policies, output_file, indent=4)
    except OSError as e:
        print(f"Could not write export file ({type(e).__name__})")
        raise HTTPException(status_code=500, detail="Could not write the export file")
    return {"message": f"{len(policies)} security rules exported", "file": os.path.relpath(output_file_path, work_dir())}


@app.post("/apply-policy/")
async def apply_policy(config_file_path: str, target_file_path: str) -> Dict:
    config_file_path = safe_path(config_file_path)
    target_file_path = safe_path(target_file_path)
    if not os.path.isfile(config_file_path):
        raise HTTPException(status_code=404, detail="Config file not found")
    try:
        with open(config_file_path) as config_file:
            raw = json.load(config_file)
    except (OSError, ValueError):
        raise HTTPException(status_code=400, detail="Config file is not valid JSON")
    rule = validate_policy(raw.get("policy") if isinstance(raw, dict) else None)

    host, _, _ = firewall_settings()
    api_key = get_api_key()
    body = {"entry": {"@name": rule["name"], "action": rule["action"],
                      **{f: {"member": rule[f]} for f in REQUIRED_LIST_FIELDS}}}
    try:
        response = requests.post(f"https://{host}/restapi/v11.1/Policies/SecurityRules",
                                 headers={"X-PAN-KEY": api_key},
                                 params={"location": "vsys", "vsys": "vsys1", "name": rule["name"]},
                                 json=body, verify=tls_verify(), timeout=30)
        print(f"Create rule request: HTTP {response.status_code}")
        response.raise_for_status()
    except requests.RequestException as e:
        status = getattr(getattr(e, "response", None), "status_code", None)
        print(f"Create rule failed ({type(e).__name__}, HTTP {status})")
        raise HTTPException(status_code=502, detail=f"Firewall rejected the rule (HTTP {status})")

    with open(target_file_path, "w") as target_file:
        json.dump({"policy": rule}, target_file, indent=4)
    return {"message": f"Rule '{rule['name']}' added to the candidate configuration (not committed); "
                       "local copy saved",
            "file": os.path.relpath(target_file_path, work_dir())}


@app.post("/clear-local-policy-copy/")
async def clear_local_policy_copy(target_file_path: str) -> Dict:
    """Empty a local JSON copy written by /apply-policy/. This does NOT change the firewall."""
    target_file_path = safe_path(target_file_path)
    if not os.path.isfile(target_file_path):
        raise HTTPException(status_code=404, detail="Target file not found")
    with open(target_file_path, "w") as target_file:
        target_file.write("")
    return {"message": "Local copy cleared. The firewall was not changed."}


if __name__ == "__main__":
    import uvicorn
    if not os.environ.get("NET_SCRIPTS_API_TOKEN"):
        sys.exit("Set NET_SCRIPTS_API_TOKEN before starting the API.")
    prompt_missing_credentials()
    uvicorn.run(app, host="127.0.0.1", port=8000)
