from fastapi import FastAPI, HTTPException
import json
import os
import requests
from typing import Dict
import getpass
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
from panos_safety import configure_tls, tls_verify

# TLS verification is on by default. Under uvicorn, configure it with
# NET_SCRIPTS_VERIFY_TLS=false (lab only) or NET_SCRIPTS_CA_BUNDLE=/path/to/ca.pem.
configure_tls()

app = FastAPI()

# Interactively prompt for firewall details
try:
    print("Enter Palo Alto firewall details:")
    FIREWALL_IP = os.environ.get("PANOS_HOST") or input("Firewall IP (e.g., 192.0.2.1): ").strip()
    USERNAME = os.environ.get("PANOS_USERNAME") or input("Username (e.g., admin): ").strip()
    PASSWORD = os.environ.get("PANOS_PASSWORD") or getpass.getpass("Password: ").strip()
except Exception as e:
    print(f"Error during input prompt: {str(e)}")
    sys.exit(1)

def get_api_key() -> str:
    print(f"Attempting to authenticate to {FIREWALL_IP}")
    url = f"https://{FIREWALL_IP}/api/"
    data = {"type": "keygen", "user": USERNAME, "password": PASSWORD}
    
    try:
        # POST keeps the password out of the URL; the response (which holds the key) is never printed.
        response = requests.post(url, data=data, verify=tls_verify(), timeout=10)
        response.raise_for_status()
        from xml.etree import ElementTree
        root = ElementTree.fromstring(response.text)
        key = root.find(".//key")
        if key is None:
            print("Authentication failed: no API key in the firewall response")
            raise HTTPException(status_code=401, detail="Failed to retrieve API key")
        print("Authentication succeeded (API key not shown)")
        return key.text
    except requests.RequestException as e:
        status = getattr(getattr(e, "response", None), "status_code", None)
        print(f"Authentication failed ({type(e).__name__}, HTTP {status})")
        raise HTTPException(status_code=500, detail="Authentication to the firewall failed")

@app.get("/")
async def root():
    return {"message": "Welcome to the Palo Alto API. Use /export-security-policies/, /apply-policy/, or /clear-local-policy-copy/ endpoints. Docs at /docs."}

@app.post("/export-security-policies/")
async def export_security_policies(output_file_path: str) -> Dict:
    # Normalize file path for Windows compatibility
    output_file_path = os.path.normpath(output_file_path)
    
    print(f"Exporting security policies to {output_file_path}")
    
    # Ensure the directory exists
    output_dir = os.path.dirname(output_file_path)
    if output_dir:
        try:
            os.makedirs(output_dir, exist_ok=True)
            print(f"Ensured directory exists: {output_dir}")
        except Exception as e:
            print(f"Error creating directory {output_dir}: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Error creating directory: {str(e)}")

    # Authenticate to Palo Alto firewall
    try:
        api_key = get_api_key()
    except HTTPException as e:
        print(f"Authentication error: {str(e)}")
        raise e

    # Fetch security policies using PAN-OS 11.1 REST API
    policies = []
    try:
        url = f"https://{FIREWALL_IP}/restapi/v11.1/Policies/SecurityRules"
        headers = {"X-PAN-KEY": api_key}
        # Try multiple parameter combinations
        param_sets = [
            {"location": "shared"},
            {"location": "shared", "name": "security"},
            {}  # Try without parameters as a last resort
        ]
        
        for params in param_sets:
            print(f"Requesting security policies from: {url} with params {params}")
            response = requests.get(url, headers=headers, params=params, verify=tls_verify(), timeout=30)
            if response.status_code == 200:
                policies = response.json()
                print(f"Security policies retrieved via REST API: {policies}")
                break
            else:
                print(f"REST API attempt failed with params {params}: {response.status_code} {response.reason}")
                print(f"Firewall response: {response.text if response.text else 'No response'}")
    except requests.RequestException as e:
        print(f"REST API failed: {str(e)}")
        print(f"Firewall response: {e.response.text if e.response else 'No response'}")

    # If REST API didn't retrieve policies, fall back to XML API
    if not policies:
        print("Falling back to XML API to fetch security policies")
        xpaths = [
            "/config/shared/rulebase/security",  # Shared rulebase
            "/config/devices/entry[@name='localhost.localdomain']/rulebase/security",  # Device-level rulebase
            "/config/shared/pre-rulebase/security",  # Pre-rulebase
            "/config/shared/post-rulebase/security",  # Post-rulebase
            "/config/devices/entry[@name='localhost.localdomain']/pre-rulebase/security",  # Device-level pre-rulebase
            "/config/devices/entry[@name='localhost.localdomain']/post-rulebase/security"  # Device-level post-rulebase
        ]
        
        for xpath in xpaths:
            try:
                url = f"https://{FIREWALL_IP}/api/?type=config&action=get&xpath={xpath}"
                headers = {"X-PAN-KEY": api_key}
                print(f"Trying XPath: {xpath}")
                response = requests.get(url, headers=headers, verify=tls_verify(), timeout=30)
                response.raise_for_status()
                print(f"XML API response for XPath {xpath}: {response.text}")
                
                from xml.etree import ElementTree
                root = ElementTree.fromstring(response.text)
                # Extract security policies
                policies = []
                for rule in root.findall(".//entry"):
                    rule_dict = {attr: rule.get(attr) for attr in rule.attrib}
                    for child in rule:
                        rule_dict[child.tag] = [member.text for member in child.findall("member")]
                    policies.append(rule_dict)
                print(f"Security policies retrieved via XML API (XPath: {xpath}): {policies}")
                if policies:
                    break  # Stop if we found policies
            except Exception as e:
                print(f"XML API failed for XPath {xpath}: {str(e)}")
                continue
        
        # If no policies found in specific rulebases, fetch full config to find the correct path
        if not policies:
            print("No policies found in specific rulebases, fetching full configuration to locate security policies")
            try:
                url = f"https://{FIREWALL_IP}/api/?type=config&action=get"
                headers = {"X-PAN-KEY": api_key}
                response = requests.get(url, headers=headers, verify=tls_verify(), timeout=30)
                response.raise_for_status()
                print(f"Full XML API response: {response.text}")
                
                from xml.etree import ElementTree
                root = ElementTree.fromstring(response.text)
                # Search for security policies anywhere in the config
                policies = []
                for rule in root.findall(".//rulebase/security//entry"):
                    rule_dict = {attr: rule.get(attr) for attr in rule.attrib}
                    for child in rule:
                        rule_dict[child.tag] = [member.text for member in child.findall("member")]
                    policies.append(rule_dict)
                print(f"Security policies retrieved from full config: {policies}")
            except Exception as e:
                print(f"Failed to fetch full configuration: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Error fetching security policies: {str(e)}")

    # Save policies to file
    try:
        with open(output_file_path, 'w') as output_file:
            json.dump(policies, output_file, indent=4)
        print(f"Security policies saved to {output_file_path}")
    except PermissionError as e:
        print(f"Permission denied when writing to {output_file_path}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Permission denied: {str(e)}. Ensure the script has write access to the directory.")
    except Exception as e:
        print(f"Error writing to file {output_file_path}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error writing to file: {str(e)}")
    
    return {"message": f"Security policies exported to {output_file_path}"}

@app.post("/apply-policy/")
async def apply_policy(config_file_path: str, target_file_path: str) -> Dict:
    # Normalize file paths for Windows compatibility
    config_file_path = os.path.normpath(config_file_path)
    target_file_path = os.path.normpath(target_file_path)
    
    print(f"Applying policy from {config_file_path} to {target_file_path}")
    if not os.path.exists(config_file_path):
        print(f"Config file {config_file_path} not found")
        raise HTTPException(status_code=404, detail="Config file not found")

    try:
        with open(config_file_path, 'r') as config_file:
            policy = json.load(config_file)
        print(f"Policy loaded: {policy}")
    except Exception as e:
        print(f"Error reading config: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Error reading config: {str(e)}")

    try:
        api_key = get_api_key()
    except HTTPException as e:
        print(f"Authentication error: {str(e)}")
        raise e

    try:
        url = f"https://{FIREWALL_IP}/restapi/v11.1/Policies/SecurityRules"
        headers = {"X-PAN-KEY": api_key}
        params = {"location": "shared"}
        firewall_policy = {
            "entry": [
                {
                    "@name": policy.get("policy", {}).get("name", "new-rule"),
                    "source": {"member": policy.get("policy", {}).get("source", ["any"])},
                    "destination": {"member": policy.get("policy", {}).get("destination", ["any"])},
                    "action": policy.get("policy", {}).get("action", "allow")
                }
            ]
        }
        print(f"Sending policy to firewall: {firewall_policy}")
        response = requests.post(url, headers=headers, params=params, json=firewall_policy, verify=tls_verify(), timeout=30)
        response.raise_for_status()
        print(f"Firewall response: {response.text}")
        
        with open(target_file_path, 'w') as target_file:
            json.dump(policy, target_file, indent=4)
        print(f"Policy saved to {target_file_path}")
        
        return {"message": f"Policy applied to firewall and saved to {target_file_path}"}
    except requests.RequestException as e:
        print(f"Error applying policy to firewall: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error applying policy to firewall: {str(e)}")
    except Exception as e:
        print(f"Error saving policy: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error saving policy: {str(e)}")

@app.post("/clear-local-policy-copy/")
async def clear_local_policy_copy(target_file_path: str) -> Dict:
    """Empty the local JSON copy written by /apply-policy/.

    This does NOT change the firewall. To remove a rule that /apply-policy/ created,
    delete it on the firewall (or restore a config backup) and commit there.
    """
    target_file_path = os.path.normpath(target_file_path)
    print(f"Clearing local policy copy {target_file_path}")
    if not os.path.exists(target_file_path):
        raise HTTPException(status_code=404, detail="Target file not found")
    try:
        with open(target_file_path, 'w') as target_file:
            target_file.write('')
        return {"message": f"Local copy {target_file_path} cleared. The firewall was not changed."}
    except Exception as e:
        print(f"Error clearing local copy: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error clearing local copy: {str(e)}")

# To run the API: `uvicorn policy_export_api:app --reload`