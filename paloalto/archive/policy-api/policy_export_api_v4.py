from fastapi import FastAPI, HTTPException
import json
import os
import requests
from typing import Dict
import getpass
import sys

app = FastAPI()

# Interactively prompt for firewall details
try:
    print("Enter Palo Alto firewall details:")
    FIREWALL_IP = input("Firewall IP (e.g., 192.0.2.1): ").strip()
    USERNAME = input("Username (e.g., admin): ").strip()
    PASSWORD = getpass.getpass("Password: ").strip()
except Exception as e:
    print(f"Error during input prompt: {str(e)}")
    sys.exit(1)

def get_api_key() -> str:
    print(f"Attempting to authenticate to {FIREWALL_IP}")
    url = f"https://{FIREWALL_IP}/api/?type=keygen"
    params = {"user": USERNAME, "password": PASSWORD}
    
    try:
        response = requests.get(url, params=params, verify=False, timeout=10)
        response.raise_for_status()
        print(f"Authentication response: {response.text}")
        
        from xml.etree import ElementTree
        root = ElementTree.fromstring(response.text)
        key = root.find(".//key")
        if key is None:
            print("API key not found in response")
            raise HTTPException(status_code=401, detail="Failed to retrieve API key")
        print("API key retrieved successfully")
        return key.text
    except requests.RequestException as e:
        print(f"Authentication failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Authentication error: {str(e)}")

@app.get("/")
async def root():
    return {"message": "Welcome to the Palo Alto API. Use /apply-policy/, /undo-policy/, or /export-security-policies/ endpoints. Docs at /docs."}

@app.post("/export-security-policies/")
async def export_security_policies(output_file_path: str, vsys: str = "vsys1", location: str = "vsys") -> Dict:
    # Normalize file path for Windows compatibility
    output_file_path = os.path.normpath(output_file_path)
    
    print(f"Exporting security policies to {output_file_path} with location={location}, vsys={vsys}")
    
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
    try:
        url = f"https://{FIREWALL_IP}/restapi/v11.1/Policies/SecurityRules"
        headers = {"X-PAN-KEY": api_key}
        params = {"location": location, "vsys": vsys}
        print(f"Requesting security policies from: {url} with params {params}")
        response = requests.get(url, headers=headers, params=params, verify=False)
        response.raise_for_status()
        policies = response.json()
        print(f"Security policies retrieved via REST API: {policies}")
    except requests.RequestException as e:
        print(f"REST API failed: {str(e)}")
        print(f"Firewall response: {e.response.text if e.response else 'No response'}")
        
        # Fallback: Use XML API to fetch the full configuration and extract security policies
        print("Falling back to XML API to fetch full configuration")
        try:
            url = f"https://{FIREWALL_IP}/api/?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']/rulebase/security"
            headers = {"X-PAN-KEY": api_key}
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            from xml.etree import ElementTree
            root = ElementTree.fromstring(response.text)
            # Extract security policies
            policies = []
            for rule in root.findall(".//entry"):
                rule_dict = {attr: rule.get(attr) for attr in rule.attrib}
                for child in rule:
                    rule_dict[child.tag] = [member.text for member in child.findall("member")]
                policies.append(rule_dict)
            print(f"Security policies retrieved via XML API: {policies}")
        except Exception as e:
            print(f"XML API failed: {str(e)}")
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
async def apply_policy(config_file_path: str, target_file_path: str, vsys: str = "vsys1", location: str = "vsys") -> Dict:
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
        params = {"location": location, "vsys": vsys}
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
        response = requests.post(url, headers=headers, params=params, json=firewall_policy, verify=False)
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

@app.post("/undo-policy/")
async def undo_policy(target_file_path: str) -> Dict:
    # Normalize file path for Windows compatibility
    target_file_path = os.path.normpath(target_file_path)
    
    print(f"Undoing policy for {target_file_path}")
    if not os.path.exists(target_file_path):
        print(f"Target file {target_file_path} not found")
        raise HTTPException(status_code=404, detail="Target file not found")

    try:
        api_key = get_api_key()
    except HTTPException as e:
        print(f"Authentication error: {str(e)}")
        raise e

    try:
        with open(target_file_path, 'w') as target_file:
            target_file.write('')
        print(f"Target file {target_file_path} cleared")
        return {"message": f"Policy undone for {target_file_path}"}
    except Exception as e:
        print(f"Error undoing policy: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error undoing policy: {str(e)}")

# To run the API: `uvicorn policy_export_api_v4:app --reload`