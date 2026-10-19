from fastapi import FastAPI, HTTPException
import json
import os
import requests
from typing import Dict
import getpass

app = FastAPI()

# Interactively prompt for firewall details
print("Enter Palo Alto firewall details:")
FIREWALL_IP = input("Firewall IP (e.g., 192.0.2.1): ").strip()
USERNAME = input("Username (e.g., admin): ").strip()
PASSWORD = getpass.getpass("Password: ").strip()

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
        url = f"https://{FIREWALL_IP}/restapi/v10.1/Policies/SecurityRules"
        headers = {"X-PAN-KEY": api_key}
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
        response = requests.post(url, headers=headers, json=firewall_policy, verify=False)
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

# To run the API: `uvicorn policy_apply_api_v0_4_windows:app --reload`