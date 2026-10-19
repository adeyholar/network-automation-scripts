import getpass
from fastapi import FastAPI, HTTPException
import json
import os
import requests
from typing import Dict

app = FastAPI()

# Palo Alto firewall details (replace with your own)
FIREWALL_IP = os.environ.get("PANOS_HOST") or input("Firewall IP/hostname (e.g., 192.0.2.1): ").strip()
USERNAME = os.environ.get("PANOS_USERNAME") or input("PAN-OS username: ").strip()
PASSWORD = os.environ.get("PANOS_PASSWORD") or getpass.getpass("PAN-OS password: ")

def get_api_key() -> str:
    """
    Authenticate to the Palo Alto firewall and retrieve an API key.
    Returns:
        API key as a string.
    Raises:
        HTTPException on failure.
    """
    url = f"https://{FIREWALL_IP}/api/?type=keygen"
    params = {"user": USERNAME, "password": PASSWORD}
    
    try:
        # Disable SSL verification for simplicity (use proper certificates in production)
        response = requests.get(url, params=params, verify=False, timeout=10)
        response.raise_for_status()
        
        # Parse XML response to extract API key
        from xml.etree import ElementTree
        root = ElementTree.fromstring(response.text)
        key = root.find(".//key")
        if key is None:
            raise HTTPException(status_code=401, detail="Failed to retrieve API key")
        return key.text
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Authentication error: {str(e)}")

@app.post("/apply-policy/")
async def apply_policy(config_file_path: str, target_file_path: str) -> Dict:
    """
    Import policy from a config file, authenticate to Palo Alto, and apply it.
    Args:
        config_file_path: Path to the JSON config file containing the policy.
        target_file_path: Path to the target file to store the applied policy.
    Returns:
        JSON response confirming success or error.
    """
    # Check if config file exists
    if not os.path.exists(config_file_path):
        raise HTTPException(status_code=404, detail="Config file not found")

    # Read policy from config file
    try:
        with open(config_file_path, 'r') as config_file:
            policy = json.load(config_file)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading config: {str(e)}")

    # Authenticate to Palo Alto firewall
    try:
        api_key = get_api_key()
    except HTTPException as e:
        raise e

    # Apply policy to firewall (example: push security rule)
    # Customize this based on your policy structure and API endpoints
    try:
        # Example: Create a security rule (modify as needed)
        url = f"https://{FIREWALL_IP}/restapi/v10.1/Policies/SecurityRules"
        headers = {"X-PAN-KEY": api_key}
        # Sample policy payload (adjust to match your JSON policy structure)
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
        
        response = requests.post(url, headers=headers, json=firewall_policy, verify=False)
        response.raise_for_status()
        
        # Save policy to target file for reference
        with open(target_file_path, 'w') as target_file:
            json.dump(policy, target_file, indent=4)
        
        return {"message": f"Policy applied to firewall and saved to {target_file_path}"}
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error applying policy to firewall: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving policy: {str(e)}")

@app.post("/undo-policy/")
async def undo_policy(target_file_path: str) -> Dict:
    """
    Undo the policy by clearing the target file and optionally reverting firewall changes.
    Args:
        target_file_path: Path to the target file to clear.
    Returns:
        JSON response confirming success or error.
    """
    # Check if target file exists
    if not os.path.exists(target_file_path):
        raise HTTPException(status_code=404, detail="Target file not found")

    # Authenticate to Palo Alto firewall
    try:
        api_key = get_api_key()
    except HTTPException as e:
        raise e

    # Clear the policy file (undo action)
    try:
        with open(target_file_path, 'w') as target_file:
            target_file.write('')
        
        # Optionally: Delete the rule from firewall (example)
        # You’d need to track the rule name or ID to delete it
        # url = f"https://{FIREWALL_IP}/restapi/v10.1/Policies/SecurityRules?name=rule_name"
        # headers = {"X-PAN-KEY": api_key}
        # response = requests.delete(url, headers=headers, verify=False)
        # response.raise_for_status()
        
        return {"message": f"Policy undone for {target_file_path}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error undoing policy: {str(e)}")

# To run the API: `uvicorn policy_apply_api_v0_1:app --reload`