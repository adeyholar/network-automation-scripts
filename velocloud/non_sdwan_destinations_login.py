import os
import getpass
import requests
import json
from tabulate import tabulate

# Step 1: Read credentials from environment variables (or prompt), prompt for Orchestrator URL
orchestrator_url = os.environ.get("VCO_URL") or input("Enter the Orchestrator URL (e.g., https://orchestrator.example.com): ").strip()
username = os.environ.get("VCO_USERNAME") or input("VeloCloud username: ").strip()
password = os.environ.get("VCO_PASSWORD") or getpass.getpass("VeloCloud password: ")

# Step 2: Authenticate with the Orchestrator API
def authenticate(orchestrator_url, username, password):
    login_endpoint = f"{orchestrator_url}/login/enterpriseLogin"
    payload = {
        "username": username,
        "password": password
    }
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(login_endpoint, headers=headers, json=payload)
        response.raise_for_status()  # Raise an error if the request fails
        
        # Extract the session token from the response
        token = response.json().get("token")
        if not token:
            raise ValueError("Authentication failed: No token received.")
        return token
    except Exception as e:
        raise Exception(f"Authentication failed: {e}")

# Step 3: Fetch Non SD-WAN Destinations
def get_non_sdwan_destinations(orchestrator_url, token, enterprise_id=1):
    endpoint = f"{orchestrator_url}/enterprise/getEnterpriseNetworkServices"
    headers = {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json"
    }
    payload = {"enterpriseId": enterprise_id}  # Adjust enterpriseId as needed
    
    try:
        response = requests.post(endpoint, headers=headers, json=payload)
        response.raise_for_status()  # Raise an error if the request fails
        return response.json()
    except Exception as e:
        raise Exception(f"Failed to fetch Non SD-WAN Destinations: {e}")

# Step 4: Parse and extract relevant data
def parse_non_sdwan_data(data):
    table_data = []
    for service in data.get("networkServices", []):
        if service.get("type") == "nonSdwanDestination":  # Filter for Non SD-WAN Destinations
            name = service.get("name", "N/A")
            # Extract the network (subnets) from the VPN configuration
            vpn_config = service.get("vpnConfiguration", {})
            networks = vpn_config.get("remoteSubnets", ["N/A"])  # Adjust based on actual API response structure
            network_str = ", ".join(networks)
            table_data.append([name, network_str])
    return table_data

# Step 5: Create and print the table
def print_table(table_data):
    headers = ["Non SD-WAN Destination Name", "Network Behind"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

# Main execution
if __name__ == "__main__":
    try:
        # Authenticate and get token
        print("Authenticating...")
        token = authenticate(orchestrator_url, username, password)
        print("Authentication successful!")
        
        # Fetch data
        print("Fetching Non SD-WAN Destinations...")
        data = get_non_sdwan_destinations(orchestrator_url, token)
        
        # Parse data
        table_data = parse_non_sdwan_data(data)
        
        # Print table
        if table_data:
            print("\nNon SD-WAN Destinations Table:")
            print_table(table_data)
        else:
            print("No Non SD-WAN Destinations found.")
            
    except Exception as e:
        print(f"Error: {e}")