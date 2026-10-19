import os
import getpass
import requests
import json
from tabulate import tabulate

# Step 1: Read credentials from environment variables (or prompt), prompt for Orchestrator URL
orchestrator_url = os.environ.get("VCO_URL") or input("Enter the Orchestrator URL (e.g., https://orchestrator.example.com): ").strip()
api_token = os.environ.get("VCO_API_TOKEN") or getpass.getpass("VeloCloud API token: ")

# Step 2: Fetch Non SD-WAN Destinations (no separate authentication step needed)
def get_non_sdwan_destinations(orchestrator_url, api_token, enterprise_id=1):
    endpoint = f"{orchestrator_url}/enterprise/getEnterpriseNetworkServices"
    headers = {
        "Authorization": f"Token {api_token}",
        "Content-Type": "application/json"
    }
    payload = {"enterpriseId": enterprise_id}  # Adjust enterpriseId as needed
    
    try:
        print(f"Fetching data from: {endpoint}")
        response = requests.post(endpoint, headers=headers, json=payload)
        
        # Debug: Print status code and raw response
        print(f"Response Status Code: {response.status_code}")
        print(f"Raw Response: {response.text}")
        
        response.raise_for_status()  # Raise an error if the request fails
        return response.json()
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to fetch Non SD-WAN Destinations: {e}\nRaw Response: {getattr(e.response, 'text', 'No response text available')}")

# Step 3: Parse and extract relevant data
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

# Step 4: Create and print the table
def print_table(table_data):
    headers = ["Non SD-WAN Destination Name", "Network Behind"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

# Main execution
if __name__ == "__main__":
    try:
        # Fetch data
        print("Fetching Non SD-WAN Destinations...")
        data = get_non_sdwan_destinations(orchestrator_url, api_token)
        
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