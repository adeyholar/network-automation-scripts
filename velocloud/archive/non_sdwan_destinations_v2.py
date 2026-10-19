import os
import getpass
import requests
import json
from tabulate import tabulate

# API details
orchestrator_url = os.environ.get("VCO_URL", "https://orchestrator.example.com")
api_token = os.environ.get("VCO_API_TOKEN") or getpass.getpass("VeloCloud API token: ")

# Headers for authentication
headers = {
    "Authorization": f"Token {api_token}",
    "Content-Type": "application/json"
}

# Step 1: Fetch Non SD-WAN Destinations
def get_non_sdwan_destinations():
    endpoint = f"{orchestrator_url}/enterprise/getEnterpriseNetworkServices"
    response = requests.post(endpoint, headers=headers, json={"enterpriseId": 1})  # Adjust enterpriseId as needed
    response.raise_for_status()  # Raise an error if the request fails
    return response.json()

# Step 2: Parse and extract relevant data
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

# Step 3: Create and print the table
def print_table(table_data):
    headers = ["Non SD-WAN Destination Name", "Network Behind"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

# Main execution
if __name__ == "__main__":
    try:
        # Fetch data
        data = get_non_sdwan_destinations()  # Fixed the function name here
        
        # Parse data
        table_data = parse_non_sdwan_data(data)
        
        # Print table
        print_table(table_data)
        
    except Exception as e:
        print(f"Error: {e}")