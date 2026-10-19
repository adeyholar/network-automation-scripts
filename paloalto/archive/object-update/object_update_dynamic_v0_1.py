import requests
import xml.etree.ElementTree as ET
from urllib.parse import quote
import socket
import time
import msvcrt
import os

# File to store the last connected host
LAST_HOST_FILE = "last_host.txt"

# Load the last connected host from file, if it exists
def load_last_host():
    if os.path.exists(LAST_HOST_FILE):
        with open(LAST_HOST_FILE, "r") as f:
            host = f.read().strip()
            if host:
                print(f"Found last connected host: {host}")
                return host
    return None

# Save the last connected host to file
def save_last_host(host):
    with open(LAST_HOST_FILE, "w") as f:
        f.write(host)
    print(f"Saved last connected host: {host}")

# Prompt for firewall or Panorama IP/hostname with timeout and reachability check (Windows)
def get_host():
    # Try to load the last connected host
    last_host = load_last_host()
    if last_host and is_host_reachable(last_host):
        # Prompt user to confirm if they want to use the last host
        print(f"Last connected host {last_host} is reachable.")
        while True:
            try:
                print("Do you want to use this host? (y/n): ", end='', flush=True)
                start_time = time.time()
                choice_input = ""
                
                while time.time() - start_time < 60:  # 60-second timeout for confirmation
                    if msvcrt.kbhit():  # Check if a key is pressed
                        char = msvcrt.getch().decode('utf-8')
                        if char == '\r':  # Enter key
                            print()  # New line after input
                            break
                        elif char == '\x03':  # Ctrl+C
                            raise KeyboardInterrupt
                        choice_input += char
                        print(char, end='', flush=True)
                    time.sleep(0.1)  # Small delay to reduce CPU usage
                
                if not choice_input:
                    print("\nNo entry provided for 60 seconds. Exiting.")
                    exit(0)
                
                choice = choice_input.lower()
                if choice in ['y', 'yes']:
                    return last_host
                elif choice in ['n', 'no']:
                    break  # Break out of the confirmation loop to prompt for a new host
                else:
                    print("Invalid input. Please enter 'y' or 'n'.")
            except KeyboardInterrupt:
                print("\nOperation cancelled by user (Ctrl+C). Exiting.")
                exit(0)

    # If no last host, it's not reachable, or user declines to use it, prompt for a new one
    while True:
        try:
            print("Enter the Palo Alto firewall or Panorama IP address or hostname (e.g., 192.0.2.10): ", end='', flush=True)
            start_time = time.time()
            host_input = ""
            
            while time.time() - start_time < 60:  # 60-second timeout
                if msvcrt.kbhit():  # Check if a key is pressed
                    char = msvcrt.getch().decode('utf-8')
                    if char == '\r':  # Enter key
                        print()  # New line after input
                        break
                    elif char == '\x03':  # Ctrl+C
                        raise KeyboardInterrupt
                    host_input += char
                    print(char, end='', flush=True)
                time.sleep(0.1)  # Small delay to reduce CPU usage
            
            if not host_input:
                print("\nNo entry provided for 60 seconds. Exiting.")
                exit(0)
            
            # Test reachability
            if is_host_reachable(host_input):
                save_last_host(host_input)  # Save the new host if reachable
                return host_input
            else:
                print(f"\nError: IP address or hostname '{host_input}' is not reachable. Please enter a valid hostname or IP.")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user (Ctrl+C). Exiting.")
            exit(0)

# Check if host is reachable on port 443 (HTTPS) - Simplified TCP check
def is_host_reachable(host, port=443, timeout=5):
    try:
        ip = socket.gethostbyname(host)
        print(f"Resolved {host} to IP: {ip}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        print(f"Reachability check for {host}:{port} - Result: {result == 0}")
        return result == 0
    except (socket.gaierror, socket.timeout, OSError) as e:
        print(f"Reachability check failed for {host}:{port} - Error: {str(e)}")
        return False

# Prompt for credentials
def get_credentials():
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    return username, password

# Get API key
def get_api_key(host, username, password):
    api_url = f"https://{host}/api/"
    url = f"{api_url}?type=keygen&user={quote(username)}&password={quote(password)}"
    print(f"Attempting to get API key from: {url}")
    try:
        response = requests.get(url, verify=False, timeout=10)
        print(f"API Response Status: {response.status_code}")
        print(f"API Response Text: {response.text}")
        response.raise_for_status()
        root = ET.fromstring(response.text)
        key = root.find(".//key").text
        return key, api_url
    except requests.RequestException as e:
        print(f"Failed to get API key: {str(e)}")
        raise

# List all address objects
def list_address_objects(api_key, api_url):
    url = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address"
    headers = {"X-PAN-KEY": api_key}
    response = requests.get(url, headers=headers, verify=False, timeout=10)
    response.raise_for_status()
    root = ET.fromstring(response.text)
    objects = []
    print("\nCurrent Address Objects:")
    for idx, entry in enumerate(root.findall(".//entry")):
        name = entry.get("name")
        value = entry.findtext("ip-netmask") or entry.findtext("fqdn") or entry.findtext("ip-range") or "N/A"
        print(f"{idx + 1}. Name: {name}, Value: {value}")
        objects.append({"name": name, "value": value})
    return objects

# Prompt user to select objects to update with 10-minute inactivity timeout
def select_objects_to_update(objects):
    selected_indices = []
    print("\nYou have 10 minutes to select objects. Inactivity will log you out.")
    while True:
        try:
            print("\nEnter the number of the object to update (or 'done' to finish): ", end='', flush=True)
            start_time = time.time()
            choice_input = ""
            
            while time.time() - start_time < 600:  # 10-minute (600 seconds) timeout
                if msvcrt.kbhit():  # Check if a key is pressed
                    char = msvcrt.getch().decode('utf-8')
                    if char == '\r':  # Enter key
                        print()  # New line after input
                        break
                    elif char == '\x03':  # Ctrl+C
                        raise KeyboardInterrupt
                    choice_input += char
                    print(char, end='', flush=True)
                time.sleep(0.1)  # Small delay to reduce CPU usage
            
            if not choice_input:
                print("\nNo activity detected for 10 minutes. Logging out and exiting.")
                exit(0)
            
            if choice_input.lower() == 'done':
                break
            
            index = int(choice_input) - 1
            if 0 <= index < len(objects):
                selected_indices.append(index)
                print(f"Selected object: {objects[index]['name']}")
            else:
                print("Invalid selection. Try again.")
        except ValueError:
            print("Invalid input. Enter a number or 'done'.")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user (Ctrl+C). Exiting.")
            exit(0)
    return [objects[i] for i in selected_indices]

# Prompt for new values and prepare updates
def update_selected_objects(selected_objects):
    updates = []
    for obj in selected_objects:
        print(f"\nUpdating: {obj['name']} (Current Value: {obj['value']})")
        new_value = input(f"Enter new value for {obj['name']} (e.g., 192.0.2.20): ")
        updates.append({"name": obj["name"], "new_value": new_value})
    return updates

# Apply batch changes
def apply_batch_changes(api_key, api_url, updates):
    if not updates:
        print("No changes to apply.")
        return
    
    print("\nApplying changes...")
    headers = {"X-PAN-KEY": api_key}
    for update in updates:
        xml_data = f"""
        <entry name='{update['name']}'>
            <ip-netmask>{update['new_value']}</ip-netmask>
        </entry>
        """
        url = f"{api_url}?type=config&action=edit&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{update['name']}']&element={quote(xml_data)}"
        response = requests.post(url, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        print(f"Updated {update['name']} to {update['new_value']}")

    commit_url = f"{api_url}?type=commit&cmd=<commit></commit>"
    commit_response = requests.post(commit_url, headers=headers, verify=False, timeout=10)
    commit_response.raise_for_status()
    print("Changes committed successfully.")

# Main execution
def main():
    try:
        # Get host with reachability check and timeout
        host = get_host()

        # Get credentials only if host is reachable
        username, password = get_credentials()

        # Get API key and API URL
        api_key, api_url = get_api_key(host, username, password)
        print(f"Connected to device at {host}")

        # List objects
        all_objects = list_address_objects(api_key, api_url)

        # Select objects to update
        selected_objects = select_objects_to_update(all_objects)

        # Update selected objects
        updated_objects = update_selected_objects(selected_objects)

        # Apply batch changes
        apply_batch_changes(api_key, api_url, updated_objects)

    except requests.RequestException as e:
        print(f"Error: {e}")
    except ET.ParseError as e:
        print(f"XML Parse Error: {e}")
    except Exception as e:
        print(f"Unexpected Error: {e}")

if __name__ == "__main__":
    # Disable SSL warnings (optional, for self-signed certs; use with caution)
    requests.packages.urllib3.disable_warnings()
    main()