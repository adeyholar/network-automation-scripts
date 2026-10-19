import requests
import xml.etree.ElementTree as ET
from urllib.parse import quote
import socket
import ssl
import time
import msvcrt
import os
import getpass

# Load last accessible firewall from cache
def load_cached_firewall():
    cache_file = "last_firewall.txt"
    if os.path.exists(cache_file):
        with open(cache_file, 'r') as f:
            cached_host = f.read().strip()
            if cached_host:
                return cached_host
    return None

# Save accessible firewall to cache
def save_cached_firewall(host):
    with open("last_firewall.txt", "w") as f:
        f.write(host)

# Prompt for firewall or Panorama IP/hostname with timeout, reachability check, and caching (Windows)
def get_host():
    cached_host = load_cached_firewall()
    default_msg = f" (default: {cached_host})" if cached_host else ""
    
    while True:
        try:
            print(f"Enter the Palo Alto firewall or Panorama IP address or hostname (e.g., 192.0.2.10){default_msg}: ", end='', flush=True)
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
            
            # Use cached host if no input provided
            if not host_input and cached_host:
                host = cached_host
                print(f"\nUsing cached host: {host}")
            elif not host_input:
                print("\nNo entry provided for 60 seconds and no cached host available. Exiting.")
                exit(0)
            else:
                host = host_input
            
            # Test reachability
            if is_host_reachable(host):
                save_cached_firewall(host)  # Cache the new host if reachable
                return host
            else:
                print(f"\nError: IP address or hostname '{host}' is not reachable via script (port 443). Ensure API access is allowed.")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user (Ctrl+C). Exiting.")
            exit(0)

# Check if host is reachable on port 443 (HTTPS) with diagnostics
def is_host_reachable(host, port=443, timeout=10):
    try:
        ip = socket.gethostbyname(host)
        print(f"Resolved '{host}' to IP: {ip}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            ssl_sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            result = ssl_sock.connect_ex((ip, port))
            ssl_sock.close()
            if result == 0:
                print(f"SSL connection to {host}:{port} succeeded.")
                return True
            else:
                print(f"SSL connection failed with error code {result}. Trying non-SSL connection...")
        except ssl.SSLError as e:
            print(f"SSL error: {e}. Falling back to non-SSL check.")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            print(f"Non-SSL connection to {host}:{port} succeeded.")
            return True
        else:
            print(f"Non-SSL connection failed with error code {result}.")
            return False
    except socket.gaierror as e:
        print(f"DNS resolution failed: {e}")
        return False
    except socket.timeout:
        print(f"Connection timed out after {timeout} seconds.")
        return False
    except Exception as e:
        print(f"Unexpected error during reachability check: {e}")
        return False

# Prompt for credentials with obscured password
def get_credentials():
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")  # Obscures password input
    return username, password

# Read objects from a file (format: name,value)
def read_objects_from_file(filename):
    objects = {}
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and ',' in line:
                    name, value = line.split(',', 1)
                    objects[name] = value
        return objects
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        exit(1)
    except Exception as e:
        print(f"Error reading '{filename}': {e}")
        exit(1)

# Get API key
def get_api_key(host, username, password):
    api_url = f"https://{host}/api/"
    url = f"{api_url}?type=keygen&user={quote(username)}&password={quote(password)}"
    response = requests.get(url, verify=False, timeout=10)
    response.raise_for_status()
    root = ET.fromstring(response.text)
    key = root.find(".//key").text
    return key, api_url

# List all address objects and groups from the firewall
def list_all_objects_and_groups(api_key, api_url):
    objects = {}
    groups = {}
    
    # Fetch address objects
    url_objects = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address"
    headers = {"X-PAN-KEY": api_key}
    response = requests.get(url_objects, headers=headers, verify=False, timeout=10)
    response.raise_for_status()
    root = ET.fromstring(response.text)
    for entry in root.findall(".//entry"):
        name = entry.get("name")
        value = entry.findtext("ip-netmask") or entry.findtext("fqdn") or entry.findtext("ip-range") or "N/A"
        objects[name] = value
    
    # Fetch address groups
    url_groups = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group"
    response = requests.get(url_groups, headers=headers, verify=False, timeout=10)
    response.raise_for_status()
    root = ET.fromstring(response.text)
    for entry in root.findall(".//entry"):
        name = entry.get("name")
        members = [member.text for member in entry.findall(".//member")]
        groups[name] = members
    
    # Display objects and groups
    print("\nAddress Objects:")
    for name, value in objects.items():
        print(f"  - {name}: {value}")
    print("\nAddress Groups:")
    for name, members in groups.items():
        print(f"  - {name}: {', '.join(members)}")
    
    return objects, groups

# Prompt to confirm files are ready
def confirm_files_ready():
    while True:
        response = input("\nAre the files 'old_objects.txt' and 'new_objects.txt' ready to proceed with changes? (Yes/No): ").strip().lower()
        if response == "yes":
            return True
        elif response == "no":
            print("Please prepare the files and run the script again when ready.")
            exit(0)
        else:
            print("Please enter 'Yes' or 'No'.")

# Verify old objects match firewall
def verify_old_objects(firewall_objects, old_objects):
    mismatches = []
    for name, old_value in old_objects.items():
        if name not in firewall_objects:
            mismatches.append(f"Object '{name}' not found on firewall.")
        elif firewall_objects[name] != old_value:
            mismatches.append(f"Object '{name}' mismatch: Firewall={firewall_objects[name]}, File={old_value}")
    return mismatches

# Apply batch changes and generate report
def apply_batch_changes(api_key, api_url, firewall_objects, new_objects):
    if not new_objects:
        print("No new objects to apply.")
        return None
    
    report = {
        "successful": [],
        "unchanged": [],
        "new_added": [],
        "modified": []
    }
    
    print("\nApplying changes...")
    headers = {"X-PAN-KEY": api_key}
    for name, new_value in new_objects.items():
        # Check if object exists and value matches
        if name in firewall_objects:
            current_value = firewall_objects[name]
            if current_value == new_value:
                print(f"Skipped '{name}': Value '{new_value}' already matches.")
                continue
        
        # Update or create object
        xml_data = f"""
        <entry name='{name}'>
            <ip-netmask>{new_value}</ip-netmask>
        </entry>
        """
        url = f"{api_url}?type=config&action=edit&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{name}']&element={quote(xml_data)}"
        try:
            response = requests.post(url, headers=headers, verify=False, timeout=10)
            if response.status_code == 200:
                report["successful"].append(f"'{name}' updated to '{new_value}'")
                report["modified"].append(f"'{name}' modified from '{firewall_objects.get(name, 'N/A')}' to '{new_value}'")
                print(f"Updated '{name}' to '{new_value}'")
            else:
                # If edit fails (e.g., object doesn’t exist), try creating it
                create_url = f"{api_url}?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address&element={quote(xml_data)}"
                create_response = requests.post(create_url, headers=headers, verify=False, timeout=10)
                create_response.raise_for_status()
                report["successful"].append(f"'{name}' created with value '{new_value}'")
                report["new_added"].append(f"'{name}' added as new object with value '{new_value}'")
                print(f"Created new object '{name}' with value '{new_value}'")
        except requests.RequestException as e:
            report["unchanged"].append(f"'{name}' not changed due to error: {str(e)}")
            print(f"Failed to update '{name}': {str(e)}")

    # Commit changes if there were any updates
    if report["successful"]:
        commit_url = f"{api_url}?type=commit&cmd=<commit></commit>"
        try:
            commit_response = requests.post(commit_url, headers=headers, verify=False, timeout=10)
            commit_response.raise_for_status()
            print("Changes committed successfully.")
        except requests.RequestException as e:
            print(f"Commit failed: {e}")
            report["unchanged"].extend([f"'{name}' not committed due to commit failure: {str(e)}" for name in new_objects.keys() if name in [entry.split("'")[1] for entry in report["successful"]]])

    return report

# Generate and save report with object count
def generate_report(report, total_objects, total_groups):
    if not report:
        print("No report to generate.")
        return
    
    print("\nUpdate Report:")
    print("==============")
    
    print(f"\nTotal Objects Discovered: {total_objects} address objects, {total_groups} address groups")
    print("\nSuccessfully Changed Objects:")
    for item in report["successful"]:
        print(f"  - {item}")
    
    print("\nNew Objects Added:")
    for item in report["new_added"]:
        print(f"  - {item}")
    
    print("\nObjects Modified:")
    for item in report["modified"]:
        print(f"  - {item}")
    
    # Save to file
    with open("update_report.txt", "w") as f:
        f.write("Update Report\n=============\n\n")
        f.write(f"Total Objects Discovered: {total_objects} address objects, {total_groups} address groups\n")
        f.write("\nSuccessfully Changed Objects:\n")
        for item in report["successful"]:
            f.write(f"  - {item}\n")
        f.write("\nNew Objects Added:\n")
        for item in report["new_added"]:
            f.write(f"  - {item}\n")
        f.write("\nObjects Modified:\n")
        for item in report["modified"]:
            f.write(f"  - {item}\n")
    print("\nReport saved to 'update_report.txt'.")

# Main execution
def main():
    try:
        # Get host with reachability check, timeout, and caching
        host = get_host()

        # Get credentials
        username, password = get_credentials()

        # Get API key and API URL
        api_key, api_url = get_api_key(host, username, password)
        print(f"Connected to device at {host}")

        # List all objects and groups
        firewall_objects, firewall_groups = list_all_objects_and_groups(api_key, api_url)

        # Confirm files are ready
        if not confirm_files_ready():
            return

        # Read old and new objects from files
        old_objects = read_objects_from_file("old_objects.txt")
        new_objects = read_objects_from_file("new_objects.txt")

        # Verify old objects match firewall
        mismatches = verify_old_objects(firewall_objects, old_objects)
        if mismatches:
            print("\nMismatches found:")
            for mismatch in mismatches:
                print(mismatch)
            print("Proceeding with updates despite mismatches.")

        # Apply updates and generate report
        report = apply_batch_changes(api_key, api_url, firewall_objects, new_objects)

        # Generate and save report with object count
        generate_report(report, len(firewall_objects), len(firewall_groups))

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