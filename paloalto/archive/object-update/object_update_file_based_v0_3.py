import requests
import xml.etree.ElementTree as ET
from urllib.parse import quote
import socket
import ssl
import time
import msvcrt

# Prompt for firewall or Panorama IP/hostname with timeout and reachability check (Windows)
def get_host():
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
                return host_input
            else:
                print(f"\nError: IP address or hostname '{host_input}' is not reachable via script (port 443). Ensure API access is allowed.")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user (Ctrl+C). Exiting.")
            exit(0)

# Check if host is reachable on port 443 (HTTPS) with diagnostics
def is_host_reachable(host, port=443, timeout=10):
    try:
        # Resolve hostname to IP
        ip = socket.gethostbyname(host)
        print(f"Resolved '{host}' to IP: {ip}")

        # Try SSL connection first (port 443)
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

        # Fallback to basic TCP connection (non-SSL) on port 443
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

# Prompt for credentials
def get_credentials():
    username = input("Enter your username: ")
    password = input("Enter your password: ")
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

# List all address objects from the firewall
def list_address_objects(api_key, api_url):
    url = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address"
    headers = {"X-PAN-KEY": api_key}
    response = requests.get(url, headers=headers, verify=False, timeout=10)
    response.raise_for_status()
    root = ET.fromstring(response.text)
    objects = {}
    for entry in root.findall(".//entry"):
        name = entry.get("name")
        value = entry.findtext("ip-netmask") or entry.findtext("fqdn") or entry.findtext("ip-range") or "N/A"
        objects[name] = value
    return objects

# Verify old objects match firewall
def verify_old_objects(firewall_objects, old_objects):
    mismatches = []
    for name, old_value in old_objects.items():
        if name not in firewall_objects:
            mismatches.append(f"Object '{name}' not found on firewall.")
        elif firewall_objects[name] != old_value:
            mismatches.append(f"Object '{name}' mismatch: Firewall={firewall_objects[name]}, File={old_value}")
    return mismatches

# Apply batch changes (update or create objects)
def apply_batch_changes(api_key, api_url, new_objects):
    if not new_objects:
        print("No new objects to apply.")
        return
    
    print("\nApplying changes...")
    headers = {"X-PAN-KEY": api_key}
    for name, new_value in new_objects.items():
        xml_data = f"""
        <entry name='{name}'>
            <ip-netmask>{new_value}</ip-netmask>
        </entry>
        """
        url = f"{api_url}?type=config&action=edit&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{name}']&element={quote(xml_data)}"
        response = requests.post(url, headers=headers, verify=False, timeout=10)
        if response.status_code == 200:
            print(f"Updated '{name}' to '{new_value}'")
        else:
            # If edit fails (e.g., object doesn’t exist), try creating it
            create_url = f"{api_url}?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address&element={quote(xml_data)}"
            create_response = requests.post(create_url, headers=headers, verify=False, timeout=10)
            create_response.raise_for_status()
            print(f"Created new object '{name}' with value '{new_value}'")

    # Commit changes
    commit_url = f"{api_url}?type=commit&cmd=<commit></commit>"
    commit_response = requests.post(commit_url, headers=headers, verify=False, timeout=10)
    commit_response.raise_for_status()
    print("Changes committed successfully.")

# Main execution
def main():
    try:
        # Get host with reachability check and timeout
        host = get_host()

        # Get credentials
        username, password = get_credentials()

        # Get API key and API URL
        api_key, api_url = get_api_key(host, username, password)
        print(f"Connected to device at {host}")

        # Read old and new objects from files
        old_objects = read_objects_from_file("old_objects.txt")
        new_objects = read_objects_from_file("new_objects.txt")

        # List objects from firewall
        firewall_objects = list_address_objects(api_key, api_url)

        # Verify old objects match firewall
        mismatches = verify_old_objects(firewall_objects, old_objects)
        if mismatches:
            print("\nMismatches found:")
            for mismatch in mismatches:
                print(mismatch)
            print("Proceeding with updates despite mismatches.")

        # Apply updates from new objects file
        apply_batch_changes(api_key, api_url, new_objects)

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