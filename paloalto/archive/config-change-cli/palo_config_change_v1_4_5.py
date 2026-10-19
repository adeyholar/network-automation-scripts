import requests
import xml.etree.ElementTree as ET
from urllib.parse import quote
import socket
import ssl
import time
import msvcrt
import os
import getpass
import re
import ipaddress

# Script version
SCRIPT_VERSION = "1.4.5"

# Version History:
# 1.0.0 - Initial version with object parsing in copyable format, version control added
# 1.1.0 - Added IP address format validation with error flagging in report
# 1.2.0 - Added support for multiple address types: IP with netmask, IP range, IP wildcard mask, FQDN, IPv6
# 1.2.1 - Updated Yes/No prompt to accept Y/y/Yes/N/n/No in any case; corrected to maintain (Yes/No) display with case-insensitive handling
# 1.3.0 - Added option to download current running configuration as running-config.xml
# 1.3.1 - Modified running config download to append date and time (e.g., running-config_20240101_120000.xml) instead of overwriting
# 1.4.0 - Added option to list objects and groups in copyable format for object files (e.g., name,value and group_name,member1;member2)
# 1.4.1 - Prefixed firewall hostname to running configuration filename (e.g., FW01_running-config_20240101_120000.xml)
# 1.4.2 - Fixed WinError 10038 in is_host_reachable by using context managers for socket handling
# 1.4.3 - Added functionality to delete specific address objects based on a provided list
# 1.4.4 - Added mandatory configuration backup prompt before changes and specified expected format for objects_to_delete.txt
# 1.4.5 - Corrected objects_to_delete.txt format to one object name per line and updated script filename to palo_config_change.py format

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
            
            while time.time() - start_time < 60:
                if msvcrt.kbhit():
                    char = msvcrt.getch().decode('utf-8')
                    if char == '\r':
                        print()
                        break
                    elif char == '\x03':
                        raise KeyboardInterrupt
                    host_input += char
                    print(char, end='', flush=True)
                time.sleep(0.1)
            
            if not host_input and cached_host:
                host = cached_host
                print(f"\nUsing cached host: {host}")
            elif not host_input:
                print("\nNo entry provided for 60 seconds and no cached host available. Exiting.")
                exit(0)
            else:
                host = host_input
            
            if is_host_reachable(host):
                save_cached_firewall(host)
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
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                ssl_sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
                result = ssl_sock.connect_ex((ip, port))
                if result == 0:
                    print(f"SSL connection to {host}:{port} succeeded.")
                    return True
                else:
                    print(f"SSL connection failed with error code {result}. Trying non-SSL connection...")
            except ssl.SSLError as e:
                print(f"SSL error: {e}. Falling back to non-SSL check.")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
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
    password = getpass.getpass("Enter your password: ")
    return username, password

# Read objects to delete from a file (format: one object name per line)
def read_objects_to_delete(filename="objects_to_delete.txt"):
    objects = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    # Take only the object name (first element if tab/space-separated)
                    name = line.split(None, 1)[0]
                    objects.append(name)
        return objects
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found. No objects will be deleted.")
        return []
    except Exception as e:
        print(f"Error reading '{filename}': {e}. No objects will be deleted.")
        return []

# Delete specified address objects
def delete_address_objects(api_key, api_url, object_names):
    if not object_names:
        print("No objects specified for deletion.")
        return None
    
    report = {
        "successful": [],
        "failed": []
    }
    
    print("\nDeleting objects...")
    headers = {"X-PAN-KEY": api_key}
    for name in object_names:
        url = f"{api_url}?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{name}']"
        try:
            response = requests.get(url, headers=headers, verify=False, timeout=10)
            response.raise_for_status()
            report["successful"].append(f"'{name}' deleted")
            print(f"Deleted '{name}'")
        except requests.RequestException as e:
            report["failed"].append(f"'{name}' not deleted due to error: {str(e)}")
            print(f"Failed to delete '{name}': {str(e)}")
    
    if report["successful"]:
        commit_url = f"{api_url}?type=commit&cmd=<commit></commit>"
        try:
            commit_response = requests.post(commit_url, headers=headers, verify=False, timeout=10)
            commit_response.raise_for_status()
            print("Deletions committed successfully.")
        except requests.RequestException as e:
            print(f"Commit failed: {e}")
            report["failed"].extend([f"'{name}' deletion not committed due to commit failure: {str(e)}" for name in object_names if name in [entry.split("'")[1] for entry in report["successful"]]])
    
    return report

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

# Validate address type format
def validate_address_type(value):
    ip_netmask_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/(?:[0-2]?[0-9]|3[0-2]))$|^(?:[0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}(?:/(?:[0-9]|[1-9][0-9]|1[0-2][0-8]))?$"
    ip_range_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)-(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    ip_wildcard_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    fqdn_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"

    if re.match(ip_netmask_pattern, value):
        try:
            ipaddress.ip_network(value, strict=False)
            return "ip-netmask"
        except ValueError:
            return None
    elif re.match(ip_range_pattern, value):
        start, end = value.split('-')
        try:
            start_ip = ipaddress.ip_address(start)
            end_ip = ipaddress.ip_address(end)
            if start_ip <= end_ip and start_ip.version == end_ip.version == 4:
                return "ip-range"
            return None
        except ValueError:
            return None
    elif re.match(ip_wildcard_pattern, value):
        ip, mask = value.split('/')
        try:
            ipaddress.ip_address(ip)
            mask_parts = [int(x) for x in mask.split('.')]
            if all(0 <= x <= 255 for x in mask_parts):
                return "ip-wildcard"
            return None
        except ValueError:
            return None
    elif re.match(fqdn_pattern, value):
        return "fqdn"
    return None

# Get API key
def get_api_key(host, username, password):
    api_url = f"https://{host}/api/"
    url = f"{api_url}?type=keygen&user={quote(username)}&password={quote(password)}"
    response = requests.get(url, verify=False, timeout=10)
    response.raise_for_status()
    root = ET.fromstring(response.text)
    key = root.find(".//key").text
    return key, api_url

# Get firewall hostname
def get_firewall_hostname(api_key, api_url):
    url = f"{api_url}?type=op&cmd=<show><system><info></info></system></show>"
    headers = {"X-PAN-KEY": api_key}
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        hostname = root.find(".//hostname").text
        return hostname
    except (requests.RequestException, AttributeError) as e:
        print(f"Failed to retrieve hostname: {e}. Using 'unknown' as prefix.")
        return "unknown"

# Download running configuration with hostname and timestamp
def download_running_config(api_key, api_url):
    hostname = get_firewall_hostname(api_key, api_url)
    url = f"{api_url}?type=export&category=configuration"
    headers = {"X-PAN-KEY": api_key}
    timestamp = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    filename = f"{hostname}_running-config_{timestamp}.xml"
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=30)
        response.raise_for_status()
        with open(filename, "wb") as f:
            f.write(response.content)
        print(f"Running configuration downloaded successfully as '{filename}'.")
    except requests.RequestException as e:
        print(f"Failed to download running configuration: {e}")

# List all address objects and groups from the firewall in copyable format
def list_all_objects_and_groups(api_key, api_url):
    objects = {}
    groups = {}
    
    url_objects = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address"
    headers = {"X-PAN-KEY": api_key}
    response = requests.get(url_objects, headers=headers, verify=False, timeout=10)
    response.raise_for_status()
    root = ET.fromstring(response.text)
    for entry in root.findall(".//entry"):
        name = entry.get("name")
        value = entry.findtext("ip-netmask") or entry.findtext("ip-range") or entry.findtext("ip-wildcard") or entry.findtext("fqdn") or "N/A"
        objects[name] = value
    
    url_groups = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group"
    response = requests.get(url_groups, headers=headers, verify=False, timeout=10)
    response.raise_for_status()
    root = ET.fromstring(response.text)
    for entry in root.findall(".//entry"):
        name = entry.get("name")
        members = [member.text for member in entry.findall(".//member")]
        groups[name] = members
    
    print("\nAddress Objects (Copyable Format for old_objects.txt/new_objects.txt):")
    for name, value in objects.items():
        print(f"  {name},{value}")
    print("\nAddress Groups:")
    for name, members in groups.items():
        print(f"  - {name}: {', '.join(members)}")
    
    return objects, groups

# List objects and groups in copyable format for object files
def list_objects_and_groups_copyable(api_key, api_url):
    objects = {}
    groups = {}
    
    url_objects = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address"
    headers = {"X-PAN-KEY": api_key}
    response = requests.get(url_objects, headers=headers, verify=False, timeout=10)
    response.raise_for_status()
    root = ET.fromstring(response.text)
    for entry in root.findall(".//entry"):
        name = entry.get("name")
        value = entry.findtext("ip-netmask") or entry.findtext("ip-range") or entry.findtext("ip-wildcard") or entry.findtext("fqdn") or "N/A"
        objects[name] = value
    
    url_groups = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group"
    response = requests.get(url_groups, headers=headers, verify=False, timeout=10)
    response.raise_for_status()
    root = ET.fromstring(response.text)
    for entry in root.findall(".//entry"):
        name = entry.get("name")
        members = [member.text for member in entry.findall(".//member")]
        groups[name] = members
    
    print("\nCopyable Format for Objects and Groups (name,value or group_name,member1;member2;...):")
    for name, value in objects.items():
        print(f"  {name},{value}")
    for name, members in groups.items():
        print(f"  {name},{';'.join(members)}")
    
    return objects, groups

# Prompt to confirm files are ready with y/Y/n/N support
def confirm_files_ready():
    while True:
        response = input("\nAre the files 'old_objects.txt' and 'new_objects.txt' ready to proceed with changes? (Yes/No): ").strip()
        response_lower = response.lower()
        if response_lower in ['y', 'yes']:
            return True
        elif response_lower in ['n', 'no']:
            print("Please prepare the files and run the script again when ready.")
            exit(0)
        else:
            print("Please enter 'Y', 'y', 'Yes', 'N', 'n', or 'No'.")

# Prompt to download running configuration with y/Y/n/N support
def confirm_download_config():
    while True:
        response = input("\nWould you like to download the current running configuration? (Yes/No): ").strip()
        response_lower = response.lower()
        if response_lower in ['y', 'yes']:
            return True
        elif response_lower in ['n', 'no']:
            return False
        else:
            print("Please enter 'Y', 'y', 'Yes', 'N', 'n', or 'No'.")

# Prompt to list objects and groups in copyable format with y/Y/n/N support
def confirm_list_copyable():
    while True:
        response = input("\nWould you like to list objects and groups in a copyable format for object files? (Yes/No): ").strip()
        response_lower = response.lower()
        if response_lower in ['y', 'yes']:
            return True
        elif response_lower in ['n', 'no']:
            return False
        else:
            print("Please enter 'Y', 'y', 'Yes', 'N', 'n', or 'No'.")

# Prompt to confirm object deletion with y/Y/n/N support and expected format
def confirm_delete_objects():
    print("\nExpected format for 'objects_to_delete.txt': One object name per line, matching the 'OBJECTS NAME' column from object-change-tracker.xlsx (e.g., Remote-VPN-Subnet). Addresses or extra data will be ignored.")
    while True:
        response = input("\nWould you like to delete specific address objects listed in 'objects_to_delete.txt'? (Yes/No): ").strip()
        response_lower = response.lower()
        if response_lower in ['y', 'yes']:
            return True
        elif response_lower in ['n', 'no']:
            return False
        else:
            print("Please enter 'Y', 'y', 'Yes', 'N', 'n', or 'No'.")

# Verify old objects match firewall
def verify_old_objects(firewall_objects, old_objects):
    mismatches = []
    for name, old_value in old_objects.items():
        if name not in firewall_objects:
            mismatches.append(f"Object '{name}' not found on firewall.")
        elif firewall_objects[name] != old_value:
            mismatches.append(f"Object '{name}' mismatch: Firewall={firewall_objects[name]}, File={old_value}")
    return mismatches

# Apply batch changes and generate report with address type handling
def apply_batch_changes(api_key, api_url, firewall_objects, new_objects):
    if not new_objects:
        print("No new objects to apply.")
        return None
    
    report = {
        "successful": [],
        "unchanged": [],
        "new_added": [],
        "modified": [],
        "invalid_format": []
    }
    
    print("\nApplying changes...")
    headers = {"X-PAN-KEY": api_key}
    for name, new_value in new_objects.items():
        address_type = validate_address_type(new_value)
        if not address_type:
            report["invalid_format"].append(f"'{name}' has invalid format: '{new_value}'")
            print(f"Skipped '{name}': Invalid format '{new_value}'")
            continue
        
        if name in firewall_objects:
            current_value = firewall_objects[name]
            if current_value == new_value:
                print(f"Skipped '{name}': Value '{new_value}' already matches.")
                continue
        
        xml_data = f"""
        <entry name='{name}'>
            <{address_type}>{new_value}</{address_type}>
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
                create_url = f"{api_url}?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address&element={quote(xml_data)}"
                create_response = requests.post(create_url, headers=headers, verify=False, timeout=10)
                create_response.raise_for_status()
                report["successful"].append(f"'{name}' created with value '{new_value}'")
                report["new_added"].append(f"'{name}' added as new object with value '{new_value}'")
                print(f"Created new object '{name}' with value '{new_value}'")
        except requests.RequestException as e:
            report["unchanged"].append(f"'{name}' not changed due to error: {str(e)}")
            print(f"Failed to update '{name}': {str(e)}")

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

# Generate and save report with object count and invalid format section
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
    
    if report["invalid_format"]:
        print("\nObjects with Invalid Format:")
        for item in report["invalid_format"]:
            print(f"  - {item}")
    
    with open("update_report.txt", "w") as f:
        f.write(f"Update Report (Script Version: {SCRIPT_VERSION})\n=============\n\n")
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
        if report["invalid_format"]:
            f.write("\nObjects with Invalid Format:\n")
            for item in report["invalid_format"]:
                f.write(f"  - {item}\n")
    print("\nReport saved to 'update_report.txt'.")

# Main execution
def main():
    print(f"Script Version: {SCRIPT_VERSION}")
    try:
        host = get_host()
        username, password = get_credentials()
        api_key, api_url = get_api_key(host, username, password)
        print(f"Connected to device at {host}")

        # Request configuration backup before any changes
        if confirm_download_config():
            download_running_config(api_key, api_url)
        else:
            print("Warning: Proceeding without a configuration backup. This is not recommended.")

        # Delete specific objects if confirmed
        if confirm_delete_objects():
            objects_to_delete = read_objects_to_delete()
            if objects_to_delete:
                deletion_report = delete_address_objects(api_key, api_url, objects_to_delete)
                if deletion_report:
                    print("\nDeletion Report:")
                    print("==============")
                    print("\nSuccessfully Deleted Objects:")
                    for item in deletion_report["successful"]:
                        print(f"  - {item}")
                    if deletion_report["failed"]:
                        print("\nFailed Deletions:")
                        for item in deletion_report["failed"]:
                            print(f"  - {item}")
                    with open("deletion_report.txt", "w") as f:
                        f.write(f"Deletion Report (Script Version: {SCRIPT_VERSION})\n=============\n\n")
                        f.write("\nSuccessfully Deleted Objects:\n")
                        for item in deletion_report["successful"]:
                            f.write(f"  - {item}\n")
                        if deletion_report["failed"]:
                            f.write("\nFailed Deletions:\n")
                            for item in deletion_report["failed"]:
                                f.write(f"  - {item}\n")
                    print("\nDeletion report saved to 'deletion_report.txt'.")

        firewall_objects, firewall_groups = list_all_objects_and_groups(api_key, api_url)

        if confirm_list_copyable():
            list_objects_and_groups_copyable(api_key, api_url)

        if not confirm_files_ready():
            return

        old_objects = read_objects_from_file("old_objects.txt")
        new_objects = read_objects_from_file("new_objects.txt")

        mismatches = verify_old_objects(firewall_objects, old_objects)
        if mismatches:
            print("\nMismatches found:")
            for mismatch in mismatches:
                print(mismatch)
            print("Proceeding with updates despite mismatches.")

        report = apply_batch_changes(api_key, api_url, firewall_objects, new_objects)
        generate_report(report, len(firewall_objects), len(firewall_groups))

    except requests.RequestException as e:
        print(f"Error: {e}")
    except ET.ParseError as e:
        print(f"XML Parse Error: {e}")
    except Exception as e:
        print(f"Unexpected Error: {e}")

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()