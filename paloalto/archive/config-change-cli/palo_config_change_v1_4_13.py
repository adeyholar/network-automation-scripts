import requests
import xml.etree.ElementTree as ET
from urllib.parse import quote
import socket
import ssl
import time
import os
import getpass
import re
import ipaddress

# Script version
SCRIPT_VERSION = "1.4.13"

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
# 1.4.6 - Added checks for object usage in firewall policies, prompted for replacement objects, and managed policy retention or deletion based on user input
# 1.4.7 - Added support for separate files (objects_to_delete.txt, objects_to_add.txt, objects_to_update.txt) to manage deletions, additions, and value changes
# 1.4.8 - Optimized deletion process by verifying object presence, prompting for per-object deletion confirmation, and saving backup objects and groups in a reusable format
# 1.4.9 - Error was found and fixed
# 1.4.10 - Fixed error where 'keep_policy' variable was undefined when an object is used only in address groups during deletion
# 1.4.11 - Optimized deletion process by adding prompt to remove object from address group if it is a member, allowing automatic removal and continuation
# 1.4.12 - Added graceful handling of KeyboardInterrupt (Ctrl+C) during user prompts to exit cleanly with a message
# 1.4.13 - Optimized script for bash workflow: pre-optimize objects in the firewall, process deletions in batches, update object values if used in policies, delete if not in use, and update or remove from groups if in groups

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

# Prompt for firewall or Panorama IP/hostname with timeout, reachability check, and caching
def get_host():
    cached_host = load_cached_firewall()
    default_msg = f" (default: {cached_host})" if cached_host else ""
    
    while True:
        try:
            host_input = input(f"Enter the Palo Alto firewall or Panorama IP address or hostname (e.g., 192.0.2.10){default_msg}: ").strip()
            if not host_input and cached_host:
                host = cached_host
                print(f"Using cached host: {host}")
            elif not host_input:
                print("No entry provided and no cached host available. Exiting.")
                exit(0)
            else:
                host = host_input
            
            if is_host_reachable(host):
                save_cached_firewall(host)
                return host
            else:
                print(f"Error: IP address or hostname '{host}' is not reachable via script (port 443). Ensure API access is allowed.")
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

# Pre-optimize by fetching and saving all address objects and groups
def pre_optimize_objects_and_groups(api_key, api_url):
    objects = {}
    groups = {}
    
    # Fetch address objects
    url_objects = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address"
    headers = {"X-PAN-KEY": api_key}
    try:
        response = requests.get(url_objects, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        for entry in root.findall(".//entry"):
            name = entry.get("name")
            value = entry.findtext("ip-netmask") or entry.findtext("ip-range") or entry.findtext("ip-wildcard") or entry.findtext("fqdn") or "N/A"
            objects[name] = value
    except requests.RequestException as e:
        print(f"Error pre-optimizing objects: {e}")
        return False
    
    # Fetch address groups
    url_groups = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group"
    try:
        response = requests.get(url_groups, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        for entry in root.findall(".//entry"):
            name = entry.get("name")
            members = [member.text for member in entry.findall(".//member")]
            groups[name] = members
    except requests.RequestException as e:
        print(f"Error pre-optimizing groups: {e}")
        return False
    
    # Save objects to pre_optimized_objects.txt
    with open("pre_optimized_objects.txt", "w") as f:
        for name, value in objects.items():
            f.write(f"{name},{value}\n")
    
    # Save groups to pre_optimized_groups.txt
    with open("pre_optimized_groups.txt", "w") as f:
        for name, members in groups.items():
            f.write(f"{name},{';'.join(members)}\n")
    
    print("Pre-optimized objects saved to 'pre_optimized_objects.txt' and groups to 'pre_optimized_groups.txt'.")
    return objects, groups

# Read objects from a file (format: name only or name,value)
def read_objects_file(filename, name_only=False):
    objects = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    if name_only:
                        # Take only the object name (first element if tab/space-separated)
                        name = line.split(None, 1)[0]
                        objects.append(name)
                    else:
                        # Expect name,value format
                        if ',' in line:
                            name, value = line.split(',', 1)
                            objects.append((name, value))
                        else:
                            print(f"Skipping invalid line in '{filename}': {line}")
        return objects
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found. No objects will be processed.")
        return []
    except Exception as e:
        print(f"Error reading '{filename}': {e}. No objects will be processed.")
        return []

# Check if an address object exists on the firewall
def check_object_exists(api_key, api_url, object_name):
    url = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{object_name}']"
    headers = {"X-PAN-KEY": api_key}
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        return root.find(".//entry") is not None
    except requests.RequestException:
        return False

# Check if an address object is used in policies, NAT rules, or address groups
def check_object_usage(api_key, api_url, object_name):
    headers = {"X-PAN-KEY": api_key}
    usage = {
        "security_policies": [],
        "nat_rules": [],
        "address_groups": []
    }
    
    # Check security policies
    url_policies = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules"
    try:
        response = requests.get(url_policies, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        for rule in root.findall(".//entry"):
            rule_name = rule.get("name")
            for member in rule.findall(".//member"):
                if member.text == object_name:
                    usage["security_policies"].append(rule_name)
    except requests.RequestException as e:
        print(f"Error checking security policies for '{object_name}': {e}")
    
    # Check NAT rules
    url_nat = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/nat/rules"
    try:
        response = requests.get(url_nat, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        for rule in root.findall(".//entry"):
            rule_name = rule.get("name")
            for member in rule.findall(".//member"):
                if member.text == object_name:
                    usage["nat_rules"].append(rule_name)
    except requests.RequestException as e:
        print(f"Error checking NAT rules for '{object_name}': {e}")
    
    # Check address groups
    url_groups = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group"
    try:
        response = requests.get(url_groups, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        for group in root.findall(".//entry"):
            group_name = group.get("name")
            for member in group.findall(".//member"):
                if member.text == object_name:
                    usage["address_groups"].append(group_name)
    except requests.RequestException as e:
        print(f"Error checking address groups for '{object_name}': {e}")
    
    return usage

# Remove an object from an address group
def remove_object_from_group(api_key, api_url, object_name, group_name):
    headers = {"X-PAN-KEY": api_key}
    url = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='{group_name}']"
    try:
        # Fetch the current group configuration
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        
        # Find the members list
        members = root.find(".//static")
        if members is None:
            print(f"Address group '{group_name}' has no static members to modify.")
            return False
        
        # Remove the specified object from the members list
        updated = False
        for member in members.findall("member"):
            if member.text == object_name:
                members.remove(member)
                updated = True
                break
        
        if not updated:
            print(f"Object '{object_name}' not found in address group '{group_name}'.")
            return False
        
        # If no members remain, remove the static tag to avoid empty group issues
        if len(members.findall("member")) == 0:
            root.remove(members)
            xml_data = "<static/>"
        else:
            xml_data = ET.tostring(root, encoding='unicode')
        
        # Update the address group
        edit_url = f"{api_url}?type=config&action=edit&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='{group_name}']&element={quote(xml_data)}"
        response = requests.post(edit_url, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        print(f"Removed '{object_name}' from address group '{group_name}'")
        return True
    except requests.RequestException as e:
        print(f"Failed to remove '{object_name}' from address group '{group_name}': {e}")
        return False

# Update an object's value
def update_object_value(api_key, api_url, object_name, new_value):
    headers = {"X-PAN-KEY": api_key}
    address_type = validate_address_type(new_value)
    if not address_type:
        print(f"Invalid value format for '{object_name}': '{new_value}'")
        return False
    
    xml_data = f"""
    <entry name='{object_name}'>
        <{address_type}>{new_value}</{address_type}>
    </entry>
    """
    url = f"{api_url}?type=config&action=edit&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{object_name}']&element={quote(xml_data)}"
    try:
        response = requests.post(url, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        print(f"Updated '{object_name}' to value '{new_value}'")
        return True
    except requests.RequestException as e:
        print(f"Failed to update '{object_name}' to '{new_value}': {e}")
        return False

# Delete a batch of objects
def delete_batch_objects(api_key, api_url, object_names):
    if not object_names:
        return True
    
    headers = {"X-PAN-KEY": api_key}
    successes = []
    failures = []
    
    print(f"Deleting batch of {len(object_names)} objects...")
    for name in object_names:
        url = f"{api_url}?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{name}']"
        try:
            response = requests.get(url, headers=headers, verify=False, timeout=10)
            response.raise_for_status()
            successes.append(f"'{name}' deleted")
            print(f"Deleted '{name}'")
        except requests.RequestException as e:
            failures.append(f"'{name}' not deleted due to error: {str(e)}")
            print(f"Failed to delete '{name}': {str(e)}")
    
    if successes:
        commit_url = f"{api_url}?type=commit&cmd=<commit></commit>"
        try:
            commit_response = requests.post(commit_url, headers=headers, verify=False, timeout=10)
            commit_response.raise_for_status()
            print("Batch deletions committed successfully.")
        except requests.RequestException as e:
            print(f"Commit failed: {e}")
            failures.extend([f"'{name}' deletion not committed due to commit failure: {str(e)}" for name in object_names if name in [entry.split("'")[1] for entry in successes]])
    
    return successes, failures

# Delete specified address objects in batches based on usage
def delete_address_objects(api_key, api_url, object_names):
    if not object_names:
        print("No objects specified for deletion.")
        return None
    
    report = {
        "successful": [],
        "failed": []
    }
    
    # Batch objects based on usage
    batch_not_in_use = []  # Objects to delete immediately
    batch_in_policy = []   # Objects used in policies (update value)
    batch_in_group = []    # Objects used in groups (update or remove)
    
    print("\nAnalyzing objects for batch processing...")
    for name in object_names:
        # Verify object exists
        if not check_object_exists(api_key, api_url, name):
            report["failed"].append(f"'{name}' not deleted: not found on firewall")
            print(f"Object '{name}' not found on firewall. Skipping.")
            continue
        
        usage = check_object_usage(api_key, api_url, name)
        if usage["security_policies"] or usage["nat_rules"]:
            batch_in_policy.append((name, usage))
        elif usage["address_groups"]:
            batch_in_group.append((name, usage))
        else:
            batch_not_in_use.append(name)
    
    # Process batch: Not in use (delete immediately)
    if batch_not_in_use:
        successes, failures = delete_batch_objects(api_key, api_url, batch_not_in_use)
        report["successful"].extend(successes)
        report["failed"].extend(failures)
    
    # Process batch: Used in policies (update value)
    for name, usage in batch_in_policy:
        print(f"\nObject '{name}' is used in:")
        if usage["security_policies"]:
            print(f"  Security Policies: {', '.join(usage['security_policies'])}")
        if usage["nat_rules"]:
            print(f"  NAT Rules: {', '.join(usage['nat_rules'])}")
        try:
            new_value = input(f"Enter new value for '{name}' (e.g., 10.0.0.0/24, example.com, leave blank to skip): ").strip()
        except KeyboardInterrupt:
            print("\nOperation cancelled by user (Ctrl+C). Exiting.")
            exit(0)
        if new_value:
            if update_object_value(api_key, api_url, name, new_value):
                report["successful"].append(f"'{name}' updated to '{new_value}'")
            else:
                report["failed"].append(f"'{name}' not updated due to error")
        else:
            report["failed"].append(f"'{name}' not deleted as it is used in policies and no new value provided")
            print(f"Skipping '{name}' as no new value provided.")
    
    # Process batch: Used in groups (update value or remove)
    for name, usage in batch_in_group:
        print(f"\nObject '{name}' is used in:")
        print(f"  Address Groups: {', '.join(usage['address_groups'])}")
        try:
            new_value = input(f"Enter new value for '{name}' (e.g., 10.0.0.0/24, example.com, leave blank to remove from group and delete): ").strip()
        except KeyboardInterrupt:
            print("\nOperation cancelled by user (Ctrl+C). Exiting.")
            exit(0)
        if new_value:
            if update_object_value(api_key, api_url, name, new_value):
                report["successful"].append(f"'{name}' updated to '{new_value}'")
            else:
                report["failed"].append(f"'{name}' not updated due to error")
        else:
            # Remove from all groups and delete
            skip_deletion = False
            for group_name in usage["address_groups"]:
                if not remove_object_from_group(api_key, api_url, name, group_name):
                    report["failed"].append(f"'{name}' not deleted due to failure removing from address group '{group_name}'")
                    print(f"Failed to remove '{name}' from address group '{group_name}'. Skipping deletion.")
                    skip_deletion = True
                    break
            if skip_deletion:
                continue
            # Add to deletion batch
            successes, failures = delete_batch_objects(api_key, api_url, [name])
            report["successful"].extend(successes)
            report["failed"].extend(failures)
    
    return report

# Apply batch additions or updates and generate report
def apply_batch_changes(api_key, api_url, firewall_objects, objects, operation="update"):
    if not objects:
        print(f"No objects to {operation}.")
        return None
    
    report = {
        "successful": [],
        "unchanged": [],
        "new_added": [],
        "modified": [],
        "invalid_format": []
    }
    
    print(f"\nApplying {operation}s...")
    headers = {"X-PAN-KEY": api_key}
    for name, value in objects:
        address_type = validate_address_type(value)
        if not address_type:
            report["invalid_format"].append(f"'{name}' has invalid format: '{value}'")
            print(f"Skipped '{name}': Invalid format '{value}'")
            continue
        
        if name in firewall_objects and operation == "update":
            current_value = firewall_objects[name]
            if current_value == value:
                print(f"Skipped '{name}': Value '{value}' already matches.")
                continue
        
        xml_data = f"""
        <entry name='{name}'>
            <{address_type}>{value}</{address_type}>
        </entry>
        """
        url = f"{api_url}?type=config&action=edit&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{name}']&element={quote(xml_data)}"
        try:
            response = requests.post(url, headers=headers, verify=False, timeout=10)
            if response.status_code == 200:
                report["successful"].append(f"'{name}' {operation}d to '{value}'")
                report["modified"].append(f"'{name}' modified from '{firewall_objects.get(name, 'N/A')}' to '{value}'")
                print(f"{operation.capitalize()}d '{name}' to '{value}'")
            else:
                create_url = f"{api_url}?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address&element={quote(xml_data)}"
                create_response = requests.post(create_url, headers=headers, verify=False, timeout=10)
                create_response.raise_for_status()
                report["successful"].append(f"'{name}' created with value '{value}'")
                report["new_added"].append(f"'{name}' added as new object with value '{value}'")
                print(f"Created new object '{name}' with value '{value}'")
        except requests.RequestException as e:
            report["unchanged"].append(f"'{name}' not {operation}d due to error: {str(e)}")
            print(f"Failed to {operation} '{name}': {str(e)}")

    if report["successful"]:
        commit_url = f"{api_url}?type=commit&cmd=<commit></commit>"
        try:
            commit_response = requests.post(commit_url, headers=headers, verify=False, timeout=10)
            commit_response.raise_for_status()
            print(f"{operation.capitalize()}s committed successfully.")
        except requests.RequestException as e:
            print(f"Commit failed: {e}")
            report["unchanged"].extend([f"'{name}' not committed due to commit failure: {str(e)}" for name, _ in objects if name in [entry.split("'")[1] for entry in report["successful"]]])

    return report

# Generate and save report with object count and invalid format section
def generate_report(report, total_objects, total_groups, operation="update"):
    if not report:
        print(f"No {operation} report to generate.")
        return
    
    print(f"\n{operation.capitalize()} Report:")
    print("==============")
    
    print(f"\nTotal Objects Discovered: {total_objects} address objects, {total_groups} address groups")
    print(f"\nSuccessfully {operation.capitalize()}d Objects:")
    for item in report["successful"]:
        print(f"  - {item}")
    
    print(f"\nNew Objects Added:")
    for item in report["new_added"]:
        print(f"  - {item}")
    
    print(f"\nObjects Modified:")
    for item in report["modified"]:
        print(f"  - {item}")
    
    if report["invalid_format"]:
        print(f"\nObjects with Invalid Format:")
        for item in report["invalid_format"]:
            print(f"  - {item}")
    
    if "failed" in report and report["failed"]:
        print(f"\nFailed {operation.capitalize()}s:")
        for item in report["failed"]:
            print(f"  - {item}")
    
    report_file = f"{operation}_report.txt"
    with open(report_file, "w") as f:
        f.write(f"{operation.capitalize()} Report (Script Version: {SCRIPT_VERSION})\n=============\n\n")
        f.write(f"Total Objects Discovered: {total_objects} address objects, {total_groups} address groups\n")
        f.write(f"\nSuccessfully {operation.capitalize()}d Objects:\n")
        for item in report["successful"]:
            f.write(f"  - {item}\n")
        f.write(f"\nNew Objects Added:\n")
        for item in report["new_added"]:
            f.write(f"  - {item}\n")
        f.write(f"\nObjects Modified:\n")
        for item in report["modified"]:
            f.write(f"  - {item}\n")
        if report["invalid_format"]:
            f.write(f"\nObjects with Invalid Format:\n")
            for item in report["invalid_format"]:
                f.write(f"  - {item}\n")
        if "failed" in report and report["failed"]:
            f.write(f"\nFailed {operation.capitalize()}s:\n")
            for item in report["failed"]:
                f.write(f"  - {item}\n")
    print(f"\n{operation.capitalize()} report saved to '{report_file}'.")

# Prompt to confirm processing additions with y/Y/n/N support
def confirm_add_objects():
    print("\nExpected format for 'objects_to_add.txt': One line per object in the format 'name,value' (e.g., New-Object-1,192.0.2.99/32).")
    while True:
        try:
            response = input("\nWould you like to add new address objects listed in 'objects_to_add.txt'? (Yes/No): ").strip()
            response_lower = response.lower()
            if response_lower in ['y', 'yes']:
                return True
            elif response_lower in ['n', 'no']:
                return False
            else:
                print("Please enter 'Y', 'y', 'Yes', 'N', 'n', or 'No'.")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user (Ctrl+C). Exiting.")
            exit(0)

# Prompt to confirm processing updates with y/Y/n/N support
def confirm_update_objects():
    print("\nExpected format for 'objects_to_update.txt': One line per object in the format 'name,new_value' (e.g., SRV-APP01,192.0.2.21/32).")
    while True:
        try:
            response = input("\nWould you like to update address objects listed in 'objects_to_update.txt'? (Yes/No): ").strip()
            response_lower = response.lower()
            if response_lower in ['y', 'yes']:
                return True
            elif response_lower in ['n', 'no']:
                return False
            else:
                print("Please enter 'Y', 'y', 'Yes', 'N', 'n', or 'No'.")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user (Ctrl+C). Exiting.")
            exit(0)

# Prompt to confirm object deletion with y/Y/n/N support and expected format
def confirm_delete_objects():
    print("\nExpected format for 'objects_to_delete.txt': One object name per line, matching the 'OBJECTS NAME' column from object-change-tracker.xlsx (e.g., Remote-VPN-Subnet). Addresses or extra data will be ignored.")
    while True:
        try:
            response = input("\nWould you like to delete specific address objects listed in 'objects_to_delete.txt'? (Yes/No): ").strip()
            response_lower = response.lower()
            if response_lower in ['y', 'yes']:
                return True
            elif response_lower in ['n', 'no']:
                return False
            else:
                print("Please enter 'Y', 'y', 'Yes', 'N', 'n', or 'No'.")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user (Ctrl+C). Exiting.")
            exit(0)

# Prompt to confirm downloading running configuration with y/Y/n/N support
def confirm_download_config():
    while True:
        try:
            response = input("\nWould you like to download the current running configuration and pre-optimize objects/groups? (Yes/No): ").strip()
            response_lower = response.lower()
            if response_lower in ['y', 'yes']:
                return True
            elif response_lower in ['n', 'no']:
                return False
            else:
                print("Please enter 'Y', 'y', 'Yes', 'N', 'n', or 'No'.")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user (Ctrl+C). Exiting.")
            exit(0)

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

# Prompt to confirm listing objects and groups with y/Y/n/N support
def confirm_list_copyable():
    while True:
        try:
            response = input("\nWould you like to list objects and groups in a copyable format for object files? (Yes/No): ").strip()
            response_lower = response.lower()
            if response_lower in ['y', 'yes']:
                return True
            elif response_lower in ['n', 'no']:
                return False
            else:
                print("Please enter 'Y', 'y', 'Yes', 'N', 'n', or 'No'.")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user (Ctrl+C). Exiting.")
            exit(0)

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

# Main execution
def main():
    print(f"Script Version: {SCRIPT_VERSION}")
    try:
        host = get_host()
        username, password = get_credentials()
        api_key, api_url = get_api_key(host, username, password)
        print(f"Connected to device at {host}")

        # Request configuration backup and pre-optimize objects/groups before any changes
        if confirm_download_config():
            download_running_config(api_key, api_url)
            firewall_objects, firewall_groups = pre_optimize_objects_and_groups(api_key, api_url)
        else:
            print("Warning: Proceeding without a configuration backup or pre-optimization. This is not recommended.")
            firewall_objects, firewall_groups = list_all_objects_and_groups(api_key, api_url)

        # Delete specific objects if confirmed
        if confirm_delete_objects():
            objects_to_delete = read_objects_file("objects_to_delete.txt", name_only=True)
            if objects_to_delete:
                deletion_report = delete_address_objects(api_key, api_url, objects_to_delete)
                if deletion_report:
                    generate_report(deletion_report, len(firewall_objects), len(firewall_groups), operation="deletion")

        # Add new objects if confirmed
        if confirm_add_objects():
            objects_to_add = read_objects_file("objects_to_add.txt")
            if objects_to_add:
                firewall_objects, firewall_groups = list_all_objects_and_groups(api_key, api_url)
                add_report = apply_batch_changes(api_key, api_url, firewall_objects, objects_to_add, operation="add")
                if add_report:
                    generate_report(add_report, len(firewall_objects), len(firewall_groups), operation="add")

        # Update existing objects if confirmed
        if confirm_update_objects():
            objects_to_update = read_objects_file("objects_to_update.txt")
            if objects_to_update:
                firewall_objects, firewall_groups = list_all_objects_and_groups(api_key, api_url)
                update_report = apply_batch_changes(api_key, api_url, firewall_objects, objects_to_update, operation="update")
                if update_report:
                    generate_report(update_report, len(firewall_objects), len(firewall_groups), operation="update")

        # List objects and groups if confirmed
        if confirm_list_copyable():
            list_all_objects_and_groups(api_key, api_url)

    except requests.RequestException as e:
        print(f"Error: {e}")
    except ET.ParseError as e:
        print(f"XML Parse Error: {e}")
    except Exception as e:
        print(f"Unexpected Error: {e}")

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()