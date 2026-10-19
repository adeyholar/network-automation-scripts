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
import msvcrt

# Script version
SCRIPT_VERSION = "1.5.10"

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
# 1.4.14 - Fixed error in generate_report where 'new_added' key was accessed unconditionally, causing an unexpected error when processing deletions
# 1.4.15 - Added option to choose between batch deletion or replacing old object values with new ones without deletion, with case-insensitive Y/N input handling
# 1.4.16 - Corrected non-batch deletion to use new_objects.txt for replacing old object values instead of a separate object_replacements.txt file
# 1.4.17 - Implemented structured flow: added backup prompt after login, structured object deletion with policy impact listing, object replacement with sync check, and exit countdown option
# 1.5.0 - Corrected filename to palo_config_change.py and reset version to v1
# 1.5.1 - Enhanced KeyboardInterrupt handling to ensure consistent graceful exit across all user prompts in the new structured flow
# 1.5.2 - Added ability to restore running configuration, modified countdown timer to allow restore option, and introduced a menu-driven interface for selecting actions with iterative flow
# 1.5.3 - Adjusted running configuration backup filename to be <=32 characters, added options to add new objects and object groups with interactive input and commit confirmation
# 1.5.4 - Modified report generation to append reports to a single file with timestamps instead of overwriting, for audit purposes
# 1.5.5 - Fixed SyntaxError in add_objects_or_groups by removing backslash in f-string expression and using alternative string splitting method
# 1.5.6 - Fixed potential SyntaxError or runtime issue in add_objects_or_groups by correcting non-ASCII characters in the commit confirmation condition
# 1.5.7 - Reverted to working version 1.5.3 and reapplied changes from 1.5.4 through 1.5.6, ensuring the script compiles and runs on Windows 11 x64, fixing early failure before login prompts; corrected XML parsing in check_object_usage
# 1.5.8 - Fixed SyntaxError in add_objects_or_groups by correcting the f-string expression with conflicting quotes, ensuring proper string termination
# 1.5.9 - Added automatic commit after successful running configuration backup in download_running_config to ensure changes are committed before proceeding
# 1.5.10 - Optimized script flow by separating delete, add, and replace operations into distinct tasks with clear user prompts; reverted menu structure to working version 1.5.3 and updated to meet new requirements for improved clarity and audit reporting

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

# Check if an address object group exists on the firewall
def check_group_exists(api_key, api_url, group_name):
    url = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='{group_name}']"
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

# Delete a security policy or NAT rule
def delete_policy(api_key, api_url, policy_type, policy_name):
    headers = {"X-PAN-KEY": api_key}
    if policy_type == "security":
        xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='{policy_name}']"
    elif policy_type == "nat":
        xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/nat/rules/entry[@name='{policy_name}']"
    else:
        return False
    
    url = f"{api_url}?type=config&action=delete&xpath={xpath}"
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        print(f"Deleted {policy_type} policy '{policy_name}'")
        return True
    except requests.RequestException as e:
        print(f"Failed to delete {policy_type} policy '{policy_name}': {e}")
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

# Add a new object or object group
def add_objects_or_groups(api_key, api_url):
    while True:
        try:
            response = input("\nDo you want to add new objects or object groups? (Yes/No): ").strip()
            response_lower = response.lower()
            if response_lower in ['y', 'yes']:
                break
            elif response_lower in ['n', 'no']:
                return None
            else:
                print("Please enter 'Y', 'y', 'Yes', 'N', 'n', or 'No'.")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user (Ctrl+C). Exiting.")
            exit(0)
    
    report = {
        "successful": [],
        "failed": []
    }
    headers = {"X-PAN-KEY": api_key}
    
    while True:
        try:
            # Only adding objects (not groups) as per requirement
            name = input("\nEnter the object name: ").strip()
            if not name:
                print("Object name cannot be empty.")
                continue
            if check_object_exists(api_key, api_url, name):
                print(f"Object '{name}' already exists. Skipping.")
                report["failed"].append(f"'{name}' not added: already exists")
                continue
            
            value = input("Enter the object value (e.g., 192.0.2.99/32, example.com): ").strip()
            address_type = validate_address_type(value)
            if not address_type:
                print(f"Invalid value format for '{name}': '{value}'")
                report["failed"].append(f"'{name}' not added: invalid value format")
                continue
            
            xml_data = f"""
            <entry name='{name}'>
                <{address_type}>{value}</{address_type}>
            </entry>
            """
            url = f"{api_url}?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address&element={quote(xml_data)}"
            response = requests.post(url, headers=headers, verify=False, timeout=10)
            response.raise_for_status()
            report["successful"].append(f"Added object '{name}' with value '{value}'")
            print(f"Added object '{name}' with value '{value}'")
        
        except KeyboardInterrupt:
            print("\nOperation cancelled by user (Ctrl+C). Exiting.")
            exit(0)
        except requests.RequestException as e:
            print(f"Failed to add object '{name}': {e}")
            report["failed"].append(f"'{name}' not added due to error: {str(e)}")
        
        # Prompt to check if done adding objects
        while True:
            try:
                done_response = input("\nDone adding new objects? (Yes/No): ").strip()
                done_response_lower = done_response.lower()
                if done_response_lower in ['y', 'yes']:
                    # Commit changes if there are successful additions
                    if report["successful"]:
                        commit_url = f"{api_url}?type=commit&cmd=<commit></commit>"
                        try:
                            response = requests.post(commit_url, headers=headers, verify=False, timeout=30)
                            response.raise_for_status()
                            print("Changes committed successfully.")
                        except requests.RequestException as e:
                            print(f"Commit failed: {e}")
                            failed_entries = []
                            for entry in report["successful"]:
                                name = entry.split("'")[1]
                                failed_entries.append(f"'{name}' not committed due to commit failure: {str(e)}")
                            report["failed"].extend(failed_entries)
                            report["successful"] = []
                    return report
                elif done_response_lower in ['n', 'no']:
                    break  # Continue adding more objects
                else:
                    print("Please enter 'Y', 'y', 'Yes', 'N', 'n', or 'No'.")
            except KeyboardInterrupt:
                print("\nOperation cancelled by user (Ctrl+C). Exiting.")
                exit(0)

# Delete specified address objects after listing affected policies
def delete_batch_objects(api_key, api_url, object_names, usage_dict):
    if not object_names:
        return True
    
    headers = {"X-PAN-KEY": api_key}
    successes = []
    failures = []
    
    print(f"\nDeleting batch of {len(object_names)} objects...")
    for name in object_names:
        usage = usage_dict.get(name, {})
        # Remove from address groups
        for group_name in usage.get("address_groups", []):
            if not remove_object_from_group(api_key, api_url, name, group_name):
                failures.append(f"'{name}' not deleted due to failure removing from address group '{group_name}'")
                continue
        
        # Delete from policies
        for policy_name in usage.get("security_policies", []):
            if not delete_policy(api_key, api_url, "security", policy_name):
                failures.append(f"'{name}' not deleted due to failure deleting security policy '{policy_name}'")
                continue
        
        for policy_name in usage.get("nat_rules", []):
            if not delete_policy(api_key, api_url, "nat", policy_name):
                failures.append(f"'{name}' not deleted due to failure deleting NAT policy '{policy_name}'")
                continue
        
        # Delete the object
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

# Delete specified address objects after listing affected policies
def delete_address_objects(api_key, api_url):
    # Prompt to confirm if objects_to_delete.txt is updated
    while True:
        try:
            response = input("\nAre the objects updated in objects_to_delete.txt? (Yes/No): ").strip()
            response_lower = response.lower()
            if response_lower in ['y', 'yes']:
                break
            elif response_lower in ['n', 'no']:
                return None
            else:
                print("Please enter 'Y', 'y', 'Yes', 'N', 'n', or 'No'.")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user (Ctrl+C). Exiting.")
            exit(0)
    
    objects_to_delete = read_objects_file("objects_to_delete.txt", name_only=True)
    if not objects_to_delete:
        print("No objects specified for deletion.")
        return None
    
    report = {
        "successful": [],
        "failed": []
    }
    
    # List objects and their usage
    print("\nObjects marked for deletion and their affected policies:")
    usage_dict = {}
    for name in objects_to_delete:
        if not check_object_exists(api_key, api_url, name):
            report["failed"].append(f"'{name}' not deleted: not found on firewall")
            print(f"Object '{name}' not found on firewall. Skipping.")
            continue
        
        usage = check_object_usage(api_key, api_url, name)
        usage_dict[name] = usage
        print(f"\nObject '{name}':")
        if usage["security_policies"]:
            print(f"  Security Policies: {', '.join(usage['security_policies'])}")
        if usage["nat_rules"]:
            print(f"  NAT Rules: {', '.join(usage['nat_rules'])}")
        if usage["address_groups"]:
            print(f"  Address Groups: {', '.join(usage['address_groups'])}")
        if not any(usage.values()):
            print("  No policies or groups affected.")
    
    # Confirm deletion
    while True:
        try:
            response = input("\nContinue with deletion after listing affected policies? (Yes/No): ").strip()
            response_lower = response.lower()
            if response_lower in ['y', 'yes']:
                break
            elif response_lower in ['n', 'no']:
                print("Skipping deletion.")
                return None
            else:
                print("Please enter 'Y', 'y', 'Yes', 'N', 'n', or 'No'.")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user (Ctrl+C). Exiting.")
            exit(0)
    
    # Proceed with deletion
    successes, failures = delete_batch_objects(api_key, api_url, objects_to_delete, usage_dict)
    report["successful"].extend(successes)
    report["failed"].extend(failures)
    
    return report

# Replace old object values with new ones using new_objects.txt
def replace_object_values(api_key, api_url):
    # Prompt to confirm if new_objects.txt is updated
    while True:
        try:
            response = input("\nAre the objects updated in new_objects.txt? (Yes/No): ").strip()
            response_lower = response.lower()
            if response_lower in ['y', 'yes']:
                break
            elif response_lower in ['n', 'no']:
                return None
            else:
                print("Please enter 'Y', 'y', 'Yes', 'N', 'n', or 'No'.")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user (Ctrl+C). Exiting.")
            exit(0)
    
    objects_to_replace = read_objects_file("objects_to_delete.txt", name_only=True)
    if not objects_to_replace:
        print("No objects specified for replacement.")
        return None
    
    report = {
        "successful": [],
        "failed": []
    }
    
    # Read replacement values from new_objects.txt
    replacements = read_objects_file("new_objects.txt")
    if not replacements:
        print("No replacements provided in 'new_objects.txt'. Exiting replacement process.")
        return None
    
    # Convert replacements to a dictionary for quick lookup
    replacement_dict = dict(replacements)
    
    # Process each object
    print("\nReplacing object values using 'new_objects.txt'...")
    headers = {"X-PAN-KEY": api_key}
    for name in objects_to_replace:
        if name not in replacement_dict:
            report["failed"].append(f"'{name}' not updated: no replacement value found in new_objects.txt")
            print(f"Skipping '{name}': no replacement value found in new_objects.txt.")
            continue
        
        new_value = replacement_dict[name]
        if not check_object_exists(api_key, api_url, name):
            report["failed"].append(f"'{name}' not updated: not found on firewall")
            print(f"Object '{name}' not found on firewall. Skipping.")
            continue
        
        if update_object_value(api_key, api_url, name, new_value):
            report["successful"].append(f"'{name}' updated to '{new_value}'")
        else:
            report["failed"].append(f"'{name}' not updated due to error")
    
    if report["successful"]:
        commit_url = f"{api_url}?type=commit&cmd=<commit></commit>"
        try:
            commit_response = requests.post(commit_url, headers=headers, verify=False, timeout=10)
            commit_response.raise_for_status()
            print("Replacements committed successfully.")
        except requests.RequestException as e:
            print(f"Commit failed: {e}")
            report["failed"].extend([f"'{name}' update not committed due to commit failure: {str(e)}" for name in objects_to_replace if name in [entry.split("'")[1] for entry in report["successful"]]])
    
    return report

# Restore a running configuration from a file
def restore_running_config(api_key, api_url):
    try:
        config_file = input("\nEnter the path to the configuration file (e.g., FW01_cfg_202401011200.xml): ").strip()
        if not os.path.exists(config_file):
            print(f"Error: Configuration file '{config_file}' not found.")
            return None
        
        # Step 1: Upload the configuration file
        headers = {"X-PAN-KEY": api_key}
        files = {'file': open(config_file, 'rb')}
        upload_url = f"{api_url}?type=import&category=configuration"
        try:
            response = requests.post(upload_url, headers=headers, files=files, verify=False, timeout=30)
            response.raise_for_status()
            print(f"Uploaded configuration file '{config_file}' successfully.")
        except requests.RequestException as e:
            print(f"Failed to upload configuration file: {e}")
            return None
        finally:
            files['file'].close()
        
        # Step 2: Load the configuration
        filename = os.path.basename(config_file)
        load_url = f"{api_url}?type=op&cmd=<load><config><from>{filename}</from></config></load>"
        try:
            response = requests.get(load_url, headers=headers, verify=False, timeout=30)
            response.raise_for_status()
            print(f"Loaded configuration from '{filename}' successfully.")
        except requests.RequestException as e:
            print(f"Failed to load configuration: {e}")
            return None
        
        # Step 3: Commit the loaded configuration
        commit_url = f"{api_url}?type=commit&cmd=<commit></commit>"
        try:
            response = requests.post(commit_url, headers=headers, verify=False, timeout=30)
            response.raise_for_status()
            print("Configuration committed successfully.")
        except requests.RequestException as e:
            print(f"Commit failed: {e}")
            return None
        
        return {"successful": [f"Restored configuration from '{filename}'"], "failed": []}

    except Exception as e:
        print(f"Error during restore: {e}")
        return None

# Generate and append report to a single audit file with timestamp
def generate_report(report, total_objects, total_groups, operation="update"):
    if not report:
        print(f"No {operation} report to generate.")
        return
    
    # Use a single audit report file and append mode
    report_file = "audit_report.txt"
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    # Prepare the report content
    report_content = []
    report_content.append(f"{timestamp}")
    report_content.append(f"{operation.capitalize()} Report (Script Version: {SCRIPT_VERSION})")
    report_content.append("=" * 10)
    report_content.append("")
    report_content.append(f"Total Objects Discovered: {total_objects} address objects, {total_groups} address groups")
    report_content.append("")
    report_content.append(f"Successfully {operation.capitalize()}d Objects:")
    for item in report.get("successful", []):
        report_content.append(f"  - {item}")
    report_content.append("")
    if report.get("failed", []):
        report_content.append(f"Failed {operation.capitalize()}s:")
        for item in report.get("failed", []):
            report_content.append(f"  - {item}")
    report_content.append("")
    report_content.append("=" * 50)
    report_content.append("")
    
    # Append to the audit report file
    with open(report_file, "a") as f:
        f.write("\n".join(report_content))
    
    # Print the report to console
    print("\n".join(report_content))
    print(f"Audit report appended to '{report_file}'.")

# Prompt to confirm downloading running configuration with y/Y/n/N support
def confirm_download_config():
    while True:
        try:
            response = input("\nWould you like to backup the current running configuration? (Yes/No): ").strip()
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

# Prompt to confirm if new_objects.txt and old_objects.txt are synced
def confirm_files_synced():
    while True:
        try:
            response = input("\nHave the new_objects.txt and old_objects.txt files been updated and synced with the running-config object store? (Yes/No): ").strip()
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

# Prompt to confirm restore during countdown with y/Y/n/N support
def confirm_restore():
    while True:
        try:
            response = input("\nDo you want to restore a running configuration? (Yes/No): ").strip()
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

# Prompt to confirm exit with y/Y/n/N support
def confirm_exit():
    while True:
        try:
            response = input("\nDo you want to exit now? (Yes/No): ").strip()
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

# Countdown timer for exit
def exit_countdown():
    total_seconds = 10 * 60  # 10 minutes in seconds
    print("\nStarting 10-minute countdown. Press Enter to interrupt and continue...")
    start_time = time.time()
    while total_seconds > 0:
        if msvcrt.kbhit():
            char = msvcrt.getch().decode('utf-8')
            if char == '\r':  # Enter key
                print("\nCountdown interrupted. Returning to menu.")
                return
        elapsed_time = time.time() - start_time
        remaining_seconds = max(0, 10 * 60 - int(elapsed_time))
        minutes = remaining_seconds // 60
        seconds = remaining_seconds % 60
        print(f"\rExiting in {minutes:02d}:{seconds:02d}...", end='', flush=True)
        time.sleep(1)
        total_seconds -= 1
    print("\nExiting now.")
    exit(0)

# Display menu and get user selection (reverted to 1.5.3 structure)
def display_menu():
    print("\nWhat do you want to do now? (Enter the number to select an option):")
    print("1. Backup running configuration")
    print("2. Delete objects")
    print("3. Replace objects")
    print("4. Add new objects or object groups")
    print("5. Restore running configuration")
    print("6. Exit")
    
    while True:
        try:
            choice = input("Enter your choice (1-6): ").strip()
            if choice in ['1', '2', '3', '4', '5', '6']:
                return int(choice)
            else:
                print("Invalid choice. Please enter a number between 1 and 6.")
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

# Download running configuration with hostname and timestamp (filename <= 32 characters)
def download_running_config(api_key, api_url):
    hostname = get_firewall_hostname(api_key, api_url)
    timestamp = time.strftime("%Y%m%d%H%M", time.localtime())
    
    # Base filename format: <hostname>_cfg_<timestamp>.xml
    # Example: FW01_cfg_202401011200.xml (25 characters)
    # Max length: 32 characters
    base_filename = f"{hostname}_cfg_{timestamp}.xml"
    if len(base_filename) > 32:
        # Truncate hostname to fit within 32 characters
        max_hostname_len = 32 - len(f"_cfg_{timestamp}.xml")
        hostname = hostname[:max_hostname_len]
        base_filename = f"{hostname}_cfg_{timestamp}.xml"
    
    url = f"{api_url}?type=export&category=configuration"
    headers = {"X-PAN-KEY": api_key}
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=30)
        response.raise_for_status()
        with open(base_filename, "wb") as f:
            f.write(response.content)
        print(f"Running configuration downloaded successfully as '{base_filename}'.")
        
        # Perform a commit after successful download
        commit_url = f"{api_url}?type=commit&cmd=<commit></commit>"
        try:
            commit_response = requests.post(commit_url, headers=headers, verify=False, timeout=30)
            commit_response.raise_for_status()
            print("Configuration committed successfully after backup.")
        except requests.RequestException as e:
            print(f"Warning: Commit after backup failed: {e}. Proceeding without committing.")
    
    except requests.RequestException as e:
        print(f"Failed to download running configuration: {e}")

# Main execution
def main():
    try:
        print(f"Script Version: {SCRIPT_VERSION}")
        host = get_host()
        username, password = get_credentials()
        api_key, api_url = get_api_key(host, username, password)
        print(f"Connected to device at {host}")

        total_objects, total_groups = 0, 0  # Used for reporting
        while True:
            choice = display_menu()
            
            if choice == 1:  # Backup running configuration
                if confirm_download_config():
                    download_running_config(api_key, api_url)
            
            elif choice == 2:  # Delete objects
                deletion_report = delete_address_objects(api_key, api_url)
                if deletion_report:
                    generate_report(deletion_report, total_objects, total_groups, operation="deletion")
            
            elif choice == 3:  # Replace objects
                replacement_report = replace_object_values(api_key, api_url)
                if replacement_report:
                    generate_report(replacement_report, total_objects, total_groups, operation="replacement")
            
            elif choice == 4:  # Add new objects or object groups
                add_report = add_objects_or_groups(api_key, api_url)
                if add_report:
                    generate_report(add_report, total_objects, total_groups, operation="add")
            
            elif choice == 5:  # Restore running configuration
                restore_report = restore_running_config(api_key, api_url)
                if restore_report:
                    generate_report(restore_report, total_objects, total_groups, operation="restore")
            
            elif choice == 6:  # Exit
                print("\nStarting 10-minute countdown before exiting...")
                restored = restore_countdown(api_key, api_url)
                if not restored:
                    print("Exiting now.")
                    exit(0)

    except KeyboardInterrupt:
        print("\nOperation cancelled by user (Ctrl+C). Exiting.")
        exit(0)
    except requests.RequestException as e:
        print(f"Error: {e}")
    except ET.ParseError as e:
        print(f"XML Parse Error: {e}")
    except Exception as e:
        print(f"Unexpected Error: {e}")

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()