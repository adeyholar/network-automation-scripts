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
try:
    import msvcrt  # Windows console; the countdown falls back to a plain timer elsewhere
except ImportError:
    msvcrt = None
import argparse
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
from panos_safety import (configure_tls, tls_verify, remove_object_from_rule,
                          commit_own_changes)

ADMIN_USER = None   # admin whose changes a partial commit includes
DRY_RUN = False     # --dry-run: list changes, make no API writes
import csv

# Script version
SCRIPT_VERSION = "1.5.20"

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
# 1.5.11 - Added new menu option to create or update objects in batches from a file, allowing efficient processing of large object sets with format validation, updates, and commits
# 1.5.12 - Updated script to support certificate-based API authentication to address deprecated KeyGen algorithm warning; added fallback warning for users who have not configured API key certificates
# 1.5.13 - Updated restore_running_config to ensure the imported running configuration is explicitly loaded and committed into the firewall's live configuration
# 1.5.14 - Added functionality to pull all firewall policies via API and output them to a CSV file for easy analysis
# 1.5.15 - Added functionality to pull dynamic and static routing configurations via API and output them to separate CSV files for comprehensive network analysis
# 1.5.16 - Added a dedicated menu option to export only routing configurations (static and dynamic) to CSV files, providing more flexibility in output selection
# 1.5.17 - Updated script filename versioning to reset to v1 each day and increment within the day, appending the current date in MMDDYYYY format, as per the specified requirements
# 1.5.18 - Added functionality to pull the 'default' virtual router configuration via API and output it to a CSV file for detailed analysis
# 1.5.19 - Fixed SyntaxError in main() function by completing the try-except block and ensuring proper function call syntax
# 1.5.20 - Safety fixes: TLS verification on by default (--insecure / NET_SCRIPTS_* env), --dry-run, backups never commit, commits are partial (own admin only) after typed confirmation, deleting an object removes it from rules instead of deleting rules, Ctrl+C during the exit countdown returns to the menu, keygen uses POST

# Ask the operator to type 'commit' before a partial commit of their own changes
def confirm_partial_commit(admin):
    try:
        answer = input(f"\nCommit ONLY changes made by admin '{admin}' (partial commit)? Type 'commit' to confirm: ").strip()
    except KeyboardInterrupt:
        print("\nCommit cancelled.")
        return False
    return answer.lower() == "commit"

def commit_my_changes(host, cert_files, api_key=None):
    global ADMIN_USER
    if DRY_RUN:
        print("[dry-run] no commit.")
        return False
    if not ADMIN_USER:
        try:
            ADMIN_USER = input("\nAdmin username whose changes should be committed (blank to skip): ").strip() or None
        except KeyboardInterrupt:
            return False
    return commit_own_changes(host, cert_files, api_key, ADMIN_USER, confirm_partial_commit)

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

# Prompt for credentials with obscured password (used only for deprecated method)
def get_credentials():
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    return username, password

# Prompt for certificate and key files
def get_certificate_files():
    cert_file = input("Enter the path to the client certificate file (e.g., api_cert.pem, or press Enter to use deprecated method): ").strip()
    key_file = input("Enter the path to the private key file (e.g., api_key.key, or press Enter to use deprecated method): ").strip()
    
    if not cert_file or not key_file:
        print("Warning: Using deprecated API KeyGen method. Configure API key certificate on the firewall for secure access.")
        print("Web Interface: Setup -> Management -> Authentication Settings -> API Key Certificate")
        print("CLI: set deviceconfig setting management api key certificate")
        return None
    
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print(f"Error: Certificate file '{cert_file}' or key file '{key_file}' not found. Falling back to deprecated method.")
        return None
    
    return (cert_file, key_file)

# Generate API key using deprecated method (fallback)
def get_api_key(host, username, password):
    api_url = f"https://{host}/api/"
    # POST keeps the password out of the URL (and out of logs and error messages).
    try:
        response = requests.post(api_url, data={"type": "keygen", "user": username, "password": password},
                                 verify=tls_verify(), timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        status = getattr(getattr(e, "response", None), "status_code", None)
        raise requests.RequestException(f"API key request failed ({type(e).__name__}, HTTP {status})") from None
    root = ET.fromstring(response.text)
    key = root.find(".//key").text
    return key, api_url

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
def check_object_exists(host, cert_files, object_name, api_key=None):
    api_url = f"https://{host}/api/"
    url = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{object_name}']"
    
    if cert_files:
        response = requests.get(url, cert=cert_files, verify=tls_verify(), timeout=10)
    else:
        headers = {"X-PAN-KEY": api_key}
        response = requests.get(url, headers=headers, verify=tls_verify(), timeout=10)
    
    response.raise_for_status()
    root = ET.fromstring(response.text)
    return root.find(".//entry") is not None

# Check if an address object group exists on the firewall
def check_group_exists(host, cert_files, group_name, api_key=None):
    api_url = f"https://{host}/api/"
    url = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='{group_name}']"
    
    if cert_files:
        response = requests.get(url, cert=cert_files, verify=tls_verify(), timeout=10)
    else:
        headers = {"X-PAN-KEY": api_key}
        response = requests.get(url, headers=headers, verify=tls_verify(), timeout=10)
    
    response.raise_for_status()
    root = ET.fromstring(response.text)
    return root.find(".//entry") is not None

# Check if an address object is used in policies, NAT rules, or address groups
def check_object_usage(host, cert_files, object_name, api_key=None):
    api_url = f"https://{host}/api/"
    usage = {
        "security_policies": [],
        "nat_rules": [],
        "address_groups": []
    }
    
    # Check security policies
    url_policies = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules"
    try:
        if cert_files:
            response = requests.get(url_policies, cert=cert_files, verify=tls_verify(), timeout=10)
        else:
            headers = {"X-PAN-KEY": api_key}
            response = requests.get(url_policies, headers=headers, verify=tls_verify(), timeout=10)
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
        if cert_files:
            response = requests.get(url_nat, cert=cert_files, verify=tls_verify(), timeout=10)
        else:
            headers = {"X-PAN-KEY": api_key}
            response = requests.get(url_nat, headers=headers, verify=tls_verify(), timeout=10)
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
        if cert_files:
            response = requests.get(url_groups, cert=cert_files, verify=tls_verify(), timeout=10)
        else:
            headers = {"X-PAN-KEY": api_key}
            response = requests.get(url_groups, headers=headers, verify=tls_verify(), timeout=10)
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
def remove_object_from_group(host, cert_files, object_name, group_name, api_key=None):
    api_url = f"https://{host}/api/"
    url = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='{group_name}']"
    
    if cert_files:
        response = requests.get(url, cert=cert_files, verify=tls_verify(), timeout=10)
    else:
        headers = {"X-PAN-KEY": api_key}
        response = requests.get(url, headers=headers, verify=tls_verify(), timeout=10)
    
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
    
    if DRY_RUN:
        print(f"[dry-run] would remove '{object_name}' from address group '{group_name}'")
        return True
    
    # Update the address group
    edit_url = f"{api_url}?type=config&action=edit&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='{group_name}']&element={quote(xml_data)}"
    if cert_files:
        response = requests.post(edit_url, cert=cert_files, verify=tls_verify(), timeout=10)
    else:
        headers = {"X-PAN-KEY": api_key}
        response = requests.post(edit_url, headers=headers, verify=tls_verify(), timeout=10)
    
    response.raise_for_status()
    print(f"Removed '{object_name}' from address group '{group_name}'")
    return True

# Update or create an object
def update_or_create_object(host, cert_files, object_name, value, api_key=None):
    api_url = f"https://{host}/api/"
    address_type = validate_address_type(value)
    if not address_type:
        print(f"Invalid value format for '{object_name}': '{value}'")
        return False
    
    xml_data = f"""
    <entry name='{object_name}'>
        <{address_type}>{value}</{address_type}>
    </entry>
    """
    
    # Check if the object exists to decide between update or create
    if check_object_exists(host, cert_files, object_name, api_key):
        # Update existing object
        url = f"{api_url}?type=config&action=edit&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{object_name}']&element={quote(xml_data)}"
        action = "updated"
    else:
        # Create new object
        url = f"{api_url}?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address&element={quote(xml_data)}"
        action = "created"
    
    if DRY_RUN:
        print(f"[dry-run] object '{object_name}' would be {action} with value '{value}'")
        return True
    try:
        if cert_files:
            response = requests.post(url, cert=cert_files, verify=tls_verify(), timeout=10)
        else:
            headers = {"X-PAN-KEY": api_key}
            response = requests.post(url, headers=headers, verify=tls_verify(), timeout=10)
        response.raise_for_status()
        print(f"Object '{object_name}' {action} with value '{value}'")
        return True
    except requests.RequestException as e:
        print(f"Failed to {action} object '{object_name}': {e}")
        return False

# Add a new object or object group
def add_objects_or_groups(host, cert_files, api_key=None):
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
    
    while True:
        try:
            # Only adding objects (not groups) as per requirement
            name = input("\nEnter the object name: ").strip()
            if not name:
                print("Object name cannot be empty.")
                continue
            if check_object_exists(host, cert_files, name, api_key):
                print(f"Object '{name}' already exists. Skipping.")
                report["failed"].append(f"'{name}' not added: already exists")
                continue
            
            value = input("Enter the object value (e.g., 192.0.2.99/32, example.com): ").strip()
            address_type = validate_address_type(value)
            if not address_type:
                print(f"Invalid value format for '{name}': '{value}'")
                report["failed"].append(f"'{name}' not added: invalid value format")
                continue
            
            if update_or_create_object(host, cert_files, name, value, api_key):
                report["successful"].append(f"Added object '{name}' with value '{value}'")
        
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
                        if not commit_my_changes(host, cert_files, api_key):
                            report["failed"].append("Changes not committed; they remain in the candidate configuration.")
                    return report
                elif done_response_lower in ['n', 'no']:
                    break  # Continue adding more objects
                else:
                    print("Please enter 'Y', 'y', 'Yes', 'N', 'n', or 'No'.")
            except KeyboardInterrupt:
                print("\nOperation cancelled by user (Ctrl+C). Exiting.")
                exit(0)

# Delete address objects. Referencing rules are edited (object removed as a member), never deleted.
def delete_batch_objects(host, cert_files, object_names, usage_dict, api_key=None):
    if not object_names:
        return [], []
    
    api_url = f"https://{host}/api/"
    successes = []
    failures = []
    
    prefix = "[dry-run] " if DRY_RUN else ""
    print(f"\n{prefix}Processing batch of {len(object_names)} objects...")
    for name in object_names:
        if name not in usage_dict:
            continue  # not found on firewall; already reported
        usage = usage_dict.get(name, {})
        blocked = False
        # Remove from address groups
        for group_name in usage.get("address_groups", []):
            if not remove_object_from_group(host, cert_files, name, group_name, api_key):
                failures.append(f"'{name}' not deleted: could not remove it from address group '{group_name}'")
                blocked = True
        
        # Remove the object from referencing rules (the rules themselves are kept)
        for rule_type, key in (("security", "security_policies"), ("nat", "nat_rules")):
            for rule_name in usage.get(key, []):
                try:
                    ok = remove_object_from_rule(host, cert_files, api_key, rule_type, rule_name, name, dry_run=DRY_RUN)
                except (requests.RequestException, ET.ParseError) as e:
                    print(f"Failed to update {rule_type} rule '{rule_name}': {e}")
                    ok = False
                if not ok:
                    failures.append(f"'{name}' not deleted: still referenced by {rule_type} rule '{rule_name}'")
                    blocked = True
        
        if blocked:
            print(f"Skipping deletion of '{name}' because it is still referenced.")
            continue
        
        # Delete the object
        if DRY_RUN:
            print(f"[dry-run] would delete address object '{name}'")
            successes.append(f"'{name}' would be deleted (dry-run)")
            continue
        url = f"{api_url}?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{name}']"
        try:
            if cert_files:
                response = requests.get(url, cert=cert_files, verify=tls_verify(), timeout=10)
            else:
                headers = {"X-PAN-KEY": api_key}
                response = requests.get(url, headers=headers, verify=tls_verify(), timeout=10)
            response.raise_for_status()
            successes.append(f"'{name}' deleted")
            print(f"Deleted '{name}'")
        except requests.RequestException as e:
            failures.append(f"'{name}' not deleted due to error: {str(e)}")
            print(f"Failed to delete '{name}': {str(e)}")
    
    if successes and not DRY_RUN:
        if not commit_my_changes(host, cert_files, api_key):
            failures.append("Changes not committed; they remain in the candidate configuration.")
    
    return successes, failures

# Delete specified address objects after listing affected policies
def delete_address_objects(host, cert_files, api_key=None):
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
        if not check_object_exists(host, cert_files, name, api_key):
            report["failed"].append(f"'{name}' not deleted: not found on firewall")
            print(f"Object '{name}' not found on firewall. Skipping.")
            continue
        
        usage = check_object_usage(host, cert_files, name, api_key)
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
    successes, failures = delete_batch_objects(host, cert_files, objects_to_delete, usage_dict, api_key)
    report["successful"].extend(successes)
    report["failed"].extend(failures)
    
    return report

# Replace old object values with new ones using new_objects.txt
def replace_object_values(host, cert_files, api_key=None):
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
    for name in objects_to_replace:
        if name not in replacement_dict:
            report["failed"].append(f"'{name}' not updated: no replacement value found in new_objects.txt")
            print(f"Skipping '{name}': no replacement value found in new_objects.txt.")
            continue
        
        new_value = replacement_dict[name]
        if not check_object_exists(host, cert_files, name, api_key):
            report["failed"].append(f"'{name}' not updated: not found on firewall")
            print(f"Object '{name}' not found on firewall. Skipping.")
            continue
        
        if update_or_create_object(host, cert_files, name, new_value, api_key):
            report["successful"].append(f"'{name}' updated to '{new_value}'")
        else:
            report["failed"].append(f"'{name}' not updated due to error")
    
    if report["successful"]:
        if not commit_my_changes(host, cert_files, api_key):
            report["failed"].append("Changes not committed; they remain in the candidate configuration.")
    
    return report

# Create or update objects in batch from file
def batch_create_or_update_objects(host, cert_files, api_key=None):
    # Prompt to confirm if new_objects_batch.txt is populated and correctly formatted
    while True:
        try:
            response = input("\nIs the new_objects_batch.txt file populated with objects in the correct format (name,value per line, e.g., obj1,192.0.2.11/32)? (Yes/No): ").strip()
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
    
    objects_to_process = read_objects_file("new_objects_batch.txt")
    if not objects_to_process:
        print("No objects specified in 'new_objects_batch.txt'.")
        return None
    
    report = {
        "successful": [],
        "failed": []
    }
    
    print(f"\nProcessing batch of {len(objects_to_process)} objects from 'new_objects_batch.txt'...")
    for name, value in objects_to_process:
        if update_or_create_object(host, cert_files, name, value, api_key):
            report["successful"].append(f"Object '{name}' processed with value '{value}'")
        else:
            report["failed"].append(f"Object '{name}' failed to process with value '{value}'")
    
    # Commit changes if there are successful operations
    if report["successful"]:
        if not commit_my_changes(host, cert_files, api_key):
            report["failed"].append("Changes not committed; they remain in the candidate configuration.")
    
    return report

# Restore a running configuration from a file
def restore_running_config(host, cert_files, api_key=None):
    try:
        config_file = input("\nEnter the path to the configuration file (e.g., FW01_cfg_202401011200.xml): ").strip()
        if not os.path.exists(config_file):
            print(f"Error: Configuration file '{config_file}' not found.")
            return None
        
        if DRY_RUN:
            print(f"[dry-run] would import and load '{config_file}' into the candidate configuration.")
            return None
        api_url = f"https://{host}/api/"
        
        # Step 1: Import the configuration file to the firewall
        print("\nStep 1: Importing the configuration file to the firewall...")
        upload_url = f"{api_url}?type=import&category=configuration"
        files = {'file': open(config_file, 'rb')}
        try:
            if cert_files:
                response = requests.post(upload_url, files=files, cert=cert_files, verify=tls_verify(), timeout=30)
            else:
                headers = {"X-PAN-KEY": api_key}
                response = requests.post(upload_url, headers=headers, files=files, verify=tls_verify(), timeout=30)
            response.raise_for_status()
            print(f"Successfully imported configuration file '{config_file}' to the firewall.")
        except requests.RequestException as e:
            print(f"Failed to import configuration file: {e}")
            return None
        finally:
            files['file'].close()
        
        # Step 2: Load the imported configuration into the candidate configuration
        print("\nStep 2: Loading the imported configuration into the candidate configuration...")
        filename = os.path.basename(config_file)
        load_url = f"{api_url}?type=op&cmd=<load><config><from>{filename}</from></config></load>"
        try:
            if cert_files:
                response = requests.get(load_url, cert=cert_files, verify=tls_verify(), timeout=30)
            else:
                headers = {"X-PAN-KEY": api_key}
                response = requests.get(load_url, headers=headers, verify=tls_verify(), timeout=30)
            response.raise_for_status()
            print(f"Successfully loaded configuration from '{filename}' into the candidate configuration.")
        except requests.RequestException as e:
            print(f"Failed to load configuration: {e}")
            return None
        
        # Step 3: Optionally commit (partial, your admin only) after explicit confirmation
        print("\nStep 3: Commit is optional and limited to your own admin changes.")
        if not commit_my_changes(host, cert_files, api_key):
            print("Restored config is loaded in the candidate configuration but NOT committed.")
            return {"successful": [f"Loaded configuration from '{filename}' into the candidate configuration (not committed)"], "failed": []}
        
        return {"successful": [f"Restored and loaded configuration from '{filename}' into live configuration"], "failed": []}

    except Exception as e:
        print(f"Error during restore: {e}")
        return None

# Export firewall policies to a CSV file
def export_firewall_policies_only(host, cert_files, api_key=None):
    # Generate a timestamp for the filename
    timestamp = time.strftime("%Y%m%d_%H%M")
    
    # Call the existing export_firewall_policies function
    return export_firewall_policies(host, cert_files, api_key, timestamp)

# Export firewall policies to a CSV file (core function)
def export_firewall_policies(host, cert_files, api_key=None, timestamp=None):
    api_url = f"https://{host}/api/"
    url = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules"
    
    # Fetch the policies
    try:
        if cert_files:
            response = requests.get(url, cert=cert_files, verify=tls_verify(), timeout=10)
        else:
            headers = {"X-PAN-KEY": api_key}
            response = requests.get(url, headers=headers, verify=tls_verify(), timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Failed to retrieve firewall policies: {e}")
        return False
    
    root = ET.fromstring(response.text)
    policies = []
    
    # Extract policy details
    for policy in root.findall(".//entry"):
        policy_data = {}
        policy_data["Policy Name"] = policy.get("name", "N/A")
        
        # Source Zone
        source_zone = policy.find("from")
        if source_zone is not None:
            source_zone_values = [member.text for member in source_zone.findall("member") if member.text]
            policy_data["Source Zone"] = ", ".join(source_zone_values) if source_zone_values else "any"
        else:
            policy_data["Source Zone"] = "any"
        
        # Destination Zone
        dest_zone = policy.find("to")
        if dest_zone is not None:
            dest_zone_values = [member.text for member in dest_zone.findall("member") if member.text]
            policy_data["Destination Zone"] = ", ".join(dest_zone_values) if dest_zone_values else "any"
        else:
            policy_data["Destination Zone"] = "any"
        
        # Source Address
        source_addr = policy.find("source")
        if source_addr is not None:
            source_addr_values = [member.text for member in source_addr.findall("member") if member.text]
            policy_data["Source Address"] = ", ".join(source_addr_values) if source_addr_values else "any"
        else:
            policy_data["Source Address"] = "any"
        
        # Destination Address
        dest_addr = policy.find("destination")
        if dest_addr is not None:
            dest_addr_values = [member.text for member in dest_addr.findall("member") if member.text]
            policy_data["Destination Address"] = ", ".join(dest_addr_values) if dest_addr_values else "any"
        else:
            policy_data["Destination Address"] = "any"
        
        # Service
        service = policy.find("service")
        if service is not None:
            service_values = [member.text for member in service.findall("member") if member.text]
            policy_data["Service"] = ", ".join(service_values) if service_values else "any"
        else:
            policy_data["Service"] = "any"
        
        # Application
        application = policy.find("application")
        if application is not None:
            app_values = [member.text for member in application.findall("member") if member.text]
            policy_data["Application"] = ", ".join(app_values) if app_values else "any"
        else:
            policy_data["Application"] = "any"
        
        # Action
        action = policy.find("action")
        policy_data["Action"] = action.text if action is not None and action.text else "N/A"
        
        # Description
        description = policy.find("description")
        policy_data["Description"] = description.text if description is not None and description.text else ""
        
        policies.append(policy_data)
    
    if not policies:
        print("No firewall policies found.")
        return False
    
    # Generate CSV filename with timestamp
    csv_filename = f"firewall_policies_{timestamp}.csv"
    
    # Define CSV headers
    headers = ["Policy Name", "Source Zone", "Destination Zone", "Source Address", "Destination Address", "Service", "Application", "Action", "Description"]
    
    # Write to CSV
    try:
        print(f"Exporting firewall policies to '{csv_filename}'...")
        with open(csv_filename, mode='w', newline='', encoding='utf-8') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=headers)
            writer.writeheader()
            for policy in policies:
                writer.writerow(policy)
        print(f"Successfully exported {len(policies)} firewall policies to '{csv_filename}'.")
        return True
    except Exception as e:
        print(f"Failed to export firewall policies to CSV: {e}")
        return False

# Export static routes to a CSV file
def export_static_routes(host, cert_files, api_key=None, timestamp=None):
    api_url = f"https://{host}/api/"
    url = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/network/virtual-router/entry[@name='default']/routing-table/ip/static-route"
    
    # Fetch the static routes
    try:
        if cert_files:
            response = requests.get(url, cert=cert_files, verify=tls_verify(), timeout=10)
        else:
            headers = {"X-PAN-KEY": api_key}
            response = requests.get(url, headers=headers, verify=tls_verify(), timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Failed to retrieve static routes: {e}")
        return False
    
    root = ET.fromstring(response.text)
    routes = []
    
    # Extract static route details
    for route in root.findall(".//entry"):
        route_data = {}
        route_data["Route Name"] = route.get("name", "N/A")
        
        # Destination
        destination = route.find("destination")
        route_data["Destination"] = destination.text if destination is not None and destination.text else "N/A"
        
        # Nexthop
        nexthop = route.find("nexthop/ip-address")
        route_data["Nexthop"] = nexthop.text if nexthop is not None and nexthop.text else "N/A"
        
        # Interface
        interface = route.find("interface")
        route_data["Interface"] = interface.text if interface is not None and interface.text else "N/A"
        
        # Metric
        metric = route.find("metric")
        route_data["Metric"] = metric.text if metric is not None and metric.text else "N/A"
        
        routes.append(route_data)
    
    if not routes:
        print("No static routes found.")
        return False
    
    # Generate CSV filename with timestamp
    csv_filename = f"static_routes_{timestamp}.csv"
    
    # Define CSV headers
    headers = ["Route Name", "Destination", "Nexthop", "Interface", "Metric"]
    
    # Write to CSV
    try:
        print(f"Exporting static routes to '{csv_filename}'...")
        with open(csv_filename, mode='w', newline='', encoding='utf-8') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=headers)
            writer.writeheader()
            for route in routes:
                writer.writerow(route)
        print(f"Successfully exported {len(routes)} static routes to '{csv_filename}'.")
        return True
    except Exception as e:
        print(f"Failed to export static routes to CSV: {e}")
        return False

# Export dynamic routing configurations to a CSV file
def export_dynamic_routing(host, cert_files, api_key=None, timestamp=None):
    api_url = f"https://{host}/api/"
    url = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/network/virtual-router/entry[@name='default']/protocol"
    
    # Fetch the dynamic routing protocols
    try:
        if cert_files:
            response = requests.get(url, cert=cert_files, verify=tls_verify(), timeout=10)
        else:
            headers = {"X-PAN-KEY": api_key}
            response = requests.get(url, headers=headers, verify=tls_verify(), timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Failed to retrieve dynamic routing configurations: {e}")
        return False
    
    root = ET.fromstring(response.text)
    routing_data = []
    
    # Extract OSPF details
    ospf = root.find("ospf")
    if ospf is not None:
        for area in ospf.findall(".//area"):
            area_id = area.get("id", "N/A")
            for neighbor in area.findall(".//neighbor"):
                neighbor_data = {}
                neighbor_data["Protocol"] = "OSPF"
                neighbor_data["Area"] = area_id
                neighbor_data["Neighbor"] = neighbor.get("address", "N/A")
                neighbor_data["Status"] = neighbor.find("state").text if neighbor.find("state") is not None else "N/A"
                routing_data.append(neighbor_data)
    
    # Extract BGP details
    bgp = root.find("bgp")
    if bgp is not None:
        for peer in bgp.findall(".//peer"):
            peer_data = {}
            peer_data["Protocol"] = "BGP"
            peer_data["Area"] = "N/A"
            peer_data["Neighbor"] = peer.find("peer-address/ip").text if peer.find("peer-address/ip") is not None else "N/A"
            peer_data["Status"] = peer.find("peer-status").text if peer.find("peer-status") is not None else "N/A"
            routing_data.append(peer_data)
    
    if not routing_data:
        print("No dynamic routing configurations found.")
        return False
    
    # Generate CSV filename with timestamp
    csv_filename = f"dynamic_routing_{timestamp}.csv"
    
    # Define CSV headers
    headers = ["Protocol", "Area", "Neighbor", "Status"]
    
    # Write to CSV
    try:
        print(f"Exporting dynamic routing configurations to '{csv_filename}'...")
        with open(csv_filename, mode='w', newline='', encoding='utf-8') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=headers)
            writer.writeheader()
            for data in routing_data:
                writer.writerow(data)
        print(f"Successfully exported dynamic routing configurations to '{csv_filename}'.")
        return True
    except Exception as e:
        print(f"Failed to export dynamic routing configurations to CSV: {e}")
        return False

# Export only routing configurations (static and dynamic) to CSV files
def export_routing_configurations(host, cert_files, api_key=None):
    # Generate a timestamp for consistent filenames
    timestamp = time.strftime("%Y%m%d_%H%M")
    
    # Export static routes
    export_static_routes(host, cert_files, api_key, timestamp)
    
    # Export dynamic routing configurations
    export_dynamic_routing(host, cert_files, api_key, timestamp)

# Export the 'default' virtual router configuration to a CSV file
def export_default_virtual_router_config(host, cert_files, api_key=None):
    api_url = f"https://{host}/api/"
    url = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/network/virtual-router/entry[@name='default']"
    
    # Fetch the virtual router configuration
    try:
        if cert_files:
            response = requests.get(url, cert=cert_files, verify=tls_verify(), timeout=10)
        else:
            headers = {"X-PAN-KEY": api_key}
            response = requests.get(url, headers=headers, verify=tls_verify(), timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Failed to retrieve 'default' virtual router configuration: {e}")
        return False
    
    root = ET.fromstring(response.text)
    config_data = []
    
    # Extract interfaces
    interfaces = root.find("interface")
    if interfaces is not None:
        for member in interfaces.findall("member"):
            interface_name = member.text if member.text else "N/A"
            config_data.append({
                "Category": "Interface",
                "Field": interface_name,
                "Value": "Enabled"
            })
    
    # Extract protocol settings (OSPF, BGP, etc.)
    protocol = root.find("protocol")
    if protocol is not None:
        # OSPF
        ospf = protocol.find("ospf")
        if ospf is not None:
            for area in ospf.findall(".//area"):
                area_id = area.get("id", "N/A")
                for neighbor in area.findall(".//neighbor"):
                    neighbor_address = neighbor.get("address", "N/A")
                    status = neighbor.find("state").text if neighbor.find("state") is not None else "N/A"
                    config_data.append({
                        "Category": "Protocol",
                        "Field": f"OSPF Area {area_id} Neighbor {neighbor_address}",
                        "Value": status
                    })
        
        # BGP
        bgp = protocol.find("bgp")
        if bgp is not None:
            for peer in bgp.findall(".//peer"):
                peer_address = peer.find("peer-address/ip").text if peer.find("peer-address/ip") is not None else "N/A"
                status = peer.find("peer-status").text if peer.find("peer-status") is not None else "N/A"
                config_data.append({
                    "Category": "Protocol",
                    "Field": f"BGP Peer {peer_address}",
                    "Value": status
                })
    
    # Extract administrative distances
    admin_dists = root.find("admin-dists")
    if admin_dists is not None:
        for dist in admin_dists:
            dist_name = dist.tag
            dist_value = dist.text if dist.text else "N/A"
            config_data.append({
                "Category": "Admin Distance",
                "Field": dist_name.capitalize(),
                "Value": dist_value
            })
    
    # Extract redistribution profiles
    redist_profiles = root.find("redist-profile")
    if redist_profiles is not None:
        for profile in redist_profiles.findall("entry"):
            profile_name = profile.get("name", "N/A")
            action = profile.find("action").text if profile.find("action") is not None else "N/A"
            config_data.append({
                "Category": "Redistribution Profile",
                "Field": profile_name,
                "Value": action
            })
    
    if not config_data:
        print("No configuration data found for 'default' virtual router.")
        return False
    
    # Generate CSV filename with timestamp
    timestamp = time.strftime("%Y%m%d_%H%M")
    csv_filename = f"virtual_router_default_{timestamp}.csv"
    
    # Define CSV headers
    headers = ["Category", "Field", "Value"]
    
    # Write to CSV
    try:
        print(f"Exporting 'default' virtual router configuration to '{csv_filename}'...")
        with open(csv_filename, mode='w', newline='', encoding='utf-8') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=headers)
            writer.writeheader()
            for data in config_data:
                writer.writerow(data)
        print(f"Successfully exported 'default' virtual router configuration to '{csv_filename}'.")
        return True
    except Exception as e:
        print(f"Failed to export 'default' virtual router configuration to CSV: {e}")
        return False

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

# Countdown timer for exit.
# Returns True if the operator interrupted it (Enter or Ctrl+C): go back to the menu.
# Returns False when the countdown finishes: the caller exits.
def exit_countdown(total_seconds=10 * 60, sleep=time.sleep, clock=time.time):
    print(f"\nStarting {total_seconds // 60}-minute countdown. Press Enter or Ctrl+C to return to the menu...")
    start_time = clock()
    try:
        while True:
            if msvcrt is not None and msvcrt.kbhit():
                char = msvcrt.getch().decode('utf-8', errors='ignore')
                if char == '\r':  # Enter key
                    print("\nCountdown interrupted. Returning to menu.")
                    return True
            remaining_seconds = max(0, total_seconds - int(clock() - start_time))
            if remaining_seconds <= 0:
                break
            minutes, seconds = divmod(remaining_seconds, 60)
            print(f"\rExiting in {minutes:02d}:{seconds:02d}...", end='', flush=True)
            sleep(1)
    except KeyboardInterrupt:
        print("\nCountdown interrupted (Ctrl+C). Returning to menu.")
        return True
    return False

# Display menu and get user selection (updated with new option)
def display_menu():
    print("\nWhat do you want to do now? (Enter the number to select an option):")
    print("1. Backup running configuration")
    print("2. Delete objects")
    print("3. Replace objects")
    print("4. Add new objects interactively")
    print("5. Restore running configuration")
    print("6. Exit")
    print("7. Create or update objects in batch from file")
    print("8. Export firewall policies to CSV")
    print("9. Export routing configurations to CSV")
    print("10. Export default virtual router configuration to CSV")
    
    while True:
        try:
            choice = input("Enter your choice (1-10): ").strip()
            if choice in ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10']:
                return int(choice)
            else:
                print("Invalid choice. Please enter a number between 1 and 10.")
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

# Get firewall hostname
def get_firewall_hostname(host, cert_files, api_key=None):
    api_url = f"https://{host}/api/"
    url = f"{api_url}?type=op&cmd=<show><system><info></info></system></show>"
    try:
        if cert_files:
            response = requests.get(url, cert=cert_files, verify=tls_verify(), timeout=10)
        else:
            headers = {"X-PAN-KEY": api_key}
            response = requests.get(url, headers=headers, verify=tls_verify(), timeout=10)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        hostname = root.find(".//hostname").text
        return hostname
    except (requests.RequestException, AttributeError) as e:
        print(f"Failed to retrieve hostname: {e}. Using 'unknown' as prefix.")
        return "unknown"

# Download running configuration with hostname and timestamp (filename <= 32 characters)
def download_running_config(host, cert_files, api_key=None):
    hostname = get_firewall_hostname(host, cert_files, api_key)
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
    
    api_url = f"https://{host}/api/"
    url = f"{api_url}?type=export&category=configuration"
    try:
        if cert_files:
            response = requests.get(url, cert=cert_files, verify=tls_verify(), timeout=30)
        else:
            headers = {"X-PAN-KEY": api_key}
            response = requests.get(url, headers=headers, verify=tls_verify(), timeout=30)
        response.raise_for_status()
        with open(base_filename, "wb") as f:
            f.write(response.content)
        print(f"Running configuration downloaded successfully as '{base_filename}'.")
        
        print("Backup only: nothing was committed.")
    
    except requests.RequestException as e:
        print(f"Failed to download running configuration: {e}")

# Main execution
def main():
    global ADMIN_USER
    try:
        print(f"Script Version: {SCRIPT_VERSION}")
        host = get_host()
        
        # Prompt for certificate files
        cert_files = get_certificate_files()
        api_key = None
        if not cert_files:
            # Fallback to deprecated method
            username, password = get_credentials()
            api_key, _ = get_api_key(host, username, password)
            ADMIN_USER = username
        
        print(f"Connected to device at {host}")

        total_objects, total_groups = 0, 0  # Used for reporting
        while True:
            choice = display_menu()
            
            if choice == 1:  # Backup running configuration
                if confirm_download_config():
                    download_running_config(host, cert_files, api_key)
            
            elif choice == 2:  # Delete objects
                deletion_report = delete_address_objects(host, cert_files, api_key)
                if deletion_report:
                    generate_report(deletion_report, total_objects, total_groups, operation="deletion")
            
            elif choice == 3:  # Replace objects
                replacement_report = replace_object_values(host, cert_files, api_key)
                if replacement_report:
                    generate_report(replacement_report, total_objects, total_groups, operation="replacement")
            
            elif choice == 4:  # Add new objects interactively
                add_report = add_objects_or_groups(host, cert_files, api_key)
                if add_report:
                    generate_report(add_report, total_objects, total_groups, operation="add")
            
            elif choice == 5:  # Restore running configuration
                restore_report = restore_running_config(host, cert_files, api_key)
                if restore_report:
                    generate_report(restore_report, total_objects, total_groups, operation="restore")
            
            elif choice == 6:  # Exit
                print("\nStarting 10-minute countdown before exiting...")
                if exit_countdown():
                    continue  # interrupted: back to the menu
                print("\nExiting now.")
                exit(0)
            
            elif choice == 7:  # Create or update objects in batch
                batch_report = batch_create_or_update_objects(host, cert_files, api_key)
                if batch_report:
                    generate_report(batch_report, total_objects, total_groups, operation="batch_create_update")
            
            elif choice == 8:  # Export firewall policies to CSV
                export_firewall_policies_only(host, cert_files, api_key)
            
            elif choice == 9:  # Export routing configurations to CSV
                export_routing_configurations(host, cert_files, api_key)
            
            elif choice == 10:  # Export default virtual router configuration to CSV
                export_default_virtual_router_config(host, cert_files, api_key)

    except KeyboardInterrupt:
        print("\nOperation cancelled by user (Ctrl+C). Exiting.")
        exit(0)
    except requests.RequestException as e:
        print(f"Error: {e}")
    except ET.ParseError as e:
        print(f"XML Parse Error: {e}")
    except Exception as e:
        print(f"Unexpected Error: {e}")

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="PAN-OS config change CLI")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS certificate verification (lab only). Prefer NET_SCRIPTS_CA_BUNDLE.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would change; make no configuration writes or commits.")
    return parser.parse_args(argv)

if __name__ == "__main__":
    args = parse_args()
    DRY_RUN = args.dry_run
    if DRY_RUN:
        print("DRY-RUN mode: no configuration changes or commits will be made.")
    configure_tls(insecure=args.insecure)
    main()