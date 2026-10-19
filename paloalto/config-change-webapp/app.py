from flask import Flask, render_template, request, redirect, url_for
import requests
import xml.etree.ElementTree as ET
from urllib.parse import quote
import socket
import ssl
import time
import os
import re
import ipaddress

app = Flask(__name__)

# Script version
SCRIPT_VERSION = "1.0.1"

# Global variable to store output
output = []

# Helper function to append output
def append_output(message):
    output.append(message)

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

# Check if host is reachable on port 443 (HTTPS) with diagnostics
def is_host_reachable(host, port=443, timeout=10):
    try:
        ip = socket.gethostbyname(host)
        append_output(f"Resolved '{host}' to IP: {ip}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                ssl_sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
                result = ssl_sock.connect_ex((ip, port))
                if result == 0:
                    append_output(f"SSL connection to {host}:{port} succeeded.")
                    return True
                else:
                    append_output(f"SSL connection failed with error code {result}. Trying non-SSL connection...")
            except ssl.SSLError as e:
                append_output(f"SSL error: {e}. Falling back to non-SSL check.")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                append_output(f"Non-SSL connection to {host}:{port} succeeded.")
                return True
            else:
                append_output(f"Non-SSL connection failed with error code {result}.")
                return False
    except socket.gaierror as e:
        append_output(f"DNS resolution failed: {e}")
        return False
    except socket.timeout:
        append_output(f"Connection timed out after {timeout} seconds.")
        return False
    except Exception as e:
        append_output(f"Unexpected error during reachability check: {e}")
        return False

# Generate API key using deprecated method (fallback)
def get_api_key(host, username, password):
    api_url = f"https://{host}/api/"
    url = f"{api_url}?type=keygen&user={quote(username)}&password={quote(password)}"
    response = requests.get(url, verify=False, timeout=10)
    response.raise_for_status()
    root = ET.fromstring(response.text)
    key = root.find(".//key").text
    return key, api_url

# Read objects from a file (format: name only or name,value)
def read_objects_file(file_obj, name_only=False):
    objects = []
    try:
        content = file_obj.read().decode('utf-8').splitlines()
        for line in content:
            line = line.strip()
            if line:
                if name_only:
                    name = line.split(None, 1)[0]
                    objects.append(name)
                else:
                    if ',' in line:
                        name, value = line.split(',', 1)
                        objects.append((name, value))
                    else:
                        append_output(f"Skipping invalid line: {line}")
        return objects
    except Exception as e:
        append_output(f"Error reading file: {e}")
        return []

# Check if an address object exists on the firewall
def check_object_exists(host, cert_files, object_name, api_key=None):
    api_url = f"https://{host}/api/"
    url = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{object_name}']"
    
    if cert_files:
        response = requests.get(url, cert=cert_files, verify=False, timeout=10)
    else:
        headers = {"X-PAN-KEY": api_key}
        response = requests.get(url, headers=headers, verify=False, timeout=10)
    
    response.raise_for_status()
    root = ET.fromstring(response.text)
    return root.find(".//entry") is not None

# Check if an address object group exists on the firewall
def check_group_exists(host, cert_files, group_name, api_key=None):
    api_url = f"https://{host}/api/"
    url = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='{group_name}']"
    
    if cert_files:
        response = requests.get(url, cert=cert_files, verify=False, timeout=10)
    else:
        headers = {"X-PAN-KEY": api_key}
        response = requests.get(url, headers=headers, verify=False, timeout=10)
    
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
            response = requests.get(url_policies, cert=cert_files, verify=False, timeout=10)
        else:
            headers = {"X-PAN-KEY": api_key}
            response = requests.get(url_policies, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        for rule in root.findall(".//entry"):
            rule_name = rule.get("name")
            for member in rule.findall(".//member"):
                if member.text == object_name:
                    usage["security_policies"].append(rule_name)
    except requests.RequestException as e:
        append_output(f"Error checking security policies for '{object_name}': {e}")
    
    # Check NAT rules
    url_nat = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/nat/rules"
    try:
        if cert_files:
            response = requests.get(url_nat, cert=cert_files, verify=False, timeout=10)
        else:
            headers = {"X-PAN-KEY": api_key}
            response = requests.get(url_nat, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        for rule in root.findall(".//entry"):
            rule_name = rule.get("name")
            for member in rule.findall(".//member"):
                if member.text == object_name:
                    usage["nat_rules"].append(rule_name)
    except requests.RequestException as e:
        append_output(f"Error checking NAT rules for '{object_name}': {e}")
    
    # Check address groups
    url_groups = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group"
    try:
        if cert_files:
            response = requests.get(url_groups, cert=cert_files, verify=False, timeout=10)
        else:
            headers = {"X-PAN-KEY": api_key}
            response = requests.get(url_groups, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        for group in root.findall(".//entry"):
            group_name = group.get("name")
            for member in group.findall(".//member"):
                if member.text == object_name:
                    usage["address_groups"].append(group_name)
    except requests.RequestException as e:
        append_output(f"Error checking address groups for '{object_name}': {e}")
    
    return usage

# Remove an object from an address group
def remove_object_from_group(host, cert_files, object_name, group_name, api_key=None):
    api_url = f"https://{host}/api/"
    url = f"{api_url}?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='{group_name}']"
    
    if cert_files:
        response = requests.get(url, cert=cert_files, verify=False, timeout=10)
    else:
        headers = {"X-PAN-KEY": api_key}
        response = requests.get(url, headers=headers, verify=False, timeout=10)
    
    response.raise_for_status()
    root = ET.fromstring(response.text)
    
    # Find the members list
    members = root.find(".//static")
    if members is None:
        append_output(f"Address group '{group_name}' has no static members to modify.")
        return False
    
    # Remove the specified object from the members list
    updated = False
    for member in members.findall("member"):
        if member.text == object_name:
            members.remove(member)
            updated = True
            break
    
    if not updated:
        append_output(f"Object '{object_name}' not found in address group '{group_name}'.")
        return False
    
    # If no members remain, remove the static tag to avoid empty group issues
    if len(members.findall("member")) == 0:
        root.remove(members)
        xml_data = "<static/>"
    else:
        xml_data = ET.tostring(root, encoding='unicode')
    
    # Update the address group
    edit_url = f"{api_url}?type=config&action=edit&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='{group_name}']&element={quote(xml_data)}"
    if cert_files:
        response = requests.post(edit_url, cert=cert_files, verify=False, timeout=10)
    else:
        headers = {"X-PAN-KEY": api_key}
        response = requests.post(edit_url, headers=headers, verify=False, timeout=10)
    
    response.raise_for_status()
    append_output(f"Removed '{object_name}' from address group '{group_name}'")
    return True

# Delete a security policy or NAT rule
def delete_policy(host, cert_files, policy_type, policy_name, api_key=None):
    api_url = f"https://{host}/api/"
    if policy_type == "security":
        xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='{policy_name}']"
    elif policy_type == "nat":
        xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/nat/rules/entry[@name='{policy_name}']"
    else:
        return False
    
    url = f"{api_url}?type=config&action=delete&xpath={xpath}"
    if cert_files:
        response = requests.get(url, cert=cert_files, verify=False, timeout=10)
    else:
        headers = {"X-PAN-KEY": api_key}
        response = requests.get(url, headers=headers, verify=False, timeout=10)
    
    response.raise_for_status()
    append_output(f"Deleted {policy_type} policy '{policy_name}'")
    return True

# Update or create an object
def update_or_create_object(host, cert_files, object_name, value, api_key=None):
    api_url = f"https://{host}/api/"
    address_type = validate_address_type(value)
    if not address_type:
        append_output(f"Invalid value format for '{object_name}': '{value}'")
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
    
    try:
        if cert_files:
            response = requests.post(url, cert=cert_files, verify=False, timeout=10)
        else:
            headers = {"X-PAN-KEY": api_key}
            response = requests.post(url, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        append_output(f"Object '{object_name}' {action} with value '{value}'")
        return True
    except requests.RequestException as e:
        append_output(f"Failed to {action} object '{object_name}': {e}")
        return False

# Add a new object or object group
def add_objects_or_groups(host, cert_files, object_name, object_value, api_key=None):
    report = {
        "successful": [],
        "failed": []
    }
    
    if not object_name:
        append_output("Object name cannot be empty.")
        report["failed"].append("Object name cannot be empty.")
        return report
    
    if check_object_exists(host, cert_files, object_name, api_key):
        append_output(f"Object '{object_name}' already exists. Skipping.")
        report["failed"].append(f"'{object_name}' not added: already exists")
        return report
    
    address_type = validate_address_type(object_value)
    if not address_type:
        append_output(f"Invalid value format for '{object_name}': '{object_value}'")
        report["failed"].append(f"'{object_name}' not added: invalid value format")
        return report
    
    if update_or_create_object(host, cert_files, object_name, object_value, api_key):
        report["successful"].append(f"Added object '{object_name}' with value '{object_value}'")
    
    # Commit changes if there are successful additions
    if report["successful"]:
        api_url = f"https://{host}/api/"
        commit_url = f"{api_url}?type=commit&cmd=<commit></commit>"
        try:
            if cert_files:
                response = requests.post(commit_url, cert=cert_files, verify=False, timeout=30)
            else:
                headers = {"X-PAN-KEY": api_key}
                response = requests.post(commit_url, headers=headers, verify=False, timeout=30)
            response.raise_for_status()
            append_output("Changes committed successfully.")
        except requests.RequestException as e:
            append_output(f"Commit failed: {e}")
            failed_entries = []
            for entry in report["successful"]:
                name = entry.split("'")[1]
                failed_entries.append(f"'{name}' not committed due to commit failure: {str(e)}")
            report["failed"].extend(failed_entries)
            report["successful"] = []
    
    return report

# Delete specified address objects after listing affected policies
def delete_batch_objects(host, cert_files, object_names, usage_dict, api_key=None):
    if not object_names:
        return True, []
    
    api_url = f"https://{host}/api/"
    successes = []
    failures = []
    
    append_output(f"\nDeleting batch of {len(object_names)} objects...")
    for name in object_names:
        usage = usage_dict.get(name, {})
        # Remove from address groups
        for group_name in usage.get("address_groups", []):
            if not remove_object_from_group(host, cert_files, name, group_name, api_key):
                failures.append(f"'{name}' not deleted due to failure removing from address group '{group_name}'")
                continue
        
        # Delete from policies
        for policy_name in usage.get("security_policies", []):
            if not delete_policy(host, cert_files, "security", policy_name, api_key):
                failures.append(f"'{name}' not deleted due to failure deleting security policy '{policy_name}'")
                continue
        
        for policy_name in usage.get("nat_rules", []):
            if not delete_policy(host, cert_files, "nat", policy_name, api_key):
                failures.append(f"'{name}' not deleted due to failure deleting NAT policy '{policy_name}'")
                continue
        
        # Delete the object
        url = f"{api_url}?type=config&action=delete&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{name}']"
        try:
            if cert_files:
                response = requests.get(url, cert=cert_files, verify=False, timeout=10)
            else:
                headers = {"X-PAN-KEY": api_key}
                response = requests.get(url, headers=headers, verify=False, timeout=10)
            response.raise_for_status()
            successes.append(f"'{name}' deleted")
            append_output(f"Deleted '{name}'")
        except requests.RequestException as e:
            failures.append(f"'{name}' not deleted due to error: {str(e)}")
            append_output(f"Failed to delete '{name}': {str(e)}")
    
    if successes:
        commit_url = f"{api_url}?type=commit&cmd=<commit></commit>"
        try:
            if cert_files:
                commit_response = requests.post(commit_url, cert=cert_files, verify=False, timeout=10)
            else:
                headers = {"X-PAN-KEY": api_key}
                commit_response = requests.post(commit_url, headers=headers, verify=False, timeout=10)
            commit_response.raise_for_status()
            append_output("Batch deletions committed successfully.")
        except requests.RequestException as e:
            append_output(f"Commit failed: {e}")
            failures.extend([f"'{name}' deletion not committed due to commit failure: {str(e)}" for name in object_names if name in [entry.split("'")[1] for entry in successes]])
    
    return successes, failures

# Delete specified address objects after listing affected policies
def delete_address_objects(host, cert_files, objects_to_delete_file, api_key=None):
    objects_to_delete = read_objects_file(objects_to_delete_file, name_only=True)
    if not objects_to_delete:
        append_output("No objects specified for deletion.")
        return None
    
    report = {
        "successful": [],
        "failed": []
    }
    
    # List objects and their usage
    append_output("\nObjects marked for deletion and their affected policies:")
    usage_dict = {}
    for name in objects_to_delete:
        if not check_object_exists(host, cert_files, name, api_key):
            report["failed"].append(f"'{name}' not deleted: not found on firewall")
            append_output(f"Object '{name}' not found on firewall. Skipping.")
            continue
        
        usage = check_object_usage(host, cert_files, name, api_key)
        usage_dict[name] = usage
        append_output(f"\nObject '{name}':")
        if usage["security_policies"]:
            append_output(f"  Security Policies: {', '.join(usage['security_policies'])}")
        if usage["nat_rules"]:
            append_output(f"  NAT Rules: {', '.join(usage['nat_rules'])}")
        if usage["address_groups"]:
            append_output(f"  Address Groups: {', '.join(usage['address_groups'])}")
        if not any(usage.values()):
            append_output("  No policies or groups affected.")
    
    # Proceed with deletion (assuming confirmation in web UI)
    successes, failures = delete_batch_objects(host, cert_files, objects_to_delete, usage_dict, api_key)
    report["successful"].extend(successes)
    report["failed"].extend(failures)
    
    return report

# Replace old object values with new ones using new_objects.txt
def replace_object_values(host, cert_files, objects_to_replace_file, new_objects_file, api_key=None):
    objects_to_replace = read_objects_file(objects_to_replace_file, name_only=True)
    if not objects_to_replace:
        append_output("No objects specified for replacement.")
        return None
    
    report = {
        "successful": [],
        "failed": []
    }
    
    # Read replacement values from new_objects.txt
    replacements = read_objects_file(new_objects_file)
    if not replacements:
        append_output("No replacements provided in 'new_objects.txt'. Exiting replacement process.")
        return None
    
    # Convert replacements to a dictionary for quick lookup
    replacement_dict = dict(replacements)
    
    # Process each object
    append_output("\nReplacing object values using 'new_objects.txt'...")
    for name in objects_to_replace:
        if name not in replacement_dict:
            report["failed"].append(f"'{name}' not updated: no replacement value found in new_objects.txt")
            append_output(f"Skipping '{name}': no replacement value found in new_objects.txt.")
            continue
        
        new_value = replacement_dict[name]
        if not check_object_exists(host, cert_files, name, api_key):
            report["failed"].append(f"'{name}' not updated: not found on firewall")
            append_output(f"Object '{name}' not found on firewall. Skipping.")
            continue
        
        if update_or_create_object(host, cert_files, name, new_value, api_key):
            report["successful"].append(f"'{name}' updated to '{new_value}'")
        else:
            report["failed"].append(f"'{name}' not updated due to error")
    
    if report["successful"]:
        api_url = f"https://{host}/api/"
        commit_url = f"{api_url}?type=commit&cmd=<commit></commit>"
        try:
            if cert_files:
                commit_response = requests.post(commit_url, cert=cert_files, verify=False, timeout=10)
            else:
                headers = {"X-PAN-KEY": api_key}
                commit_response = requests.post(commit_url, headers=headers, verify=False, timeout=10)
            commit_response.raise_for_status()
            append_output("Replacements committed successfully.")
        except requests.RequestException as e:
            append_output(f"Commit failed: {e}")
            report["failed"].extend([f"'{name}' update not committed due to commit failure: {str(e)}" for name in objects_to_replace if name in [entry.split("'")[1] for entry in report["successful"]]])
    
    return report

# Create or update objects in batch from file
def batch_create_or_update_objects(host, cert_files, batch_file, api_key=None):
    objects_to_process = read_objects_file(batch_file)
    if not objects_to_process:
        append_output("No objects specified in 'new_objects_batch.txt'.")
        return None
    
    report = {
        "successful": [],
        "failed": []
    }
    
    append_output(f"\nProcessing batch of {len(objects_to_process)} objects from 'new_objects_batch.txt'...")
    for name, value in objects_to_process:
        if update_or_create_object(host, cert_files, name, value, api_key):
            report["successful"].append(f"Object '{name}' processed with value '{value}'")
        else:
            report["failed"].append(f"Object '{name}' failed to process with value '{value}'")
    
    # Commit changes if there are successful operations
    if report["successful"]:
        api_url = f"https://{host}/api/"
        commit_url = f"{api_url}?type=commit&cmd=<commit></commit>"
        try:
            if cert_files:
                commit_response = requests.post(commit_url, cert=cert_files, verify=False, timeout=30)
            else:
                headers = {"X-PAN-KEY": api_key}
                commit_response = requests.post(commit_url, headers=headers, verify=False, timeout=30)
            commit_response.raise_for_status()
            append_output("Batch object creation/update committed successfully.")
        except requests.RequestException as e:
            append_output(f"Commit failed: {e}")
            failed_entries = []
            for entry in report["successful"]:
                name = entry.split("'")[1]
                failed_entries.append(f"'{name}' not committed due to commit failure: {str(e)}")
            report["failed"].extend(failed_entries)
            report["successful"] = []
    
    return report

# Restore a running configuration from a file
def restore_running_config(host, cert_files, config_file, api_key=None):
    api_url = f"https://{host}/api/"
    
    # Step 1: Import the configuration file to the firewall
    append_output("\nStep 1: Importing the configuration file to the firewall...")
    upload_url = f"{api_url}?type=import&category=configuration"
    files = {'file': config_file}
    try:
        if cert_files:
            response = requests.post(upload_url, files=files, cert=cert_files, verify=False, timeout=30)
        else:
            headers = {"X-PAN-KEY": api_key}
            response = requests.post(upload_url, headers=headers, files=files, verify=False, timeout=30)
        response.raise_for_status()
        append_output(f"Successfully imported configuration file to the firewall.")
    except requests.RequestException as e:
        append_output(f"Failed to import configuration file: {e}")
        return None
    
    # Step 2: Load the imported configuration into the candidate configuration
    append_output("\nStep 2: Loading the imported configuration into the candidate configuration...")
    filename = config_file.filename
    load_url = f"{api_url}?type=op&cmd=<load><config><from>{filename}</from></config></load>"
    try:
        if cert_files:
            response = requests.get(load_url, cert=cert_files, verify=False, timeout=30)
        else:
            headers = {"X-PAN-KEY": api_key}
            response = requests.get(load_url, headers=headers, verify=False, timeout=30)
        response.raise_for_status()
        append_output(f"Successfully loaded configuration from '{filename}' into the candidate configuration.")
    except requests.RequestException as e:
        append_output(f"Failed to load configuration: {e}")
        return None
    
    # Step 3: Commit the loaded configuration to the live (active) configuration
    append_output("\nStep 3: Committing the loaded configuration to the live configuration...")
    commit_url = f"{api_url}?type=commit&cmd=<commit></commit>"
    try:
        if cert_files:
            response = requests.post(commit_url, cert=cert_files, verify=False, timeout=30)
        else:
            headers = {"X-PAN-KEY": api_key}
            response = requests.post(commit_url, headers=headers, verify=False, timeout=30)
        response.raise_for_status()
        append_output("Configuration successfully committed to the live configuration.")
    except requests.RequestException as e:
        append_output(f"Commit failed: {e}")
        return None
    
    return {"successful": [f"Restored and loaded configuration from '{filename}' into live configuration"], "failed": []}

# Generate and append report to a single audit file with timestamp
def generate_report(report, total_objects, total_groups, operation="update"):
    if not report:
        append_output(f"No {operation} report to generate.")
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
    
    # Add to output
    append_output("\n".join(report_content))
    append_output(f"Audit report appended to '{report_file}'.")

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
            response = requests.get(url, cert=cert_files, verify=False, timeout=10)
        else:
            headers = {"X-PAN-KEY": api_key}
            response = requests.get(url, headers=headers, verify=False, timeout=10)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        hostname = root.find(".//hostname").text
        return hostname
    except (requests.RequestException, AttributeError) as e:
        append_output(f"Failed to retrieve hostname: {e}. Using 'unknown' as prefix.")
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
            response = requests.get(url, cert=cert_files, verify=False, timeout=30)
        else:
            headers = {"X-PAN-KEY": api_key}
            response = requests.get(url, headers=headers, verify=False, timeout=30)
        response.raise_for_status()
        with open(base_filename, "wb") as f:
            f.write(response.content)
        append_output(f"Running configuration downloaded successfully as '{base_filename}'.")
        
        # Perform a commit after successful download
        commit_url = f"{api_url}?type=commit&cmd=<commit></commit>"
        try:
            if cert_files:
                commit_response = requests.post(commit_url, cert=cert_files, verify=False, timeout=30)
            else:
                headers = {"X-PAN-KEY": api_key}
                commit_response = requests.post(commit_url, headers=headers, verify=False, timeout=30)
            commit_response.raise_for_status()
            append_output("Configuration committed successfully after backup.")
        except requests.RequestException as e:
            append_output(f"Warning: Commit after backup failed: {e}. Proceeding without committing.")
    
    except requests.RequestException as e:
        append_output(f"Failed to download running configuration: {e}")

@app.route('/', methods=['GET', 'POST'])
def index():
    global output
    output = []  # Reset output for each request
    
    cached_host = load_cached_firewall()
    
    if request.method == 'POST':
        host = request.form.get('host')
        cert_file = request.files.get('cert_file')
        key_file = request.files.get('key_file')
        username = request.form.get('username')
        password = request.form.get('password')
        action = request.form.get('action')
        
        # Validate host
        if not is_host_reachable(host):
            return render_template('index.html', output="\n".join(output), cached_host=cached_host)
        
        save_cached_firewall(host)
        
        # Handle certificate files
        cert_files = None
        api_key = None
        if cert_file and key_file and cert_file.filename and key_file.filename:
            cert_path = os.path.join("uploads", cert_file.filename)
            key_path = os.path.join("uploads", key_file.filename)
            if not os.path.exists("uploads"):
                os.makedirs("uploads")
            cert_file.save(cert_path)
            key_file.save(key_path)
            cert_files = (cert_path, key_path)
        else:
            if not username or not password:
                append_output("Username and password are required when not using certificate authentication.")
                return render_template('index.html', output="\n".join(output), cached_host=cached_host)
            api_key, _ = get_api_key(host, username, password)
        
        append_output(f"Connected to device at {host}")
        
        total_objects, total_groups = 0, 0
        
        if action == '1':  # Backup running config
            download_running_config(host, cert_files, api_key)
        
        elif action == '2':  # Delete objects
            objects_to_delete_file = request.files.get('objects_to_delete_file')
            if not objects_to_delete_file or not objects_to_delete_file.filename:
                append_output("Please upload objects_to_delete.txt.")
            else:
                deletion_report = delete_address_objects(host, cert_files, objects_to_delete_file, api_key)
                if deletion_report:
                    generate_report(deletion_report, total_objects, total_groups, operation="deletion")
        
        elif action == '3':  # Replace objects
            objects_to_replace_file = request.files.get('objects_to_replace_file')
            new_objects_file = request.files.get('new_objects_file')
            if not objects_to_replace_file or not objects_to_replace_file.filename or not new_objects_file or not new_objects_file.filename:
                append_output("Please upload both objects_to_delete.txt and new_objects.txt.")
            else:
                replacement_report = replace_object_values(host, cert_files, objects_to_replace_file, new_objects_file, api_key)
                if replacement_report:
                    generate_report(replacement_report, total_objects, total_groups, operation="replacement")
        
        elif action == '4':  # Add new objects interactively
            object_name = request.form.get('object_name')
            object_value = request.form.get('object_value')
            if not object_name or not object_value:
                append_output("Please provide both object name and value.")
            else:
                add_report = add_objects_or_groups(host, cert_files, object_name, object_value, api_key)
                if add_report:
                    generate_report(add_report, total_objects, total_groups, operation="add")
        
        elif action == '5':  # Restore running config
            config_file = request.files.get('config_file')
            if not config_file or not config_file.filename:
                append_output("Please upload a configuration file.")
            else:
                restore_report = restore_running_config(host, cert_files, config_file, api_key)
                if restore_report:
                    generate_report(restore_report, total_objects, total_groups, operation="restore")
        
        elif action == '7':  # Create/update objects in batch
            batch_file = request.files.get('batch_file')
            if not batch_file or not batch_file.filename:
                append_output("Please upload new_objects_batch.txt.")
            else:
                batch_report = batch_create_or_update_objects(host, cert_files, batch_file, api_key)
                if batch_report:
                    generate_report(batch_report, total_objects, total_groups, operation="batch_create_update")
        
        # Clean up uploaded files
        if cert_files:
            try:
                os.remove(cert_files[0])
                os.remove(cert_files[1])
            except:
                pass
        
        return render_template('index.html', output="\n".join(output), cached_host=cached_host)
    
    return render_template('index.html', output="", cached_host=cached_host)

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    app.run(host=os.environ.get("FLASK_HOST", "127.0.0.1"), port=int(os.environ.get("FLASK_PORT", "5000")), debug=os.environ.get("FLASK_DEBUG") == "1")