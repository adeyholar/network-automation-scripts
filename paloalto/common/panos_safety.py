"""Shared safety helpers for the PAN-OS scripts in this repository.

- TLS verification: on by default, configurable by env var or --insecure.
- Partial commits scoped to one admin, so other admins' pending changes are never committed.
- Removing an address object from rules as a member instead of deleting whole rules.
"""
import os
import sys
import xml.etree.ElementTree as ET
from urllib.parse import quote
from xml.sax.saxutils import escape

_FALSE_VALUES = {"0", "false", "no", "off"}
_verify = True


def configure_tls(insecure=False, log=print):
    """Set TLS verification for all requests made by these scripts.

    Order: --insecure flag, then NET_SCRIPTS_VERIFY_TLS (true/false),
    then NET_SCRIPTS_CA_BUNDLE (path to a CA bundle). Default: verify with system CAs.
    """
    global _verify
    env = os.environ.get("NET_SCRIPTS_VERIFY_TLS", "true").strip().lower()
    ca_bundle = os.environ.get("NET_SCRIPTS_CA_BUNDLE", "").strip()
    if insecure or env in _FALSE_VALUES:
        _verify = False
        log("WARNING: TLS certificate verification is OFF. Connections can be intercepted. "
            "Use only in a lab; set NET_SCRIPTS_CA_BUNDLE to your management CA instead.")
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except ImportError:
            pass
    elif ca_bundle:
        if not os.path.exists(ca_bundle):
            log(f"ERROR: NET_SCRIPTS_CA_BUNDLE points to a missing file: {ca_bundle}")
            sys.exit(2)
        _verify = ca_bundle
    else:
        _verify = True
    return _verify


def tls_verify():
    """Value to pass as requests' verify= argument."""
    return _verify


def partial_commit_cmd(admin):
    """XML for a commit limited to changes made by one admin."""
    if not admin:
        raise ValueError("An admin username is required for a partial commit.")
    return f"<commit><partial><admin><member>{escape(admin)}</member></admin></partial></commit>"


def partial_commit_url(api_url, admin):
    return f"{api_url}?type=commit&cmd={quote(partial_commit_cmd(admin))}"


def remove_member_from_rule(rule, object_name):
    """Remove object_name from every <member> list in a rule element (in place).

    Returns (changed_fields, blocked_fields). A field is blocked when removing the
    object would leave it empty; in that case the rule is NOT modified at all, because
    an empty list is invalid and silently defaulting to 'any' would widen the rule.
    """
    changed, blocked = [], []
    plan = []
    for parent in rule.iter():
        members = parent.findall("member")
        hits = [m for m in members if (m.text or "").strip() == object_name]
        if not hits:
            continue
        field = parent.tag
        if len(hits) == len(members):
            blocked.append(field)
        else:
            plan.append((parent, hits, field))
    if blocked:
        return [], blocked
    for parent, hits, field in plan:
        for m in hits:
            parent.remove(m)
        changed.append(field)
    return changed, blocked


VSYS_XPATH = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"
RULEBASE_XPATH = {
    "security": VSYS_XPATH + "/rulebase/security/rules",
    "nat": VSYS_XPATH + "/rulebase/nat/rules",
}


def api_call(method, url, cert_files=None, api_key=None, timeout=10, **kwargs):
    """Send one PAN-OS API request with the configured TLS setting."""
    import requests
    if cert_files:
        kwargs["cert"] = cert_files
    else:
        kwargs["headers"] = {"X-PAN-KEY": api_key}
    response = requests.request(method, url, verify=tls_verify(), timeout=timeout, **kwargs)
    response.raise_for_status()
    return response


def remove_object_from_rule(host, cert_files, api_key, rule_type, rule_name, object_name,
                            dry_run=False, log=print):
    """Remove object_name as a member of one security/NAT rule. Never deletes the rule.

    Returns True when the rule no longer references the object (or would not, in dry-run),
    False when the rule was skipped (a field would become empty) or an error occurred.
    """
    api_url = f"https://{host}/api/"
    xpath = f"{RULEBASE_XPATH[rule_type]}/entry[@name='{rule_name}']"
    response = api_call("GET", f"{api_url}?type=config&action=get&xpath={quote(xpath)}",
                        cert_files, api_key)
    entry = ET.fromstring(response.text).find(".//entry")
    if entry is None:
        log(f"WARNING: {rule_type} rule '{rule_name}' not found; skipping.")
        return False
    changed, blocked = remove_member_from_rule(entry, object_name)
    if blocked:
        log(f"WARNING: skipping {rule_type} rule '{rule_name}': removing '{object_name}' would leave "
            f"{', '.join(sorted(set(blocked)))} empty. Edit this rule by hand.")
        return False
    if not changed:
        return True
    if dry_run:
        log(f"[dry-run] would remove '{object_name}' from {rule_type} rule '{rule_name}' "
            f"({', '.join(changed)})")
        return True
    element = quote(ET.tostring(entry, encoding="unicode"))
    api_call("POST", f"{api_url}?type=config&action=edit&xpath={quote(xpath)}&element={element}",
             cert_files, api_key)
    log(f"Removed '{object_name}' from {rule_type} rule '{rule_name}' ({', '.join(changed)})")
    return True


def commit_own_changes(host, cert_files, api_key, admin, confirm, log=print, timeout=60):
    """Partial commit of only `admin`'s changes, after explicit confirmation.

    confirm(admin) must return True to proceed. Returns True only if committed.
    """
    if not admin:
        log("Not committed: admin username unknown. Changes remain in the candidate config; "
            "review and commit them on the firewall.")
        return False
    if not confirm(admin):
        log("Not committed. Changes remain in the candidate configuration.")
        return False
    api_url = f"https://{host}/api/"
    try:
        response = api_call("POST", partial_commit_url(api_url, admin), cert_files, api_key, timeout=timeout)
    except Exception as e:  # requests errors, bad admin, etc.
        log(f"Commit failed: {e}")
        return False
    status = ET.fromstring(response.text).get("status") if response.text else None
    if status not in (None, "success"):
        log(f"Commit failed: firewall returned status '{status}'.")
        return False
    log(f"Partial commit queued for admin '{admin}' only.")
    return True
