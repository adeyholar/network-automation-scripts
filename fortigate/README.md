# FortiGate tools

## ipsec_vpn_runbook_to_docx.py

**What:** Generates a Word document with a staged implementation plan for a FortiGate client-to-site IPsec VPN managed through FortiManager, with FortiAuthenticator RADIUS (MFA) authentication, running alongside an existing SSL VPN. Each stage lists steps plus risks and mitigations, ordered from least to most intrusive.

**Requirements:** Python 3.9+, `python-docx`.

**Usage:**
```bash
python ipsec_vpn_runbook_to_docx.py                # writes FortiGate_IPsec_VPN_Implementation.docx
OUTPUT_DOCX=my-runbook.docx python ipsec_vpn_runbook_to_docx.py
```
Edit the addresses, interface names and ports in the script to match your environment; the defaults are documentation placeholders (`203.0.113.162`, `vpn.example.com`).
