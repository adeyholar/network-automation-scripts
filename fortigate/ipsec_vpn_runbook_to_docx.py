import os
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt

def add_heading(doc, text, level):
    heading = doc.add_heading(text, level)
    heading.alignment = WD_ALIGN_PARAGRAPH.LEFT
    heading.runs[0].font.size = Pt(14 if level == 1 else 12)
    heading.runs[0].bold = True

def add_paragraph(doc, text, bold=False):
    p = doc.add_paragraph(text)
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    if bold:
        p.runs[0].bold = True
    p.runs[0].font.size = Pt(11)
    return p

def add_bullet_list(doc, items):
    for item in items:
        p = doc.add_paragraph(item, style='List Bullet')
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        p.runs[0].font.size = Pt(11)

doc = Document()

# Title
add_heading(doc, "FortiGate 100F IPsec VPN Implementation Document with FortiAuthenticator via FortiManager", 1)

# Objective
add_heading(doc, "Objective", 2)
add_paragraph(doc, "Configure a client-to-site IPsec VPN on a FortiGate 100F using FortiManager, running FortiOS 7.6.2, to provide secure remote access alongside the existing SSL VPN. The VPN will use WAN2 (203.0.113.162, vpn.example.com), assign client IPs from 198.51.100.10–198.51.100.250 (subnet 198.51.100.0/24), authenticate via FortiAuthenticator (192.0.2.90) for LDAP (first factor) and FortiToken Mobile (second factor), and connect users through FortiClient.")

# Prerequisites
add_heading(doc, "Prerequisites", 2)
prerequisites = [
    "FortiManager Access: Administrative access to FortiManager for managing the FortiGate 100F.",
    "FortiAuthenticator: Fully configured at IP 192.0.2.90 with:",
    "  - LDAP integration for first-factor authentication.",
    "  - Token-based 2FA (FortiToken Mobile) for second-factor authentication.",
    "  - Existing user group for VPN access (VPNUsers).",
    "FortiGate Details:",
    "  - WAN2 interface with IP 203.0.113.162/29.",
    "  - Existing SSL VPN with IP range 203.0.113.0/25.",
    "FortiClient: Latest version from www.forticlient.com.",
    "Network Information:",
    "  - Internal LAN subnet: 192.168.0.0/16.",
    "  - IPsec VPN client range: 198.51.100.10–198.51.100.250 (subnet 198.51.100.0/24).",
    "Backup: Current FortiGate, FortiManager, and FortiAuthenticator configurations backed up."
]
add_bullet_list(doc, prerequisites)

# Implementation Stages
add_heading(doc, "Implementation Stages", 2)
add_paragraph(doc, "The implementation is divided into five stages, progressing from non-intrusive (no impact on existing services) to most intrusive (potential downtime if mishandled). Each stage includes steps, estimated time, and risk mitigation strategies.")

# Stage 1
add_heading(doc, "Stage 1: Planning and Verification (Non-Intrusive)", 3)
add_paragraph(doc, "Objective: Gather information and verify existing configurations without making changes.", bold=True)
add_paragraph(doc, "Impact: No downtime; no changes to production systems.", bold=True)
add_paragraph(doc, "Estimated Time: 1–2 hours.", bold=True)
add_paragraph(doc, "Steps:", bold=True)
steps1 = [
    "Verify SSL VPN Configuration:",
    "  - In FortiManager (Device Manager > VPN > SSL-VPN Settings), confirm SSL VPN uses 203.0.113.0/25 and a port (e.g., 443 or 10443) that won’t conflict with IPsec VPN’s IKE port (10428).",
    "  - Review SSL VPN firewall policies to ensure no overlap with IPsec VPN range (198.51.100.0/24).",
    "Validate FortiAuthenticator:",
    "  - Log in to FortiAuthenticator (192.0.2.90) and verify:",
    "    - LDAP integration for VPNUsers group.",
    "    - FortiToken Mobile 2FA enabled for VPNUsers.",
    "    - RADIUS service configured for FortiGate authentication.",
    "  - Test user authentication (Authentication > User Management > Test User) with LDAP credentials and FortiToken Mobile.",
    "Plan IPsec VPN Parameters:",
    "  - Interface: WAN2 (203.0.113.162, vpn.example.com).",
    "  - Client IP Range: 198.51.100.10–198.51.100.250 (198.51.100.0/24).",
    "  - Authentication: FortiAuthenticator (RADIUS with LDAP + FortiToken Mobile).",
    "  - Encryption: AES-256, SHA-256, IKEv2.",
    "  - IKE Port: 10428.",
    "Backup Configurations:",
    "  - FortiManager: System Settings > Configuration > Backup.",
    "  - FortiGate (CLI): execute backup config flash <filename>.",
    "  - FortiAuthenticator: System > Administration > Configuration Backup."
]
add_bullet_list(doc, steps1)
add_paragraph(doc, "Risks and Mitigations:", bold=True)
risks1 = [
    "Risk: Missing SSL VPN details could cause conflicts.",
    "  - Mitigation: Document SSL VPN IP range, ports, and policies.",
    "Risk: FortiAuthenticator misconfiguration.",
    "  - Mitigation: Test authentication for a sample user."
]
add_bullet_list(doc, risks1)

# Stage 2
add_heading(doc, "Stage 2: FortiManager Configuration (Low Intrusiveness)", 3)
add_paragraph(doc, "Objective: Configure objects and policies in FortiManager without pushing to FortiGate.", bold=True)
add_paragraph(doc, "Impact: No downtime; changes are staged in FortiManager.", bold=True)
add_paragraph(doc, "Estimated Time: 2–3 hours.", bold=True)
add_paragraph(doc, "Steps:", bold=True)
steps2 = [
    "Configure RADIUS Server Object:",
    "  - In FortiManager (User & Authentication > RADIUS Servers, Policy & Objects), create:",
    "    - Name: FAC_Radius.",
    "    - Server IP: 192.0.2.90.",
    "    - Authentication Port: 1812.",
    "    - Secret: Match FortiAuthenticator’s shared secret.",
    "    - Authentication Type: PAP.",
    "  - Test connectivity and save.",
    "Create User Group:",
    "  - In User & Authentication > User Groups, create:",
    "    - Name: VPNUsers.",
    "    - Type: Firewall.",
    "    - Remote Server: FAC_Radius.",
    "    - Group Filter: Match VPNUsers from FortiAuthenticator.",
    "  - Save.",
    "Configure IPsec VPN Community:",
    "  - In VPN Manager > IPsec VPN, create:",
    "    - Name: IPsec_VPN_Remote.",
    "    - Type: Remote Access.",
    "    - Client Type: FortiClient.",
    "    - Incoming Interface: WAN2 (203.0.113.162).",
    "    - Authentication Method: Pre-shared Key (32-character PSK).",
    "    - User Group: VPNUsers.",
    "    - IKE Version: IKEv2.",
    "    - Local Gateway: 203.0.113.162 (or vpn.example.com).",
    "    - Client Address Range: 198.51.100.10–198.51.100.250 (198.51.100.0/24).",
    "    - DNS Server: Internal DNS (e.g., 192.0.2.53) or 8.8.8.8.",
    "    - Phase 1 Proposal: aes256-sha256.",
    "    - Phase 2 Proposal: aes256-sha256.",
    "    - IKE Port: 10428.",
    "  - Save.",
    "Create Address Object:",
    "  - In Policy & Objects > Addresses, create:",
    "    - Name: ipsec_vpn_range.",
    "    - Type: Subnet.",
    "    - Subnet/IP Range: 198.51.100.0/24.",
    "  - Save.",
    "Create Firewall Policies:",
    "  - In Policy & Objects > Firewall Policy, create:",
    "    - Inbound Policy:",
    "      - Name: ipsec_vpn_access.",
    "      - Incoming Interface: IPsec_VPN_Remote.",
    "      - Outgoing Interface: port1 (internal).",
    "      - Source: Address = ipsec_vpn_range, User = VPNUsers.",
    "      - Destination: all (or 192.168.0.0/16).",
    "      - Schedule: always.",
    "      - Service: ALL.",
    "      - Action: Accept.",
    "    - Outbound Policy:",
    "      - Name: ipsec_vpn_outgoing.",
    "      - Incoming Interface: IPsec_VPN_Remote.",
    "      - Outgoing Interface: wan2.",
    "      - Source: Address = ipsec_vpn_range, User = VPNUsers.",
    "      - Destination: all.",
    "      - Schedule: always.",
    "      - Service: ALL.",
    "      - Action: Accept.",
    "  - Save."
]
add_bullet_list(doc, steps2)
add_paragraph(doc, "Risks and Mitigations:", bold=True)
risks2 = [
    "Risk: Incorrect RADIUS or VPN settings.",
    "  - Mitigation: Validate RADIUS connectivity and VPN parameters.",
    "Risk: Policy conflicts.",
    "  - Mitigation: Review policies for ipsec_vpn_range uniqueness."
]
add_bullet_list(doc, risks2)

# Stage 3
add_heading(doc, "Stage 3: FortiClient Setup and Pilot Testing (Low to Moderate Intrusiveness)", 3)
add_paragraph(doc, "Objective: Distribute FortiClient and test IPsec VPN with a small user group.", bold=True)
add_paragraph(doc, "Impact: Minimal; affects only pilot users, no impact on SSL VPN.", bold=True)
add_paragraph(doc, "Estimated Time: 2–3 hours.", bold=True)
add_paragraph(doc, "Steps:", bold=True)
steps3 = [
    "Distribute FortiClient:",
    "  - Provide 2–3 pilot users from VPNUsers with FortiClient from www.forticlient.com.",
    "Configure FortiClient:",
    "  - Users configure (Remote Access > Configure VPN):",
    "    - VPN Type: IPsec VPN.",
    "    - Connection Name: IPsec_VPN_Remote.",
    "    - Remote Gateway: vpn.example.com (or 203.0.113.162).",
    "    - Port: 10428.",
    "    - Authentication Method: Prompt for username/password.",
    "  - Save.",
    "Test Pilot Connections:",
    "  - Pilot users connect using LDAP credentials and FortiToken Mobile code.",
    "  - Verify access to internal resources (e.g., ping 192.0.2.53).",
    "  - Confirm IPs from 198.51.100.10–198.51.100.250.",
    "Validate SSL VPN:",
    "  - Test SSL VPN (203.0.113.0/25) to ensure no disruption."
]
add_bullet_list(doc, steps3)
add_paragraph(doc, "Risks and Mitigations:", bold=True)
risks3 = [
    "Risk: Authentication failures.",
    "  - Mitigation: Check FortiAuthenticator logs and VPNUsers membership.",
    "Risk: FortiClient misconfiguration.",
    "  - Mitigation: Provide clear setup instructions."
]
add_bullet_list(doc, risks3)

# Stage 4
add_heading(doc, "Stage 4: Push Configuration to FortiGate (Moderately Intrusive)", 3)
add_paragraph(doc, "Objective: Deploy VPN and policies to FortiGate, enabling the VPN tunnel.", bold=True)
add_paragraph(doc, "Impact: Low risk of downtime; misconfiguration could affect WAN2 or VPN services.", bold=True)
add_paragraph(doc, "Estimated Time: 1–2 hours.", bold=True)
add_paragraph(doc, "Steps:", bold=True)
steps4 = [
    "Assign VPN Community:",
    "  - In FortiManager (VPN Manager > IPsec VPN), assign IPsec_VPN_Remote to FortiGate 100F.",
    "Install Policy Package:",
    "  - In Policy & Objects > Policy Package, select FortiGate package and click Install Wizard.",
    "  - Schedule during low-traffic window (e.g., after business hours).",
    "Verify Deployment:",
    "  - On FortiGate, check Monitor > IPsec Monitor for IPsec_VPN_Remote status.",
    "  - Use CLI:",
    "    get vpn ipsec tunnel summary",
    "    show vpn ipsec phase1-interface IPsec_VPN_Remote",
    "    show vpn ipsec phase2-interface IPsec_VPN_Remote",
    "    show user radius FAC_Radius",
    "    show user group VPNUsers",
    "  - Test RADIUS:",
    "    diagnose test authserver radius FAC_Radius pap <username> <password+token>"
]
add_bullet_list(doc, steps4)
add_paragraph(doc, "Risks and Mitigations:", bold=True)
risks4 = [
    "Risk: Policy installation errors disrupt services.",
    "  - Mitigation: Use Install Preview; test in maintenance window.",
    "Risk: WAN2 connectivity issues.",
    "  - Mitigation: Confirm IKE port 10428 and WAN2 settings."
]
add_bullet_list(doc, risks4)

# Stage 5
add_heading(doc, "Stage 5: Full User Rollout and Monitoring (Most Intrusive)", 3)
add_paragraph(doc, "Objective: Deploy IPsec VPN to all users and monitor performance.", bold=True)
steps5 = [
    "Step 5.1: Expand the VPN user group from the pilot group to all remote users.",
    "Step 5.2: Communicate FortiClient installation and connection instructions to users.",
    "Step 5.3: Monitor VPN tunnels (Monitor > IPsec Monitor) and RADIUS authentication logs on FortiAuthenticator.",
    "Step 5.4: Review bandwidth and session counts on WAN2 during peak hours.",
    "Step 5.5: Keep the SSL VPN available as a fallback until the IPsec rollout is confirmed stable."
]
add_bullet_list(doc, steps5)
add_paragraph(doc, "Risks and Mitigations:", bold=True)
risks5 = [
    "Risk: Increased load or authentication failures at full scale.",
    "  - Mitigation: Roll out in phases and monitor FortiAuthenticator and FortiGate resource usage."
]
add_bullet_list(doc, risks5)

output_path = os.environ.get("OUTPUT_DOCX", "FortiGate_IPsec_VPN_Implementation.docx")
doc.save(output_path)
print(f"Document saved to {output_path}")
