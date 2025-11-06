
# Open Ports & Security Controls — Research & Development
**Author:** Reginald D  
**Category:** Cybersecurity Research | Network Defense | Ethical Hacking

---

## Table of Contents
- [Introduction](#introduction)
- [Overview](#overview)
- [Environment & Tools](#environment--tools)
- [Open Ports Exercise](#open-ports-exercise)
  - [Border Firewall Scan](#border-firewall-scan)
  - [Guest Network Scan](#guest-network-scan)
  - [Internal Server Scan](#internal-server-scan)
  - [Usage Example and Sample Output](#usage-example-and-sample-output)
  - [Recommended Mitigations](#recommended-mitigations)
- [Security Controls Lab](#security-controls-lab)
  - [Preventive Controls (File-Share Permissions)](#preventive-controls-file-share-permissions)
  - [Detective Controls (Object Access Auditing)](#detective-controls-object-access-auditing)
  - [Directive Controls (Legal Notice / Banner)](#directive-controls-legal-notice--banner)
  - [Corrective Controls (File Integrity & Automated Repair)](#corrective-controls-file-integrity--automated-repair)
  - [PowerShell Examples (Corrective Control Scripts)](#powershell-examples-corrective-control-scripts)
- [Screenshots](#screenshots)
- [Security Takeaways](#security-takeaways)
- [References](#references)
- [Disclaimer](#disclaimer)
- [Contact](#contact)

---

## Introduction

Welcome to the No Lack LLC Cybersecurity Research & Development repository. This repository contains structured, hands-on labs and documentation demonstrating practical techniques for asset discovery, open-port enumeration, and security control configuration. The material is intended for controlled lab environments, training, and professional development and is aligned with industry frameworks such as NIST, CIS, and DoD STIG guidance.

---

## Overview

This repository combines two complementary exercises:

1. **Open Ports** — Demonstrates port scanning and service enumeration using `nmap` across three network zones (border, guest, internal), interpreting findings, and identifying attack surface issues.
2. **Security Controls** — Demonstrates implementing and validating preventive, detective, directive, and corrective security controls on Windows Server and client systems, including practical PowerShell scripts for basic corrective automation.

All steps assume a contained lab environment and administrative privileges where required.

---

## Environment & Tools

- Primary VM: Kali Linux (for scanning and enumeration)
- Windows VMs: DC10 (Domain Controller), PC10 (Client / Windows Server 2019)
- Tools:
  - Nmap (network scanning)
  - Windows Event Viewer / Local Security Policy
  - PowerShell (for scripting and automation)
  - Windows Server Manager (File and Storage Services)
  - Sysinternals (NotMyFault for corrective control testing)

Example target IPs used in exercises:
- Border: `203.0.113.1`
- Guest Gateway: `192.168.16.254`
- Server (internal): `10.1.16.2`
- File share: `\\10.1.16.1\TOOLS`

---

## Open Ports Exercise

Purpose: Identify open service ports, enumerate services and OS, and evaluate associated risks across three network contexts: Border, Guest, and Internal.

### Border Firewall Scan

Command used:

```bash
nmap 203.0.113.1 -F -sS -sV -O -Pn -oN border-scan.nmap
````

Parameters:

* `-F` : top 100 common ports
* `-sS`: SYN scan (fast, stealthy)
* `-sV`: version detection
* `-O` : OS detection
* `-Pn`: skip host discovery (assume host is up)
* `-oN`: output to a normal file

Quick result check:

```bash
grep open border-scan.nmap
```

Typical finding in lab: `25/tcp (SMTP)` discovered open on the border IP. Exposed SMTP can be leveraged for spam relay, information disclosure, or exploited via vulnerable mail software.

### Guest Network Scan

Acquire new DHCP lease and verify interface:

```bash
dhclient -r && dhclient
ip a s eth0
```

Scan command:

```bash
nmap 192.168.16.254 -F -sS -sV -O -oN guest-scan.nmap
```

Result summary:

```bash
grep open guest-scan.nmap
```

Typical findings: `80/tcp`, `443/tcp`, `8000/tcp` (web management interface). If firewall management interfaces are accessible from the guest network, that indicates misconfiguration and a serious risk.

### Internal Server Scan

Acquire new DHCP lease (client subnet) and scan server in server subnet:

```bash
dhclient -r && dhclient
ip a s eth0
nmap 10.1.16.2 -F -sS -sV -O -oN server-scan.nmap
grep open server-scan.nmap
```

Typical findings: Multiple service ports open (FTP/SSH/HTTP/MSRPC/SMB/RDP). OS detection in lab: `Windows Server 2016` with EOL considerations which must be addressed.

---

## Usage Example and Sample Output

Reproduce scan, list open ports, and interpret common entries:


# Perform scan
```bash
nmap -sS -sV -O 10.1.16.2 -oN server-scan.nmap
```
# Show open ports
```
grep open server-scan.nmap
```

Sample output (example only — actual results will vary by environment):

```
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           vsftpd 3.0.3
22/tcp   open  ssh           OpenSSH 8.2 (protocol 2.0)
80/tcp   open  http          Apache httpd 2.4.41 ((Ubuntu))
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds  Windows Server 2016
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

Interpretation guidance:

* Harden and restrict management interfaces.
* Disable unused services and apply network segmentation.
* Replace insecure protocols (FTP) with secure alternatives (SFTP).
* Apply patches and upgrade EOL systems.

---

## Recommended Mitigations

* Restrict management ports to a trusted admin VLAN/IP range.
* Implement least privilege and harden exposed services with TLS.
* Enforce network segmentation (firewall rules, VLANs) between client and server subnets.
* Replace or upgrade end-of-life operating systems before they reach EOSL.
* Enable logging and monitoring for exposed services and critical events.

---

## Security Controls Lab

This lab covers four control types: Preventive, Detective, Directive, and Corrective. The exercises are performed on Windows Server and client systems (PC10, DC10).

### Preventive Controls (File-Share Permissions)

Goal: Ensure only authorized administrator groups can access the `\\10.1.16.1\TOOLS` share.

Procedure Summary:

1. Log on to DC10 with administrative credentials.
2. Open Server Manager -> File and Storage Services -> Shares.
3. Right-click `TOOLS` -> Properties -> Permissions -> Customize permissions.
4. Disable inheritance and convert inherited permissions.
5. Remove `Users (structureality\Users)` entries and remove `Everyone` if present.
6. Verify Sam (non-admin) cannot access `\\10.1.16.1\TOOLS`.
7. Verify Jaime (LocalAdmin) can access the share.

A best practice is to avoid adding explicit deny rules that could inadvertently block administrators. Use explicit allow for admin groups and implicit deny for all others.

### Detective Controls (Object Access Auditing)

Goal: Configure auditing to record object deletions and verify event records.

Procedure Summary:

1. Log in as Jaime (member of LocalAdmin).
2. Delete an empty folder under `LABFILES`.
3. Open Event Viewer -> Windows Logs -> Security.
4. Use Local Security Policy -> Local Policies -> Audit Policy -> Audit object access -> enable Success and Failure.
5. On the target folder `LABFILES`: Security -> Advanced -> Auditing -> Add -> select `Everyone` -> Show advanced permissions -> enable `Delete subfolders and files` and `Delete`.
6. Delete `pcaps` folder under `LABFILES`.
7. In Event Viewer, find Event ID `4660` (object deleted) and `4663` (object access) to identify the object name and confirm auditing.

Notes:

* Event ID `4660` indicates an object was deleted; associated `4663` will include `Object Name`.
* If auditing doesn't generate entries immediately, restart the system and re-attempt.

### Directive Controls (Legal Notice / Banner)

Goal: Display an authorized-use banner at logon to provide notice and deter unauthorized access.

PowerShell example used in lab:

```powershell
$BannerText = "This computer system is the property of Structureality Inc. It is for authorized use only. By using this system, all users acknowledge notice of and agree to comply with the Acceptable Use Policy (AUP). Unauthorized or improper use of this system may result in administrative disciplinary action, civil charges/criminal penalties, and/or other sanctions set forth in the AUP. By continuing to use this system, you indicate your awareness of and consent to these terms and conditions. If you are physically located in the European Union, you may have additional rights per the GDPR. Visit the website gdpr-info.eu for more information."

New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption" -Value "Authorized Use Only" -PropertyType "String" -Force | Out-Null
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext" -Value $BannerText -PropertyType "String" -Force | Out-Null
```

Important: Consult legal counsel before deploying a banner in production to ensure it meets jurisdictional requirements.

### Corrective Controls (File Integrity & Automated Repair)

Goal: Create a simple corrective control that validates a file hash and restores contents if altered.

Manual example:

```powershell
# Create baseline file
"This is important" | Set-Content notes.txt

# Compute hash and save
Get-FileHash ./notes.txt -Algorithm SHA256 | Select-Object -ExpandProperty Hash | Set-Content ./hash.txt

# Modify file (simulate tamper)
echo "blah" >> notes.txt

# Check and correct (one-liner)
if((Get-FileHash ./notes.txt -Algorithm SHA256).Hash -eq (Get-Content ./hash.txt)) {
  Write-Host "The file is correct."
} else {
  Write-Host "The file has changed. Corrective action should be initiated."
}
```

PowerShell scripts for automation are provided in the lab and demonstrated below.

---

## PowerShell Examples (Corrective Control Scripts)

**calchash.ps1**

```powershell
Get-FileHash ./notes.txt -Algorithm SHA256 | Select-Object -ExpandProperty Hash | Set-Content ./hash.txt
```

**check.ps1**

```powershell
if((Get-FileHash ./notes.txt -Algorithm SHA256).Hash -ne (Get-Content ./hash.txt))
{
  "This is important" | Set-Content ./notes.txt
  Write-Host "The file has changed. Corrective action initiated."
}
else
{
  Write-Host "The file is correct. No corrective action needed."
}
```

Execution workflow:

1. Run `./calchash.ps1` after establishing the desired file content.
2. Periodically run `./check.ps1` (via scheduled task or boot-time task) to detect and auto-correct modifications.

---

## Screenshots

For documentation completeness, include screenshots in the repository under `./screenshots/`. The README references these images — add real captures to replace the placeholders.

Recommended screenshot filenames and where they should be inserted:

* `screenshots/tools-share-permissions.png`

  * Location: Preventive Controls section (showing `TOOLS` share properties and permissions)
  * Markdown insertion example:

    ```markdown
    ![TOOLS share permissions](screenshots/tools-share-permissions.png)
    ```

* `screenshots/event-viewer-audit-4660.png`

  * Location: Detective Controls (showing Event ID 4660 selected in Event Viewer)
  * Markdown insertion example:

    ```markdown
    ![Event Viewer - 4660 object deleted](screenshots/event-viewer-audit-4660.png)
    ```

* `screenshots/local-security-policy-audit.png`

  * Location: Detective Controls (showing Audit object access enabled)
  * Markdown insertion example:

    ```markdown
    ![Local Security Policy - Audit Object Access](screenshots/local-security-policy-audit.png)
    ```

* `screenshots/powershell-banner.png`

  * Location: Directive Controls (showing PowerShell commands or the displayed login banner)
  * Markdown insertion example:

    ```markdown
    ![Login banner configuration and login screen](screenshots/powershell-banner.png)
    ```

* `screenshots/nmap-scan-sample.png`

  * Location: Open Ports / Usage Example (screenshot of nmap output or terminal)
  * Markdown insertion example:

    ```markdown
    ![Nmap sample output](screenshots/nmap-scan-sample.png)
    ```

Notes for screenshots:

* Use PNG format for clarity (recommended resolution: 1200x675 or similar).
* Name files using the recommended filenames and place them in the `screenshots` directory at the repository root.
* Keep sensitive data redacted before committing (IP addresses, usernames if required).

---

## Security Takeaways

* Open and externally discoverable ports increase attack surface; minimize exposure.
* Guest networks must not provide access to administrative management interfaces.
* Internal segmentation limits lateral movement; implement VLANs and firewall rules.
* Audit object access to detect malicious or accidental changes; ensure on-object auditing is configured.
* Use directive controls (banners) to provide legal notice and act as a deterrent.
* Implement corrective automation for critical configuration or data files; schedule and test corrective scripts.
* Replace EOL operating systems prior to loss of vendor support.

---

## References

* Nmap Documentation: [https://nmap.org/docs.html](https://nmap.org/docs.html)
* CIS Benchmarks: [https://www.cisecurity.org/cis-benchmarks](https://www.cisecurity.org/cis-benchmarks)
* NIST SP 800-53: [https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)
* ISO/IEC 27001: [https://www.iso.org/isoiec-27001-information-security.html](https://www.iso.org/isoiec-27001-information-security.html)
* Windows Event IDs and Auditing documentation (Microsoft Docs)

---

## Disclaimer

This documentation is part of a controlled research and development initiative conducted by No Lack LLC. All exercises are intended for lawful, authorized lab environments only. No unauthorized testing or system access was performed. Users must obtain explicit authorization before performing scans or making changes on production networks. Consult applicable policies, governance, and legal counsel prior to deploying directives such as login banners.

---

## Contact

No Lack LLC
Email: [[replace-with-contact@example.com](info@nolackllc.com)]
Repository maintained by No Lack LLC — use issues or pull requests for feedback and contributions.
