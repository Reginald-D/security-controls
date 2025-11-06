
# Implementing Security Controls  
**Author:** Reginald D  
**Category:** Cybersecurity Research | System Hardening | Access Control  

---

## 🏁 Introduction

Welcome to the **No Lack LLC Cybersecurity Research & Development Repository**, where we explore and document real-world implementations of defensive security mechanisms.  
This project focuses on the **design, configuration, and validation of security controls** within enterprise environments.  
Through controlled experimentation, this research demonstrates how **preventive**, **detective**, **directive**, and **corrective** controls are applied to protect organizational assets, strengthen compliance, and mitigate cyber risk.

> *"No Lack in Knowledge. No Lack in Security."* — No Lack LLC

---

##  Overview

Security controls are the backbone of cybersecurity operations.  
They safeguard sensitive information, secure access to systems, and reduce exposure to threats.  
This documentation walks through a complete lab scenario demonstrating the application of multiple control types within a Windows Server 2019 domain environment.

Each control type addresses a unique aspect of cybersecurity defense:
- **Preventive:** Stops unwanted activity before it occurs  
- **Detective:** Identifies and logs security-relevant events  
- **Directive:** Informs or directs user behavior through policies and warnings  
- **Corrective:** Restores systems or data after detecting issues  

---

## Environment & Tools

- **Client System:** PC10 (Windows Server 2019)
- **Domain Controller:** DC10 (Active Directory Enabled)
- **Lab Resources:**  
  - `\\10.1.16.1\TOOLS` shared folder  
  - `LABFILES` directory  
  - Windows Event Viewer  
  - Windows Local Security Policy  
  - PowerShell  
  - Sysinternals Utilities  

---

## Preventive Controls

**Objective:** Restrict unauthorized users from accessing administrative file shares.

1. Log into the **DC10 Domain Controller**.  
2. Navigate to:
```

File and Storage Services > Shares

````
3. Right-click **TOOLS**, select **Properties → Permissions → Customize permissions**.  
4. Disable inheritance and **remove the Domain Users and Everyone groups**.  
5. Retain only **Domain Admins** and **LocalAdmin** groups for access.

>  **Result:** Unauthorized user “Sam” is denied access, while “Jaime” (LocalAdmin group) can access the TOOLS share successfully.  
> This demonstrates the enforcement of **principle of least privilege**.

---

## Detective Controls

**Objective:** Enable file deletion auditing and verify event logging in Windows Security Logs.

1. Log into **PC10** as **Jaime (LocalAdmin)**.  
2. Delete a folder (e.g., `LABFILES\empty`) to simulate an action.  
3. Open **Event Viewer → Windows Logs → Security**.  
4. Use **Find (Ctrl+F)** → search for *Event ID 4660* (object deletion).  
- If not found, configure **Audit Object Access** in *Local Security Policy*:
  ```
  Local Policies → Audit Policy → Audit Object Access
  Enable Success and Failure
  ```
5. Configure on-object auditing:
````

LABFILES > Properties > Security > Advanced > Auditing
Add → Principal: Everyone
Advanced permissions: Delete subfolders and files, Delete

````

> 🔎 **Result:**  
> Event IDs **4660** and **4663** confirm the deletion and object name.  
> This validates that auditing detects file access and modification events as expected.

---

##  Directive Controls

**Objective:** Display a login banner with acceptable use policy (AUP) information.

Execute the following PowerShell commands as an administrator:

```powershell
$BannerText = "This computer system is the property of Structureality Inc. It is for authorized use only. By using this system, all users acknowledge notice of and agree to comply with the Acceptable Use Policy (AUP). Unauthorized or improper use of this system may result in disciplinary action, civil/criminal penalties, and/or other sanctions set forth in the AUP. By continuing to use this system, you indicate your awareness of and consent to these terms and conditions. If you are located in the European Union, you may have additional rights under the GDPR."

New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption" -Value "Authorized Use Only" -PropertyType "String" -Force | Out-Null
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext" -Value $BannerText -PropertyType "String" -Force | Out-Null
````

> 🧾 **Result:** Upon next login, a security banner is displayed.
> This **directive control** provides users with clear policy awareness and legal notification.

---

## Corrective Controls

**Objective:** Implement a corrective mechanism that detects file tampering and restores it to its original state.

### Step 1: Create and Hash a File

```powershell
"This is important" | Set-Content notes.txt
Get-FileHash ./notes.txt -Algorithm SHA256 | Select-Object -ExpandProperty Hash | Set-Content ./hash.txt
```

### Step 2: Simulate Unauthorized Change

```powershell
echo blah >> notes.txt
if((Get-FileHash ./notes.txt -Algorithm SHA256).Hash -eq (Get-Content ./hash.txt)) {
  Write-Host "The file is correct."
} else {
  Write-Host "The file has changed. Corrective action should be initiated."
}
```

### Step 3: Manual Correction

```powershell
"This is important" | Set-Content notes.txt
```

### Step 4: Automate Correction with PowerShell Script

#### `calchash.ps1`

```powershell
Get-FileHash ./notes.txt -Algorithm SHA256 | Select-Object -ExpandProperty Hash | Set-Content ./hash.txt
```

#### `check.ps1`

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

> ⚙️ **Result:** When the file is modified, the script detects the change and restores the correct content automatically — demonstrating a **self-healing corrective control**.

---

## 🧩 Additional Control Types

| Control Type     | Purpose                         | Example                          |
| ---------------- | ------------------------------- | -------------------------------- |
| **Deterrent**    | Discourages malicious behavior  | Warning signs, login banners     |
| **Compensating** | Provides alternative protection | Data backups, redundancy systems |

---

## 📚 References

* [NIST SP 800-53 Rev.5 – Security and Privacy Controls](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)
* [CIS Controls Framework](https://www.cisecurity.org/controls)
* [Microsoft Security Auditing Overview](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-object-access)

---

## 🧾 Disclaimer

This documentation is part of a **structured research and development initiative** conducted by **No Lack LLC** to enhance cybersecurity awareness and professional skill development.
All exercises were performed in a **controlled, lawful lab environment** aligned with **NIST**, **ISO**, and **CIS** standards.
No unauthorized testing or exploitation was performed.
This project supports ethical hacking education and organizational readiness.

---

##  About No Lack LLC

**No Lack LLC** (est. 2020) is an IT and Cybersecurity Consulting firm specializing in:

* IT Infrastructure & Security Architecture
* Cyber Threat Analysis
* Compliance & Hardening (STIG, CIS, NIST)
* Automation & Script Development

> Empowering businesses to secure their digital assets with precision, integrity, and innovation.
