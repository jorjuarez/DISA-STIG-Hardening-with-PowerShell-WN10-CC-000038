# Windows STIG Hardening Script - WN10-CC-000038

## Overview
This repository contains a PowerShell script designed to automate the remediation of security findings based on the Defense Information Systems Agency (DISA) Security Technical Implementation Guides (STIGs) for Windows systems.

The goal of this script is to provide a reliable and efficient way to apply security configurations, ensuring compliance and hardening systems against vulnerabilities.

---

## Script
This repository contains the script for the following STIG:

| STIG ID | Description | Script File |
| :--- | :--- | :--- |
| **WN10-CC-000038** | WDigest Authentication must be disabled. | [`Set-StigCompliance.WN10-CC-000038.ps1`](https://github.com/jorjuarez/DISA-STIG-Hardening-with-PowerShell-WN10-CC-000038/blob/main/STIG-ID-WN10-CC-000038.ps1) |

---

## Usage
The script is designed to be run individually with administrative privileges in a PowerShell console.

**Example:**

To apply the remediation for STIG `WN10-CC-000038`:

```powershell
# First, open PowerShell as an Administrator.

# Navigate to the folder where you saved the script.
cd C:\Path\To\Your\Scripts

# If you downloaded the script from the internet, unblock it first.
Unblock-File -Path '.\Set-StigCompliance.WN10-CC-000038.ps1'

# Execute the script to apply the remediation.
.\'Set-StigCompliance.WN10-CC-000038.ps1'
```

---
## Disclaimer
This script is provided as-is. Always test it in a non-production environment before deploying to live systems. The user assumes all risk associated with running this script.

---
## Connect With Me
* **LinkedIn:** linkedin.com/in/jorgejuarez1
* **GitHub:** github.com/jorjuarez
