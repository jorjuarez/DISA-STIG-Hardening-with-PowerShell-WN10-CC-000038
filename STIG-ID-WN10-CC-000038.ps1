<#
.SYNOPSIS
    Disables WDigest Authentication to prevent plaintext passwords from being stored in memory.

.DESCRIPTION
    This script remediates the DISA STIG finding WN10-CC-000038 by setting a registry value.
    It ensures that the registry key 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest'
    has the DWORD value 'UseLogonCredential' set to '0'. This prevents the Local Security
    Authority Subsystem Service (LSASS) from storing credentials in plain text.

.NOTES
    Author          : Jorge Juarez
    LinkedIn        : linkedin.com/in/jorgejuarez1
    GitHub          : github.com/jorjuarez
    Date Created    : 2025-07-14
    Last Modified   : 2025-07-14
    Version         : 1.0
    STIG-ID         : WN10-CC-000038
    Vulnerability-ID: V-220800

.LINK
    https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220800

.EXAMPLE
    PS C:\> .\'Set-StigCompliance.WN10-CC-000038.ps1'

    Executes the script from an elevated PowerShell prompt to apply the remediation.

.REQUIREMENTS
    - Requires administrative privileges to modify the HKLM registry hive.
    - Designed for Windows 10 and later.
#>

# --- Start of Script ---

# This command ensures that the script will stop if any command fails.
$ErrorActionPreference = "Stop"

# --- Configuration Parameters ---
$RegPath      = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest"
$ValueName    = "UseLogonCredential"
$ValueData    = 0
$ValueType    = "DWord"

# --- Main Logic ---
Write-Host "--- Applying STIG WN10-CC-000038 Remediation ---" -ForegroundColor Yellow

try {
    # Step 1: Check if the Wdigest registry key exists. If not, create it.
    if (-not (Test-Path $RegPath)) {
        Write-Host "Registry path not found. Creating path: $RegPath"
        New-Item -Path $RegPath -Force | Out-Null
    } else {
        Write-Host "Registry path already exists: $RegPath"
    }

    # Step 2: Set the 'UseLogonCredential' DWORD value to 0.
    Write-Host "Setting '$ValueName' to '$ValueData' at path '$RegPath'."
    Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ValueData -Type $ValueType -Force
    Write-Host "'$ValueName' has been set successfully." -ForegroundColor Green
}
catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    # The script will stop here due to $ErrorActionPreference.
}

# --- Verification ---
Write-Host "`n--- Verifying Changes ---" -ForegroundColor Yellow
try {
    $currentValue = (Get-ItemProperty -Path $RegPath -Name $ValueName).$ValueName
    Write-Host "Current value of '$ValueName' is: $currentValue"

    if ($currentValue -eq $ValueData) {
        Write-Host "SUCCESS: Remediation for WN10-CC-000038 applied and verified." -ForegroundColor Green
    } else {
        Write-Warning "WARNING: Verification failed. The value is not set to the required state."
    }
}
catch {
    # This catch block will trigger if the value/key doesn't exist after attempting to set it.
    Write-Error "Failed to verify registry value. An error occurred: $($_.Exception.Message)"
}

Write-Host "`n--- Script Complete ---"

# --- End of Script ---
