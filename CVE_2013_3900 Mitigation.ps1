 <# This Script follows CVE mitigation notes to resolve WinVerifyTrust Signature Validation CVE-2013-3900 Mitigation EnableCertPaddingCheck 
 This showed up in the Win Server Vuln Management course project as of 1/15/25
 #>

 # Define the registry paths and values
$registryPaths = @(
    "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config",
    "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"
)

$registryValueName = "EnableCertPaddingCheck"
$registryValueData = 1

# Function to ensure the registry key and value exist
function Set-RegistryValue {
    param(
        [string]$path,
        [string]$valueName,
        [int]$valueData
    )
    
    # Check if the registry path exists
    if (-not (Test-Path $path)) {
        Write-Host "Creating registry path: $path"
        New-Item -Path $path -Force | Out-Null
    }

    # Set the registry value
    Write-Host "Setting registry value: $path\$valueName to $valueData"
    Set-ItemProperty -Path $path -Name $valueName -Value $valueData -Force
}

# Remediate registry for both 32-bit and 64-bit paths
foreach ($path in $registryPaths) {
    Set-RegistryValue -path $path -valueName $registryValueName -valueData $registryValueData
}

Write-Host "Well done, you. CVE-2013-3900 remediation complete: EnableCertPaddingCheck has been enabled."

# This Restarts the Cryptographic Services to immediately apply registry changes
Restart-Service -Name CryptSvc
Write-Host "Cryptographic Services restarted. Changes should be applied. Restarting is likely not required before vulnerability scanning."
