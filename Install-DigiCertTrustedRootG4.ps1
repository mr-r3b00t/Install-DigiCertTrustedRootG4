<#
.SYNOPSIS
    Downloads the DigiCert Trusted Root G4 certificate and installs it into the
    Local Machine Trusted Root Certification Authorities store.

.DESCRIPTION
    Compatible with Windows PowerShell 5.1.
    - Forces TLS 1.2 for the download (required by DigiCert).
    - Verifies the downloaded certificate's SHA-1 thumbprint against the known
      DigiCert Trusted Root G4 thumbprint before installation.
    - Requires elevation (Administrator) to write to the LocalMachine\Root store.

.NOTES
    Expected SHA-1 Thumbprint: DDFB16CD4931C973A2037D3FC83A4D7D775D05E4
#>

[CmdletBinding()]
param(
    [string]$Url       = 'https://cacerts.digicert.com/DigiCertTrustedRootG4.crt',
    [string]$WorkDir   = (Join-Path $env:TEMP 'DigiCertRootG4'),
    [string]$Expected  = 'DDFB16CD4931C973A2037D3FC83A4D7D775D05E4'
)

$ErrorActionPreference = 'Stop'

# --- Elevation check -------------------------------------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This script must be run as Administrator to modify the LocalMachine root store.'
}

# --- Prepare working directory --------------------------------------------
if (-not (Test-Path -LiteralPath $WorkDir)) {
    New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null
}
$certPath = Join-Path $WorkDir 'DigiCertTrustedRootG4.crt'

# --- Force TLS 1.2 for the download ---------------------------------------
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    Write-Warning "Unable to set TLS 1.2: $($_.Exception.Message)"
}

# --- Download -------------------------------------------------------------
Write-Host "[*] Downloading certificate from $Url" -ForegroundColor Cyan
Invoke-WebRequest -Uri $Url -OutFile $certPath -UseBasicParsing

if (-not (Test-Path -LiteralPath $certPath)) {
    throw "Download failed; file not found at $certPath."
}

# --- Load and verify thumbprint -------------------------------------------
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import($certPath)

Write-Host "[*] Subject:    $($cert.Subject)"
Write-Host "[*] Issuer:     $($cert.Issuer)"
Write-Host "[*] NotBefore:  $($cert.NotBefore)"
Write-Host "[*] NotAfter:   $($cert.NotAfter)"
Write-Host "[*] Thumbprint: $($cert.Thumbprint)"

if ($cert.Thumbprint -ne $Expected.ToUpper()) {
    throw "Thumbprint mismatch. Expected $Expected but got $($cert.Thumbprint). Aborting."
}
Write-Host "[+] Thumbprint verified against expected value." -ForegroundColor Green

# --- Install into LocalMachine\Root ---------------------------------------
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    [System.Security.Cryptography.X509Certificates.StoreName]::Root,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
)

try {
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

    $existing = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
    if ($existing) {
        Write-Host "[=] Certificate already present in LocalMachine\Root. No action taken." -ForegroundColor Yellow
    } else {
        $store.Add($cert)
        Write-Host "[+] Certificate installed into LocalMachine\Root." -ForegroundColor Green
    }
}
finally {
    $store.Close()
}

Write-Host "[*] Done." -ForegroundColor Cyan
