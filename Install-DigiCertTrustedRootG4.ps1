<#
.SYNOPSIS
    Downloads DigiCert root certificates and installs them into the Local
    Machine Trusted Root Certification Authorities store.

.DESCRIPTION
    Compatible with Windows PowerShell 5.1.
    - Forces TLS 1.2 for downloads (required by DigiCert).
    - Verifies each downloaded certificate's SHA-1 thumbprint against the
      known expected thumbprint before installation.
    - Idempotent: skips certificates that are already present.
    - Requires elevation (Administrator) to write to LocalMachine\Root.

.NOTES
    Certificates installed:
      - DigiCert Trusted Root G4   (DDFB16CD4931C973A2037D3FC83A4D7D775D05E4)
      - DigiCert Assured ID Root CA (0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43)
#>

[CmdletBinding()]
param(
    [string]$WorkDir = (Join-Path $env:TEMP 'DigiCertRoots')
)

$ErrorActionPreference = 'Stop'

# --- Certificate manifest -------------------------------------------------
$Certificates = @(
    [pscustomobject]@{
        Name       = 'DigiCert Trusted Root G4'
        Url        = 'https://cacerts.digicert.com/DigiCertTrustedRootG4.crt'
        FileName   = 'DigiCertTrustedRootG4.crt'
        Thumbprint = 'DDFB16CD4931C973A2037D3FC83A4D7D775D05E4'
    },
    [pscustomobject]@{
        Name       = 'DigiCert Assured ID Root CA'
        Url        = 'https://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt'
        FileName   = 'DigiCertAssuredIDRootCA.crt'
        Thumbprint = '0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43'
    }
)

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

# --- Force TLS 1.2 for downloads ------------------------------------------
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    Write-Warning "Unable to set TLS 1.2: $($_.Exception.Message)"
}

# --- Open root store once for all writes ----------------------------------
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    [System.Security.Cryptography.X509Certificates.StoreName]::Root,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
)
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

try {
    foreach ($entry in $Certificates) {
        Write-Host ""
        Write-Host "=== $($entry.Name) ===" -ForegroundColor Cyan

        $certPath = Join-Path $WorkDir $entry.FileName

        # Download
        Write-Host "[*] Downloading from $($entry.Url)"
        Invoke-WebRequest -Uri $entry.Url -OutFile $certPath -UseBasicParsing

        if (-not (Test-Path -LiteralPath $certPath)) {
            Write-Warning "Download failed for $($entry.Name); file not found at $certPath. Skipping."
            continue
        }

        # Load and inspect
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($certPath)

        Write-Host "[*] Subject:    $($cert.Subject)"
        Write-Host "[*] Issuer:     $($cert.Issuer)"
        Write-Host "[*] NotBefore:  $($cert.NotBefore)"
        Write-Host "[*] NotAfter:   $($cert.NotAfter)"
        Write-Host "[*] Thumbprint: $($cert.Thumbprint)"

        # Verify thumbprint
        if ($cert.Thumbprint -ne $entry.Thumbprint.ToUpper()) {
            Write-Warning ("Thumbprint mismatch for {0}. Expected {1}, got {2}. Skipping install." -f `
                $entry.Name, $entry.Thumbprint, $cert.Thumbprint)
            continue
        }
        Write-Host "[+] Thumbprint verified." -ForegroundColor Green

        # Install if not already present
        $existing = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
        if ($existing) {
            Write-Host "[=] Already present in LocalMachine\Root. No action taken." -ForegroundColor Yellow
        } else {
            $store.Add($cert)
            Write-Host "[+] Installed into LocalMachine\Root." -ForegroundColor Green
        }
    }
}
finally {
    $store.Close()
}

Write-Host ""
Write-Host "[*] Done." -ForegroundColor Cyan
