# make_test_cert.ps1 - generate a VALID self-signed code-signing cert for test-signing
# the driver in the VM. Exports certificates\knetdbg_test.pfx (+ .cer for trusting).
# (The provided Thawte cert expired in 2014 and cannot sign a loadable driver.)
param(
    [string]$OutDir   = (Join-Path $PSScriptRoot "..\certificates"),
    [string]$Password = "knetdbg"
)

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force $OutDir | Out-Null }

$cert = New-SelfSignedCertificate -Type CodeSigningCert `
    -Subject "CN=knetdbg test signing,O=knetdbg" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyUsage DigitalSignature -KeyExportPolicy Exportable `
    -NotAfter (Get-Date).AddYears(5)

$pw  = ConvertTo-SecureString $Password -AsPlainText -Force
$pfx = Join-Path $OutDir "knetdbg_test.pfx"
$cer = Join-Path $OutDir "knetdbg_test.cer"
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $pw | Out-Null
Export-Certificate    -Cert $cert -FilePath $cer | Out-Null

Write-Host "Generated $pfx  (password: $Password)"
Write-Host ""
Write-Host "In the analysis VM (elevated) trust it and enable test-signing, then load:"
Write-Host "  certutil -addstore Root `"$cer`""
Write-Host "  certutil -addstore TrustedPublisher `"$cer`""
Write-Host "  bcdedit /set testsigning on   (reboot afterwards)"
