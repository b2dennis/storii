# Registers storii with Windows as a passkey provider (Windows 11 25H2 or later). Windows only accepts providers
# with a package identity, so this signs a small "sparse" package for the storii folder with a certificate made on
# this PC and installs it. Run it from the storii folder in PowerShell:
#
#   powershell -ExecutionPolicy Bypass -File .\passkeys\install-passkeys.ps1
#   powershell -ExecutionPolicy Bypass -File .\passkeys\install-passkeys.ps1 -Uninstall
#
# It asks for administrator rights once, to trust the certificate. It needs makeappx.exe and signtool.exe from the
# Windows SDK (https://developer.microsoft.com/windows/downloads/windows-sdk/). Afterwards start storii again, choose
# "Use for passkeys in Windows" in its tray menu and turn storii on in Settings > Accounts > Passkeys > Advanced options.
param([switch]$Uninstall)
$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$storii = Split-Path $here -Parent
$subject = 'CN=storii'

if ($Uninstall) {
    Get-Process storii-tray -ErrorAction SilentlyContinue | Stop-Process
    Get-AppxPackage -Name storii | Remove-AppxPackage
    Write-Host 'Removed (first untick "Use for passkeys in Windows" in the tray menu, if you had it on). The certificate stays trusted; remove "storii" from certmgr (Trusted People) if you like.'
    exit
}

$exe = Join-Path $storii 'storii-tray.exe'
if (-not (Test-Path $exe)) { throw "storii-tray.exe isn't in $storii. Keep the passkeys folder inside the storii folder." }

$kit = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64" -Directory -ErrorAction SilentlyContinue |
    Where-Object { (Test-Path "$_\makeappx.exe") -and (Test-Path "$_\signtool.exe") } |
    Sort-Object { [version](Split-Path (Split-Path $_ -Parent) -Leaf) } | Select-Object -Last 1
if (-not $kit) {
    throw 'makeappx.exe and signtool.exe are missing. Install the Windows SDK (https://developer.microsoft.com/windows/downloads/windows-sdk/) and run this again.'
}

# The certificate, made once and kept in the user's store.
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq $subject -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) } |
    Sort-Object NotAfter | Select-Object -Last 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type Custom -Subject $subject -KeyUsage DigitalSignature -FriendlyName 'storii passkeys' `
        -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(10) `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')
}
$trusted = Get-ChildItem Cert:\LocalMachine\TrustedPeople | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
if (-not $trusted) {
    $cer = Join-Path $env:TEMP 'storii-passkeys.cer'
    Export-Certificate -Cert $cert -FilePath $cer | Out-Null
    Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile', '-Command',
        "Import-Certificate -FilePath '$cer' -CertStoreLocation Cert:\LocalMachine\TrustedPeople | Out-Null"
    Remove-Item $cer
    if (-not (Get-ChildItem Cert:\LocalMachine\TrustedPeople | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })) {
        throw "The certificate wasn't trusted (the administrator prompt was declined?)."
    }
}

# Stage, pack and sign the package. Its version follows the exe's.
$v = [version](Get-Item $exe).VersionInfo.FileVersion
$version = '{0}.{1}.{2}.0' -f $v.Major, $v.Minor, [math]::Max($v.Build, 0)
$stage = Join-Path $env:TEMP 'storii-passkeys'
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory "$stage\passkeys\Assets" | Out-Null
(Get-Content "$here\AppxManifest.xml" -Raw).Replace('Version="VERSION"', "Version=""$version""") |
    Set-Content "$stage\AppxManifest.xml" -Encoding UTF8
Copy-Item "$here\Assets\*" "$stage\passkeys\Assets"
$msix = Join-Path $env:TEMP 'storii-passkeys.msix'
& "$kit\makeappx.exe" pack /o /d $stage /p $msix /nv | Out-Null
if ($LASTEXITCODE) { throw "makeappx failed ($LASTEXITCODE)" }
& "$kit\signtool.exe" sign /q /fd SHA256 /sha1 $cert.Thumbprint $msix
if ($LASTEXITCODE) { throw "signtool failed ($LASTEXITCODE)" }

Get-Process storii-tray -ErrorAction SilentlyContinue | Stop-Process
Get-AppxPackage -Name storii | Remove-AppxPackage
Add-AppxPackage -Path $msix -ExternalLocation $storii
Remove-Item $stage -Recurse -Force
Remove-Item $msix
Start-Process $exe
Write-Host 'Done. In the storii tray menu, choose "Use for passkeys in Windows".'
