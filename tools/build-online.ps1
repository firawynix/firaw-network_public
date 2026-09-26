$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
New-Item -ItemType Directory -Force release,site/public/downloads | Out-Null
$version = (Get-Content -Raw package.json | ConvertFrom-Json).version
$source = Join-Path $root "src-tauri/target/release/bundle/nsis/Firaw Network_${version}_x64-setup.exe"
$name = "Firaw-Network-${version}-x64-Setup.exe"
Copy-Item -LiteralPath $source -Destination (Join-Path $root "release/$name")
$full = Get-Item "release/$name"
$signature = Get-AuthenticodeSignature -LiteralPath $full.FullName
if ($signature.Status -ne 'Valid') { throw 'O pacote completo precisa estar assinado e validado.' }
$manifest = @{ version=$version; url="https://ipscan.firawynix.com.br/downloads/$name"; size=$full.Length; sha256=(Get-FileHash -Algorithm SHA256 $full.FullName).Hash.ToLower(); signerThumbprint=$signature.SignerCertificate.Thumbprint }
[IO.File]::WriteAllText((Join-Path $root 'packaging/release.json'), ($manifest | ConvertTo-Json))
$makensis = Join-Path $env:LOCALAPPDATA 'tauri/NSIS/makensis.exe'
& $makensis /INPUTCHARSET UTF8 packaging/online.nsi
if ($LASTEXITCODE -ne 0) { throw 'Falha ao compilar instalador online.' }
& "$PSScriptRoot/sign-windows.ps1" -File 'release/Firaw-Network-Instalador-Online.exe'
& "$PSScriptRoot/sign-windows.ps1" -File 'src-tauri/target/release/FirawNetwork.exe'
Copy-Item release/*.exe site/public/downloads/
Copy-Item packaging/FirawNetwork.cer site/public/downloads/
Copy-Item packaging/release.json site/public/downloads/
$checks = Get-ChildItem site/public/downloads -File | Where-Object Name -ne 'SHA256SUMS.txt' | ForEach-Object { '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLower(),$_.Name }
[IO.File]::WriteAllLines((Join-Path $root 'site/public/downloads/SHA256SUMS.txt'),$checks)
