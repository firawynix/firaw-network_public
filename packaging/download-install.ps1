param([switch]$VerifyOnly)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$temp = Join-Path ([IO.Path]::GetTempPath()) ('FirawNetwork-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
  if (-not [Environment]::Is64BitOperatingSystem) { throw 'Esta versão requer Windows 64 bits.' }
  $manifest = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'release.json') | ConvertFrom-Json
  $uri = [Uri]$manifest.url
  if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'ipscan.firawynix.com.br') { throw 'Origem de instalação inválida.' }
  $setup = Join-Path $temp 'setup.exe'
  Invoke-WebRequest -UseBasicParsing -Uri $uri.AbsoluteUri -OutFile $setup -TimeoutSec 300
  if ((Get-Item -LiteralPath $setup).Length -ne $manifest.size) { throw 'Tamanho do download não confere.' }
  if ((Get-FileHash -Algorithm SHA256 -LiteralPath $setup).Hash -ne $manifest.sha256) { throw 'SHA-256 do instalador não confere.' }
  $signature = Get-AuthenticodeSignature -LiteralPath $setup
  if ($signature.SignerCertificate.Thumbprint -ne $manifest.signerThumbprint -or $signature.Status -notin @('Valid','NotTrusted')) { throw 'Assinatura do instalador inválida.' }
  if ($VerifyOnly) { Write-Output 'Download, SHA-256 e assinatura verificados.'; exit 0 }
  $process = Start-Process -FilePath $setup -ArgumentList '/S' -WindowStyle Hidden -Wait -PassThru
  if ($process.ExitCode -notin @(0,3010)) { throw "Instalação terminou com erro $($process.ExitCode)." }
  exit 0
} catch {
  [IO.File]::WriteAllText((Join-Path ([IO.Path]::GetTempPath()) 'FirawNetwork-install-error.txt'), $_.Exception.Message)
  exit 1
} finally {
  $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
  $resolved = [IO.Path]::GetFullPath($temp)
  if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -notmatch '^FirawNetwork-[a-f0-9]{32}$') { throw 'Pasta temporária inválida.' }
  if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
