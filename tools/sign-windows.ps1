param([Parameter(Mandatory=$true)][string]$File)
$ErrorActionPreference = 'Stop'
$thumb = $env:FIRAW_SIGNING_THUMBPRINT
if (-not $thumb) { $thumb = '668BEF56480FCA8EB1B0BC3B102A6A9CEC554CC4' }
$tool = $env:FIRAW_SIGNTOOL
if (-not $tool) {
  $tool = Get-ChildItem 'C:/Program Files (x86)/Windows Kits/10/bin' -Filter signtool.exe -Recurse | Where-Object FullName -Match '/x64/|\\x64\\' | Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $tool) { throw 'Windows SDK / signtool necessário para assinar a versão.' }
& $tool sign /fd SHA256 /sha1 $thumb /tr http://timestamp.digicert.com /td SHA256 $File
if ($LASTEXITCODE -ne 0) { throw "Falha ao assinar: $File" }
$signature = Get-AuthenticodeSignature -LiteralPath $File
if ($signature.SignerCertificate.Thumbprint -ne $thumb) { throw 'Assinatura diferente da esperada.' }
