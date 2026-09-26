$ErrorActionPreference = 'Stop'
$path = Join-Path $PSScriptRoot 'FirawNetwork.cer'
$cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($path)
if ($cert.Thumbprint -ne '668BEF56480FCA8EB1B0BC3B102A6A9CEC554CC4') { throw 'Certificado diferente do esperado.' }
Import-Certificate -FilePath $path -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
Import-Certificate -FilePath $path -CertStoreLocation Cert:\CurrentUser\TrustedPublisher | Out-Null
