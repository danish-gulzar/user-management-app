$sslDir = Join-Path -Path $PSScriptRoot -ChildPath "..\ssl"
$keyFile = Join-Path -Path $sslDir -ChildPath "key.pem"
$certFile = Join-Path -Path $sslDir -ChildPath "cert.pem"

if ((Test-Path -LiteralPath $keyFile) -and (Test-Path -LiteralPath $certFile)) {
  Write-Host "SSL certificates already exist at $sslDir"
  exit 0
}

if (-not (Test-Path -LiteralPath $sslDir)) {
  New-Item -ItemType Directory -Path $sslDir -Force | Out-Null
}

try {
  $openssl = Get-Command openssl -ErrorAction Stop
  & $openssl req -x509 -newkey rsa:2048 -keyout $keyFile -out $certFile -days 365 -nodes -subj "/CN=localhost"
  Write-Host "SSL certificates generated successfully at $sslDir"
} catch {
  Write-Host "OpenSSL not found. Install OpenSSL for Windows from https://slproweb.com/products/Win32OpenSSL.html"
  Write-Host "Or use WSL: openssl req -x509 -newkey rsa:2048 -keyout $keyFile -out $certFile -days 365 -nodes -subj '/CN=localhost'"
  exit 1
}
