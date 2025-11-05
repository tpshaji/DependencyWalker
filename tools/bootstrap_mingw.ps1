# Requires PowerShell 5+
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$root    = Split-Path -Parent $MyInvocation.MyCommand.Path
$zipPath = Join-Path $root 'mingw.zip'
$destDir = Join-Path $root 'mingw'

# WinLibs (GCC 14.2.0 + mingw-w64 12.0.0) prebuilt toolchain (x86_64, posix, seh)
# If this URL ever changes, get a fresh link from: https://github.com/brechtsanders/winlibs_mingw/releases
$url = 'https://github.com/brechtsanders/winlibs_mingw/releases/download/14.2.0-12.0.0-r2/winlibs-x86_64-posix-seh-gcc-14.2.0-mingw-w64-12.0.0-r2.zip'

Write-Host "[INFO] Downloading MinGW-w64 toolchain..." -ForegroundColor Cyan
if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zipPath

Write-Host "[INFO] Extracting MinGW-w64..." -ForegroundColor Cyan
if (Test-Path $destDir) { Remove-Item -Recurse -Force $destDir }
Expand-Archive -Path $zipPath -DestinationPath $destDir -Force

$gcc  = Get-ChildItem -Path $destDir -Recurse -Filter 'gcc.exe'  | Where-Object { $_.FullName -match '\\bin\\gcc\.exe$' }  | Select-Object -First 1
$gpp  = Get-ChildItem -Path $destDir -Recurse -Filter 'g++.exe'  | Where-Object { $_.FullName -match '\\bin\\g\+\+\.exe$' } | Select-Object -First 1
$make = Get-ChildItem -Path $destDir -Recurse -Filter 'mingw32-make.exe' | Select-Object -First 1

if (-not $gcc -or -not $gpp -or -not $make) {
    throw "Missing required tools after extraction. gcc=$($gcc.FullName), g++=$($gpp.FullName), make=$($make.FullName)"
}

Write-Host "[OK] MinGW ready." -ForegroundColor Green
Write-Host ("gcc:  " + $gcc.FullName)
Write-Host ("g++:  " + $gpp.FullName)
Write-Host ("make: " + $make.FullName)

# Also write a small JSON manifest to help scripts locate the tools
$manifest = @{
  gcc  = $gcc.FullName
  gpp  = $gpp.FullName
  make = $make.FullName
}
($manifest | ConvertTo-Json) | Out-File -Encoding UTF8 (Join-Path $root 'mingw.json')
