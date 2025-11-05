# Requires PowerShell 5+
$ErrorActionPreference = 'Stop'

# Ensure TLS 1.2 for GitHub
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

$zipPath  = Join-Path $PSScriptRoot 'cmake.zip'
$destDir  = Join-Path $PSScriptRoot 'cmake'
$url      = 'https://github.com/Kitware/CMake/releases/download/v4.1.2/cmake-4.1.2-windows-x86_64.zip'

Write-Host "[INFO] Downloading portable CMake..." -ForegroundColor Cyan
if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zipPath

Write-Host "[INFO] Extracting portable CMake..." -ForegroundColor Cyan
if (Test-Path $destDir) { Remove-Item -Recurse -Force $destDir }
Expand-Archive -Path $zipPath -DestinationPath $destDir -Force

$cm = Get-ChildItem -Path $destDir -Recurse -Filter 'cmake.exe' | Where-Object { $_.FullName -match '\\bin\\cmake\.exe$' } | Select-Object -First 1
if (-not $cm) {
    throw "cmake.exe not found after extraction under: $destDir"
}

& $cm.FullName --version

# Configure the project with VS 2022 generator (x64)
$workspace = Split-Path -Parent $PSScriptRoot
$buildDir  = Join-Path $workspace 'build\vs2022-x64'
Write-Host "[INFO] Configuring project at $workspace" -ForegroundColor Cyan
& $cm.FullName -S $workspace -B $buildDir -G 'Visual Studio 17 2022' -A x64
