#Requires -RunAsAdministrator
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'EncryptionAlgorithmRGR'),
    [string]$BuildDir = (Join-Path $PSScriptRoot 'build')
)

$ErrorActionPreference = 'Stop'
$configurationDir = Join-Path $BuildDir 'Release'
if (-not (Test-Path (Join-Path $configurationDir 'encryption_rgr.exe'))) {
    $configurationDir = $BuildDir
}
$sourceExecutable = Join-Path $configurationDir 'encryption_rgr.exe'
$sourceModules = Join-Path $configurationDir 'modules'
if (-not (Test-Path $sourceExecutable) -or
    -not (Test-Path (Join-Path $sourceModules 'cipher_hill.dll')) -or
    -not (Test-Path (Join-Path $sourceModules 'cipher_elgamal.dll'))) {
    throw 'Сначала соберите проект в конфигурации Release.'
}

$modulesDir = Join-Path $InstallDir 'modules'
New-Item -ItemType Directory -Force -Path $modulesDir | Out-Null
Copy-Item -Force $sourceExecutable (Join-Path $InstallDir 'encryption_rgr.exe')
Copy-Item -Force (Join-Path $sourceModules '*.dll') $modulesDir

$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$pathParts = @($machinePath -split ';' | Where-Object { $_ -ne '' })
if (-not ($pathParts | Where-Object { $_.TrimEnd('\') -ieq $InstallDir.TrimEnd('\') })) {
    $pathParts += $InstallDir
    [Environment]::SetEnvironmentVariable('Path', ($pathParts -join ';'), 'Machine')
}
$env:Path = "$InstallDir;$env:Path"
Write-Host "Программа установлена в $InstallDir. Запуск: encryption_rgr.exe --help"
