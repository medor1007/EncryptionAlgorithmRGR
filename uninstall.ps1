#Requires -RunAsAdministrator
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'EncryptionAlgorithmRGR')
)

$ErrorActionPreference = 'Stop'
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$pathParts = @($machinePath -split ';' | Where-Object {
    $_ -ne '' -and $_.TrimEnd('\') -ine $InstallDir.TrimEnd('\')
})
[Environment]::SetEnvironmentVariable('Path', ($pathParts -join ';'), 'Machine')
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue -LiteralPath $InstallDir
Write-Host 'Программа удалена. Пользовательские файлы и ключи не затронуты.'
