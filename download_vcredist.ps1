param(
    [string]$OutputPath = "assets\\vcredist_x64.exe"
)

$sourceUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
$destPath = Join-Path -Path $PSScriptRoot -ChildPath $OutputPath
$destDir = Split-Path -Path $destPath -Parent

if (-not (Test-Path -Path $destDir)) {
    New-Item -ItemType Directory -Path $destDir | Out-Null
}

Write-Host "Downloading VC++ runtime to $destPath"
Invoke-WebRequest -Uri $sourceUrl -OutFile $destPath
Write-Host "Done."
