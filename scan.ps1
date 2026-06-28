# Phishing Email Triage Scanner (PowerShell)
# Usage:  .\scan.ps1 "C:\path\to\email.eml"   (file or folder)
param([Parameter(Mandatory=$false)][string]$Target)

$proj = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Target) { $Target = Read-Host "Path to .eml file or folder" }
if (-not $Target) { Write-Host "No path given."; exit 1 }

Push-Location $proj
try {
  if (Test-Path $Target -PathType Container) {
    python -m phishtriage batch "$Target" -o "$proj\reports"
    Invoke-Item "$proj\reports\SUMMARY.md"
  } else {
    python -m phishtriage analyze "$Target" -f all -o "$proj\reports"
    $stem = [System.IO.Path]::GetFileNameWithoutExtension($Target)
    $html = "$proj\reports\$stem.report.html"
    if (Test-Path $html) { Invoke-Item $html }
  }
} finally { Pop-Location }
