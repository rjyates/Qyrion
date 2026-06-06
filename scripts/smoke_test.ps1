$ErrorActionPreference = "Stop"

Write-Host "Checking Qyrion CLI..."
python qyrion.py --help | Out-Null
python qyrion.py cbom --help | Out-Null
python qyrion.py evidence --help | Out-Null

Write-Host "Checking website files..."
$requiredFiles = @(
  "website/index.html",
  "website/styles.css",
  "website/script.js",
  "website/quantum-security-101.html"
)

foreach ($file in $requiredFiles) {
  if (-not (Test-Path $file)) {
    throw "Missing required file: $file"
  }
}

$sampleCbom = Get-ChildItem -Path "reports" -Filter "qyrion-cbom-*.json" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($sampleCbom) {
  Write-Host "Checking evidence pack generation with $($sampleCbom.Name)..."
  python qyrion.py evidence $sampleCbom.FullName | Out-Null
}

Write-Host "Qyrion smoke test passed."
