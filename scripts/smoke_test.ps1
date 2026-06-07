$ErrorActionPreference = "Stop"

$pythonCandidates = @(
  $env:QYRION_PYTHON,
  "python",
  "py",
  "$env:USERPROFILE\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
) | Where-Object { $_ }

$python = $null
foreach ($candidate in $pythonCandidates) {
  if (Test-Path $candidate) {
    $python = $candidate
    break
  }

  $command = Get-Command $candidate -ErrorAction SilentlyContinue
  if ($command) {
    $python = $command.Source
    break
  }
}

if (-not $python) {
  throw "Python was not found. Install Python or set QYRION_PYTHON to a python.exe path."
}

Write-Host "Checking Qyrion CLI..."
& $python qyrion.py --help | Out-Null
& $python qyrion.py cbom --help | Out-Null
& $python qyrion.py evidence --help | Out-Null

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
  & $python qyrion.py evidence $sampleCbom.FullName | Out-Null
}

Write-Host "Qyrion smoke test passed."
