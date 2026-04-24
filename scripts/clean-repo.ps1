$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

function Remove-IfExists {
  param([string]$Path)
  if (Test-Path -LiteralPath $Path) {
    Remove-Item -LiteralPath $Path -Recurse -Force
  }
}

function Clear-DirButKeepGitkeep {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    return
  }

  Get-ChildItem -LiteralPath $Path -Force | Where-Object {
    $_.Name -ne ".gitkeep"
  } | Remove-Item -Recurse -Force
}

Set-Location $repoRoot

Remove-IfExists (Join-Path $repoRoot "data\chunks")
Remove-IfExists (Join-Path $repoRoot "data\test")

$oldTrainFiles = @(
  "data\train\benign.pcap",
  "data\train\benign_150k.pcap",
  "data\train\benign_400k.pcap",
  "data\train\benign_smoke.pcap",
  "data\train\Thursday-WorkingHours.pcap",
  "data\train\mini_normal_test.pcap",
  "data\train\normal_sim.pcap"
)
foreach ($file in $oldTrainFiles) {
  Remove-IfExists (Join-Path $repoRoot $file)
}

Clear-DirButKeepGitkeep (Join-Path $repoRoot "data\live_in")
Clear-DirButKeepGitkeep (Join-Path $repoRoot "data\live_done")
Clear-DirButKeepGitkeep (Join-Path $repoRoot "data\live_error")
Clear-DirButKeepGitkeep (Join-Path $repoRoot "logs\live")
Clear-DirButKeepGitkeep (Join-Path $repoRoot "logs\offline")
Clear-DirButKeepGitkeep (Join-Path $repoRoot "output")

$oldModelFiles = @(
  "model\model_smoke.pkl",
  "model\model_eval.pkl",
  "model\meta_smoke.json",
  "model\meta_eval.json"
)
foreach ($file in $oldModelFiles) {
  Remove-IfExists (Join-Path $repoRoot $file)
}

Remove-IfExists (Join-Path $repoRoot "dashboard\__pycache__")
Remove-IfExists (Join-Path $repoRoot "pipeline\__pycache__")
Remove-IfExists (Join-Path $repoRoot "simulation\__pycache__")
Remove-IfExists (Join-Path $repoRoot "suricata\lib\cache")
Remove-IfExists (Join-Path $repoRoot "suricata\lib\update\cache")
Remove-IfExists (Join-Path $repoRoot "-b")
Remove-IfExists (Join-Path $repoRoot '$null')
Remove-IfExists (Join-Path $repoRoot ".docker")

Write-Host "[OK] Repo limpiado para el flujo PoC sintetico"
