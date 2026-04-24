param(
  [double]$Interval = 3.0,
  [int]$MinConnections = 5,
  [int]$MaxConnections = 15,
  [int]$AttackEvery = 0,
  [string]$AttackSequence = "1,2,3,4,5",
  [switch]$NoLearn,
  [switch]$PersistLearning
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$generatorLog = Join-Path $repoRoot "output\live_generator.log"
$generatorErr = Join-Path $repoRoot "output\live_generator.err.log"
$env:DOCKER_CONFIG = Join-Path $repoRoot ".docker"
New-Item -ItemType Directory -Force $env:DOCKER_CONFIG | Out-Null

function Reset-Target {
  param([string]$Path)
  if (Test-Path -LiteralPath $Path) {
    Remove-Item -LiteralPath $Path -Recurse -Force
  }
}

function Clear-DirButKeepGitkeep {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Force $Path | Out-Null
    return
  }

  Get-ChildItem -LiteralPath $Path -Force | Where-Object {
    $_.Name -ne ".gitkeep"
  } | Remove-Item -Recurse -Force
}

Set-Location $repoRoot

Clear-DirButKeepGitkeep (Join-Path $repoRoot "data\live_in")
Clear-DirButKeepGitkeep (Join-Path $repoRoot "data\live_done")
Clear-DirButKeepGitkeep (Join-Path $repoRoot "data\live_error")
Clear-DirButKeepGitkeep (Join-Path $repoRoot "logs\live")
Reset-Target (Join-Path $repoRoot "output\live_scores.jsonl")
Reset-Target (Join-Path $repoRoot "output\learning_audit.jsonl")
Reset-Target $generatorLog
Reset-Target $generatorErr

New-Item -ItemType Directory -Force (Join-Path $repoRoot "data\live_in") | Out-Null
New-Item -ItemType Directory -Force (Join-Path $repoRoot "data\live_done") | Out-Null
New-Item -ItemType Directory -Force (Join-Path $repoRoot "data\live_error") | Out-Null
New-Item -ItemType Directory -Force (Join-Path $repoRoot "logs\live") | Out-Null
New-Item -ItemType Directory -Force (Join-Path $repoRoot "output") | Out-Null

$generatorArgs = @(
  "compose",
  "run",
  "--rm",
  "py",
  "simulation/generate_live.py",
  "--outdir",
  "/app/data/live_in",
  "--interval",
  "$Interval",
  "--min-connections",
  "$MinConnections",
  "--max-connections",
  "$MaxConnections"
)
if ($AttackEvery -gt 0) {
  $generatorArgs += @("--attack-every", "$AttackEvery", "--attack-sequence", $AttackSequence)
}

$generator = Start-Process `
  -FilePath "docker" `
  -ArgumentList $generatorArgs `
  -WorkingDirectory $repoRoot `
  -RedirectStandardOutput $generatorLog `
  -RedirectStandardError $generatorErr `
  -PassThru

Write-Host "[INFO] Generador live lanzado (pid=$($generator.Id))"
Write-Host "[INFO] Logs: $generatorLog"

try {
  $watcherParams = @{}
  if ($NoLearn) {
    $watcherParams.NoLearn = $true
  }
  if ($PersistLearning) {
    $watcherParams.PersistLearning = $true
  }
  & (Join-Path $PSScriptRoot "poc-watcher.ps1") @watcherParams
} finally {
  if ($generator -and -not $generator.HasExited) {
    Stop-Process -Id $generator.Id -Force
  }
}
