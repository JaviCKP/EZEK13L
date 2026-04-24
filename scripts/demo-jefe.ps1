param(
  [double]$Interval = 2.0,
  [int]$MinConnections = 8,
  [int]$MaxConnections = 18,
  [int]$AttackEvery = 4,
  [string]$AttackSequence = "1,2,3,4,5",
  [switch]$TrainIfMissing,
  [switch]$Learn
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$modelPath = Join-Path $repoRoot "model\model.pkl"
$metaPath = Join-Path $repoRoot "model\meta.json"
$env:DOCKER_CONFIG = Join-Path $repoRoot ".docker"
New-Item -ItemType Directory -Force $env:DOCKER_CONFIG | Out-Null

function Invoke-Process {
  param(
    [string]$FilePath,
    [string[]]$Arguments
  )
  $display = "$FilePath $($Arguments -join ' ')"
  Write-Host "==> $display"
  $stdout = [System.IO.Path]::GetTempFileName()
  $stderr = [System.IO.Path]::GetTempFileName()
  try {
    $quotedParts = foreach ($a in $Arguments) {
      if ($a -match '[\s"]') { '"{0}"' -f ($a -replace '"', '\"') } else { $a }
    }
    $argLine = $quotedParts -join ' '

    $proc = Start-Process `
      -FilePath $FilePath `
      -ArgumentList $argLine `
      -WorkingDirectory $repoRoot `
      -NoNewWindow `
      -PassThru `
      -Wait `
      -RedirectStandardOutput $stdout `
      -RedirectStandardError $stderr

    $outText = if (Test-Path -LiteralPath $stdout) { Get-Content -LiteralPath $stdout -Raw } else { "" }
    $errText = if (Test-Path -LiteralPath $stderr) { Get-Content -LiteralPath $stderr -Raw } else { "" }
    if (-not [string]::IsNullOrWhiteSpace($outText)) { Write-Host $outText.TrimEnd() }
    if (-not [string]::IsNullOrWhiteSpace($errText)) { Write-Host $errText.TrimEnd() }
    if ($proc.ExitCode -ne 0) {
      throw "Fallo: $display"
    }
  } finally {
    if (Test-Path -LiteralPath $stdout) { Remove-Item -LiteralPath $stdout -Force }
    if (Test-Path -LiteralPath $stderr) { Remove-Item -LiteralPath $stderr -Force }
  }
}

Set-Location $repoRoot

if ((-not (Test-Path -LiteralPath $modelPath)) -or (-not (Test-Path -LiteralPath $metaPath))) {
  if (-not $TrainIfMissing) {
    throw "Falta model/model.pkl o model/meta.json. Ejecuta scripts/poc-train.ps1 o lanza esta demo con -TrainIfMissing."
  }
  & (Join-Path $PSScriptRoot "poc-train.ps1") -Connections 8000 -DurationMinutes 30 -ThresholdQuantile 0.999
}

Invoke-Process "docker" @("compose", "up", "-d", "--build", "dashboard")

Write-Host ""
Write-Host "[OK] Dashboard: http://localhost:8501"
Write-Host "[INFO] Demo live arrancando. Pulsa Ctrl+C para parar generador y watcher."
Write-Host "[INFO] Ataques automaticos cada $AttackEvery capturas normales: $AttackSequence"
Start-Process "http://localhost:8501" | Out-Null

$liveParams = @{
  Interval = $Interval
  MinConnections = $MinConnections
  MaxConnections = $MaxConnections
  AttackEvery = $AttackEvery
  AttackSequence = $AttackSequence
}
if (-not $Learn) {
  $liveParams.NoLearn = $true
}

& (Join-Path $PSScriptRoot "poc-live.ps1") @liveParams
