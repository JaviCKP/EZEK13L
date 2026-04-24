param(
  [int]$PollSeconds = 2,
  [int]$MaxFiles = 0,
  [switch]$NoLearn,
  [switch]$PersistLearning,
  [switch]$UseExec
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$liveInDir = Join-Path $repoRoot "data\live_in"
$liveDoneDir = Join-Path $repoRoot "data\live_done"
$liveErrorDir = Join-Path $repoRoot "data\live_error"
$liveLogsDir = Join-Path $repoRoot "logs\live"
$liveZeekDir = Join-Path $liveLogsDir "zeek"
$liveSuricataDir = Join-Path $liveLogsDir "suricata"
$cumulativeEve = Join-Path $liveSuricataDir "eve.json"
$liveScores = Join-Path $repoRoot "output\live_scores.jsonl"
$learnAudit = Join-Path $repoRoot "output\learning_audit.jsonl"
$modelPath = Join-Path $repoRoot "model\model.pkl"
$metaPath = Join-Path $repoRoot "model\meta.json"
$lockPath = Join-Path $repoRoot "output\poc-watcher.lock"
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
    # Build a single argument-line string with proper quoting for elements
    # that contain spaces.  Start-Process -ArgumentList with an array joins
    # the elements with spaces WITHOUT quoting, which breaks arguments like
    # the sh -c compound-command string.  Passing a single pre-quoted string
    # avoids this.  We use Start-Process (not &) because it handles native
    # stderr as a raw OS stream — the & operator converts each stderr line
    # into a PowerShell ErrorRecord that blows up under ErrorActionPreference
    # = Stop (Docker writes container progress to stderr).
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

function Remove-Target {
  param([string]$Path)
  if (Test-Path -LiteralPath $Path) {
    Remove-Item -LiteralPath $Path -Force
  }
}

function Ensure-File {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType File -Path $Path -Force | Out-Null
  }
}

function Test-ProcessAlive {
  param([string]$ProcessId)
  if ([string]::IsNullOrWhiteSpace($ProcessId)) {
    return $false
  }
  try {
    return $null -ne (Get-Process -Id ([int]$ProcessId) -ErrorAction SilentlyContinue)
  } catch {
    return $false
  }
}

function Enter-WatcherLock {
  New-Item -ItemType Directory -Force (Split-Path -Parent $lockPath) | Out-Null

  if (Test-Path -LiteralPath $lockPath) {
    $rawPid = Get-Content -LiteralPath $lockPath -Raw
    $existingPid = if ($null -ne $rawPid) { $rawPid.Trim() } else { "" }
    if (Test-ProcessAlive -ProcessId $existingPid) {
      throw "Ya hay un poc-watcher.ps1 activo (pid=$existingPid). Cierra ese proceso antes de lanzar otro."
    }
    Remove-Item -LiteralPath $lockPath -Force
  }

  New-Item -ItemType File -Path $lockPath -Value "$PID" -ErrorAction Stop | Out-Null
}

function Exit-WatcherLock {
  if (Test-Path -LiteralPath $lockPath) {
    Remove-Item -LiteralPath $lockPath -Force
  }
}

# ---------------------------------------------------------------------------
# Docker invocation helpers — exec (reuse running container) vs run (ephemeral)
# ---------------------------------------------------------------------------

$script:ServiceContainerMap = @{
  "py"       = "lab-ndr-py-persistent"
  "suricata" = "lab-ndr-suricata-persistent"
  "zeek"     = "lab-ndr-zeek-persistent"
}

function Invoke-Docker-Run {
  param(
    [string]$Service,
    [string[]]$Command,
    [string]$Entrypoint
  )
  $args_ = @("compose", "run", "--rm")
  if ($Entrypoint) {
    $args_ += @("--entrypoint", $Entrypoint)
  }
  $args_ += $Service
  $args_ += $Command
  Invoke-Process "docker" $args_
}

function Invoke-Docker-Exec {
  param(
    [string]$Service,
    [string[]]$Command
  )
  $container = $script:ServiceContainerMap[$Service]
  if (-not $container) {
    throw "No hay contenedor persistente mapeado para el servicio '$Service'"
  }
  $args_ = @("exec", $container) + $Command
  Invoke-Process "docker" $args_
}

function Invoke-Service {
  param(
    [string]$Service,
    [string[]]$Command,
    [string]$Entrypoint
  )
  if ($UseExec) {
    Invoke-Docker-Exec -Service $Service -Command $Command
  } else {
    $runCommand = $Command
    if ($Entrypoint -and $Command.Count -gt 0 -and $Command[0] -eq $Entrypoint) {
      $runCommand = @($Command | Select-Object -Skip 1)
    }
    Invoke-Docker-Run -Service $Service -Command $runCommand -Entrypoint $Entrypoint
  }
}

function Process-Capture {
  param([System.IO.FileInfo]$Capture)

  $captureName = $Capture.BaseName
  $hostZeekDir = Join-Path $liveZeekDir $captureName
  $hostSuricataDir = Join-Path $liveSuricataDir $captureName
  $hostChunkEve = Join-Path $hostSuricataDir "eve.json"
  $hostTempFeatures = Join-Path $repoRoot ("output\tmp_{0}.jsonl" -f $captureName)

  New-Item -ItemType Directory -Force $hostZeekDir | Out-Null
  New-Item -ItemType Directory -Force $hostSuricataDir | Out-Null

  $appCapture = "/data/live_in/$($Capture.Name)"
  $zeekDir = "/logs/live/zeek/$captureName"
  $pyZeekDir = "/app/logs/live/zeek/$captureName"
  $suricataDir = "/logs/live/suricata/$captureName"
  $tempFeatures = "/app/output/tmp_$captureName.jsonl"

  # --- Suricata ---
  Invoke-Service -Service "suricata" -Entrypoint "sh" -Command @(
    "sh", "-c",
    "mkdir -p $suricataDir && suricata -k none -c /etc/suricata/suricata.yaml -r $appCapture -l $suricataDir"
  )
  if (Test-Path -LiteralPath $hostChunkEve) {
    Get-Content -LiteralPath $hostChunkEve | Add-Content -LiteralPath $cumulativeEve
  }

  # --- Zeek ---
  Invoke-Service -Service "zeek" -Command @(
    "sh", "-c",
    "mkdir -p $zeekDir && cd $zeekDir && /usr/local/zeek/bin/zeek -C -r $appCapture LogAscii::use_json=T"
  )

  # --- Build features ---
  Invoke-Service -Service "py" -Command @(
    "python", "pipeline/build_features.py",
    "--zeek-dir", $pyZeekDir,
    "--out", $tempFeatures,
    "--allow-empty"
  )

  # --- Score ---
  $scoreCmd = @(
    "python", "pipeline/score.py",
    "--in", $tempFeatures,
    "--model", "/app/model/model.pkl",
    "--meta", "/app/model/meta.json",
    "--out", "/app/output/live_scores.jsonl",
    "--append",
    "--suricata-eve", "/app/logs/live/suricata/eve.json"
  )
  if ($NoLearn) {
    $scoreCmd += "--no-learn"
  } else {
    $scoreCmd += @("--learn-audit", "/app/output/learning_audit.jsonl")
    if ($PersistLearning) {
      $scoreCmd += "--save-model"
    }
  }
  Invoke-Service -Service "py" -Command $scoreCmd

  Remove-Target $hostTempFeatures
  Move-Item -LiteralPath $Capture.FullName -Destination (Join-Path $liveDoneDir $Capture.Name) -Force
  Write-Host "[OK] Procesado $($Capture.Name)"
}

if (-not (Test-Path -LiteralPath $modelPath)) {
  throw "No existe el modelo: $modelPath. Ejecuta scripts/poc-train.ps1 primero."
}
if (-not (Test-Path -LiteralPath $metaPath)) {
  throw "No existe la meta del modelo: $metaPath. Ejecuta scripts/poc-train.ps1 primero."
}

Set-Location $repoRoot

New-Item -ItemType Directory -Force $liveInDir | Out-Null
New-Item -ItemType Directory -Force $liveDoneDir | Out-Null
New-Item -ItemType Directory -Force $liveErrorDir | Out-Null
New-Item -ItemType Directory -Force $liveZeekDir | Out-Null
New-Item -ItemType Directory -Force $liveSuricataDir | Out-Null
New-Item -ItemType Directory -Force (Join-Path $repoRoot "output") | Out-Null
Ensure-File $cumulativeEve
Ensure-File $liveScores
Ensure-File $learnAudit

Enter-WatcherLock
try {
  $processed = 0
  while ($true) {
    $captures = @(Get-ChildItem -LiteralPath $liveInDir -Filter *.pcap -File | Sort-Object Name)
    foreach ($capture in $captures) {
      try {
        Process-Capture -Capture $capture
        $processed += 1
        if ($MaxFiles -gt 0 -and $processed -ge $MaxFiles) {
          return
        }
      } catch {
        Move-Item -LiteralPath $capture.FullName -Destination (Join-Path $liveErrorDir $capture.Name) -Force
        Write-Warning ("Fallo procesando {0}: {1}" -f $capture.Name, $_.Exception.Message)
      }
    }

    Start-Sleep -Seconds $PollSeconds
  }
} finally {
  Exit-WatcherLock
}
