param(
  [int]$NormalConnections = 12,
  [double]$NormalDurationMinutes = 1,
  [switch]$KeepArtifacts,
  [switch]$SkipDockerPrecheck,
  [switch]$RequireMl
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$reportPath = Join-Path $repoRoot "BLIND_TEST_RESULTS.md"
$metaPath = Join-Path $repoRoot "model\meta.json"
$liveScores = Join-Path $repoRoot "output\live_scores.jsonl"
$evePath = Join-Path $repoRoot "logs\live\suricata\eve.json"
$localDockerConfig = Join-Path $repoRoot ".docker"

# --- Cached normal baseline paths ---
$cacheDir = Join-Path $repoRoot "data\.baseline_cache_blind"
$cachedScores = Join-Path $cacheDir "normal_scores.jsonl"
$cachedEve = Join-Path $cacheDir "normal_eve.json"
$cachedDone = Join-Path $cacheDir "normal_000001.pcap"

function Initialize-DockerEnvironment {
  New-Item -ItemType Directory -Force $localDockerConfig | Out-Null
  $env:DOCKER_CONFIG = $localDockerConfig
}

function Get-CurrentIdentity {
  return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}

function Test-CurrentUserInDockerUsers {
  $identity = Get-CurrentIdentity
  try {
    $members = @(net localgroup docker-users 2>$null)
  } catch {
    return $false
  }
  return @($members | Where-Object { $_ -and $identity.EndsWith("\$_") }).Count -gt 0
}

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

function Invoke-PocWatcher {
  param(
    [int]$PollSeconds = 1,
    [int]$MaxFiles = 1,
    [switch]$NoLearn
  )
  $watcherParams = @{
    PollSeconds = $PollSeconds
    MaxFiles = $MaxFiles
    UseExec = $true
  }
  if ($NoLearn) {
    $watcherParams.NoLearn = $true
  }

  & (Join-Path $PSScriptRoot "poc-watcher.ps1") @watcherParams
}

function Assert-DockerReady {
  $tmpStdout = [System.IO.Path]::GetTempFileName()
  $tmpStderr = [System.IO.Path]::GetTempFileName()
  try {
    $proc = Start-Process `
      -FilePath "docker" `
      -ArgumentList @("version", "--format", "{{.Server.Version}}") `
      -NoNewWindow `
      -PassThru `
      -Wait `
      -RedirectStandardOutput $tmpStdout `
      -RedirectStandardError $tmpStderr

    $stdout = ""
    $stderr = ""
    if (Test-Path -LiteralPath $tmpStdout) {
      $rawStdout = Get-Content -LiteralPath $tmpStdout -Raw
      if ($null -ne $rawStdout) {
        $stdout = $rawStdout.Trim()
      }
    }
    if (Test-Path -LiteralPath $tmpStderr) {
      $rawStderr = Get-Content -LiteralPath $tmpStderr -Raw
      if ($null -ne $rawStderr) {
        $stderr = $rawStderr.Trim()
      }
    }

    if ($proc.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($stdout)) {
      $detail = if ($stderr) { "`nDetalle: $stderr" } else { "" }
      $identity = Get-CurrentIdentity
      $groupHint = if (Test-CurrentUserInDockerUsers) {
        "El usuario actual parece estar en docker-users; revisa que Docker Desktop tenga el backend arrancado."
      } else {
        "El usuario actual no aparece en docker-users. Anade '$identity' al grupo local docker-users o ejecuta esta validacion con el usuario que tenga acceso a Docker Desktop."
      }
      throw "Docker daemon no accesible desde esta sesion. El validador necesita docker compose para Zeek y Suricata.`nUsuario actual: $identity`n$groupHint$detail"
    }
  } finally {
    if (Test-Path -LiteralPath $tmpStdout) { Remove-Item -LiteralPath $tmpStdout -Force }
    if (Test-Path -LiteralPath $tmpStderr) { Remove-Item -LiteralPath $tmpStderr -Force }
  }
}

function Read-JsonLines {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    return @()
  }

  $rows = [System.Collections.Generic.List[object]]::new()
  foreach ($line in Get-Content -LiteralPath $Path) {
    if ([string]::IsNullOrWhiteSpace($line)) {
      continue
    }
    $rows.Add(($line | ConvertFrom-Json)) | Out-Null
  }
  return @($rows)
}

function Reset-LiveState {
  & (Join-Path $PSScriptRoot "clean-repo.ps1") | Out-Null
}

function Get-Threshold {
  if (-not (Test-Path -LiteralPath $metaPath)) {
    throw "No existe $metaPath. Ejecuta scripts/poc-train.ps1 primero."
  }
  return [double]((Get-Content -LiteralPath $metaPath -Raw | ConvertFrom-Json).threshold)
}

function Get-ValidationResult {
  param(
    [string]$Scenario,
    [string]$ExpectedFactor,
    [string]$ExpectedSignaturePattern,
    [string]$ExpectedClass,
    [int]$StartRow = 0,
    [int]$StartAlert = 0,
    [switch]$IsControl
  )

  $threshold = Get-Threshold
  $allRows = @(Read-JsonLines $liveScores)
  $allAlerts = @(Read-JsonLines $evePath | Where-Object { $_.event_type -eq "alert" })
  $rows = @($allRows | Select-Object -Skip $StartRow)
  $alerts = @($allAlerts | Select-Object -Skip $StartAlert)

  $maxScore = if ($rows.Count -gt 0) {
    [double](($rows | Measure-Object -Property score -Maximum).Maximum)
  } else {
    0.0
  }
  $hybridRows = @($rows | Where-Object { $_.PSObject.Properties.Name -contains "hybrid_score" })
  $maxHybridScore = if ($hybridRows.Count -gt 0) {
    [double](($hybridRows | Measure-Object -Property hybrid_score -Maximum).Maximum)
  } else {
    $maxScore
  }
  $maxRawScore = if ($rows.Count -gt 0) {
    [double](($rows | Measure-Object -Property raw_score -Maximum).Maximum)
  } else {
    0.0
  }
  $maxBoost = if ($rows.Count -gt 0) {
    [double](($rows | Measure-Object -Property behavioral_boost -Maximum).Maximum)
  } else {
    0.0
  }
  $mlAnomalies = @($rows | Where-Object {
    if ($_.PSObject.Properties.Name -contains "is_ml_anomaly") {
      return $_.is_ml_anomaly
    }
    return $_.is_anomaly
  }).Count
  $expertSignals = @($rows | Where-Object {
    $boost = 0.0
    if ($_.PSObject.Properties.Name -contains "behavioral_boost") {
      $boost = [double]$_.behavioral_boost
    }
    return $boost -gt 0.0
  }).Count
  $classifierRows = @($rows | Where-Object {
    $_.PSObject.Properties.Name -contains "is_attack_classifier_detection" -and $_.is_attack_classifier_detection
  })
  $classifierDetections = $classifierRows.Count
  $maxClassifierConfidence = if ($rows.Count -gt 0 -and @($rows | Where-Object { $_.PSObject.Properties.Name -contains "attack_confidence" }).Count -gt 0) {
    [double](($rows | Measure-Object -Property attack_confidence -Maximum).Maximum)
  } else {
    0.0
  }
  $classifierPredictions = @{}
  foreach ($row in $classifierRows) {
    $prediction = $row.attack_prediction
    if (-not [string]::IsNullOrWhiteSpace($prediction)) {
      $classifierPredictions[$prediction] = $true
    }
  }
  $classifierPredictionList = @($classifierPredictions.Keys | Sort-Object)
  $mlDetectionRows = @($rows | Where-Object {
    if ($_.PSObject.Properties.Name -contains "is_ml_detection") {
      return $_.is_ml_detection
    }
    if ($_.PSObject.Properties.Name -contains "is_attack_classifier_detection" -and $_.is_attack_classifier_detection) {
      return $true
    }
    if ($_.PSObject.Properties.Name -contains "is_ml_anomaly") {
      return $_.is_ml_anomaly
    }
    return $_.is_anomaly
  })
  $mlDetections = $mlDetectionRows.Count
  $mlLabels = @{}
  foreach ($row in $mlDetectionRows) {
    $label = if ($row.PSObject.Properties.Name -contains "ml_label") { $row.ml_label } else { $row.attack_prediction }
    if (-not [string]::IsNullOrWhiteSpace($label)) {
      $mlLabels[$label] = $true
    }
  }
  $mlLabelList = @($mlLabels.Keys | Sort-Object)

  $factors = @{}
  foreach ($row in $rows) {
    foreach ($factor in @($row.behavioral_factors)) {
      if (-not [string]::IsNullOrWhiteSpace($factor)) {
        $factors[$factor] = $true
      }
    }
  }
  $factorList = @($factors.Keys | Sort-Object)

  $signatures = @{}
  foreach ($alert in $alerts) {
    $signature = $alert.alert.signature
    if (-not [string]::IsNullOrWhiteSpace($signature)) {
      $signatures[$signature] = $true
    }
  }
  $signatureList = @($signatures.Keys | Sort-Object)

  $factorOk = $true
  if (-not [string]::IsNullOrWhiteSpace($ExpectedFactor)) {
    $factorOk = $factorList -contains $ExpectedFactor
  }

  $signatureOk = $true
  if (-not [string]::IsNullOrWhiteSpace($ExpectedSignaturePattern)) {
    $signatureOk = @($signatureList | Where-Object { $_ -like "*$ExpectedSignaturePattern*" }).Count -gt 0
  }

  $noveltyOk = ($mlAnomalies -gt 0) -and ($maxRawScore -gt $threshold)
  $expertOk = ($expertSignals -gt 0) -and $factorOk
  $suricataOk = $signatureOk -and (-not [string]::IsNullOrWhiteSpace($ExpectedSignaturePattern))
  $classifierOk = $classifierDetections -gt 0
  if (-not [string]::IsNullOrWhiteSpace($ExpectedClass)) {
    $classifierOk = $classifierPredictionList -contains $ExpectedClass
  }
  $mlOk = $mlDetections -gt 0
  if (-not [string]::IsNullOrWhiteSpace($ExpectedClass)) {
    $mlOk = ($mlLabelList -contains $ExpectedClass) -or $classifierOk
  }
  $requiresFactor = -not [string]::IsNullOrWhiteSpace($ExpectedFactor)
  $requiresSignature = -not [string]::IsNullOrWhiteSpace($ExpectedSignaturePattern)

  if ($IsControl) {
    $passed = ($mlDetections -eq 0) -and ($expertSignals -eq 0) -and ($maxRawScore -lt $threshold)
  } else {
    $expectedLayersOk = ((-not $requiresFactor) -or $factorOk) -and ((-not $requiresSignature) -or $signatureOk)
    $detected = $mlOk -or ($requiresFactor -and $expertOk) -or ($requiresSignature -and $suricataOk)
    $passed = $detected -and $expectedLayersOk
    if ($RequireMl) {
      $passed = $mlOk
    }
  }

  $layers = @()
  if ($mlOk) { $layers += "ML" }
  if ($noveltyOk) { $layers += "DerivaML" }
  if ($expertSignals -gt 0) { $layers += "Expert" }
  if ($signatureOk -and $signatureList.Count -gt 0) { $layers += "Suricata" }

  return [pscustomobject]@{
    Scenario = $Scenario
    EvaluatedRows = $rows.Count
    Threshold = [math]::Round($threshold, 6)
    MaxRawScore = [math]::Round($maxRawScore, 6)
    MaxBoost = [math]::Round($maxBoost, 6)
    MaxHybridScore = [math]::Round($maxHybridScore, 6)
    MlAnomalies = $mlAnomalies
    MlDetections = $mlDetections
    MlLabels = if ($mlLabelList.Count) { $mlLabelList -join ", " } else { "-" }
    ClassifierDetections = $classifierDetections
    MaxClassifierConfidence = [math]::Round($maxClassifierConfidence, 6)
    ClassifierPredictions = if ($classifierPredictionList.Count) { $classifierPredictionList -join ", " } else { "-" }
    ExpertSignals = $expertSignals
    Factors = if ($factorList.Count) { $factorList -join ", " } else { "-" }
    Suricata = if ($signatureList.Count) { $signatureList -join " | " } else { "-" }
    Layers = if ($layers.Count) { $layers -join ", " } else { "-" }
    Passed = if ($passed) { "PASS" } else { "FAIL" }
  }
}

# ---------------------------------------------------------------------------
# Persistent-container helpers
# ---------------------------------------------------------------------------

function Start-PersistentContainers {
  Write-Host "[INFO] Arrancando contenedores persistentes (py, suricata, zeek)..."
  Invoke-Process "docker" @(
    "compose", "run", "-d", "--rm", "--name", "lab-ndr-py-persistent",
    "--entrypoint", "tail", "py", "-f", "/dev/null"
  )
  Invoke-Process "docker" @(
    "compose", "run", "-d", "--rm", "--name", "lab-ndr-suricata-persistent",
    "--entrypoint", "tail", "suricata", "-f", "/dev/null"
  )
  Invoke-Process "docker" @(
    "compose", "run", "-d", "--rm", "--name", "lab-ndr-zeek-persistent",
    "--entrypoint", "tail", "zeek", "-f", "/dev/null"
  )
  Write-Host "[OK] Contenedores persistentes arrancados"
}

function Stop-PersistentContainers {
  Write-Host "[INFO] Parando contenedores persistentes..."
  foreach ($name in @("lab-ndr-py-persistent", "lab-ndr-suricata-persistent", "lab-ndr-zeek-persistent")) {
    try {
      Invoke-Process "docker" @("stop", "-t", "2", $name)
    } catch {
      Write-Warning "No se pudo parar $name (puede que ya este parado)"
    }
  }
}

function Invoke-DockerExec {
  param(
    [string]$ContainerName,
    [string[]]$Command
  )
  $args_ = @("exec", $ContainerName) + $Command
  Invoke-Process "docker" $args_
}

# ---------------------------------------------------------------------------
# Normal baseline caching
# ---------------------------------------------------------------------------

function Build-NormalBaseline {
  Write-Host "[INFO] Generando y procesando baseline normal (una sola vez)..."
  Reset-LiveState

  Invoke-DockerExec "lab-ndr-py-persistent" @(
    "python", "simulation/generate_normal.py",
    "--out", "/app/data/live_in/normal_000001.pcap",
    "--connections", "$NormalConnections",
    "--duration-minutes", "$NormalDurationMinutes"
  )

  Invoke-PocWatcher -PollSeconds 1 -MaxFiles 1 -NoLearn

  New-Item -ItemType Directory -Force $cacheDir | Out-Null
  if (Test-Path -LiteralPath $liveScores) {
    Copy-Item -LiteralPath $liveScores -Destination $cachedScores -Force
  }
  if (Test-Path -LiteralPath $evePath) {
    Copy-Item -LiteralPath $evePath -Destination $cachedEve -Force
  }
  $donePcap = Join-Path $repoRoot "data\live_done\normal_000001.pcap"
  if (Test-Path -LiteralPath $donePcap) {
    Copy-Item -LiteralPath $donePcap -Destination $cachedDone -Force
  }
  Write-Host "[OK] Baseline normal cacheada"
}

function Restore-NormalBaseline {
  Reset-LiveState

  $outDir = Join-Path $repoRoot "output"
  $suricataDir = Join-Path $repoRoot "logs\live\suricata"
  New-Item -ItemType Directory -Force $outDir | Out-Null
  New-Item -ItemType Directory -Force $suricataDir | Out-Null

  if (Test-Path -LiteralPath $cachedScores) {
    Copy-Item -LiteralPath $cachedScores -Destination $liveScores -Force
  } else {
    New-Item -ItemType File -Path $liveScores -Force | Out-Null
  }
  if (Test-Path -LiteralPath $cachedEve) {
    Copy-Item -LiteralPath $cachedEve -Destination $evePath -Force
  } else {
    New-Item -ItemType File -Path $evePath -Force | Out-Null
  }
}

# ---------------------------------------------------------------------------
# Scenario runners
# ---------------------------------------------------------------------------

function Run-Control {
  Restore-NormalBaseline
  return Get-ValidationResult -Scenario "Control benigno" -IsControl
}

function Run-BlindAttack {
  param(
    [string]$Choice,
    [string]$Scenario,
    [string]$ExpectedFactor,
    [string]$ExpectedSignaturePattern,
    [string]$ExpectedClass
  )

  Restore-NormalBaseline
  $baselineRowCount = @(Read-JsonLines $liveScores).Count
  $baselineAlertCount = @(Read-JsonLines $evePath | Where-Object { $_.event_type -eq "alert" }).Count

  # Use the BLIND injector instead of the standard one
  Invoke-DockerExec "lab-ndr-py-persistent" @(
    "python", "simulation/inject_blind_attack.py",
    "--outdir", "/app/data/live_in",
    "--choice", $Choice
  )
  Invoke-PocWatcher -PollSeconds 1 -MaxFiles 1 -NoLearn

  return Get-ValidationResult -Scenario $Scenario -ExpectedFactor $ExpectedFactor -ExpectedSignaturePattern $ExpectedSignaturePattern -ExpectedClass $ExpectedClass -StartRow $baselineRowCount -StartAlert $baselineAlertCount
}

Set-Location $repoRoot
Initialize-DockerEnvironment

if (-not $SkipDockerPrecheck) {
  Assert-DockerReady
}

if (-not (Test-Path -LiteralPath $metaPath)) {
  throw "No existe $metaPath. Ejecuta scripts/poc-train.ps1 primero."
}

# --- Start persistent containers ---
Start-PersistentContainers

try {
  Build-NormalBaseline

  $results = @()
  $results += @(Run-Control | Where-Object { $_.PSObject.Properties.Name -contains "Passed" })

  # Suricata signature patterns intentionally left empty for brute force and SQLi
  # because the new endpoints and MSSQL payloads may not match the community rules
  # that fired on the training variants. The test question is whether ML detects them.
  $results += @(Run-BlindAttack -Choice "1" -Scenario "Port Scan (blind)" -ExpectedFactor "scan_ports_60s" -ExpectedSignaturePattern "SYN scan" -ExpectedClass "port_scan" | Where-Object { $_.PSObject.Properties.Name -contains "Passed" })
  $results += @(Run-BlindAttack -Choice "2" -Scenario "DNS Exfiltration (blind)" -ExpectedFactor "dns_query_shape" -ExpectedSignaturePattern "" -ExpectedClass "dns_exfiltration" | Where-Object { $_.PSObject.Properties.Name -contains "Passed" })
  $results += @(Run-BlindAttack -Choice "3" -Scenario "Brute Force HTTP (blind)" -ExpectedFactor "" -ExpectedSignaturePattern "" -ExpectedClass "brute_force_http" | Where-Object { $_.PSObject.Properties.Name -contains "Passed" })
  $results += @(Run-BlindAttack -Choice "4" -Scenario "SQL Injection (blind)" -ExpectedFactor "http_payload_shape" -ExpectedSignaturePattern "" -ExpectedClass "sql_injection" | Where-Object { $_.PSObject.Properties.Name -contains "Passed" })
  $results += @(Run-BlindAttack -Choice "5" -Scenario "Data Exfiltration (blind)" -ExpectedFactor "volume_spike" -ExpectedSignaturePattern "" -ExpectedClass "data_exfiltration" | Where-Object { $_.PSObject.Properties.Name -contains "Passed" })
} finally {
  Stop-PersistentContainers
}

$lines = @(
  "# Blind Generalization Test",
  "",
  "> Ataques generados con IPs, dominios, endpoints y payloads **distintos** a los del entrenamiento.",
  "> El modelo no fue reentrenado. Esta tabla mide generalización, no memorización.",
  "",
  "Threshold usado: ``$($results[0].Threshold)``",
  "Modo RequireMl: ``$RequireMl``",
  "",
  "| Escenario | Flujos evaluados | Threshold | Max ML raw | Detecciones ML | Etiqueta ML | Deriva raw | Conf clase | Senales expert | Capas | Factors expert | Suricata | Resultado |",
  "| --- | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | --- | --- | --- | --- |"
)
foreach ($result in $results) {
  $lines += "| $($result.Scenario) | $($result.EvaluatedRows) | $($result.Threshold) | $($result.MaxRawScore) | $($result.MlDetections) | $($result.MlLabels) | $($result.MlAnomalies) | $($result.MaxClassifierConfidence) | $($result.ExpertSignals) | $($result.Layers) | $($result.Factors) | $($result.Suricata) | $($result.Passed) |"
}

$attackResults = @($results | Select-Object -Skip 1)
$passCount = @($attackResults | Where-Object { $_.Passed -eq "PASS" }).Count
$failCount = @($attackResults | Where-Object { $_.Passed -ne "PASS" }).Count
$allPassed = ($failCount -eq 0)

$lines += ""
$lines += "## Interpretacion"
$lines += ""

if ($allPassed) {
  $lines += "**Generalizacion completa ($passCount/5):** el sistema detecta las 5 familias de ataque incluso con IPs, dominios y payloads distintos a los del entrenamiento. La arquitectura multi-capa aprende comportamiento, no patrones exactos."
} elseif ($passCount -ge 3) {
  $passedNames = @($attackResults | Where-Object { $_.Passed -eq "PASS" } | ForEach-Object { $_.Scenario }) -join ", "
  $failedNames = @($attackResults | Where-Object { $_.Passed -ne "PASS" } | ForEach-Object { $_.Scenario }) -join ", "
  $lines += "**Generalizacion parcial ($passCount/5):** el sistema detecta [$passedNames] incluso con variaciones de parametros. Falla en [$failedNames]. Esto valida el diseno multi-capa: donde el clasificador supervisado no generaliza, las capas de anomalia o expert signals cubren el gap."
} else {
  $failedNames = @($attackResults | Where-Object { $_.Passed -ne "PASS" } | ForEach-Object { $_.Scenario }) -join ", "
  $lines += "**Generalizacion limitada ($passCount/5):** el modelo falla en [$failedNames] cuando los parametros cambian. El clasificador supervisado aprende los patrones especificos del generador de entrenamiento mas que el comportamiento de ataque en general. Para produccion seria necesario ampliar el corpus con variaciones de cada familia."
}

$lines += ""
$lines += "---"
$lines += "_Generado por ``scripts/validate-blind.ps1``_"

Set-Content -LiteralPath $reportPath -Value $lines -Encoding UTF8

# Clean the blind baseline cache
if (Test-Path -LiteralPath $cacheDir) {
  Remove-Item -LiteralPath $cacheDir -Recurse -Force
}

if (-not $KeepArtifacts) {
  Reset-LiveState
}

Write-Host ""
Write-Host "[OK] Reporte generado en $reportPath"
foreach ($result in $results) {
  Write-Host ("[{0}] {1}: ml_raw={2}, ml_detections={3}, ml_label={4}, raw_drift={5}, expert_signals={6}, layers={7}" -f $result.Passed, $result.Scenario, $result.MaxRawScore, $result.MlDetections, $result.MlLabels, $result.MlAnomalies, $result.ExpertSignals, $result.Layers)
}
Write-Host ""
Write-Host ("Resultado blind: {0}/5 ataques detectados" -f $passCount)
