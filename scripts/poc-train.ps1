param(
  [int]$Connections = 8000,
  [double]$DurationMinutes = 30,
  [int]$QuietConnections = 1200,
  [double]$QuietDurationMinutes = 100,
  [int]$AttackRepeats = 12,
  [switch]$SkipClassifier,
  [double]$ThresholdQuantile = 0.999
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
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

function Reset-Target {
  param([string]$Path)
  if (Test-Path -LiteralPath $Path) {
    Remove-Item -LiteralPath $Path -Recurse -Force
  }
}

function Move-IntoPlace {
  param(
    [string]$Source,
    [string]$Destination
  )
  if (-not (Test-Path -LiteralPath $Source)) {
    throw "No se genero el artefacto esperado: $Source"
  }
  Reset-Target $Destination
  Move-Item -LiteralPath $Source -Destination $Destination -Force
}

function Join-JsonLinesNoBom {
  param(
    [string[]]$Sources,
    [string]$Destination
  )
  $encoding = New-Object System.Text.UTF8Encoding($false)
  $writer = [System.IO.StreamWriter]::new($Destination, $false, $encoding)
  try {
    foreach ($source in $Sources) {
      if (-not (Test-Path -LiteralPath $source)) {
        throw "No existe el fichero de features esperado: $source"
      }
      foreach ($line in [System.IO.File]::ReadLines($source)) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
          $writer.WriteLine($line)
        }
      }
    }
  } finally {
    $writer.Close()
  }
}

Set-Location $repoRoot

$trainPcap = Join-Path $repoRoot "data\train\normal_sim.pcap"
$quietPcap = Join-Path $repoRoot "data\train\normal_quiet_sim.pcap"
$zeekDir = Join-Path $repoRoot "logs\offline\poc_train_zeek"
$quietZeekDir = Join-Path $repoRoot "logs\offline\poc_train_quiet_zeek"
$featuresOut = Join-Path $repoRoot "output\train_poc_features.jsonl"
$modelOut = Join-Path $repoRoot "model\model.pkl"
$metaOut = Join-Path $repoRoot "model\meta.json"
$classifierOut = Join-Path $repoRoot "model\attack_classifier.pkl"
$classifierMetaOut = Join-Path $repoRoot "model\attack_classifier_meta.json"

$tempTrainPcap = Join-Path $repoRoot "data\train\normal_sim.next.pcap"
$tempQuietPcap = Join-Path $repoRoot "data\train\normal_quiet_sim.next.pcap"
$tempZeekDir = Join-Path $repoRoot "logs\offline\poc_train_zeek_next"
$tempQuietZeekDir = Join-Path $repoRoot "logs\offline\poc_train_quiet_zeek_next"
$tempFeaturesOut = Join-Path $repoRoot "output\train_poc_features.next.jsonl"
$tempBusyFeaturesOut = Join-Path $repoRoot "output\train_poc_features_busy.next.jsonl"
$tempQuietFeaturesOut = Join-Path $repoRoot "output\train_poc_features_quiet.next.jsonl"
$tempModelOut = Join-Path $repoRoot "model\model.next.pkl"
$tempMetaOut = Join-Path $repoRoot "model\meta.next.json"
$tempClassifierOut = Join-Path $repoRoot "model\attack_classifier.next.pkl"
$tempClassifierMetaOut = Join-Path $repoRoot "model\attack_classifier_meta.next.json"

New-Item -ItemType Directory -Force (Join-Path $repoRoot "data\train") | Out-Null
New-Item -ItemType Directory -Force (Join-Path $repoRoot "logs\offline") | Out-Null
New-Item -ItemType Directory -Force (Join-Path $repoRoot "output") | Out-Null
New-Item -ItemType Directory -Force (Join-Path $repoRoot "model") | Out-Null

Reset-Target $tempTrainPcap
Reset-Target $tempQuietPcap
Reset-Target $tempZeekDir
Reset-Target $tempQuietZeekDir
Reset-Target $tempFeaturesOut
Reset-Target $tempBusyFeaturesOut
Reset-Target $tempQuietFeaturesOut
Reset-Target $tempModelOut
Reset-Target $tempMetaOut
Reset-Target $tempClassifierOut
Reset-Target $tempClassifierMetaOut

Invoke-Process "docker" @("compose", "build", "py")
Invoke-Process "docker" @(
  "compose", "run", "--rm", "py",
  "simulation/generate_normal.py",
  "--out", "/app/data/train/normal_sim.next.pcap",
  "--connections", "$Connections",
  "--duration-minutes", "$DurationMinutes"
)
Invoke-Process "docker" @(
  "compose", "run", "--rm", "py",
  "simulation/generate_normal.py",
  "--out", "/app/data/train/normal_quiet_sim.next.pcap",
  "--connections", "$QuietConnections",
  "--duration-minutes", "$QuietDurationMinutes",
  "--seed", "7331"
)
Invoke-Process "docker" @(
  "compose", "run", "--rm", "zeek", "sh", "-lc",
  "mkdir -p /logs/offline/poc_train_zeek_next && cd /logs/offline/poc_train_zeek_next && /usr/local/zeek/bin/zeek -C -r /data/train/normal_sim.next.pcap LogAscii::use_json=T"
)
Invoke-Process "docker" @(
  "compose", "run", "--rm", "zeek", "sh", "-lc",
  "mkdir -p /logs/offline/poc_train_quiet_zeek_next && cd /logs/offline/poc_train_quiet_zeek_next && /usr/local/zeek/bin/zeek -C -r /data/train/normal_quiet_sim.next.pcap LogAscii::use_json=T"
)
Invoke-Process "docker" @(
  "compose", "run", "--rm", "py",
  "pipeline/build_features.py",
  "--zeek-dir", "/app/logs/offline/poc_train_zeek_next",
  "--out", "/app/output/train_poc_features_busy.next.jsonl"
)
Invoke-Process "docker" @(
  "compose", "run", "--rm", "py",
  "pipeline/build_features.py",
  "--zeek-dir", "/app/logs/offline/poc_train_quiet_zeek_next",
  "--out", "/app/output/train_poc_features_quiet.next.jsonl"
)

Join-JsonLinesNoBom -Sources @($tempBusyFeaturesOut, $tempQuietFeaturesOut) -Destination $tempFeaturesOut

Invoke-Process "docker" @(
  "compose", "run", "--rm", "py",
  "pipeline/train_baseline.py",
  "--in", "/app/output/train_poc_features.next.jsonl",
  "--model-out", "/app/model/model.next.pkl",
  "--meta-out", "/app/model/meta.next.json",
  "--threshold-quantile", "$ThresholdQuantile",
  "--min-threshold", "0.95"
)

if (-not $SkipClassifier) {
  $attackSpecs = @(
    @{ Choice = "1"; Label = "port_scan"; Repeats = $AttackRepeats; Seed = "9101" },
    @{ Choice = "2"; Label = "dns_exfiltration"; Repeats = $AttackRepeats; Seed = "9102" },
    @{ Choice = "3"; Label = "brute_force_http"; Repeats = $AttackRepeats; Seed = "9103" },
    @{ Choice = "4"; Label = "sql_injection"; Repeats = $AttackRepeats; Seed = "9104" },
    @{ Choice = "5"; Label = "data_exfiltration"; Repeats = [math]::Max($AttackRepeats, 12); Seed = "9105" }
  )

  $classifierInputs = @("normal=/app/output/train_poc_features.next.jsonl")
  foreach ($spec in $attackSpecs) {
    $choice = $spec.Choice
    $label = $spec.Label
    $repeats = $spec.Repeats
    $seed = $spec.Seed
    $pcapPyContainer = "/app/data/train/attack_${choice}.next.pcap"
    $pcapZeekContainer = "/data/train/attack_${choice}.next.pcap"
    $zeekContainer = "/logs/offline/poc_train_attack_${choice}_zeek_next"
    $pyZeekContainer = "/app/logs/offline/poc_train_attack_${choice}_zeek_next"
    $featuresContainer = "/app/output/train_attack_${choice}.next.jsonl"
    $pcapHost = Join-Path $repoRoot "data\train\attack_${choice}.next.pcap"
    $zeekHost = Join-Path $repoRoot "logs\offline\poc_train_attack_${choice}_zeek_next"
    $featuresHost = Join-Path $repoRoot "output\train_attack_${choice}.next.jsonl"

    Reset-Target $pcapHost
    Reset-Target $zeekHost
    Reset-Target $featuresHost

    Invoke-Process "docker" @(
      "compose", "run", "--rm", "py",
      "simulation/generate_attack_train.py",
      "--out", $pcapPyContainer,
      "--choice", $choice,
      "--repeats", "$repeats",
      "--seed", $seed
    )
    Invoke-Process "docker" @(
      "compose", "run", "--rm", "zeek", "sh", "-lc",
      "mkdir -p $zeekContainer && cd $zeekContainer && /usr/local/zeek/bin/zeek -C -r $pcapZeekContainer LogAscii::use_json=T"
    )
    Invoke-Process "docker" @(
      "compose", "run", "--rm", "py",
      "pipeline/build_features.py",
      "--zeek-dir", $pyZeekContainer,
      "--out", $featuresContainer
    )
    $classifierInputs += @("${label}=${featuresContainer}")
  }

  $classifierArgs = @(
    "compose", "run", "--rm", "py",
    "pipeline/train_attack_classifier.py"
  )
  foreach ($inputSpec in $classifierInputs) {
    $classifierArgs += @("--input", $inputSpec)
  }
  $classifierArgs += @(
    "--model-out", "/app/model/attack_classifier.next.pkl",
    "--meta-out", "/app/model/attack_classifier_meta.next.json"
  )
  Invoke-Process "docker" $classifierArgs
}

Move-IntoPlace $tempTrainPcap $trainPcap
Move-IntoPlace $tempQuietPcap $quietPcap
Move-IntoPlace $tempZeekDir $zeekDir
Move-IntoPlace $tempQuietZeekDir $quietZeekDir
Move-IntoPlace $tempFeaturesOut $featuresOut
Move-IntoPlace $tempModelOut $modelOut
Move-IntoPlace $tempMetaOut $metaOut
if (-not $SkipClassifier) {
  Move-IntoPlace $tempClassifierOut $classifierOut
  Move-IntoPlace $tempClassifierMetaOut $classifierMetaOut
}
Reset-Target $tempBusyFeaturesOut
Reset-Target $tempQuietFeaturesOut
if (-not $SkipClassifier) {
  foreach ($spec in $attackSpecs) {
    $choice = $spec.Choice
    Reset-Target (Join-Path $repoRoot "data\train\attack_${choice}.next.pcap")
    Reset-Target (Join-Path $repoRoot "logs\offline\poc_train_attack_${choice}_zeek_next")
    Reset-Target (Join-Path $repoRoot "output\train_attack_${choice}.next.jsonl")
  }
}

Write-Host ""
Write-Host "[OK] Entrenamiento PoC completado"
Write-Host "     pcap     = $trainPcap"
Write-Host "     quiet    = $quietPcap"
Write-Host "     zeek     = $zeekDir"
Write-Host "     features = $featuresOut"
Write-Host "     model    = $modelOut"
Write-Host "     meta     = $metaOut"
if (-not $SkipClassifier) {
  Write-Host "     clf      = $classifierOut"
  Write-Host "     clf meta = $classifierMetaOut"
}
