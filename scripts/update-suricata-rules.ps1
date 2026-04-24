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

Set-Location $repoRoot
Invoke-Process "docker" @(
  "compose", "run", "--rm", "--entrypoint", "sh", "suricata", "-lc",
  "suricata-update --no-reload && suricata -T -c /etc/suricata/suricata.yaml"
)
