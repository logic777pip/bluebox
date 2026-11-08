# =============================================================================
#  start.ps1 -- one-click launcher for the blue-team agent (Windows / PowerShell)
#
#  Deployment backend: llama.cpp (llama-server, OpenAI-compatible API).
#  NO Ollama required.
#
#  Usage:
#    powershell -ExecutionPolicy Bypass -File start.ps1                 # full: setup+convert+serve+test
#    powershell -ExecutionPolicy Bypass -File start.ps1 -Action status
#    powershell -ExecutionPolicy Bypass -File start.ps1 -Action down
#    powershell -ExecutionPolicy Bypass -File start.ps1 -Action test
#    powershell -ExecutionPolicy Bypass -File start.ps1 -Accel cpu -Port 8081
#
#  NOTE: comments are ASCII-only on purpose -- PowerShell 5.1 mis-decodes
#        UTF-8 files without BOM, which would garble non-ASCII comments.
# =============================================================================
[CmdletBinding()]
param(
    [ValidateSet('up', 'down', 'status', 'test', 'convert')]
    [string]$Action = 'up',

    [ValidateSet('cuda', 'cpu', 'vulkan')]
    [string]$Accel = 'cuda',

    # auto  = reuse an existing CUDA runtime (e.g. torch/lib) and skip the 373MB cudart download
    # bundle= always download the official cudart package
    # none  = reuse only; fail if no local CUDA runtime is found
    [ValidateSet('auto', 'bundle', 'none')]
    [string]$Cudart = 'auto',

    [int]$Port = 8080,
    [int]$Ctx = 4096,
    [int]$Ngl = 99,
    [int]$Threads = 6,

    [switch]$SkipSetup,      # do not download llama.cpp binaries
    [switch]$Force,          # force re-convert GGUF
    [switch]$SkipTest,       # skip the agent smoke test
    [string]$Merged = ''     # override merged HF weights dir
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = $PSScriptRoot
$DeployPy    = Join-Path $ProjectRoot 'deployment\llamacpp\deploy_llamacpp.py'

# UTF-8 console so Chinese alert text / logs are not garbled (PS 5.1 defaults to the OEM codepage)
try {
    [Console]::OutputEncoding = [Text.Encoding]::UTF8
    [Console]::InputEncoding  = [Text.Encoding]::UTF8
    $OutputEncoding           = [Text.Encoding]::UTF8
} catch { }
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONUTF8       = '1'

function Write-Ok    { param($m) Write-Host "[ok]    $m" -ForegroundColor Green }
function Write-Step  { param($m) Write-Host "[step]  $m" -ForegroundColor Cyan }
function Write-Warn2 { param($m) Write-Host "[warn]  $m" -ForegroundColor Yellow }
function Write-Err   { param($m) Write-Host "[error] $m" -ForegroundColor Red }

# --- 1. locate an interpreter that has the project deps -----------------------
#
# NOTE: candidates must be *validated*, not just found. On Windows the
# `WindowsApps\python3.exe` app-execution alias is present and executable but
# only prints "Python was not found" -- picking it produces a confusing handoff
# where every later step fails for no visible reason.
function Test-Python {
    param([string]$Exe)
    if ([string]::IsNullOrWhiteSpace($Exe)) { return $false }
    if (-not (Test-Path $Exe)) { return $false }
    try {
        & $Exe -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>$null | Out-Null
        return ($LASTEXITCODE -eq 0)
    } catch { return $false }
}

function Get-Python {
    $candidates = @(
        $env:PYTHON,
        (Join-Path $env:VIRTUAL_ENV 'Scripts\python.exe'),
        (Join-Path $ProjectRoot '.venv\Scripts\python.exe'),
        (Join-Path $ProjectRoot 'venv\Scripts\python.exe'),
        (Join-Path (Split-Path $ProjectRoot -Parent) '.venv\Scripts\python.exe'),  # workspace-level venv (parent folder)
        (Get-Command python -ErrorAction SilentlyContinue).Source,
        (Get-Command python3 -ErrorAction SilentlyContinue).Source
    )
    foreach ($c in $candidates) {
        if (Test-Python $c) { return $c }
    }
    throw 'No usable Python 3.8+ interpreter found. Create a venv first (see README section 0) or set $env:PYTHON.'
}

$Python = Get-Python
Write-Step "interpreter: $Python"
if (-not (Test-Path $DeployPy)) { throw "deployment tool not found: $DeployPy" }

# --- 2. actions ---------------------------------------------------------------
function Invoke-Deploy {
    param([string[]]$DeployArgs)
    & $Python $DeployPy @DeployArgs
    if ($LASTEXITCODE -ne 0) {
        throw ("deploy_llamacpp.py failed (exit $LASTEXITCODE): " + ($DeployArgs -join ' '))
    }
}

function Invoke-HealthCheck {
    param([int]$TimeoutSec = 180)
    Write-Step "waiting for llama-server on port $Port (timeout ${TimeoutSec}s) ..."
    Invoke-Deploy @('wait', '--host', '127.0.0.1', '--port', "$Port", '--timeout', "$TimeoutSec")
}

function Invoke-AgentTest {
    Write-Step 'agent smoke test (backend=llamacpp) ...'

    # The alert text lives in a UTF-8 file on purpose. This script stays pure
    # ASCII: PowerShell 5.1 decodes a BOM-less .ps1 as ANSI, which would mangle
    # any non-ASCII literal (observed: "\u6587\u4ef6\u540e\u7f00" became mojibake).
    # Python reads the file as UTF-8, so the Chinese alert survives intact.
    # A Chinese alert is used because the model was fine-tuned mostly on Chinese
    # security data; English alerts measurably degrade retrieval + grounding
    # (an English alert pulled unrelated SSH-brute-force chunks and produced only
    # schema-rejected actions). Keep this in sync with start.sh.
    $alertFile = Join-Path $ProjectRoot 'deployment\llamacpp\smoke_alert.txt'
    if (-not (Test-Path $alertFile)) { throw "smoke alert file not found: $alertFile" }

    Push-Location $ProjectRoot
    try {
        $env:PYTHONPATH = $ProjectRoot
        & $Python 'agent\agent.py' --backend llamacpp --alert-file $alertFile
        if ($LASTEXITCODE -ne 0) { Write-Warn2 "agent reported exit $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
}

switch ($Action) {
    'up' {
        if (-not $SkipSetup) {
            Write-Step "llama.cpp setup (accel=$Accel, cudart=$Cudart, prebuilt)"
            Invoke-Deploy @('setup', '--mode', 'prebuilt', '--accel', $Accel, '--cudart', $Cudart)
        } else {
            Write-Warn2 'skipping llama.cpp setup (-SkipSetup)'
        }

        $convertArgs = @('convert', '--quant', 'Q4_K_M')
        if ($Force)  { $convertArgs += '--force' }
        if ($Merged) { $convertArgs += @('--merged', $Merged) }
        Write-Step 'converting HF weights -> GGUF -> Q4_K_M'
        Invoke-Deploy $convertArgs

        Write-Step 'starting llama-server'
        Invoke-Deploy @('serve', '--host', '127.0.0.1', '--port', "$Port",
                        '--ctx', "$Ctx", '--ngl', "$Ngl", '--threads', "$Threads")

        Invoke-HealthCheck
        Write-Ok "llama-server is up: http://127.0.0.1:$Port  (OpenAI-compatible /v1/chat/completions)"

        if (-not $SkipTest) { Invoke-AgentTest }
        Write-Ok 'done. Stop the server with:  start.ps1 -Action down'
    }

    'convert' {
        $convertArgs = @('convert', '--quant', 'Q4_K_M')
        if ($Force)  { $convertArgs += '--force' }
        if ($Merged) { $convertArgs += @('--merged', $Merged) }
        Invoke-Deploy $convertArgs
        Write-Ok 'GGUF conversion finished'
    }

    'status' {
        Invoke-Deploy @('status', '--port', "$Port")
        try {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/health" -TimeoutSec 5 -UseBasicParsing
            Write-Ok "health: $($r.Content)"
        } catch {
            Write-Warn2 'server not responding on /health'
        }
    }

    'down' {
        Invoke-Deploy @('stop')
        Write-Ok 'stopped'
    }

    'test' {
        Invoke-AgentTest
        Write-Ok 'test finished'
    }
}
