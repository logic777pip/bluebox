# ============================================================================
#  training/run_train.ps1  --  Windows PowerShell runner for this project.
#
#  Why this file exists:
#    The workspace has TWO Python installs:
#      * D:\work\.venv            -> has unsloth/trl/datasets/bitsandbytes
#                                        (must be the CUDA build of torch!)
#      * system Python 3.10           -> has torch cu128 but no unsloth
#    Training MUST run with the .venv interpreter, so pin it here explicitly.
#
#  Usage:
#    powershell -ExecutionPolicy Bypass -File training\run_train.ps1 -Mode check
#    powershell -ExecutionPolicy Bypass -File training\run_train.ps1 -Mode prep
#    powershell -ExecutionPolicy Bypass -File training\run_train.ps1 -Mode smoke
#    powershell -ExecutionPolicy Bypass -File training\run_train.ps1 -Mode train
#    powershell -ExecutionPolicy Bypass -File training\run_train.ps1 -Mode deploy
#
#  NOTE: ASCII-only comments on purpose -- PS 5.1 mis-decodes UTF-8 without BOM.
# ============================================================================
[CmdletBinding()]
param(
    [ValidateSet('check', 'prep', 'smoke', 'train', 'deploy', 'loop')]
    [string]$Mode = 'check',

    [int]$MaxSamples = 3000,
    [switch]$ExportGguf,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# Project root = parent of this script's folder (script lives in training\).
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$VenvPy      = 'D:\work\.venv\Scripts\python.exe'

if (-not (Test-Path $VenvPy)) {
    throw "Interpreter not found: $VenvPy  (create the workspace venv first)"
}

Write-Host "[run_train] interpreter: $VenvPy" -ForegroundColor Cyan
Write-Host "[run_train] project root: $ProjectRoot" -ForegroundColor Cyan

# --- Guard: refuse to run on a CPU-only torch build -------------------------
$GpuProbe = & $VenvPy -c "import torch;print(torch.__version__, torch.version.cuda, torch.cuda.is_available())" 2>&1
Write-Host "[run_train] torch: $GpuProbe"
if ($GpuProbe -notmatch 'True') {
    Write-Warning "CUDA is NOT available in the venv. Fix with:"
    Write-Warning "  & `"$VenvPy`" -m pip install --force-reinstall --no-deps torch --index-url https://download.pytorch.org/whl/cu128"
    if ($Mode -in @('smoke', 'train')) { throw "Refusing to train on CPU-only torch." }
}

Push-Location $ProjectRoot
try {
    switch ($Mode) {
        'check' {
            & $VenvPy 'training\check_dataset.py'
        }
        'prep' {
            # --no-stream: hf-mirror 的流式迭代会循环吐同一批行（实测 200 行仅 11 唯一），
            # 整份下载后 shuffle+select 更可靠，代价是带宽。
            $env:PYTHONIOENCODING = 'utf-8'
            $env:HF_ENDPOINT = 'https://hf-mirror.com'
            & $VenvPy 'training\data_prep.py' --sources all --no-stream --max-samples $MaxSamples --yes
            & $VenvPy 'training\check_dataset.py'
        }
        'smoke' {
            & $VenvPy 'training\train_qlora.py' --config 'training\config.yaml' --smoke
        }
        'train' {
            $extra = @()
            if ($ExportGguf) { $extra += '--export-gguf' }
            & $VenvPy 'training\train_qlora.py' --config 'training\config.yaml' @extra
        }
        'deploy' {
            $args = @()
            if ($DryRun) { $args += '--dry-run' }
            & bash 'deployment/serve.sh' @args
        }
        'loop' {
            & $VenvPy 'cyber_range\red_blue_loop.py' --offline --episodes 3
        }
    }
}
finally {
    Pop-Location
}

Write-Host "[run_train] done (mode=$Mode, exit=$LASTEXITCODE)" -ForegroundColor Green
