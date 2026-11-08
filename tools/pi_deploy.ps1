# Deploy the Raspberry Pi IDS appliance over SSH from this Windows PC.
#
# NOTE: this file is intentionally ASCII-only. Windows PowerShell 5.1 reads .ps1
# files using the system ANSI code page unless a BOM is present, so non-ASCII
# text here would show up as mojibake. Other .ps1 files in this project follow
# the same rule. (Chinese docs live in docs/RASPI_IDS.md instead.)
#
# What it does:
#   1) checks ssh/scp exist and that key-based auth works (no password in scripts)
#   2) copies raspi-ids/ to the Pi under /tmp/blueteam/raspi-ids
#   3) runs install_pi.sh remotely with sudo (you type the sudo password in your
#      own terminal -- it is never captured by any tool)
#   4) optionally runs verify_pi.sh and shows capture drop rate / top signatures
#
# Usage:
#   .\pi_deploy.ps1 -Host 192.168.1.50
#   .\pi_deploy.ps1 -Host pi4 -User ubuntu -Iface eth0 -Mirror tuna
#   .\pi_deploy.ps1 -Host pi4 -Verify          # only re-run verification
#   .\pi_deploy.ps1 -Host pi4 -DryRun          # print commands, change nothing
#
# If key auth is not set up yet, this script prints the exact one-time commands.

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Host,
  [string]$User = "ubuntu",
  [int]$Port = 22,
  [string]$Iface = "eth0",
  [ValidateSet("", "tuna", "ustc", "aliyun", "huawei", "163", "bfsu")]
  [string]$Mirror = "",
  [string]$Proxy = "",
  [switch]$NoRedis,
  [switch]$NoRulesUpdate,
  [string]$RulesTarball = "",
  [string]$SshKey = "",
  [switch]$SkipInstall,
  [switch]$Verify,
  [switch]$DryRun,
  [int]$TopSigs = 10
)

$ErrorActionPreference = "Stop"

function Info($m) { Write-Host "[deploy] $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "[deploy] $m" -ForegroundColor Yellow }
function Die($m) { Write-Host "[deploy] $m" -ForegroundColor Red; exit 1 }

# --------------------------------------------------------------- preconditions
foreach ($tool in @("ssh", "scp")) {
  if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
    Die "$tool not found. Install the Windows OpenSSH Client: Settings > Apps > Optional features > OpenSSH Client"
  }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$srcDir = Join-Path (Split-Path -Parent $scriptDir) "raspi-ids"
if (-not (Test-Path $srcDir)) { Die "cannot find raspi-ids directory next to tools/: $srcDir" }
$srcDir = (Resolve-Path $srcDir).Path
Info "local source: $srcDir"

$target = "$User@$Host"
$sshBase = @("-p", "$Port", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new")
if ($SshKey) { $sshBase += @("-i", $SshKey) }
$scpBase = @("-P", "$Port", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new")
if ($SshKey) { $scpBase += @("-i", $SshKey) }

$remoteStage = "/tmp/blueteam"
$remoteDir = "$remoteStage/raspi-ids"

function Invoke-Remote([string]$cmd) {
  $sshArgs = @()
  if ($DryRun) { $sshArgs += @("-n") }   # no tty for the dry-run probe
  $sshArgs += $sshBase
  $sshArgs += @("$target", $cmd)
  if ($DryRun) {
    Write-Host ("  [dry-run] ssh " + ($sshArgs -join " "))
    return 0
  }
  & ssh @sshArgs
  return $LASTEXITCODE
}

# --------------------------------------------------------------- 1) key auth
Info "checking key-based SSH auth to $target (password auth is not used by scripts)"
$probe = & ssh @($sshBase + @("-o", "BatchMode=yes", "-o", "NumberOfPasswordPrompts=0", $target, "true")) 2>&1
if ($LASTEXITCODE -ne 0) {
  Warn "key-based auth failed. Reason:"
  ($probe | Select-Object -First 3) | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
  Write-Host ""
  Write-Host "Set it up once (run these yourself, then re-run this script):" -ForegroundColor Yellow
  Write-Host "  1) create a key if you do not have one:"
  Write-Host "       ssh-keygen -t ed25519 -C `"$env:USERNAME@pc`""
  Write-Host "  2) copy the public key to the Pi (type the Pi password when asked):"
  Write-Host "       type `$env:USERPROFILE\.ssh\id_ed25519.pub | ssh -p $Port $target `"mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`""
  Write-Host "  3) verify:  ssh -p $Port $target true"
  Write-Host ""
  Die "stopping here (no secrets are passed through scripts by design)"
}
Info "key auth OK"

# --------------------------------------------------------------- 2) ship files
if (-not $SkipInstall) {
  Info "staging files to ${target}:$remoteDir"
  if ($DryRun) {
    Write-Host ("  [dry-run] ssh " + (@($sshBase + @($target, "mkdir -p $remoteStage")) -join " "))
    Write-Host ("  [dry-run] scp " + (@($scpBase + @("-r", $srcDir, "${target}:$remoteStage/")) -join " "))
  } else {
    $null = & ssh @($sshBase + @($target, "mkdir -p $remoteStage"))
    if ($LASTEXITCODE -ne 0) { Die "failed to create $remoteStage on the Pi" }
    & scp @($scpBase + @("-r", $srcDir, "${target}:$remoteStage/"))
    if ($LASTEXITCODE -ne 0) { Die "scp failed" }
    # The Pi side runs bash on these files; strip any CR that a Windows editor
    # may have introduced (a CRLF .sh fails with 'bad interpreter: /bin/bash^M').
    $null = & ssh @($sshBase + @($target, "cd $remoteDir && find . -type f -name '*.sh' -exec sed -i 's/\r$//' {} + "))
    Info "files staged"
  }
}

# --------------------------------------------------------------- 3) install
if (-not $SkipInstall) {
  $installArgs = @("--iface", $Iface)
  if ($Mirror) { $installArgs += @("--mirror", $Mirror) }
  if ($Proxy) { $installArgs += @("--proxy", $Proxy) }
  if ($NoRedis) { $installArgs += "--no-redis" }
  if ($NoRulesUpdate) { $installArgs += "--no-rules-update" }
  if ($RulesTarball) { $installArgs += @("--rules-tarball", $RulesTarball) }
  $remoteCmd = "sudo bash $remoteDir/install_pi.sh " + ($installArgs -join " ")

  Info "running installer on the Pi (sudo will prompt for your password)"
  Write-Host "  > $remoteCmd" -ForegroundColor DarkGray
  if ($DryRun) {
    Write-Host ("  [dry-run] ssh -t " + (@($sshBase + @($target, $remoteCmd)) -join " "))
  } else {
    # -t is required so that sudo can prompt and so that the generated Redis
    # password (printed once, at the end) reaches YOUR terminal and not a log.
    & ssh @($sshBase + @("-t", $target, $remoteCmd))
    if ($LASTEXITCODE -ne 0) { Die "installer exited with code $LASTEXITCODE (see output above)" }
    Info "installer finished"
    Write-Host ""
    Write-Host "IMPORTANT: copy the Redis password printed above into" -ForegroundColor Yellow
    Write-Host "  \$env:IDS_REDIS_PASSWORD  on this PC (or pass --password to the bridge)." -ForegroundColor Yellow
    Write-Host "It is stored on the Pi at /etc/default/blueteam-ids (mode 600)." -ForegroundColor Yellow
    Write-Host ""
  }
}

# --------------------------------------------------------------- 4) verify
if ($Verify -or -not $SkipInstall) {
  Info "running verification on the Pi"
  $vcmd = "sudo bash $remoteDir/verify_pi.sh --iface $Iface --top-sigs $TopSigs"
  Write-Host "  > $vcmd" -ForegroundColor DarkGray
  if ($DryRun) {
    Write-Host ("  [dry-run] ssh " + (@($sshBase + @($target, $vcmd)) -join " "))
  } else {
    & ssh @($sshBase + @($target, $vcmd))
    $rc = $LASTEXITCODE
    if ($rc -ne 0) {
      Warn "verification reported failures (exit $rc). Fix the lines marked with x before trusting any alert."
    } else {
      Info "verification passed"
    }
  }
}

# --------------------------------------------------------------- next steps
if (-not $DryRun) {
  Write-Host ""
  Info "next: start the PC-side bridge that consumes the stream"
  Write-Host "  cd $((Get-Item $scriptDir).Parent.FullName)"
  Write-Host "  `$env:IDS_REDIS_PASSWORD = '<password from the installer output>'"
  Write-Host "  .\.venv\Scripts\python.exe tools\suricata_bridge.py --broker ${Host}:6379 --llm --notify"
  Write-Host ""
  Write-Host "  then check it end-to-end from the Pi:  ssh -p $Port $target 'sudo bash $remoteDir/verify_pi.sh --test-push'"
}
