# Register the PC-side Suricata bridge as a logon scheduled task.
#
# NOTE: ASCII-only on purpose (PowerShell 5.1 reads .ps1 with the system ANSI
# code page unless a BOM is present, so non-ASCII here would be mojibake).
#
# Why a wrapper .cmd instead of putting everything in the task action:
#   The bridge reads its Redis password from the environment variable
#   IDS_REDIS_PASSWORD. Windows scheduled tasks cannot define environment
#   variables in the action, so we generate a tiny launcher that loads the
#   password from a file (ACL-restricted to the current user) and then execs
#   the bridge. The password itself is never stored in the task definition,
#   never passed on a command line (so it does not show up in `Get-Process`
#   command lines or in the task XML), and never printed by this script.
#
# Usage:
#   .\install_bridge_task.ps1 -Broker 192.168.1.50:6379 -PasswordPrompt -Install
#   .\install_bridge_task.ps1 -Status
#   .\install_bridge_task.ps1 -StartNow
#   .\install_bridge_task.ps1 -Uninstall

[CmdletBinding()]
param(
  [string]$Broker = "",
  [int]$Threshold = 30,
  [int]$MaxLlmPerMin = 3,
  [switch]$WithLlm,
  [switch]$Notify,
  [switch]$PasswordPrompt,
  [switch]$Install,
  [switch]$Uninstall,
  [switch]$Status,
  [switch]$StartNow,
  [string]$TaskName = "BlueTeamSuricataBridge"
)

$ErrorActionPreference = "Stop"
function Info($m) { Write-Host "[bridge-task] $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "[bridge-task] $m" -ForegroundColor Yellow }
function Die($m) { Write-Host "[bridge-task] $m" -ForegroundColor Red; exit 1 }

$projRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$pythonw = Join-Path $projRoot ".venv\Scripts\pythonw.exe"
$bridge = Join-Path $projRoot "tools\suricata_bridge.py"
$logDir = Join-Path $projRoot "logs"
$secretDir = Join-Path $env:LOCALAPPDATA "BlueTeamAgent"
$secretFile = Join-Path $secretDir "ids_redis_password"
$launcher = Join-Path $secretDir "run_suricata_bridge.cmd"

if ($Status) {
  $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if (-not $t) { Write-Host "task '$TaskName' is not registered"; exit 1 }
  $i = Get-ScheduledTaskInfo -TaskName $TaskName
  Write-Host "task      : $($t.TaskName)  state=$($t.State)"
  Write-Host "last run  : $($i.LastRunTime)  result=$($i.LastTaskResult)"
  Write-Host "next run  : $($i.NextRunTime)"
  Write-Host "launcher  : $launcher"
  Write-Host "password  : $(if (Test-Path $secretFile) { 'present' } else { 'MISSING' })"
  $log = Join-Path $logDir "suricata_bridge.log"
  if (Test-Path $log) {
    Write-Host ""
    Write-Host "last 3 log lines:"
    Get-Content -LiteralPath $log -Tail 3 | ForEach-Object { Write-Host "  $_" }
  }
  exit 0
}

if ($Uninstall) {
  $null = Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Info "task '$TaskName' removed (log/password files are left in place)"
  exit 0
}

if (-not $Install -and -not $StartNow) {
  Die "nothing to do. Use -Install, -StartNow, -Status or -Uninstall. See -? for details."
}

if (-not (Test-Path $pythonw)) {
  Die "pythonw.exe not found at $pythonw -- is the venv at .venv\Scripts?"
}
if (-not (Test-Path $bridge)) { Die "bridge not found: $bridge" }

New-Item -ItemType Directory -Force -Path $secretDir | Out-Null
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

# ---- password file ----------------------------------------------------------
if ($PasswordPrompt) {
  Write-Host ""
  Write-Host "Enter the Redis password (from the Pi installer output)." -ForegroundColor Yellow
  Write-Host "It is written to:" -ForegroundColor DarkGray
  Write-Host "  $secretFile" -ForegroundColor DarkGray
  Write-Host "and locked to your user account only. It is never echoed." -ForegroundColor DarkGray
  $sec = Read-Host -AsSecureString "Redis password"
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
  try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
  } finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
  }
  if ([string]::IsNullOrWhiteSpace($plain)) { Die "empty password, aborting" }
  # Write without a trailing newline so the launcher does not need to trim
  [IO.File]::WriteAllText($secretFile, $plain, (New-Object Text.UTF8Encoding($false)))
  $plain = $null
  $acl = Get-Acl $secretFile
  $acl.SetAccessRuleProtection($true, $false)   # drop inherited rules
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
  $rule = New-Object Security.AccessControl.FileSystemAccessRule(
    $me, "FullControl", "Allow")
  $acl.SetAccessRule($rule)
  Set-Acl -Path $secretFile -AclObject $acl
  Info "password saved (ACL restricted to $me)"
}

if (-not (Test-Path $secretFile)) {
  Warn "no password file yet: $secretFile"
  Warn "re-run with -PasswordPrompt, or create it yourself with the Redis password."
  Warn "(If your Redis has no password, create an empty file instead.)"
}

# ---- launcher ---------------------------------------------------------------
if (-not $Broker) {
  if (Test-Path $launcher) {
    # keep the broker from an earlier install
    $prev = Select-String -LiteralPath $launcher -Pattern '--broker\s+(\S+)' |
            Select-Object -First 1
    if ($prev) { $Broker = $prev.Matches[0].Groups[1].Value }
  }
  if (-not $Broker) { Die "-Broker is required for a fresh install, e.g. -Broker 192.168.1.50:6379" }
}

$args = @(
  "--broker", $Broker,
  "--threshold", "$Threshold",
  "--max-llm-per-min", "$MaxLlmPerMin",
  "--notify",
  "--log-file", (Join-Path $logDir "suricata_bridge.log"),
  "--out", (Join-Path $logDir "suricata_findings.jsonl")
)
if ($WithLlm) { $args += "--llm" } else { $args += "--no-llm" }
if (-not $Notify) { $args = $args | Where-Object { $_ -ne "--notify" } }

$cmd = @()
$cmd += "@echo off"
$cmd += "rem Generated by tools/install_bridge_task.ps1 -- do not edit by hand."
$cmd += "rem Password is read from a file instead of being embedded here."
$cmd += "set IDS_REDIS_PASSWORD="
$cmd += "if exist `"$secretFile`" set /p IDS_REDIS_PASSWORD=<`"$secretFile`""
$cmd += "`"$pythonw`" `"$bridge`" " + ($args -join " ")
[IO.File]::WriteAllLines($launcher, $cmd, (New-Object Text.UTF8Encoding($false)))
Info "launcher written: $launcher"

# ---- task -------------------------------------------------------------------
if ($Install) {
  $action = New-ScheduledTaskAction -Execute $launcher -WorkingDirectory $projRoot
  # AtLogOn + restart-on-failure: the bridge should come back by itself, and a
  # failed start (e.g. Pi offline) should not need a human.
  $trigger = New-ScheduledTaskTrigger -AtLogOn
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -RestartInterval (New-TimeSpan -Minutes 5) -RestartCount 999 `
    -ExecutionTimeLimit (New-TimeSpan -Days 0)
  $null = Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Description "Consumes Suricata alerts from the Raspberry Pi IDS appliance" `
    -Force
  Info "task '$TaskName' registered (at logon, auto-restart every 5 min on failure)"
}

if ($StartNow -or ($Install -and (Test-Path $secretFile))) {
  if (-not (Test-Path $secretFile)) {
    Warn "skipping start: no password file"
  } else {
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 4
    $i = Get-ScheduledTaskInfo -TaskName $TaskName
    Info "started; last result = $($i.LastTaskResult) (0 = ok)"
    $log = Join-Path $logDir "suricata_bridge.log"
    if (Test-Path $log) {
      Write-Host "recent log:"
      Get-Content -LiteralPath $log -Tail 6 | ForEach-Object { Write-Host "  $_" }
    }
  }
}

Write-Host ""
Info "next steps"
Write-Host "  check status : .\tools\install_bridge_task.ps1 -Status"
Write-Host "  report       : .\.venv\Scripts\python.exe tools\suricata_bridge.py --report $(Get-Date -Format 'yyyy-MM-dd')"
Write-Host "  end-to-end   : ssh ubuntu@<pi> 'sudo bash /tmp/blueteam/raspi-ids/verify_pi.sh --test-push'"
