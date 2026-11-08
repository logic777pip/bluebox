# tools/install_autostart.ps1 -- register the network sensor to start at logon
#
# Pure-ASCII script on purpose: PowerShell 5.1 decodes BOM-less UTF-8 as ANSI,
# so non-ASCII text inside a .ps1 gets mangled. All messages are English here.
#
# Usage (no admin needed for a per-user logon task):
#   powershell -ExecutionPolicy Bypass -File tools\install_autostart.ps1 -Install
#   powershell -ExecutionPolicy Bypass -File tools\install_autostart.ps1 -Status
#   powershell -ExecutionPolicy Bypass -File tools\install_autostart.ps1 -Uninstall
param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Status,
    [switch]$StartNow,
    [int]$Interval = 15,
    [int]$Threshold = 30,
    [string]$TaskName = 'BlueTeamNetSensor'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$sensor = Join-Path $root 'tools\net_sensor.py'
$logFile = Join-Path $root 'logs\net_sensor.log'

function Get-Python {
    # Prefer pythonw.exe so the task runs without a console window.
    $venv = Join-Path (Split-Path -Parent $root) '.venv\Scripts'
    foreach ($n in @('pythonw.exe', 'python.exe')) {
        $p = Join-Path $venv $n
        if (Test-Path -LiteralPath $p) { return $p }
    }
    foreach ($n in @('pythonw.exe', 'python.exe')) {
        $c = Get-Command $n -ErrorAction SilentlyContinue
        if ($c) { return $c.Source }
    }
    throw 'python not found; set up the venv first'
}

function Show-Status {
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $t) { Write-Output "STATUS not-installed"; return }
    $i = Get-ScheduledTaskInfo -TaskName $TaskName
    Write-Output ("STATUS installed state={0} last={1} result={2} next={3}" -f `
        $t.State, $i.LastRunTime, $i.LastTaskResult, $i.NextRunTime)
    $proc = Get-Process -Name pythonw, python -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -like '*blue-team-agent*' }
    Write-Output ("PROCESS sensor-running={0}" -f ([bool]$proc))
}

if ($Uninstall) {
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($t) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Output 'RESULT uninstalled'
    } else {
        Write-Output 'RESULT not-present'
    }
    Get-Process -Name pythonw, python -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -like '*blue-team-agent*' } |
        ForEach-Object { Stop-Process -Id $_.Id -Force }
    Write-Output 'RESULT sensor-processes-stopped'
    exit 0
}

if ($Status -and -not $Install) { Show-Status; exit 0 }

if (-not $Install) {
    Write-Output 'USAGE -Install | -Uninstall | -Status [-StartNow] [-Interval N] [-Threshold N]'
    exit 1
}

if (-not (Test-Path -LiteralPath $sensor)) { throw "sensor not found: $sensor" }
$py = Get-Python

# NOTE: the action is intentionally READ-ONLY capable only. net_sensor.py has no
# code path that executes response actions, and tools/triage_logs.py (which it
# reuses) forces actions.enable_executor=false with a read-back assertion.
$args = '"{0}" --loop --llm --notify --interval {1} --threshold {2} --log-file "{3}"' -f `
    $sensor, $Interval, $Threshold, $logFile

$action = New-ScheduledTaskAction -Execute $py -Argument $args -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive `
    -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal -Force | Out-Null
Write-Output ("RESULT installed task={0} python={1}" -f $TaskName, $py)
Write-Output ("RESULT interval={0}s threshold={1} log={2}" -f $Interval, $Threshold, $logFile)

if ($StartNow) {
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 6
    Write-Output 'RESULT started-now'
    Show-Status
}
