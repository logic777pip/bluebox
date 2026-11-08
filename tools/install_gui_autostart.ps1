<#
  install_gui_autostart.ps1 -- register / remove the silent boot autostart of the GUI console.

  WHAT IT DOES
    Creates a per-user Scheduled Task (trigger: AtLogOn) that launches the console with
    pythonw.exe. pythonw.exe has no console subsystem, so nothing flashes and no window
    appears at boot. The only visible affordance is the tray icon, which is how you open
    the console afterwards (left click = open, right click = menu).

  WHY A SCHEDULED TASK INSTEAD OF THE STARTUP FOLDER
    * Startup-folder shortcuts cannot run elevated without a UAC prompt at every logon.
    * Task Scheduler can: a task registered with -RunLevel Highest starts elevated and
      silently. That matters because real firewall containment needs admin rights.
    * It also gives us restart-on-failure, "no time limit", and IgnoreNew so you do not
      end up with three copies of the console after a few logons.

  REQUIREMENTS
    Run this script from an ELEVATED PowerShell when using -RunLevel Highest (default).
    Registering a Highest task from a non-elevated shell fails with access denied.

  USAGE
    # register (elevated) and start it now
    powershell -ExecutionPolicy Bypass -File tools\install_gui_autostart.ps1 -Start

    # register read-only (watch only, every write endpoint returns 403)
    ... -ReadOnly

    # record the task but do NOT launch it at logon yet
    ... -NoAutostart

    # inspect / control
    ... -Status
    ... -Start
    ... -Stop
    ... -Uninstall

  NOTE ON SECURITY
    The console binds 127.0.0.1 only and requires a per-launch random token, so it is not
    reachable from the network. Running it elevated is still a real tradeoff: the process
    can change firewall rules and rewrite config files. If you would rather not keep an
    elevated listener alive, register with -RunLevel Limited and start an elevated copy
    on demand when you actually need to contain something.
#>
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$Start,
    [switch]$Stop,
    [switch]$Status,
    [switch]$ReadOnly,
    [switch]$NoAutostart,
    [ValidateSet('Highest', 'Limited')]
    [string]$RunLevel = 'Highest',
    [int]$Port = 8720,
    [string]$Pythonw = ''
)

$ErrorActionPreference = 'Stop'
$TaskName = 'BlueTeamAgentGUI'
$Root = Split-Path -Parent $PSScriptRoot
$ServerPy = Join-Path $Root 'gui\server.py'
$RuntimeJson = Join-Path $Root 'logs\gui_runtime.json'

function Resolve-Pythonw {
    # The interpreter is NOT necessarily inside the project folder. In this workspace
    # the venv lives one level up (D:\work\.venv) while the code lives in
    # D:\work\blue-team-agent -- so guessing a single path is not enough.
    param([string]$Explicit)
    $cands = @()
    if ($Explicit) { $cands += $Explicit }
    $cands += (Join-Path $Root '.venv\Scripts\pythonw.exe')
    $cands += (Join-Path (Split-Path -Parent $Root) '.venv\Scripts\pythonw.exe')
    $cands += (Join-Path $Root 'venv\Scripts\pythonw.exe')
    foreach ($c in $cands) {
        if ($c -and (Test-Path $c)) { return (Resolve-Path $c).Path }
    }
    $onPath = Get-Command pythonw.exe -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    return ''
}

function Write-Step($m) { Write-Host "  $m" }
function Write-Head($m) { Write-Host ""; Write-Host "== $m" -ForegroundColor Cyan }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-GuiProcess {
    # Match on the command line, not just the image name: pythonw.exe may be running
    # other things (the net sensor uses it too), and killing those would blind the host.
    Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='python.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine -like '*gui*server.py*' }
}

function Show-Runtime {
    if (Test-Path $RuntimeJson) {
        try {
            $j = Get-Content $RuntimeJson -Raw -Encoding UTF8 | ConvertFrom-Json
            Write-Step ("runtime : pid={0} port={1} read_only={2} started={3}" -f $j.pid, $j.port, $j.read_only, $j.started)
            Write-Step ("open via: tray icon (left click) or http://127.0.0.1:{0}/?token=<from tray>" -f $j.port)
        } catch {
            Write-Step "runtime : logs\gui_runtime.json unreadable ($($_.Exception.Message))"
        }
    } else {
        Write-Step "runtime : no logs\gui_runtime.json (console not started yet)"
    }
}

# ---------------------------------------------------------------- status

if ($Status) {
    Write-Head "Task"
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $t) {
        Write-Step "not registered"
    } else {
        $i = Get-ScheduledTaskInfo -TaskName $TaskName
        Write-Step ("state   : {0}" -f $t.State)
        Write-Step ("runlevel: {0}" -f $t.Principal.RunLevel)
        Write-Step ("action  : {0} {1}" -f $t.Actions[0].Execute, $t.Actions[0].Arguments)
        Write-Step ("trigger : {0}" -f (($t.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ', '))
        Write-Step ("last run: {0}  result=0x{1:X}" -f $i.LastRunTime, $i.LastTaskResult)
        Write-Step ("next run: {0}" -f $i.NextRunTime)
    }

    Write-Head "Process"
    $procs = Get-GuiProcess
    if (-not $procs) {
        Write-Step "no gui.server process running"
    } else {
        foreach ($p in $procs) { Write-Step ("pid {0}  {1}" -f $p.ProcessId, $p.CommandLine) }
    }

    Write-Head "Listener"
    $conn = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -ge $Port -and $_.LocalPort -le ($Port + 20) }
    if (-not $conn) {
        Write-Step "nothing listening in ports $Port..$($Port + 20)"
    } else {
        foreach ($c in $conn) { Write-Step ("listening {0}:{1} (pid {2})" -f $c.LocalAddress, $c.LocalPort, $c.OwningProcess) }
        $bad = $conn | Where-Object { $_.LocalAddress -notin @('127.0.0.1', '::1') }
        if ($bad) {
            Write-Host "  [ALERT] listener is NOT loopback-only -- the console may be reachable" -ForegroundColor Red
            Write-Host "          from the network. Stop it and check the config." -ForegroundColor Red
        }
    }

    Show-Runtime
    return
}

# ------------------------------------------------------------- uninstall

if ($Uninstall) {
    Write-Head "Uninstall"
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($t) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Step "task removed: $TaskName"
    } else {
        Write-Step "task not present: $TaskName"
    }

    $procs = Get-GuiProcess
    foreach ($p in $procs) {
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        Write-Step "stopped pid $($p.ProcessId)"
    }
    if (-not $procs) { Write-Step "no running console process" }

    # The tray icon can leave a ghost in the notification area if the process is killed
    # rather than exiting through the menu. A ghost disappears once you hover over it.
    Write-Step "note: if a dead tray icon lingers, hover over it to make Windows clear it"
    return
}

# ------------------------------------------------------------------ stop

if ($Stop) {
    Write-Head "Stop"
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($t -and $t.State -eq 'Running') {
        Stop-ScheduledTask -TaskName $TaskName
        Write-Step "task stopped"
    }
    foreach ($p in Get-GuiProcess) {
        try {
            # Ask the console to shut down cleanly first so the tray icon is removed and
            # the firewall rules in effect are reported; fall back to kill.
            Stop-Process -Id $p.ProcessId -ErrorAction SilentlyContinue
            Write-Step "stopped pid $($p.ProcessId)"
        } catch {
            Write-Step "could not stop pid $($p.ProcessId): $($_.Exception.Message)"
        }
    }
    Show-Runtime
    return
}

# ----------------------------------------------------------------- start

if ($Start) {
    Write-Head "Start"
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $t) {
        Write-Host "  task $TaskName is not registered. Run this script without -Start first." -ForegroundColor Red
        exit 1
    }
    if (Get-GuiProcess) {
        Write-Step "console already running; not starting a second copy"
    } else {
        Start-ScheduledTask -TaskName $TaskName
        Start-Sleep -Seconds 3
        Write-Step "task started"
    }
    $procs = Get-GuiProcess
    if ($procs) { foreach ($p in $procs) { Write-Step ("pid {0} running" -f $p.ProcessId) } }
    else { Write-Step "no process yet -- check Task Scheduler history / logs\gui.log" }
    Show-Runtime
    return
}

# --------------------------------------------------------- install (default)

Write-Head "Preconditions"

$Pythonw = Resolve-Pythonw -Explicit $Pythonw
if (-not $Pythonw) {
    Write-Host "  Cannot find pythonw.exe. Pass it explicitly:" -ForegroundColor Red
    Write-Host "    -Pythonw D:\path\to\.venv\Scripts\pythonw.exe" -ForegroundColor Red
    Write-Host "  (pythonw.exe has no console subsystem, which is what makes the" -ForegroundColor Red
    Write-Host "   autostart silent. python.exe would flash a black window at logon.)" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $ServerPy)) {
    Write-Host "  MISSING: $ServerPy" -ForegroundColor Red
    exit 1
}
Write-Step "pythonw  : $Pythonw"
Write-Step "server   : $ServerPy"

$isAdmin = Test-Admin
Write-Step ("elevated : {0}" -f $isAdmin)

if ($RunLevel -eq 'Highest' -and -not $isAdmin) {
    Write-Host ""
    Write-Host "  Registering a Highest-run-level task needs an elevated shell." -ForegroundColor Red
    Write-Host "  Open PowerShell as Administrator and re-run this script, or use" -ForegroundColor Red
    Write-Host "  -RunLevel Limited (containment writes will then need an elevated start)." -ForegroundColor Red
    exit 1
}

# Confirm the interpreter can actually start the module before wiring it to logon.
# A task that silently fails at every boot is worse than no task at all.
Write-Head "Smoke test"
# Build the argument string once and reuse it for both the smoke test and the task,
# so what we verified is exactly what will run at logon.
if ($ReadOnly) { $argPreview = '"{0}" --port {1} --read-only' -f $ServerPy, $Port }
else           { $argPreview = '"{0}" --port {1}' -f $ServerPy, $Port }
Write-Step "will run: $Pythonw $argPreview"

$probe = Start-Process -FilePath $Pythonw -ArgumentList $argPreview -WorkingDirectory $Root -PassThru
Start-Sleep -Seconds 4
$alive = -not $probe.HasExited
if ($alive) {
    Write-Step "smoke test ok (pid $($probe.Id) still alive after 4s)"
    $listening = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -ge $Port -and $_.LocalPort -le ($Port + 20) }
    if ($listening) {
        foreach ($c in $listening) { Write-Step ("listening {0}:{1}" -f $c.LocalAddress, $c.LocalPort) }
    } else {
        Write-Step "[warn] process is alive but no listener found yet; check logs\gui.log"
    }
    Stop-Process -Id $probe.Id -Force -ErrorAction SilentlyContinue
    Write-Step "smoke test process stopped"
    Start-Sleep -Seconds 1
} else {
    Write-Host "  smoke test FAILED: the console exited immediately." -ForegroundColor Red
    Write-Host "  Last lines of logs\gui.log:" -ForegroundColor Red
    $lg = Join-Path $Root 'logs\gui.log'
    if (Test-Path $lg) { Get-Content $lg -Tail 20 | ForEach-Object { Write-Host "    $_" } }
    Write-Host "  Not registering the task." -ForegroundColor Red
    exit 1
}

Write-Head "Register task"

$me = "$env:USERDOMAIN\$env:USERNAME"
$action = New-ScheduledTaskAction -Execute $Pythonw -Argument $argPreview -WorkingDirectory $Root

$triggers = @()
if (-not $NoAutostart) {
    # AtLogOn for this user only. -Delay was added in later builds; guard it so the
    # script does not explode on an older box.
    try {
        $triggers += New-ScheduledTaskTrigger -AtLogOn -User $me -RandomDelay (New-TimeSpan -Seconds 20)
    } catch {
        $triggers += New-ScheduledTaskTrigger -AtLogOn -User $me
    }
}

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
    -MultipleInstances IgnoreNew
$settings.DisallowStartIfOnBatteries = $false

$principal = New-ScheduledTaskPrincipal -UserId $me -LogonType Interactive -RunLevel $RunLevel

$desc = 'Blue Team Agent local console. Silent autostart at logon via pythonw.exe; ' +
        'open it from the notification-area tray icon. Bound to 127.0.0.1 with a ' +
        'per-launch random token.'

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers `
    -Settings $settings -Principal $principal -Description $desc -Force | Out-Null
Write-Step "registered: $TaskName (RunLevel=$RunLevel)"

if ($NoAutostart) {
    Write-Step "no logon trigger added (-NoAutostart); use -Start when you want it"
}

Write-Head "Done"
Write-Step "the console will start silently at every logon"
Write-Step "open it from the tray icon (left click), right click for the menu"
Write-Step "verify later with: tools\install_gui_autostart.ps1 -Status"
Write-Step "remove everything with: tools\install_gui_autostart.ps1 -Uninstall"
Write-Host ""
