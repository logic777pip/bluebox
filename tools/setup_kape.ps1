# Configure KAPE + EZTools for the blue-team-agent forensics pipeline.
#
# NOTE: ASCII-only on purpose (PowerShell 5.1 reads .ps1 with the system ANSI
# code page unless a BOM is present, so non-ASCII here would be mojibake).
#
# Why "replace the tree" instead of "merge":
#   KapeFiles moves files between subfolders across revisions (e.g. a target can
#   move from Targets\Windows\ to Targets\Apps\). A naive merge therefore leaves
#   stale copies behind in the old location, and KAPE requires **target/module
#   names to be globally unique across the whole tree** -- it then refuses to
#   start with "A target named X already exists at ...". Observed for real.
#   So: back up, wipe Targets\ and Modules\ (keeping !Local), extract the
#   community set, re-add our own target, then let KAPE itself validate.
#
# Writes only inside the KAPE folder. Always backs up first.
#
# Usage:
#   .\tools\setup_kape.ps1 -KapeDir D:\work\KAPE
#   .\tools\setup_kape.ps1 -KapeDir D:\work\KAPE -DryRun
#   .\tools\setup_kape.ps1 -KapeDir D:\work\KAPE -NoCommunitySet   # only fix our target

[CmdletBinding()]
param(
  [string]$KapeDir = "",
  [string]$KapeFilesZip = "",
  [string]$BlueTeamTarget = "",
  [string]$EzToolsFrom = "",
  [switch]$NoCommunitySet,
  [switch]$DryRun
)

$ErrorActionPreference = "Stop"
function Info($m) { Write-Host "[kape-setup] $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "[kape-setup] $m" -ForegroundColor Yellow }
function Die($m) { Write-Host "[kape-setup] $m" -ForegroundColor Red; exit 1 }

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$projRoot = Split-Path -Parent $here

# ---------------------------------------------------------------- 1) locate
$candidates = @(
  $KapeDir,
  "D:\work\KAPE",
  "C:\Tools\KAPE",
  "C:\Program Files\KAPE",
  "C:\Program Files (x86)\KAPE",
  "C:\KAPE", "D:\KAPE", "D:\Tools\KAPE"
) | Where-Object { $_ -and $_.Trim() -ne "" }

$kapeHome = ""
foreach ($c in $candidates) {
  if (Test-Path (Join-Path $c "kape.exe")) { $kapeHome = (Resolve-Path $c).Path; break }
}
if (-not $kapeHome) { Die "kape.exe not found. Pass -KapeDir <folder containing kape.exe>." }
$exePath = Join-Path $kapeHome "kape.exe"
Info "KAPE home : $kapeHome"
Info "kape.exe  : $exePath"

$ver = ""
try { $ver = (& $exePath --help 2>&1 | Select-String -Pattern 'KAPE version' |
                 Select-Object -First 1).Line } catch { }
Info "version   : $ver"

# ---------------------------------------------------------------- 2) zip
if (-not $KapeFilesZip) {
  $KapeFilesZip = @(
    (Join-Path (Split-Path -Parent $projRoot) "KapeFiles-master.zip"),
    (Join-Path $projRoot "KapeFiles-master.zip"),
    "D:\work\KapeFiles-master.zip"
  ) | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $NoCommunitySet) {
  if (-not $KapeFilesZip) { Warn "no KapeFiles zip found; pass -KapeFilesZip or -NoCommunitySet" }
  else { Info "community : $KapeFilesZip" }
}

# ---------------------------------------------------------------- 3) backup
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$bk = Join-Path $kapeHome "_backup_$stamp"
if ($DryRun) {
  Write-Host "  [dry-run] would back up Targets\ + Modules\ to $bk"
} else {
  New-Item -ItemType Directory -Force -Path $bk | Out-Null
  foreach ($sub in @("Targets", "Modules")) {
    $src = Join-Path $kapeHome $sub
    if (Test-Path $src) { Copy-Item $src -Destination (Join-Path $bk $sub) -Recurse -Force }
  }
  Info "backup    : $bk"
}

# ---------------------------------------------------------------- 4) replace
if ($KapeFilesZip -and -not $NoCommunitySet) {
  # Preserve these before wiping:
  #   !Local  -- documented place for user customisations
  #   bin     -- third-party parser binaries (EZTools live in Modules\bin)
  # Deleting 'bin' was a real mistake made during development: it silently
  # removed every EZTool, and the only reason it was recoverable is that the
  # backup had been taken a moment earlier. Do not widen this wipe again.
  $keep = @("!Local", "bin")
  foreach ($sub in @("Targets", "Modules")) {
    $dir = Join-Path $kapeHome $sub
    if (-not (Test-Path $dir)) { continue }
    $items = @(Get-ChildItem $dir -Force | Where-Object { $keep -notcontains $_.Name })
    if ($DryRun) {
      Write-Host "  [dry-run] would remove $($items.Count) items from $sub\ (keeping $($keep -join ', '))"
    } else {
      $items | Remove-Item -Recurse -Force
      Info "cleared   : $sub\ ($($items.Count) items removed, kept: $($keep -join ', '))"
    }
  }

  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [System.IO.Compression.ZipFile]::OpenRead($KapeFilesZip)
  $written = 0; $bytes = 0
  try {
    foreach ($e in $zip.Entries) {
      $name = $e.FullName -replace '\\', '/'
      if ($name.EndsWith('/')) { continue }
      $m = [regex]::Match($name, '^[^/]+/(Targets|Modules)/(.+)$')
      if (-not $m.Success) { continue }
      $rel = "$($m.Groups[1].Value)/$($m.Groups[2].Value)"
      $dest = Join-Path $kapeHome ($rel -replace '/', '\')
      if (-not $DryRun) {
        $destDir = Split-Path -Parent $dest
        if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Force -Path $destDir | Out-Null }
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($e, $dest, $true)
      }
      $written++; $bytes += $e.Length
    }
  } finally { $zip.Dispose() }
  Info ("community : {0} files extracted ({1} MB)" -f $written, [math]::Round($bytes / 1MB, 2))
}

# ---------------------------------------------------------------- 5) our target
if (-not $BlueTeamTarget) {
  $BlueTeamTarget = @(
    (Join-Path $projRoot "forensics\targets\BlueTeam-Triage.tkape")
  ) | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if ($BlueTeamTarget) {
  $raw = [IO.File]::ReadAllText($BlueTeamTarget)
  $nonAscii = ($raw.ToCharArray() | Where-Object { $_ -gt [char]127 }).Count
  if ($nonAscii -gt 0) {
    # KAPE parses .tkape/.mkape as ANSI. Any non-ASCII byte => "Syntax error"
    # and the target silently vanishes from --tlist. Fix it, do not just warn.
    Warn "$(Split-Path -Leaf $BlueTeamTarget) has $nonAscii non-ASCII chars; stripping to ASCII"
    $raw = -join ($raw.ToCharArray() | ForEach-Object {
      if ([int]$_ -gt 127) { '?' } else { $_ }
    })
  }
  $raw = ($raw -replace "`r`n", "`n") -replace "`n", "`r`n"      # KAPE convention: CRLF
  $dstDir = Join-Path $kapeHome "Targets"
  if (-not $DryRun) {
    if (-not (Test-Path $dstDir)) { New-Item -ItemType Directory -Force -Path $dstDir | Out-Null }
    [IO.File]::WriteAllText((Join-Path $dstDir "BlueTeam-Triage.tkape"), $raw,
                            (New-Object Text.UTF8Encoding($false)))
  }
  Info "installed : Targets\BlueTeam-Triage.tkape (ASCII, CRLF)"
} else {
  Warn "BlueTeam-Triage.tkape not found under forensics\targets\"
}

# ---------------------------------------------------------------- 6) validate with KAPE itself
# This is the whole point: only kape.exe can truly validate .tkape/.mkape.
$issues = @()
if (-not $DryRun) {
  foreach ($mode in @("--tlist", "--mlist")) {
    $out = & $exePath $mode . 2>&1
    $bad = $out | Where-Object {
      $_ -match 'Syntax error' -or $_ -match 'already exists' -or
      $_ -match 'Administrator privileges'
    }
    if ($bad) { $issues += ($bad | Select-Object -First 6) }
  }
}

if ($DryRun) {
  Write-Host "  [dry-run] would run: kape.exe --tlist . ; kape.exe --mlist ."
} elseif ($issues.Count -gt 0) {
  Warn "KAPE reported problems (first few):"
  $issues | Select-Object -First 10 | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
} else {
  $t = (& $exePath --tlist . 2>&1 | Select-String -Pattern 'BlueTeam-Triage').Count
  $m = (& $exePath --mlist . 2>&1 | Select-String -Pattern 'EZParser').Count
  Info "KAPE validation: no syntax errors / no duplicate names"
  Info "  BlueTeam-Triage listed: $t    !EZParser listed: $m"
}

# ---------------------------------------------------------------- 7) EZTools check / import
# EZTools are NOT distributed with KAPE. They must be copied into Modules\bin.
# The check runs before the import so that "still missing" is reported truthfully.
$need = @("AmcacheParser.exe", "AppCompatCacheParser.exe", "PECmd.exe",
          "JLECmd.exe", "LECmd.exe", "MFTECmd.exe", "RBCmd.exe",
          "RecentFileCacheParser.exe", "SrumECmd.exe",
          "EvtxECmd\EvtxECmd.exe", "RECmd\RECmd.exe", "SQLECmd\SQLECmd.exe")
$binDir = Join-Path $kapeHome "Modules\bin"

function Get-MissingEzTools([string]$bin) {
  return @($need | Where-Object { -not (Test-Path (Join-Path $bin $_)) })
}

$missing = Get-MissingEzTools $binDir
if ($missing.Count -gt 0 -and $EzToolsFrom) {
  if (-not (Test-Path $EzToolsFrom)) {
    Warn "-EzToolsFrom not found: $EzToolsFrom"
  } else {
    # Accept either a Modules\bin folder or a flat EZTools folder.
    $src = $EzToolsFrom
    if ((Test-Path (Join-Path $EzToolsFrom "bin")) -and
        -not (Test-Path (Join-Path $EzToolsFrom "PECmd.exe"))) {
      $src = Join-Path $EzToolsFrom "bin"
    }
    if ($DryRun) {
      Write-Host "  [dry-run] would copy EZTools from $src into $binDir"
    } else {
      if (-not (Test-Path $binDir)) { New-Item -ItemType Directory -Force -Path $binDir | Out-Null }
      Copy-Item (Join-Path $src "*") -Destination $binDir -Recurse -Force
      Info "EZTools imported from $src"
    }
    $missing = Get-MissingEzTools $binDir
  }
}

Write-Host ""
if ($missing.Count -eq 0) {
  Info "EZTools: all $($need.Count) binaries referenced by !EZParser are present in Modules\bin"
} else {
  Warn "EZTools missing ($($missing.Count)): $($missing -join ', ')"
  Write-Host "  they are NOT shipped with KAPE. Either:" -ForegroundColor DarkGray
  Write-Host "    a) re-run with -EzToolsFrom <another KAPE>\Modules\bin   (fastest)" -ForegroundColor DarkGray
  Write-Host "    b) powershell -ExecutionPolicy Bypass -File C:\Tools\EZ\Get-ZimmermanTools.ps1" -ForegroundColor DarkGray
  Write-Host "       then copy the extracted exes into $binDir" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------- 8) report
$nT = (Get-ChildItem (Join-Path $kapeHome "Targets") -Recurse -Filter *.tkape -EA SilentlyContinue).Count
$nM = (Get-ChildItem (Join-Path $kapeHome "Modules") -Recurse -Filter *.mkape -EA SilentlyContinue).Count
Write-Host ""
Info "targets: $nT   modules: $nM"
Write-Host ""
Write-Host "---- config values ----" -ForegroundColor Green
Write-Host "actions/config.yaml  adapters.kape:"
Write-Host "    exe_path: '$exePath'"
Write-Host "    target:   BlueTeam-Triage"
Write-Host "    module:   '!EZParser'"
Write-Host ""
Write-Host "agent/config.yaml  forensics:"
Write-Host "    kape_exe: '$exePath'"
Write-Host "    module:   '!EZParser'"
Write-Host ""
Write-Host "NOTE: kape.exe 1.3.0.2 refuses to run without administrator rights"
Write-Host "      (even --tlist). Real collection needs an elevated shell."
