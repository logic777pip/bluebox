# Download the Ubuntu Server 22.04.5 LTS (64-bit ARM) image for Raspberry Pi 4B.
#
# NOTE: ASCII-only on purpose (PowerShell 5.1 reads .ps1 with the system ANSI
# code page unless a BOM is present, so non-ASCII here would be mojibake).
#
# Honest note about Chinese mirrors -- I tested these on 2026-10-04:
#   * mirrors.tuna.tsinghua.edu.cn/ubuntu-ports      -> OK (apt source)
#   * mirrors.ustc.edu.cn/ubuntu-ports               -> OK (apt source)
#   * <mirror>/ubuntu-cdimage/releases/22.04.5/...   -> 404 on every CN mirror tried
#     (tuna, ustc, bfsu, sjtug, nju, zju, iscas, cqu, hit, aliyun, 163, huawei)
#   * cdimage.ubuntu.com (official)                  -> 200
# So: the APT mirror switch works great, but the **Raspberry Pi image itself**
# is not mirrored domestically at the standard path. This script therefore
# probes candidates at runtime and falls back to the official URL instead of
# hardcoding a mirror path that does not exist.
#
# The official URL does support HTTP Range requests, so multi-connection
# downloaders (aria2c / IDM / Thunder) will speed it up a lot.
#
# Usage:
#   .\get_ubuntu_image.ps1                                  # download to .\images
#   .\get_ubuntu_image.ps1 -OutDir D:\images -Verify
#   .\get_ubuntu_image.ps1 -ListOnly                         # just probe URLs

[CmdletBinding()]
param(
  [string]$Version = "22.04.5",
  [string]$OutDir = "",
  [switch]$Verify,
  [switch]$ListOnly,
  [switch]$Force
)

$ErrorActionPreference = "Stop"
function Info($m) { Write-Host "[image] $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "[image] $m" -ForegroundColor Yellow }
function Die($m) { Write-Host "[image] $m" -ForegroundColor Red; exit 1 }

if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
  Die "curl.exe not found. Windows 10 1803+ ships it; otherwise install curl or use a browser."
}

if (-not $OutDir) {
  $OutDir = Join-Path (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)) "images"
}
$file = "ubuntu-$Version-preinstalled-server-arm64+raspi.img.xz"

# Candidate bases, in priority order. Chinese mirrors first (they may add the
# image later -- probing means we use them automatically the day they do).
# NOTE: arm64 lives under ubuntu-ports for APT, but release *images* live under
# the cdimage tree; both layouts are probed.
$bases = @(
  "https://mirrors.tuna.tsinghua.edu.cn/ubuntu-cdimage",
  "https://mirrors.ustc.edu.cn/ubuntu-cdimage",
  "https://mirrors.bfsu.edu.cn/ubuntu-cdimage",
  "https://mirrors.sjtug.sjtu.edu.cn/ubuntu-cdimage",
  "https://mirror.nju.edu.cn/ubuntu-cdimage",
  "https://mirrors.aliyun.com/ubuntu-cdimage",
  "https://cdimage.ubuntu.com"     # official, last resort
)
$relPaths = @(
  "releases/$Version/release/$file",
  # 系列目录（"22.04.5" -> "22.04"）。**不要用 [double] 转**：
  # [double]"22.04.5" 会直接抛 InvalidCast
  "releases/$($Version -replace '\.\d+$','')/release/$file"
)

function Test-Url([string]$u) {
  # ⚠ 两个坑，都是实测踩到的：
  #  1) Windows 的 curl 走 schannel，若证书吊销服务器不可达会报
  #     "CRYPT_E_REVOCATION_OFFLINE"。此时 curl 退出码非 0 **并且往 stderr 写东西**，
  #     在 $ErrorActionPreference='Stop' 下会被 PowerShell 当成终止错误，
  #     整个脚本直接停在第一个镜像上。所以这里临时把 EAP 降级 + 丢掉 stderr，
  #     用 --ssl-no-revoke 避开吊销检查（我们只是探测能否下载）。
  #  2) 有些服务器不支持 HEAD，所以失败时用 1 字节 Range GET 再试。
  $old = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $code = (& curl.exe -sSIL --ssl-no-revoke --max-time 20 -o NUL `
             -w "%{http_code}" $u 2>&1 | Select-Object -Last 1)
    if ("$code" -eq "200") { return $true }
    $code = (& curl.exe -sSL --ssl-no-revoke --max-time 20 -H "Range: bytes=0-0" -o NUL `
             -w "%{http_code}" $u 2>&1 | Select-Object -Last 1)
    return ("$code" -eq "200" -or "$code" -eq "206")
  } catch {
    return $false
  } finally {
    $ErrorActionPreference = $old
  }
}

$chosen = ""
$cands = @()
foreach ($b in $bases) {
  foreach ($p in $relPaths) {
    $u = "$b/$p"
    $cands += $u
    if ($ListOnly) {
      $okmark = if (Test-Url $u) { "OK " } else { "-- " }
      Write-Host "  $okmark $u"
    } elseif (-not $chosen -and (Test-Url $u)) {
      $chosen = $u
    }
  }
}
if ($ListOnly) { exit 0 }

if (-not $chosen) {
  Warn "none of the candidate URLs responded 200. Tested:"
  $cands | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
  Write-Host ""
  Write-Host "Manual options:" -ForegroundColor Yellow
  Write-Host "  1) open https://cdimage.ubuntu.com/releases/$Version/release/ in a browser"
  Write-Host "     and download $file by hand"
  Write-Host "  2) use Raspberry Pi Imager: 'Choose OS' > 'Use custom' > pick the .img.xz"
  Write-Host "  3) if the official host is slow, use a multi-connection downloader"
  Write-Host "     (aria2c -x16 -s16) -- it supports Range requests"
  exit 2
}

Info "using: $chosen"
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$dest = Join-Path $OutDir $file

if ((Test-Path $dest) -and -not $Force) {
  $sz = (Get-Item $dest).Length
  Info "already exists: $dest ($([math]::Round($sz/1MB,1)) MB). Use -Force to re-download."
} else {
  Info "downloading to $dest"
  Write-Host "  (resume is supported: Ctrl+C and re-run to continue)" -ForegroundColor DarkGray
  # -C - 续传; -L 跟重定向; --ssl-no-revoke 避开 schannel 吊销检查（见 Test-Url 注释）
  & curl.exe -L -C - --fail --ssl-no-revoke --retry 3 --retry-delay 3 -o "$dest" "$chosen"
  if ($LASTEXITCODE -ne 0) { Die "download failed (exit $LASTEXITCODE)" }
}

$size = (Get-Item $dest).Length
Info "size: $([math]::Round($size/1MB,1)) MB"
if ($size -lt 400MB) {
  Warn "that looks too small for a 22.04 Pi image (~1GB). The download may be incomplete: re-run it."
}

if ($Verify) {
  Info "verifying SHA256 against the release SHA256SUMS"
  $sumsUrl = ($chosen -replace "/$([regex]::Escape($file))$", "/SHA256SUMS")
  $sumsFile = Join-Path $OutDir "SHA256SUMS"
  & curl.exe -sSL --fail --ssl-no-revoke -o "$sumsFile" "$sumsUrl"
  if ($LASTEXITCODE -eq 0 -and (Test-Path $sumsFile)) {
    $want = (Select-String -Path $sumsFile -Pattern ([regex]::Escape($file)) |
             Select-Object -First 1).Line -split '\s+' | Select-Object -First 1
    if ($want) {
      $got = (Get-FileHash -Path $dest -Algorithm SHA256).Hash.ToLower()
      if ($got -eq $want.ToLower()) {
        Info "SHA256 OK: $got"
      } else {
        Die "SHA256 MISMATCH -- do not flash this file.`n  expected $want`n  got      $got"
      }
    } else {
      Warn "SHA256SUMS fetched but has no entry for $file"
    }
  } else {
    Warn "could not fetch SHA256SUMS ($sumsUrl); skipping verification"
  }
}

Write-Host ""
Info "next: flash it"
Write-Host "  Recommended: Raspberry Pi Imager > Choose OS > Use custom > select:"
Write-Host "    $dest"
Write-Host ""
Write-Host "  In Imager's settings (gear icon) set BEFORE writing:" -ForegroundColor Yellow
Write-Host "    * hostname, e.g. ids-pi"
Write-Host "    * enable SSH  +  paste your public key (so pi_deploy.ps1 works without passwords)"
Write-Host "    * username: ubuntu   (Ubuntu Server images use 'ubuntu', NOT 'pi')"
Write-Host "    * WiFi: only if you manage the Pi over WiFi. The wired NIC becomes the mirror port."
Write-Host ""
Write-Host "  Important: do NOT configure a static IP on eth0 -- install_pi.sh strips its"
Write-Host "  address to make it a pure passive capture port." -ForegroundColor Yellow
