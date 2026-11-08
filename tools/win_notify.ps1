# tools/win_notify.ps1 -- 发送 Windows 通知（纯 ASCII 脚本，中文文本走外部 UTF-8 XML 文件）
#
# 为什么要拆成「ASCII 脚本 + 外部数据」两步：
#   PowerShell 5.1 会把无 BOM 的 UTF-8 当 ANSI 解码，脚本里写中文会变成乱码；
#   而带 BOM 又常被工具链剥掉。本项目已有教训 -> 脚本保持纯 ASCII，
#   文本由 Python 以 UTF-8 写进临时文件，脚本只负责读取与投递。
param(
    [Parameter(Mandatory = $true)][string]$XmlFile,
    [string]$AppId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
)

if (-not (Test-Path -LiteralPath $XmlFile)) {
    Write-Output 'ERR xml-not-found'
    exit 2
}

try {
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

    $raw = Get-Content -LiteralPath $XmlFile -Encoding UTF8 -Raw
    $doc = New-Object Windows.Data.Xml.Dom.XmlDocument
    $doc.LoadXml($raw)

    $toast = New-Object Windows.UI.Notifications.ToastNotification $doc
    $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId)
    $notifier.Show($toast)
    Write-Output 'OK'
    exit 0
}
catch {
    Write-Output ('ERR ' + $_.Exception.Message)
    exit 3
}
