# tools/proc_watch.ps1 -- 常驻订阅「进程创建」事件，逐行输出到 stdout
#
# 为什么用常驻单进程 + 管道：
#   轮询式采集抓不到「新进程建立连接后立刻消失」的短连接；而要事件驱动，
#   最省事又不装驱动的办法是委托 WMI 服务去订阅。
#   但每次去查又会不停 spawn powershell -> 屏幕闪黑框。所以这里**只 spawn 一次**，
#   由 Python 侧从管道持续读取。
#
# 纯 ASCII 脚本：PowerShell 5.1 会把无 BOM 的 UTF-8 当 ANSI 解码，脚本里写中文会乱码。
# 为什么用 WMI 内在事件而不是 Win32_ProcessStartTrace：
#   实测 `Register-WmiEvent -Class Win32_ProcessStartTrace` 在**非管理员**下直接
#   报 `Access denied`（trace 类事件需要提权）。而内在事件
#   `__InstanceCreationEvent ... WITHIN 2` 由 **WMI 服务侧**去轮询，
#   不需要管理员，延迟约 2 秒 —— 远优于我们自己在进程里 5s 轮询，
#   而且不占用本进程 CPU、不弹任何窗口。
# 代价：它不是“真·内核事件”（WITHIN 2 本质是服务侧 2 秒轮询），
#   对**已存在进程**的短连接仍然看不到；要根治必须提权用 ETW。
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

$q = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_Process'"
try {
    Register-WmiEvent -Query $q -SourceIdentifier btwatch -ErrorAction Stop | Out-Null
}
catch {
    Write-Output ('ERR ' + $_.Exception.Message)
    [Console]::Out.Flush()
    exit 3
}

Write-Output 'READY'
[Console]::Out.Flush()

while ($true) {
    try {
        $e = Wait-Event -SourceIdentifier btwatch -Timeout 2
        if ($e) {
            $ti = $e.SourceEventArgs.NewEvent.TargetInstance
            # ⚠ 必须用 [char]9 拼 TAB，不能写 '{0}`t{1}'：
            #   PowerShell **单引号字符串不做反引号转义**，`t 会变成字面量，
            #   Python 侧 split("\t") 拿不到字段（自检里表现为“收到 0 个事件”）。
            Write-Output ($ti.ProcessId.ToString() + [char]9 + $ti.Name + [char]9 + $ti.ParentProcessId)
            [Console]::Out.Flush()
            Remove-Event -EventIdentifier $e.EventIdentifier -ErrorAction SilentlyContinue
        } else {
            Write-Output 'TICK'
            [Console]::Out.Flush()
        }
    }
    catch {
        Write-Output ('ERR ' + $_.Exception.Message)
        [Console]::Out.Flush()
        break
    }
}
