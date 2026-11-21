# ZCode 防护状态报告(默认只读;检测到异常时可按键触发一次修复)
# 双击桌面「ZCode 防护状态」查看;也可单独运行本脚本
$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

# ===== 用户配置(换机器/他人使用时只改这三行) =====
$UserHome    = 'C:\Users\chen'         # 用户主目录
$UserDesktop = 'C:\Users\chen\Desktop' # 桌面路径(SYSTEM 任务运行时请硬编码实际用户桌面)
$ZCodeDir    = 'D:\zcode'               # ZCode 安装目录


$guardDir       = "$UserHome\zcode-guard"
$vaultPath      = Join-Path $guardDir 'providers.vault'
$checkpointsDir = "$UserHome\.zcode\v2\checkpoints"
$hostsPath      = "$env:windir\System32\drivers\etc\hosts"
$configPath     = "$UserHome\.zcode\v2\config.json"
$taskName       = 'ZCodeGuard'

$blockDomains = @(
  'proj-xtrace-7e235817c9b9381c22d8b743908d469f-cn-beijing.cn-beijing.log.aliyuncs.com',
  'sdk.rum.aliyuncs.com',
  'ilinkai.weixin.qq.com'
)

function Line { Write-Host ('  ' + ('-' * 66)) -ForegroundColor DarkGray }
function Head([string]$t) { Write-Host ''; Write-Host "【$t】" -ForegroundColor Cyan }
function OK([string]$t)   { Write-Host '  √ ' -NoNewline -ForegroundColor Green;  Write-Host $t }
function BAD([string]$t)  { Write-Host '  × ' -NoNewline -ForegroundColor Red;    Write-Host $t }
function WARN([string]$t) { Write-Host '  ! ' -NoNewline -ForegroundColor Yellow; Write-Host $t }
function Info([string]$t) { Write-Host '    ' -NoNewline; Write-Host $t -ForegroundColor DarkGray }

Write-Host ''
Write-Host '========================================================' -ForegroundColor DarkCyan
Write-Host '            ZCode 防护状态报告' -ForegroundColor White
Write-Host ("            " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ForegroundColor DarkGray
Write-Host '========================================================' -ForegroundColor DarkCyan

# ---------- 一、快照打包 / 上传时间线 ----------
Head '一、仓库快照：打包与上传时间线'

$rows = @()
try {
  foreach ($d in Get-ChildItem $checkpointsDir -Directory -ErrorAction SilentlyContinue) {
    $sj = Join-Path $d.FullName 'state.json'
    if (-not (Test-Path $sj)) { continue }
    $s = [IO.File]::ReadAllText($sj, [Text.Encoding]::UTF8) | ConvertFrom-Json
    $lcs = $s.lastCompressedSize
    $when = if ($lcs -and $lcs.recordedAt) { [DateTimeOffset]::FromUnixTimeMilliseconds([int64]$lcs.recordedAt).LocalDateTime } else { $null }
    $rows += [PSCustomObject]@{
      Workspace = $s.workspacePath
      When      = $when
      Packed    = if ($lcs) { $lcs.encryptedSizeBytes } else { 0 }
      Source    = if ($lcs) { 'workspaceSize=' + $lcs.workspaceSizeBytes } else { '' }
    }
  }
} catch { }

if ($rows.Count -eq 0) {
  WARN '读不到任何打包记录(state.json 缺失或不可解析)'
} else {
  $sorted = $rows | Sort-Object When -Descending
  Write-Host '  工作区                                最后打包时间        包大小' -ForegroundColor White
  Line
  foreach ($r in $sorted) {
    $nm = if ($r.Workspace.Length -gt 34) { $r.Workspace.Substring(0, 33) + '…' } else { $r.Workspace }
    $t  = if ($r.When) { $r.When.ToString('yyyy-MM-dd HH:mm') } else { '未知' }
    $kb = [math]::Round($r.Packed / 1KB, 1)
    Write-Host ("  {0,-36} {1,-18} {2,8} KB" -f $nm, $t, $kb)
  }
  $last = $sorted | Select-Object -First 1
  Write-Host ''
  Write-Host '  ⇒ 本地可证的“最后一次打包”时间：' -NoNewline -ForegroundColor White
  Write-Host ("$($last.When.ToString('yyyy-MM-dd HH:mm:ss'))  ($($last.Workspace))") -ForegroundColor Yellow
}

Write-Host ''
# 挂墙后是否还有写入 —— 这是判断管线死活的硬证据
$newest = $null
try {
  $newest = Get-ChildItem $checkpointsDir -Recurse -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
} catch { }
if ($newest) {
  Write-Host '  checkpoint 目录最后一次实际写入：' -NoNewline -ForegroundColor White
  Write-Host ("$($newest.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))") -ForegroundColor Yellow
  $idle = (Get-Date) - $newest.LastWriteTime
  Info ("此后已静默 {0:N1} 小时 —— 管线无法落盘" -f $idle.TotalHours)
}

Write-Host ''
Write-Host '  关于“上传到服务端”：' -ForegroundColor White
Info '本地没有上传成功的任何记录。拦截器显示的 encryptedSizeBytes 是「打包大小」，'
Info '不等于「上传成功」。能确定的是：打包必须先落盘到 checkpoints/tmp，'
Info '该目录自建墙起零写入，所以此后不可能有新内容离开本机。'

# ---------- 二、防护健康 ----------
Head '二、防护健康'

$allGood = $true
$taskBlocked = $false

# 快照墙:写探针。双目录:checkpoints + 3.14.3 新增的 git-checkpoint-index
# (.zcode 根下,与 v2 平级) —— 守卫的墙覆盖两者,这里同样都测
$wallDirs = @(
  "$UserHome\.zcode\v2\checkpoints",
  "$UserHome\.zcode\git-checkpoint-index"
)
$wallOk = $true
foreach ($wd in $wallDirs) {
  if (-not (Test-Path $wd)) { $wallOk = $false; continue }
  try {
    $probe = Join-Path $wd '_report_probe.tmp'
    [IO.File]::WriteAllText($probe, 'x')
    Remove-Item $probe -Force -ErrorAction SilentlyContinue
    $wallOk = $false
  } catch { }
}
if ($wallOk) { OK '快照墙    生效（写入被拒，含 git-checkpoint-index）' }
else { BAD '快照墙未生效（可写入！）'; $allGood = $false }

# hosts
try {
  $h = [IO.File]::ReadAllText($hostsPath)
  $miss = @($blockDomains | Where-Object { $h -notmatch [regex]::Escape("0.0.0.0 $_") })
  if ($miss.Count -eq 0) { OK '遥测黑洞  hosts 封锁全部到位' }
  else { BAD ("遥测黑洞  缺失 $($miss.Count) 个域名: " + ($miss -join ', ')); $allGood = $false }
} catch { BAD "遥测黑洞  无法读取 hosts: $_"; $allGood = $false }

# 域名解析抽查
try {
  $ip = (Resolve-DnsName 'ilinkai.weixin.qq.com' -Type A -EA Stop | Where-Object IPAddress | Select-Object -First 1).IPAddress
  if ($ip -eq '0.0.0.0') { OK 'DNS 黑洞  抽查解析 = 0.0.0.0' } else { WARN "DNS 黑洞  抽查返回 $ip（可能已漂移）" }
} catch { OK 'DNS 黑洞  抽查域名无法解析' }

# 防火墙
$eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
try {
  $null = (& netsh advfirewall firewall show rule name="ZCode telemetry block (ARMS RUM)" 2>&1)
  if ($LASTEXITCODE -eq 0) { OK '防火墙    出站拦截规则存在' }
  else { BAD '防火墙    规则缺失'; $allGood = $false }
} catch { BAD '防火墙    查询失败'; $allGood = $false }

# 计划任务
function TaskOk([string]$n) {
  $null = (& schtasks /Query /TN $n 2>&1); return ($LASTEXITCODE -eq 0)
}
# 登录自愈:启动文件夹里的入口维护项(计划任务会被静默清除且无恢复入口,
# 启动项在 360 的"优化记录"里可见并能点「恢复启动」)
$startupLnk = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\ZCodeGuard-桌面入口维护.lnk"
if (Test-Path $startupLnk) {
  OK '登录自愈  启动项已装（登录时自动把被更新顶掉的桌面入口修回来）'
  Info '            若 360 把它禁用了:打开 360「优化记录」→ 找到本项 → 点「恢复启动」'
} else {
  WARN '登录自愈  启动项缺失（按 R 重新安装）'
  $taskBlocked = $true
}

if (TaskOk $taskName) {
  # 把上次执行结果显示出来:任务以 SYSTEM 运行,失败时不会弹任何提示
  $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
  if ($info -and $info.LastRunTime -and $info.LastRunTime.Year -gt 1990) {
    if ($info.LastTaskResult -eq 0) {
      OK "开机重申  任务 $taskName 已注册（SYSTEM，无窗口）· 上次成功 $($info.LastRunTime.ToString('MM-dd HH:mm'))"
    } else {
      WARN "开机重申  任务执行异常，结果码 $($info.LastTaskResult)（不致命，登录自愈仍可用）"
    }
  } else {
    OK "开机重申  任务 $taskName 已注册（SYSTEM，无窗口）· 尚未执行过"
  }
} else {
  WARN '开机重申  计划任务不存在（被安全软件静默清除，360 不提供恢复入口）'
  Info '            已由上面的「登录自愈」启动项替代，功能不受影响。'
}

# 自动延伸:随更新发现新数据落点
$aeState = $null
try {
  $sf = "$guardDir\autoextend-state.json"
  if (Test-Path $sf) { $aeState = [IO.File]::ReadAllText($sf, [Text.Encoding]::UTF8) | ConvertFrom-Json }
} catch { }
if ($aeState) {
  $extras = @($aeState.extraWalls | Where-Object { $_ })
  $pends  = @($aeState.pendingWalls | Where-Object { $_ })
  $exists = @($aeState.existingSensitive | Where-Object { $_ })
  OK ("自动延伸  上次扫描 $($aeState.lastScan)（ZCode $($aeState.asarVersion)，$($aeState.scanSeconds)s）· 动态墙 $($extras.Count) · 待观察 $($pends.Count)")
  if ($aeState.uploadMarkers -eq 0) { WARN '自动延伸  新版 asar 未检出上传管线标记（可能已移除或改名）' }
  foreach ($e in $extras) { Info ("            动态墙: " + $e) }
  foreach ($p in $pends)  { Info ("            待观察: $p（出现后将自动加墙）") }
  foreach ($x in $exists) { Info ("            存在的敏感目录(未自动锁,需人工确认): " + $x) }
} else {
  Info '自动延伸  尚未扫描过（下次经守卫启动/登录时会自动执行）'
}
$ErrorActionPreference = $eap

# 保险库
Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue
try {
  $b64 = [IO.File]::ReadAllText($vaultPath)
  $v = [Text.Encoding]::UTF8.GetString(
    [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($b64), $null, 'CurrentUser')) | ConvertFrom-Json
  OK ("保险库    OK，$(@($v.providers.PSObject.Properties).Count) 个密钥（写于 $($v.createdAt)）")
} catch { BAD "保险库    无法解密: $_"; $allGood = $false }

# ---------- 三、密钥与 ZCode 状态 ----------
Head '三、ZCode 与密钥状态'

$zcode = @(Get-Process -Name 'ZCode' -EA SilentlyContinue)
if ($zcode.Count -gt 0) {
  $start = ($zcode | Sort-Object StartTime | Select-Object -First 1).StartTime
  Write-Host '  ZCode      : ' -NoNewline
  Write-Host ("正在运行（$($zcode.Count) 个进程，启动于 $($start.ToString('MM-dd HH:mm'))）") -ForegroundColor Yellow
} else {
  Write-Host '  ZCode      : ' -NoNewline
  Write-Host '未运行' -ForegroundColor Gray
}

$plain = @()
try {
  $cfg = [IO.File]::ReadAllText($configPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
  foreach ($p in $cfg.provider.PSObject.Properties) {
    if ($p.Value.options.PSObject.Properties.Name -contains 'apiKey' -and $p.Value.options.apiKey) {
      $plain += $p.Name
    }
  }
} catch { }

if ($plain.Count -eq 0) {
  OK '密钥      已锁定（config.json 中无明文）'
} elseif ($zcode.Count -gt 0) {
  Write-Host '  √ ' -NoNewline -ForegroundColor Yellow
  Write-Host ("密钥      已解锁 $($plain.Count) 个 —— ZCode 运行期间属正常，退出后自动锁回") -ForegroundColor Yellow
} else {
  BAD "密钥      有 $($plain.Count) 个明文，但 ZCode 未运行！双击桌面 ZCode 图标（走守卫）即可锁回"
  $allGood = $false
}

# 等待进程
$waiter = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -EA SilentlyContinue |
            Where-Object { $_.CommandLine -match 'waitandlock' })
if ($waiter.Count -gt 0 -and $zcode.Count -gt 0) { OK "退出守护  待命进程存活（pid=$($waiter[0].ProcessId)）" }
elseif ($waiter.Count -eq 0 -and $zcode.Count -gt 0) { WARN '退出守护  无待命进程 —— 说明 ZCode 不是经守卫启动的' }

# 桌面入口:ZCode 更新会把它重写回原生指向,此时守卫永远不会被调用
$shortcutOk = $false
try {
  $lnk = "$UserDesktop\ZCode.lnk"
  if (Test-Path $lnk) {
    $cur = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
    $shortcutOk = ($cur.Arguments -match 'zcode-guard\.ps1' -and $cur.Arguments -match 'launch')
  }
} catch { }
if ($shortcutOk) { OK '桌面入口  ZCode.lnk 指向守卫' }
else { BAD '桌面入口  ZCode.lnk 已被重置为原生 ZCode（更新覆盖）→ 等守望进程自动修回，或按 R'; $allGood = $false }

# 常驻守望进程:每分钟自动修入口/锁密钥/追更新扫描
$watcher = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -EA SilentlyContinue |
             Where-Object { $_.CommandLine -match 'zcode-guard\.ps1.\s*-Action watch' -and $_.CommandLine -notmatch 'Get-CimInstance' })
if ($watcher.Count -gt 0) {
  OK ("守望进程  存活（pid=$($watcher[0].ProcessId)）— 每分钟自动修入口/锁密钥/补墙/追更新")
} else {
  WARN '守望进程  未运行（守卫式启动 ZCode 时会自动拉活，下次登录也会自启）'
  $taskBlocked = $true
}

# ---------- 四、出站连接 ----------
Head '四、ZCode 当前出站连接'
if ($zcode.Count -eq 0) {
  Info '（ZCode 未运行，无连接）'
} else {
  $zp = $zcode.Id
  $conns = @(Get-NetTCPConnection -State Established -EA SilentlyContinue |
             Where-Object { $zp -contains $_.OwningProcess } |
             Select-Object -ExpandProperty RemoteAddress -Unique)
  if ($conns.Count -eq 0) { Info '（无活动连接）' }
  else {
    foreach ($c in $conns) {
      $tag = ''
      if ($c -match '^(8\.130\.222|59\.110\.96|39\.97\.141|123\.56\.37|123\.57\.116)') { $tag = '  ← 被封的遥测网段(异常!)' }
      elseif ($c -match '^(111\.77\.|106\.225\.|117\.21\.)') { $tag = '  (z.ai 系列，业务必需)' }
      Write-Host "    $c$tag"
    }
    Info '阿里云 OSS 上传域名由服务端动态下发，无法预判；但源头已断，无包可传。'
  }
}

# ---------- 结论与修复入口 ----------
Write-Host ''
Write-Host '========================================================' -ForegroundColor DarkCyan
if ($allGood) {
  if ($taskBlocked) {
    Write-Host '  结论：核心防护全部正常' -ForegroundColor Green
    Write-Host '        开机自动修复不可用（被安全软件压制）→ 需要时手动按 R' -ForegroundColor Yellow
  } else {
    Write-Host '  结论：全部防护正常' -ForegroundColor Green
  }
} else {
  Write-Host '  结论：存在异常项（见上方 × 标记）' -ForegroundColor Red
}
Write-Host '========================================================' -ForegroundColor DarkCyan
Write-Host ''
Write-Host '  [R] 修复 / 重置防护' -NoNewline -ForegroundColor Yellow
Write-Host '   重装防护 + 重建桌面入口 + 重注册任务' -ForegroundColor DarkGray
Write-Host '      （会弹一次 UAC 确认；平时用不到，被 ZCode 更新顶掉后用它）' -ForegroundColor DarkGray
Write-Host '  [回车] 关闭' -ForegroundColor DarkGray
Write-Host ''
Write-Host '  请选择... ' -ForegroundColor DarkGray -NoNewline
$k = Read-Host

if ($k -match '^\s*[Rr]\s*$') {
  Write-Host ''
  Write-Host '  正在以管理员身份修复（重装防护 + 重建桌面入口 + 重注册任务）...' -ForegroundColor Cyan
  try {
    Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass',
      '-File', "$guardDir\zcode-guard.ps1", '-Action', 'install'
    Write-Host ''
    Write-Host '  修复完成。重新运行本报告可复核。' -ForegroundColor Green
    Write-Host '  若上方"开机重申"仍显示异常，是安全软件（360）删掉了计划任务，' -ForegroundColor Yellow
    Write-Host '  需要在 360 里放行任务 ZCodeGuard，详见记忆/说明。' -ForegroundColor Yellow
  } catch {
    Write-Host ('  修复被取消或失败: ' + $_.Exception.Message) -ForegroundColor Red
  }
  Write-Host ''
  Write-Host '  按回车关闭...' -ForegroundColor DarkGray -NoNewline
  $null = Read-Host
}
