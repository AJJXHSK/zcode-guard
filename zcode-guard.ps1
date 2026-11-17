# ZCode Guard - 统一守卫/启动器
#   集中全部拦截:快照墙(checkpoints ACL) + 遥测黑洞(hosts) + 防火墙规则 + 密钥保险库
#   本文件位于 $UserHome\zcode-guard,故意放在 $ZCodeDir(应用目录,会被更新替换)
#   和 $UserHome\.zcode(数据目录,可能被重置)之外,防更新覆盖。
param(
  [ValidateSet('lock', 'unlock', 'status', 'menu', 'launch', 'waitandlock', 'apply', 'install', 'autolock', 'fixshortcut', 'autoscan', 'unwallextra', 'watch')][string]$Action = 'menu',
  [string]$ConfigPath = "$UserHome\.zcode\v2\config.json",
  # 保持不动的 provider id,用于避免抹掉正在使用中的 provider 密钥
  [string[]]$Exclude = @()
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

# ===== 用户配置(换机器/他人使用时只改这三行) =====
$UserHome    = $env:USERPROFILE         # 用户主目录(自动检测)
$UserDesktop = "$UserHome\Desktop" # 桌面路径(自动跟随当前用户)
$ZCodeDir    = 'D:\zcode'               # ZCode 安装目录


$guardDir       = "$UserHome\zcode-guard"
$secretDir      = $guardDir
$vaultPath      = Join-Path $guardDir 'providers.vault'
$hiddenVbs      = Join-Path $guardDir 'run-hidden.vbs'
$backupDir      = "$UserHome\zcode-guard-backup"
$legacyVault    = "$UserHome\.zcode\secrets\providers.vault"
$zcodeExe       = "$ZCodeDir\ZCode.exe"
$checkpointsDir = "$UserHome\.zcode\v2\checkpoints"
$dataRoot       = "$UserHome\.zcode"
# 3.14.3 新增 .zcode\git-checkpoint-index(与 v2 平级)——上传产物可能的新落点,一并封锁
$wallDirs       = @(
  $checkpointsDir,
  "$UserHome\.zcode\git-checkpoint-index"
)
# ---- 自动延伸(随更新发现新落点) ----
$stateFile       = Join-Path $guardDir 'autoextend-state.json'
$asarPath        = "$ZCodeDir\resources\app.asar"
# 命中这些关键词的目录名才视为敏感(保守,防误伤 ZCode 功能)
$autoExtKeywords = '^(repo-|.*checkpoint|.*snapshot|.*upload|.*staging|.*pending)'
# 已知与上传无关/属于 ZCode 正常功能的目录名,永不动态加墙
$autoExtIgnore   = @('v2','cache','logs','certs','crash','runtime','bots-runtime-locks','feedback',
  'attachments','workspace','export-log-stage','plugin-workspace','checkpoints','git-checkpoint-index',
  'tmp','editor-icon','clipboard','image-cache','pdf-cache','agents','sessions','session-bindings',
  'artifacts','exec','debug','rollout','dev','acp-traffic-proxy','acp-stream-diagnostics',
  'content-bundles','pending','manifests','extra-manifests','shell-snapshots')
# 启动时把历史动态墙并入 $wallDirs
$autoExtExtra    = @()
try {
  if (Test-Path $stateFile) {
    $st0 = [IO.File]::ReadAllText($stateFile, [Text.Encoding]::UTF8) | ConvertFrom-Json
    $autoExtExtra = @($st0.extraWalls | Where-Object { $_ -and (Test-Path $_) })
  }
} catch { }
$wallDirs = @($wallDirs) + ($autoExtExtra | Where-Object { $wallDirs -notcontains $_ })
$hostsPath      = "$env:windir\System32\drivers\etc\hosts"
$taskName       = 'ZCodeGuard'
$logPath        = Join-Path $guardDir 'guard.log'
$utf8NoBom      = New-Object System.Text.UTF8Encoding $false

$rumDomains = @(
  'proj-xtrace-7e235817c9b9381c22d8b743908d469f-cn-beijing.cn-beijing.log.aliyuncs.com',
  'proj-xtrace-7e235817c9b9381c22d8b743908d469f-cn-beijing.cn-beijing-c.log.aliyuncs.com',
  'sdk.rum.aliyuncs.com',
  # 微信 ilink bot 通道(远程控制面,用户从未启用,2026-09-19 停用并封死)
  'ilinkai.weixin.qq.com'
)
$rumIps = @(
  '8.130.222.211','8.130.222.161','8.130.222.175',
  '59.110.96.118','59.110.96.221','39.97.141.140',
  '123.56.37.46','123.57.116.48'
)
$hostsMarker = '# === ZCode telemetry block (added by user) ==='
$fwRuleName  = 'ZCode telemetry block (ARMS RUM)'

# 首次运行:把保险库从 .zcode(数据目录,可能被重置)迁移到守卫目录
if (-not (Test-Path $vaultPath) -and (Test-Path $legacyVault)) {
  Copy-Item $legacyVault $vaultPath -Force
}

function Test-IsAdmin {
  ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Guard-Log([string]$m) {
  try { Add-Content -Path $logPath -Value ("[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) -Encoding UTF8 } catch {}
}

# ---------------- 密钥保险库(密钥平时 DPAPI 加密,仅 ZCode 运行时解锁) ----------------

function Protect-Json([string]$plain) {
  $raw = [Text.Encoding]::UTF8.GetBytes($plain)
  $enc = [Security.Cryptography.ProtectedData]::Protect(
    $raw, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
  return [Convert]::ToBase64String($enc)
}

function Unprotect-Json([string]$b64) {
  $bytes = [Convert]::FromBase64String($b64)
  $raw = [Security.Cryptography.ProtectedData]::Unprotect(
    $bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
  return [Text.Encoding]::UTF8.GetString($raw)
}

function Read-Config([string]$path) {
  return ([IO.File]::ReadAllText($path, [Text.Encoding]::UTF8) | ConvertFrom-Json)
}

function Get-Normalized($cfg) {
  foreach ($p in $cfg.provider.PSObject.Properties) {
    if ($p.Value.options.PSObject.Properties.Name -contains 'apiKey') {
      $p.Value.options.apiKey = ''
    }
  }
  return ($cfg | ConvertTo-Json -Depth 100)
}

function Save-Config($cfg, [string]$path) {
  [IO.File]::WriteAllText($path, ($cfg | ConvertTo-Json -Depth 100), $utf8NoBom)
}

# 只保留最近 5 份备份;并抹掉备份里的明文密钥。
# 备份只为"结构回滚"而留,密钥始终能从保险库恢复,没必要在盘上多存一份明文
# (lock 操作前的备份里恰好带着刚被锁进保险库的那批明文)。
function Remove-OldBackups {
  $all = @(Get-ChildItem "$ConfigPath.*.bak" -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
  if ($all.Count -gt 5) {
    $all | Select-Object -Skip 5 | ForEach-Object {
      Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
    }
    $all = @(Get-ChildItem "$ConfigPath.*.bak" -ErrorAction SilentlyContinue)
  }
  foreach ($b in $all) {
    try {
      if ([IO.File]::ReadAllText($b.FullName, [Text.Encoding]::UTF8) -notmatch '"apiKey":\s*"[^"]+"') { continue }
      $bc = [IO.File]::ReadAllText($b.FullName, [Text.Encoding]::UTF8) | ConvertFrom-Json
      foreach ($p in $bc.provider.PSObject.Properties) {
        if ($p.Value.options.PSObject.Properties.Name -contains 'apiKey') { $p.Value.options.apiKey = '' }
      }
      [IO.File]::WriteAllText($b.FullName, ($bc | ConvertTo-Json -Depth 100), $utf8NoBom)
    } catch { Guard-Log "backup sanitize failed: $_" }
  }
}

function Get-ZCodeProcesses {
  return @(Get-Process -Name 'ZCode' -ErrorAction SilentlyContinue)
}

function Get-KeyStats {
  $cfg = Read-Config $ConfigPath
  $plain = @(); $blank = @()
  foreach ($p in $cfg.provider.PSObject.Properties) {
    if ($p.Value.options.PSObject.Properties.Name -contains 'apiKey') {
      if ($p.Value.options.apiKey) { $plain += $p.Name } else { $blank += $p.Name }
    }
  }
  return [PSCustomObject]@{ Plain = $plain; Blank = $blank }
}

function Get-VaultInfo {
  if (-not (Test-Path $vaultPath)) { return $null }
  try {
    $v = Unprotect-Json ([IO.File]::ReadAllText($vaultPath)) | ConvertFrom-Json
    return [PSCustomObject]@{
      Count     = @($v.providers.PSObject.Properties).Count
      CreatedAt = $v.createdAt
    }
  } catch { return $null }
}

function Invoke-Unlock {
  if (-not (Test-Path $vaultPath)) { Write-Host "× 保险库不存在: $vaultPath" -ForegroundColor Red; return $false }
  $backup = "$ConfigPath.$(Get-Date -Format 'yyyyMMdd-HHmmss').bak"
  Copy-Item $ConfigPath $backup -Force
  Remove-OldBackups
  $cfg = Read-Config $ConfigPath
  $origNorm = Get-Normalized ($cfg | ConvertTo-Json -Depth 100 | ConvertFrom-Json)
  $cfg = Read-Config $ConfigPath

  $v = Unprotect-Json ([IO.File]::ReadAllText($vaultPath)) | ConvertFrom-Json
  $map = @{}
  foreach ($p in $v.providers.PSObject.Properties) { $map[$p.Name] = $p.Value }

  $n = 0
  foreach ($p in $cfg.provider.PSObject.Properties) {
    if ($map.ContainsKey($p.Name) -and $p.Value.options.PSObject.Properties.Name -contains 'apiKey') {
      $p.Value.options.apiKey = $map[$p.Name]; $n++
    }
  }
  Save-Config $cfg $ConfigPath

  $check = Read-Config $ConfigPath
  if ((Get-Normalized ($check | ConvertTo-Json -Depth 100 | ConvertFrom-Json)) -ne $origNorm) {
    Copy-Item $backup $ConfigPath -Force
    Write-Host "× 校验失败，config.json 已回滚" -ForegroundColor Red
    return $false
  }
  Write-Host "√ 已解锁 $n 个密钥" -ForegroundColor Green
  return $true
}

function Invoke-Lock {
  $backup = "$ConfigPath.$(Get-Date -Format 'yyyyMMdd-HHmmss').bak"
  Copy-Item $ConfigPath $backup -Force
  Remove-OldBackups
  $cfg = Read-Config $ConfigPath
  $origNorm = Get-Normalized ($cfg | ConvertTo-Json -Depth 100 | ConvertFrom-Json)
  $cfg = Read-Config $ConfigPath

  $map = @{}
  foreach ($p in $cfg.provider.PSObject.Properties) {
    if ($Exclude -contains $p.Name) { continue }
    if ($p.Value.options.PSObject.Properties.Name -contains 'apiKey') {
      $k = $p.Value.options.apiKey
      if ($k -and $k.Trim().Length -gt 0) { $map[$p.Name] = $k }
    }
  }
  if ($map.Count -eq 0) { Write-Host "· 没有需要锁定的明文密钥" -ForegroundColor Yellow; return $true }

  if (-not (Test-Path $secretDir)) { New-Item -ItemType Directory -Path $secretDir -Force | Out-Null }

  # 合并写入:已抹空的密钥没有别处可恢复,覆盖会永久丢失
  $merged = @{}
  if (Test-Path $vaultPath) {
    try {
      $old = Unprotect-Json ([IO.File]::ReadAllText($vaultPath)) | ConvertFrom-Json
      foreach ($p in $old.providers.PSObject.Properties) { $merged[$p.Name] = $p.Value }
    } catch { Write-Host "! 旧保险库无法读取,将重建" -ForegroundColor Yellow }
  }
  foreach ($k in $map.Keys) { $merged[$k] = $map[$k] }

  $payload = @{
    schema    = 'zcode-provider-keys/v1'
    createdAt = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    usersid   = "$env:USERDOMAIN\$env:USERNAME"
    providers = $merged
  } | ConvertTo-Json -Depth 10
  [IO.File]::WriteAllText($vaultPath, (Protect-Json $payload), $utf8NoBom)

  foreach ($p in $cfg.provider.PSObject.Properties) {
    if ($Exclude -contains $p.Name) { continue }
    if ($p.Value.options.PSObject.Properties.Name -contains 'apiKey') { $p.Value.options.apiKey = '' }
  }
  Save-Config $cfg $ConfigPath

  $check = Read-Config $ConfigPath
  if ((Get-Normalized ($check | ConvertTo-Json -Depth 100 | ConvertFrom-Json)) -ne $origNorm) {
    Copy-Item $backup $ConfigPath -Force
    Write-Host "× 校验失败，config.json 已回滚" -ForegroundColor Red
    return $false
  }
  Write-Host "√ 已锁定 $($map.Count) 个密钥（库内共 $($merged.Count) 个）" -ForegroundColor Green
  return $true
}

# ---------------- 防护墙 ----------------

# 快照墙:拒绝写探针 = 生效(功能级验证,不依赖本地化的 icacls 输出)
function Test-OneWall([string]$dir) {
  try {
    $p = Join-Path $dir '_guard_probe.tmp'
    [IO.File]::WriteAllText($p, 'x')
    Remove-Item $p -Force -ErrorAction SilentlyContinue
    return $false
  } catch { return $true }
}

function Test-CheckpointWall {
  foreach ($d in $wallDirs) {
    if (-not (Test-Path $d)) { return $false }
    if (-not (Test-OneWall $d)) { return $false }
  }
  return $true
}

# *S-1-1-0 = Everyone 的 SID 写法,不受系统语言影响;加拒绝 ACL 不需要管理员(目录属主即可)
function Assert-CheckpointWall {
  foreach ($d in $wallDirs) {
    if (-not (Test-Path $d)) {
      New-Item -ItemType Directory -Path $d -Force | Out-Null
      Guard-Log "wall dir created: $d"
    }
    if (-not (Test-OneWall $d)) {
      icacls $d /deny "*S-1-1-0:(OI)(CI)(DE,WD,AD,WEA,DC,WA)" | Out-Null
      Guard-Log "wall applied: $d"
    }
  }
  return (Test-CheckpointWall)
}

function Test-HostsBlock {
  try { $h = [IO.File]::ReadAllText($hostsPath) } catch { return $false }
  foreach ($d in $rumDomains) {
    if ($h -notmatch [regex]::Escape("0.0.0.0 $d")) { return $false }
  }
  return $true
}

function Test-FirewallRule {
  $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try {
    $null = (& netsh advfirewall firewall show rule name="$fwRuleName" 2>&1)
    return ($LASTEXITCODE -eq 0)
  } finally { $ErrorActionPreference = $eap }
}

function Test-GuardTask {
  $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try {
    $null = (& schtasks /Query /TN $taskName 2>&1)
    return ($LASTEXITCODE -eq 0)
  } finally { $ErrorActionPreference = $eap }
}

# 刷新备份:杀软误删后可从 zcode-guard-backup\restore.cmd 秒级恢复
function Backup-Guard {
  try {
    if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }
    foreach ($f in 'zcode-guard.ps1', 'guard-report.ps1', 'providers.vault') {
      $src = Join-Path $guardDir $f
      if (Test-Path $src) { Copy-Item $src (Join-Path $backupDir $f) -Force }
    }
  } catch { Guard-Log "backup failed: $_" }
}

# ---------------- 自动延伸(两层:更新检测 → 落点扫描) ----------------

# 第一层:版本指纹(毫秒级)。一致 = 未更新 = 跳过扫描,正常启动
function Get-ZCodeStamp {
  $e = Get-Item $zcodeExe -EA SilentlyContinue
  $a = Get-Item $asarPath -EA SilentlyContinue
  if (-not $e -or -not $a) { return 'missing' }
  $v = $e.VersionInfo.ProductVersion
  return "$v|$($a.Length)|$($a.LastWriteTimeUtc.Ticks)"
}

function Test-NeedsScan {
  $stamp = Get-ZCodeStamp
  if (-not (Test-Path $stateFile)) { return $true }
  try {
    $st = [IO.File]::ReadAllText($stateFile, [Text.Encoding]::UTF8) | ConvertFrom-Json
    return ($st.versionStamp -ne $stamp)
  } catch { return $true }
}

# 第二层:全量扫描新 asar,提取"根目录拼接的字面量"作为落点候选。
# 压缩后的代码里路径构造保留 fn(),"name" 的形态(如 ye(),"git-checkpoint-index"),
# 正是当初手工发现 git-checkpoint-index 的方法,这里自动化。
function Invoke-AutoExtendScan {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $stamp = Get-ZCodeStamp
  $exever = (Get-Item $zcodeExe -EA SilentlyContinue).VersionInfo.ProductVersion
  $names = New-Object 'System.Collections.Generic.HashSet[string]'
  $uploadMarkers = 0
  try {
    $rx = [regex]::new('[A-Za-z_$][\w$]{0,3}\(\s*\)\s*,\s*"([a-zA-Z][a-zA-Z0-9_-]{2,40})"',
      [Text.RegularExpressions.RegexOptions]::Compiled)
    $fs = [IO.File]::OpenRead($asarPath)
    $buf = New-Object byte[] 4194304
    $enc = [Text.Encoding]::GetEncoding(28591)
    $prev = ''
    $overlap = 512
    while (($read = $fs.Read($buf, 0, $buf.Length)) -gt 0) {
      $chunk = $prev + $enc.GetString($buf, 0, $read)
      foreach ($m in $rx.Matches($chunk)) { $null = $names.Add($m.Groups[1].Value) }
      if ($chunk.Contains('upload-credential')) { $uploadMarkers++ }
      $prev = $chunk.Substring([Math]::Max(0, $chunk.Length - $overlap))
    }
    $fs.Close()
  } catch { Guard-Log "autoextend scan failed: $_"; return $null }

  # 关键词过滤 + 已知无关名单 + 只认小写连字符目录名(排除 RPC 函数名等 CamelCase 误报)
  # 注意:PS 的 -match 不区分大小写,必须用 -cmatch 才能真的排除大写
  $cand = @($names | Where-Object {
    $_ -cmatch '^[a-z0-9][a-z0-9-]*$' -and $_ -match $autoExtKeywords -and $autoExtIgnore -notcontains $_
  })

  # 分类原则(实测教训:曾误锁正在使用的 shell-snapshots):
  #   扫描时【已存在】的敏感目录 → 只记录不锁(它们正被当前版本使用,自动锁可能弄坏 ZCode);
  #   扫描时【不存在】的候选     → 记入 pendingWalls,之后每次启动廉价复查,
  #                                一旦出现(= 新版本新建的落点)立即上墙。
  $extra = @(Get-ExtraWallsFromState)
  $existing = @()
  $pendingOld = @(Get-PendingWallsFromState)
  $pending = @()
  foreach ($n in $cand) {
    $p1 = Join-Path $dataRoot "v2\$n"
    $p2 = Join-Path $dataRoot $n
    if (Test-Path $p1 -PathType Container) { $existing += $p1; continue }
    if (Test-Path $p2 -PathType Container) { $existing += $p2; continue }
    if (Test-Path $p1) { continue }
    if (Test-Path $p2) { continue }
    # 预创建 + 立即上墙:墙必须先于 ZCode 的第一次写入存在。
    # 若等目录出现再补,"创建→打包→上传"可能发生在两次检查之间,窗口期内就会泄露。
    # 不确定落点在 v2 还是根下,两处都预建(空目录无成本,拒绝 ACL 让 ZCode 写不进)。
    $okAll = $true
    foreach ($target in @($p1, $p2)) {
      try {
        if (-not (Test-Path $target)) {
          New-Item -ItemType Directory -Path $target -Force | Out-Null
          icacls $target /deny "*S-1-1-0:(OI)(CI)(DE,WD,AD,WEA,DC,WA)" | Out-Null
        }
        if (Test-OneWall $target) {
          if ($script:wallDirs -notcontains $target) {
            $script:wallDirs = @($script:wallDirs) + $target
            $extra += $target
          }
          Guard-Log "autoextend: pre-created and walled $target"
        } else { $okAll = $false }
      } catch { $okAll = $false; Guard-Log "autoextend: pre-create failed for $target : $_" }
    }
    if (-not $okAll) { $pending += $n }
  }

  # 文件系统补漏:已存在的敏感目录只记录到 existingSensitive(不自动锁——同上理由)
  try {
    $kw = [regex]$autoExtKeywords
    Get-ChildItem $dataRoot -Recurse -Directory -Depth 3 -EA SilentlyContinue | ForEach-Object {
      if ($_.Name -notmatch $kw) { return }
      if ($autoExtIgnore -contains $_.Name) { return }
      if ($_ -notmatch '^[a-z0-9][a-z0-9-]*$') { return }
      foreach ($w in $script:wallDirs) {
        if ($_.FullName.StartsWith($w + '\')) { return }  # 已在被墙目录内,继承覆盖
      }
      if ($existing -notcontains $_.FullName) { $existing += $_.FullName }
    }
  } catch { }

  $state = @{
    versionStamp      = $stamp
    asarVersion       = $exever
    lastScan          = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    scanSeconds       = [int]$sw.Elapsed.TotalSeconds
    uploadMarkers     = $uploadMarkers
    candidates        = $cand
    extraWalls        = @($extra | Sort-Object -Unique)
    pendingWalls      = @($pending | Sort-Object -Unique)
    existingSensitive = @($existing | Sort-Object -Unique)
  }
  [IO.File]::WriteAllText($stateFile, ($state | ConvertTo-Json -Depth 5), $utf8NoBom)
  Guard-Log ("autoextend scan done: ver=$exever cands=" + $cand.Count +
    " extraWalls=" + $state.extraWalls.Count + " pending=" + $state.pendingWalls.Count +
    " existingSensitive=" + $state.existingSensitive.Count + " secs=" + $state.scanSeconds)
  return $state
}

function Get-ExtraWallsFromState {
  try {
    $st = [IO.File]::ReadAllText($stateFile, [Text.Encoding]::UTF8) | ConvertFrom-Json
    return @($st.extraWalls | Where-Object { $_ })
  } catch { return @() }
}

function Get-PendingWallsFromState {
  try {
    $st = [IO.File]::ReadAllText($stateFile, [Text.Encoding]::UTF8) | ConvertFrom-Json
    return @($st.pendingWalls | Where-Object { $_ })
  } catch { return @() }
}

# 第 1.5 层(每次启动,廉价):pendingWalls 里是"预创建失败"的候选,重试同样的预创建
function Invoke-AutoExtendFast {
  try {
    if (-not (Test-Path $stateFile)) { return }
    $st = [IO.File]::ReadAllText($stateFile, [Text.Encoding]::UTF8) | ConvertFrom-Json
    $pending = @($st.pendingWalls | Where-Object { $_ })
    $extra = @($st.extraWalls | Where-Object { $_ })
    $changed = $false
    foreach ($n in $pending) {
      $okAll = $true
      foreach ($base in "$dataRoot\v2", $dataRoot) {
        $target = Join-Path $base $n
        if (Test-Path $target -PathType Container) {
          if ($script:wallDirs -notcontains $target) { $script:wallDirs = @($script:wallDirs) + $target; $extra += $target; $changed = $true }
          continue
        }
        if (Test-Path $target) { continue }  # 是文件,跳过
        try {
          if (-not (Test-Path $target)) {
            New-Item -ItemType Directory -Path $target -Force | Out-Null
            icacls $target /deny "*S-1-1-0:(OI)(CI)(DE,WD,AD,WEA,DC,WA)" | Out-Null
          }
          if (Test-OneWall $target) {
            if ($script:wallDirs -notcontains $target) { $script:wallDirs = @($script:wallDirs) + $target; $extra += $target; $changed = $true }
          } else { $okAll = $false }
        } catch { $okAll = $false }
      }
      if ($okAll) { $pending = @($pending | Where-Object { $_ -ne $n }); $changed = $true }
    }
    foreach ($p in $extra) {
      if ($script:wallDirs -notcontains $p) { $script:wallDirs = @($script:wallDirs) + $p; $changed = $true }
    }
    if ($changed) {
      $st.extraWalls = @($extra | Sort-Object -Unique)
      $st.pendingWalls = @($pending | Sort-Object -Unique)
      [IO.File]::WriteAllText($stateFile, ($st | ConvertTo-Json -Depth 5), $utf8NoBom)
    }
  } catch { Guard-Log "autoextend fast error: $_" }
}

function Update-AutoExtend {
  try {
    if (Test-NeedsScan) {
      Write-Host "      [自动延伸] 检测到 ZCode 更新，扫描新版数据落点（一次性，约一两分钟）..." -ForegroundColor DarkYellow
      $r = Invoke-AutoExtendScan
      if ($r) { Write-Host "      [自动延伸] 完成：候选 $($r.candidates.Count) 个，动态墙 $($r.extraWalls.Count) 个，待观察 $($r.pendingWalls.Count) 个" -ForegroundColor DarkGray }
    }
    Invoke-AutoExtendFast
  } catch { Guard-Log "autoextend error: $_" }
}

# 安全阀:撤销所有动态墙(只动 auto-extend 加的,核心两目录不动)
function Unwall-Extra {
  foreach ($p in (Get-ExtraWallsFromState)) {
    icacls $p /remove:d "*S-1-1-0" | Out-Null
    Guard-Log "autoextend: unwalled $p"
    Write-Host "已撤销动态墙: $p" -ForegroundColor Yellow
  }
}

# 需要管理员上下文(install/apply 经计划任务或 UAC 运行)
function Invoke-ApplyAll {
  Update-AutoExtend
  $w = Assert-CheckpointWall
  Guard-Log "apply: wall=$w admin=$(Test-IsAdmin)"
  if (-not (Test-HostsBlock)) {
    try {
      $content = [IO.File]::ReadAllText($hostsPath)
      $add = @()
      foreach ($d in $rumDomains) {
        if ($content -notmatch [regex]::Escape("0.0.0.0 $d")) { $add += "0.0.0.0 $d"; $add += "::1 $d" }
      }
      if ($add.Count -gt 0) {
        Add-Content -Path $hostsPath -Value ("`r`n" + ($add -join "`r`n") + "`r`n")
        Guard-Log ("hosts entries added: " + $add.Count)
      }
    } catch { Guard-Log "hosts write failed: $_" }
  }
  if (-not (Test-FirewallRule)) {
    try {
      Get-NetFirewallRule -DisplayName $fwRuleName -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
      New-NetFirewallRule -DisplayName $fwRuleName -Direction Outbound -Action Block `
        -Program $zcodeExe -RemoteAddress $rumIps -Profile Any -Enabled True | Out-Null
      Guard-Log "firewall rule created"
    } catch { Guard-Log "firewall rule failed: $_" }
  }
  & ipconfig /flushdns | Out-Null
  # ZCode 更新会把桌面快捷方式重写回原生指向,这里顺手修回来
  # (这是"防更新覆盖"的关键一环:apply 开机跑一次,即使快捷方式被顶掉也能自愈)
  if (-not (Test-ShortcutOk)) { Repair-ZCodeShortcut | Out-Null }
}

# 非管理员上下文的自愈:墙直接补;hosts/防火墙漂移则触发计划任务(免 UAC 提权执行)
function Repair-DefensesSilently {
  $fixed = @()
  if (-not (Assert-CheckpointWall)) { }
  if (-not (Test-HostsBlock) -or -not (Test-FirewallRule)) {
    if (Test-GuardTask) {
      $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
      try { $null = (& schtasks /Run /TN $taskName 2>&1) } finally { $ErrorActionPreference = $eap }
      Start-Sleep -Seconds 4
      $fixed += '已触发计划任务修复遥测黑洞/防火墙'
    } else {
      $fixed += '!! 遥测黑洞/防火墙已漂移且计划任务不存在,请运行 install'
    }
  }
  if ($fixed.Count -gt 0) {
    Write-Host ("防护自愈: " + ($fixed -join '; ')) -ForegroundColor DarkYellow
  }
}

function Repair-ZCodeShortcut([switch]$Force) {
  # 桌面路径写死:apply 以 SYSTEM 身份运行时 GetFolderPath('Desktop') 会解析到 SYSTEM 的桌面
  $lnkPath = "$UserDesktop\ZCode.lnk"
  $ws = New-Object -ComObject WScript.Shell
  if (-not $Force -and (Test-Path $lnkPath)) {
    $cur = $ws.CreateShortcut($lnkPath)
    # TargetPath 永远是 powershell.exe,脚本路径在 Arguments 里
    if ($cur.Arguments -match 'zcode-guard\.ps1' -and $cur.Arguments -match 'launch') { return $true }
  }
  Remove-Item $lnkPath -Force -ErrorAction SilentlyContinue
  $l = $ws.CreateShortcut($lnkPath)
  $l.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
  $l.Arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Minimized -File "$UserHome\zcode-guard\zcode-guard.ps1" -Action launch'
  $l.WorkingDirectory = "$ZCodeDir"
  $l.IconLocation = '$ZCodeDir\ZCode.exe,0'
  $l.Description = 'ZCode - guard launcher'
  $l.WindowStyle = 7
  $l.Save()
  Write-Host "已把桌面快捷方式修复为守卫启动器" -ForegroundColor DarkGray
  Guard-Log "desktop shortcut repaired"
  return $true
}

# 登录时拉起"常驻守望进程"的启动项。
# 为什么常驻:ZCode 更新会把桌面入口重写回原生指向(发生在任意时刻,不止登录时),
# 一次性修复项盖不住"更新后、下次登录前"的窗口;常驻进程每 60 秒巡检,
# 自动修入口 + 自动锁密钥 + 自动扫描新版本落点 —— 更新响应全自动,无需用户按 R。
function Install-StartupEntry {
  $startup = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
  if (-not (Test-Path $startup)) { New-Item -ItemType Directory -Path $startup -Force | Out-Null }
  $lnkPath = Join-Path $startup 'ZCodeGuard-桌面入口维护.lnk'
  $ws = New-Object -ComObject WScript.Shell
  $l = $ws.CreateShortcut($lnkPath)
  $l.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
  $l.Arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "$UserHome\zcode-guard\zcode-guard.ps1" -Action watch'
  $l.WorkingDirectory = $guardDir
  $l.IconLocation = '$ZCodeDir\ZCode.exe,0'
  $l.Description = 'ZCode Guard - repair desktop entry at logon'
  $l.WindowStyle = 7
  $l.Save()
  Guard-Log "startup entry installed"
}

# 快捷方式是否仍指向守卫(ZCode 更新会把它重写回原生 ZCode.exe)
function Test-ShortcutOk {
  $lnkPath = "$UserDesktop\ZCode.lnk"
  if (-not (Test-Path $lnkPath)) { return $false }
  try {
    $cur = (New-Object -ComObject WScript.Shell).CreateShortcut($lnkPath)
    return ($cur.Arguments -match 'zcode-guard\.ps1' -and $cur.Arguments -match 'launch')
  } catch { return $false }
}

function Show-Status {
  $procs = Get-ZCodeProcesses
  $ks = Get-KeyStats
  $vi = Get-VaultInfo

  Write-Host "  ZCode      : " -NoNewline
  if ($procs.Count -gt 0) { Write-Host "正在运行（$($procs.Count) 个进程）" -ForegroundColor Yellow }
  else { Write-Host "未运行" -ForegroundColor Gray }

  Write-Host "  密钥       : " -NoNewline
  if ($ks.Plain.Count -gt 0) {
    Write-Host "已解锁 — $($ks.Plain.Count) 个明文" -ForegroundColor Yellow
    foreach ($n in $ks.Plain) { Write-Host "                 $n" -ForegroundColor DarkGray }
  } else { Write-Host "已锁定 — config.json 中无明文密钥" -ForegroundColor Green }

  Write-Host "  保险库     : " -NoNewline
  if ($vi) { Write-Host "OK，$($vi.Count) 个密钥，$($vi.CreatedAt)" -ForegroundColor Green }
  else { Write-Host "不存在或无法解密" -ForegroundColor Red }

  Write-Host "  快照墙     : " -NoNewline
  # status 也自愈:新目录(如 3.14.3 的 git-checkpoint-index)未建时顺带补上
  if (Assert-CheckpointWall) { Write-Host "生效（写入被拒）" -ForegroundColor Green }
  else { Write-Host "!! 未生效" -ForegroundColor Red }

  Write-Host "  遥测黑洞   : " -NoNewline
  if (Test-HostsBlock) { Write-Host "hosts 正常" -ForegroundColor Green }
  else { Write-Host "!! hosts 漂移" -ForegroundColor Red }

  Write-Host "  防火墙规则 : " -NoNewline
  if (Test-FirewallRule) { Write-Host "存在" -ForegroundColor Green }
  else { Write-Host "!! 缺失" -ForegroundColor Red }

  Write-Host "  开机重申   : " -NoNewline
  if (Test-GuardTask) { Write-Host "计划任务 $taskName 已注册" -ForegroundColor Green }
  else { Write-Host "未注册（建议运行 install）" -ForegroundColor DarkGray }

  Write-Host "  守望进程   : " -NoNewline
  $wp = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -EA SilentlyContinue |
          Where-Object { $_.CommandLine -match 'zcode-guard\.ps1.\s*-Action watch' -and $_.CommandLine -notmatch 'Get-CimInstance' })
  if ($wp.Count -gt 0) { Write-Host "存活（每分钟自动修入口/锁密钥/追更新）" -ForegroundColor Green }
  else { Write-Host "未运行（下次登录自启）" -ForegroundColor DarkGray }

  Write-Host "  桌面入口   : " -NoNewline
  if (Test-ShortcutOk) { Write-Host "ZCode.lnk 指向守卫" -ForegroundColor Green }
  else { Write-Host "!! 已被重置为原生 ZCode（更新覆盖），运行 install 或 R 修复" -ForegroundColor Red }
}

# ---------------- 启动流程 ----------------

function Wait-AndLock {
  while ((Get-ZCodeProcesses).Count -gt 0) { Start-Sleep -Seconds 10 }
  Start-Sleep -Seconds 3
  Invoke-Lock | Out-Null
  Repair-DefensesSilently
  Repair-ZCodeShortcut
}

function Start-ZCodeManaged {
  if (-not (Test-Path $zcodeExe)) { Write-Host "× 找不到 $zcodeExe" -ForegroundColor Red; return }

  Write-Host "[0/3] 防护自检..." -ForegroundColor Cyan
  Update-AutoExtend
  Repair-DefensesSilently
  Backup-Guard
  if (Assert-CheckpointWall) { Write-Host "      快照墙生效" -ForegroundColor DarkGray }

  if ((Get-ZCodeProcesses).Count -gt 0) {
    Write-Host ""
    Write-Host "! ZCode 已经在运行了。" -ForegroundColor Yellow
    Write-Host "  不做任何改动（改盘上的 config.json 影响不到已运行实例）。" -ForegroundColor Gray
    Write-Host "  如果 ZCode 提示认证失败，回菜单选 [3] 只解锁。" -ForegroundColor Gray
    Repair-ZCodeShortcut
    return
  }

  Write-Host "[1/3] 解锁密钥..." -ForegroundColor Cyan
  if (-not (Invoke-Unlock)) { Write-Host "× 解锁失败，已中止，不启动 ZCode" -ForegroundColor Red; return }

  Write-Host "[2/3] 启动 ZCode..." -ForegroundColor Cyan
  Start-Process $zcodeExe
  Start-Sleep -Seconds 2
  if ((Get-ZCodeProcesses).Count -eq 0) {
    Write-Host "× ZCode 未能启动，密钥已重新锁定。" -ForegroundColor Red
    Invoke-Lock | Out-Null
    return
  }
  Repair-ZCodeShortcut
  $waiter = Start-Process powershell -WindowStyle Hidden -PassThru -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Action', 'waitandlock')
  Write-Host "[3/3] ZCode 已启动。退出后自动锁回（后台 pid=$($waiter.Id)）。" -ForegroundColor Cyan
  Write-Host "      注意：关窗口不算退出，要从托盘右键选「退出」。" -ForegroundColor DarkGray
}

# ---------------- 菜单 ----------------

function Show-Menu {
  while ($true) {
    Clear-Host
    Write-Host "============================================" -ForegroundColor DarkCyan
    Write-Host "  ZCode Guard 守卫中心" -ForegroundColor White
    Write-Host "  快照墙 + 遥测黑洞 + 防火墙 + 密钥保险库" -ForegroundColor DarkGray
    Write-Host "============================================" -ForegroundColor DarkCyan
    Write-Host ""
    Show-Status
    Write-Host ""
    Write-Host "  ------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [1] " -NoNewline -ForegroundColor White
    Write-Host "启动 ZCode" -NoNewline -ForegroundColor Green
    Write-Host "    自检 → 解锁 → 启动 → 退出自动锁回" -ForegroundColor DarkGray
    Write-Host "      " -NoNewline
    Write-Host "← 直接回车也行" -ForegroundColor Green
    Write-Host "  [2] " -NoNewline -ForegroundColor White
    Write-Host "立即锁定密钥" -NoNewline -ForegroundColor Yellow
    Write-Host "   把明文密钥收进保险库" -ForegroundColor DarkGray
    Write-Host "  [3] " -NoNewline -ForegroundColor White
    Write-Host "只解锁" -NoNewline -ForegroundColor Yellow
    Write-Host "         不带启动，也不自动锁回" -ForegroundColor DarkGray
    Write-Host "  [4] " -NoNewline -ForegroundColor White
    Write-Host "刷新状态" -ForegroundColor Yellow
    Write-Host "  [0] " -NoNewline -ForegroundColor White
    Write-Host "退出" -ForegroundColor Yellow
    Write-Host "  ------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""

    $sel = Read-Host "  请选择"
    if ([string]::IsNullOrWhiteSpace($sel)) { $sel = '1' }

    switch ($sel.Trim()) {
      '1' { Start-ZCodeManaged; Write-Host ""; Read-Host "  按回车返回菜单" }
      '2' {
        Write-Host ""
        if ((Get-ZCodeProcesses).Count -gt 0) {
          Write-Host "! ZCode 正在运行。锁回后当前会话通常还能用，" -ForegroundColor Yellow
          Write-Host "  但任何重新读取 provider 配置的操作都会失败。" -ForegroundColor Yellow
          $c = Read-Host "  仍要锁定？(y/N)"
          if ($c -notmatch '^[Yy]') { continue }
        }
        Invoke-Lock | Out-Null
        Write-Host ""
        Read-Host "  按回车返回菜单"
      }
      '3' { Write-Host ""; Invoke-Unlock | Out-Null; Write-Host ""; Read-Host "  按回车返回菜单" }
      '4' { continue }
      '0' { return }
      default { }
    }
  }
}

# ---------------- 入口 ----------------

if ($Action -eq 'menu') {
  Show-Menu
} elseif ($Action -eq 'unlock') {
  if (-not (Invoke-Unlock)) { exit 1 }
} elseif ($Action -eq 'lock') {
  if (-not (Invoke-Lock)) { exit 1 }
} elseif ($Action -eq 'launch') {
  Start-ZCodeManaged
  exit 0
} elseif ($Action -eq 'waitandlock') {
  Wait-AndLock
  exit 0
} elseif ($Action -eq 'apply') {
  # 需要管理员(计划任务/UAC):重申全部防护
  if (-not (Test-IsAdmin)) { Guard-Log "apply skipped: not admin"; exit 1 }
  Invoke-ApplyAll
  exit 0
} elseif ($Action -eq 'autolock') {
  # 兜底自动锁:ZCode 完全关闭时,任何启动路径漏掉的解锁态都会被周期任务锁回
  if ((Get-ZCodeProcesses).Count -eq 0) {
    $ks = Get-KeyStats
    if ($ks.Plain.Count -gt 0) {
      Invoke-Lock | Out-Null
      Guard-Log "autolock: locked $($ks.Plain.Count) key(s)"
    }
  }
  exit 0
} elseif ($Action -eq 'fixshortcut') {
  # 无需管理员:只把被 ZCode 更新顶掉的桌面入口修回来。
  # 由"启动"文件夹在登录时调用 —— 计划任务会被 360 静默清除且不留恢复入口,
  # 而启动项在 360 的"优化记录"里可见、可点"恢复启动",是可管理的。
  Repair-ZCodeShortcut | Out-Null
  exit 0
} elseif ($Action -eq 'install') {
  # 一次性安装(管理员):重申防护 + 注册开机重申任务(SYSTEM 身份,完全不可见)
  if (-not (Test-IsAdmin)) {
    Write-Host 'install 需要管理员权限,请以管理员运行' -ForegroundColor Red
    exit 1
  }
  Invoke-ApplyAll
  Repair-ZCodeShortcut -Force | Out-Null
  Install-StartupEntry

  # 清理旧设计:每5分钟的自动锁监视器 + 它专用的无窗口启动器
  $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try { $null = (& schtasks /Delete /F /TN "$taskName-Watcher" 2>&1) } finally { $ErrorActionPreference = $eap }
  if (Test-Path $hiddenVbs) { Remove-Item $hiddenVbs -Force -ErrorAction SilentlyContinue }

  # 清理历史遗留:SYSTEM 计划任务、旧版监视任务与 VBS 启动器
  $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try {
    $null = (& schtasks /Delete /F /TN $taskName 2>&1)
    $null = (& schtasks /Delete /F /TN "$taskName-Watcher" 2>&1)
  } finally { $ErrorActionPreference = $eap }
  if (Test-Path $hiddenVbs) { Remove-Item $hiddenVbs -Force -ErrorAction SilentlyContinue }

  Guard-Log "install complete (wall/hosts/firewall/startup watcher; no scheduled task by design)"
  Write-Host "√ 防护已重申；登录自愈已就位（登录时守望进程自动接管全部巡检）" -ForegroundColor Green
  Write-Host "  注:不再注册 SYSTEM 计划任务（实测被安全软件静默清除，守望进程已替代）" -ForegroundColor DarkGray
  exit 0
} elseif ($Action -eq 'watch') {
  # 常驻守望进程(登录自愈启动项拉起,隐藏无窗口):每 60 秒巡检三件事——
  #   1) 桌面入口被 ZCode 更新重置 → 自动修回(解决"忘了按 R")
  #   2) ZCode 已关闭且密钥明文   → 自动锁回
  #   3) 检测到 ZCode 更新        → 自动扫描新落点并补墙(全自动适配)
  # 单实例互斥防重复;安全阀:unwallextra / 任务管理器结束进程
  $created = $false
  $mutex = New-Object System.Threading.Mutex($true, 'Local\ZCodeGuardWatch', [ref]$created)
  if (-not $created) { exit 0 }
  try {
    Guard-Log "watch: resident loop started (pid=$PID)"
    while ($true) {
      try {
        if (-not (Test-ShortcutOk)) { Repair-ZCodeShortcut | Out-Null }
        Invoke-AutoExtendFast
        if (Test-NeedsScan) {
          Guard-Log "watch: ZCode update detected, auto-rescanning"
          Invoke-AutoExtendScan | Out-Null
        }
        Backup-Guard
        if ((Get-ZCodeProcesses).Count -eq 0) {
          $ks = Get-KeyStats
          if ($ks.Plain.Count -gt 0) { Invoke-Lock | Out-Null }
        }
      } catch { Guard-Log "watch tick error: $_" }
      Start-Sleep -Seconds 60
    }
  } finally { $mutex.ReleaseMutex() }
} elseif ($Action -eq 'autoscan') {
  # 手动触发第二层全量扫描(更新检测也会自动触发,此入口用于排查)
  $r = Invoke-AutoExtendScan
  if ($r) {
    Write-Host "扫描完成:" -ForegroundColor Green
    Write-Host ("  ZCode 版本   : " + $r.asarVersion)
    Write-Host ("  扫描耗时     : " + $r.scanSeconds + " 秒")
    Write-Host ("  敏感候选     : " + (@($r.candidates) -join ', '))
    Write-Host ("  动态墙       : " + (@($r.extraWalls) -join ', '))
    Write-Host ("  待观察(未出现): " + (@($r.pendingWalls) -join ', '))
    Write-Host ("  上传管线标记 : " + $r.uploadMarkers + " 处(upload-credential 字样)" )
  }
} elseif ($Action -eq 'unwallextra') {
  Unwall-Extra
} elseif ($Action -eq 'status') {
  Invoke-AutoExtendFast
  Show-Status
}
