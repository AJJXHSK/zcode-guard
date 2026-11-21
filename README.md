# ZCode Guard — ZCode 数据外发防护守卫

针对 [ZCode](https://zcode.z.ai)（智谱 AI 编程助手桌面版）的本地防护工具，阻断其静默数据外发通道，并对 API 密钥做静态加密保管。

> 实测版本：ZCode 3.14.3 与 3.18.2（Windows 11）。**自动延伸机制会在每次更新后自动扫描新版落点并补墙**——正常情况下 ZCode 更新不需要改本工具。原理基于对 app.asar 的逆向分析，见文末"工作原理"。

## 它防什么

ZCode 桌面版存在多条数据外发通道（均在 `resources/app.asar` 中逆向确认）：

| 通道 | 内容 | 本工具的处置 |
|---|---|---|
| **仓库快照上传** | 将整个工作区打包加密，经服务端下发凭证直传阿里云 OSS | 在落盘目录挂拒绝 ACL——产物无法孵育，管线源头死掉 |
| **ARMS 遥测** | 行为/崩溃/设备信息上报阿里云 | hosts 黑洞 + 防火墙出站拦截 |
| **微信 ilink bot** | 微信远程遥控通道 | 域名黑洞 + 配置停用 |
| **每日活跃上报** | 设备号、活跃日期（走业务 API 域名） | 不封（与模型 API 同域名，封了没法用） |

另附 **API 密钥保险库**：ZCode 不提供密钥加密存储，本工具把 `config.json` 里的密钥用 DPAPI 加密进保险库，仅在 ZCode 运行期间解锁，退出自动锁回。

> ⚠️ **能力边界**：加密只覆盖 `config.json` 一处。ZCode 自身还会把密钥明文存在 `cli\db\db.sqlite` 与 `provider_config.json`（实测 `config.json` 全空时它照常工作，说明它读的是数据库）。本地明文问题只能靠**在服务商处轮换密钥**彻底解决，本工具无法代劳。

## 文件说明

| 文件 | 用途 |
|---|---|
| `zcode-guard.ps1` | 守卫本体：墙、遥测黑洞、防火墙、密钥锁/解锁、自动延伸 |
| `guard-report.ps1` | 只读状态报告（双击即查，异常时可按 R 一键修复） |
| `restore-guard.cmd` | 从本仓库恢复部署到本机的辅助脚本 |

**不包含**（也不该包含）：`providers.vault`（DPAPI 加密、绑定本机账户，离机无用且含密钥密文）、日志与状态文件。

## 快速开始

1. 把 `zcode-guard.ps1`、`guard-report.ps1` 复制到 `%USERPROFILE%\zcode-guard\`
2. 编辑 `zcode-guard.ps1` 顶部的**用户配置**（三行：用户主目录 / 桌面路径 / ZCode 安装目录）
3. 以管理员运行：
   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File "%USERPROFILE%\zcode-guard\zcode-guard.ps1" -Action install
   ```
   会自动：装登录自愈启动项（常驻守望进程）、修桌面快捷方式、挂墙、写 hosts、建防火墙规则；也会尝试注册开机 SYSTEM 重申任务——**若被安全软件静默删除属预期**，守望进程已覆盖其职能
4. 在 ZCode 配置好 provider 后锁定密钥：
   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File "%USERPROFILE%\zcode-guard\zcode-guard.ps1" -Action lock
   ```
5. 日常：**双击桌面 ZCode 图标**（install 会创建）——自动解锁→启动→退出自动锁回；**双击「ZCode 防护状态」**随时查报告

## 主要命令

```
-action launch      守卫式启动：自检→解锁→启动→退出自动锁回
-action lock        锁定密钥（收进保险库）
-action unlock      解锁密钥
-action status      终端状态页
-action autoscan    手动触发落点扫描（更新检测也会自动触发）
-action unwallextra 撤销所有自动延伸加的动态墙（安全阀）
-action fixshortcut 只修复被 ZCode 更新顶掉的桌面入口（免管理员）
-action install     全量安装/重置（需管理员）
```

## 自动延伸（随更新进化）

每次启动先做**更新检测**（毫秒级，比对版本与 asar 指纹）：

- **无更新** → 正常启动，无感
- **有更新** → 全量扫描新版 `app.asar`（约 20-40 秒），提取所有"根目录拼接"的字面量作为数据落点候选，按关键词（checkpoint/snapshot/upload/staging/pending/repo-）过滤后：
  - 扫描时**已存在**的敏感目录 → 仅记录到报告，待人工确认（避免误伤在用目录）
  - **不存在**的候选 → **立即预创建目录并上墙**——墙先于 ZCode 的第一次写入存在，不存在"目录出现→打包→上传"的窗口期
- 扫描结果与上传管线标记（upload-credential）写入报告

## 已知限制与注意事项

- **360**：`%USERPROFILE%\zcode-guard\` 加入信任区（加目录而非单文件）。SYSTEM 计划任务会被 360 静默清除且无恢复入口，因此登录自愈改用**启动文件夹**项——若被 360 禁用，在其「优化记录」里点「恢复启动」；就算守望进程没起来，守卫式启动（桌面图标）也会自动把它拉活
- **遥测层漂移自愈**：守望进程每分钟检查 hosts 与防火墙规则，被第三方软件改动后**连续两次命中**会弹确认框，确认后经 UAC 提权自动重申（拒绝/忽略后 6 小时冷却，不反复打扰）
- **墙的更新韧性（实测）**：墙是数据目录上的 NTFS 拒绝 ACL，属于**被动基础设施——不依赖守卫程序运行**。实测：桌面入口被更新重置、计划任务被安全软件删除、守望进程尚未存在（即从未按 R 的窗口期）的情况下，墙依然拦截，跨越 3.14.1 → 3.14.3 → 3.18.2 两次版本更新，checkpoints 树持续零写入。它唯一失效的情形是目录被删除重建——守卫下次启动时会自动重建并补墙
- **ZCode 更新**：会把桌面快捷方式重写回原生指向。**常驻守望进程每 60 秒巡检：自动修回入口、自动扫描新版落点并补墙、墙完整性自检（墙目录被删 60 秒内自动重建补墙）、遥测层漂移修复、ZCode 关闭后自动锁密钥——更新响应全自动，无需人工操作**。守望进程未运行时的手动兜底：报告里按 R
- **快照墙的副作用**：ZCode 的"checkpoint 回读/时间线"功能失效（写入被拒），聊天、补全、工具执行不受影响
- **密钥保管**：本仓库不含任何密钥。保险库绑定 Windows 账户（DPAPI），换机器需重新录入密钥
- `credentials.json`（OAuth token）**不要加密**：ZCode 会自行刷新回写

## 灾备恢复指引（写给协助恢复的 AI 或助手）

如果你正在协助用户从零恢复本工具，**按顺序执行**，并遵守文末红线：

1. **环境确认**：Windows + PowerShell 5.1（系统自带）；ZCode 桌面版已安装且登录过
2. **部署**：运行 `restore-guard.cmd`，或手动把两个 `.ps1` 复制到 `%USERPROFILE%\zcode-guard\`
3. **改配置**：`zcode-guard.ps1` 顶部「用户配置」三行对准实际环境
4. **安装**：管理员运行 `-Action install`（自动：登录重申任务、登录自愈启动项、桌面快捷方式、快照墙、hosts、防火墙）
5. **验证**：运行 `guard-report.ps1`，逐项核对——快照墙=写探针被拒（双目录：`v2\checkpoints` 与 `.zcode\git-checkpoint-index`）、hosts 四条封锁、防火墙规则存在、登录自愈启动项在位
6. **密钥**：仓库不含密钥（故意）。让用户在各服务商重建并填进 ZCode，然后 `-Action lock` 入库
7. **日常入口**：桌面 ZCode 图标（launch：自检→解锁→启动→退出自动锁回）+ 桌面「ZCode 防护状态」（报告）
8. **收尾**：若 install 输出"开机重申任务被安全软件删除"，属预期——登录启动项+守望进程已接管其职能（修入口/锁密钥/补墙/追更新/遥测漂移修复），可在安全软件的"优化记录"里确认启动项未被禁用

### 恢复红线（每一条都真实踩过坑）

- **不要加密 `credentials.json`**：ZCode 自行刷新并回写该文件，加密会破坏登录态刷新
- **不要动 `cli\db\db.sqlite`**：运行中数据库；且密钥轮换后其中副本无保护价值
- **`lock` 必须合并式写保险库**：覆盖式会永久丢失密钥（config 里已抹空的密钥无处可恢复）
- **PS 5.1 两个坑**：脚本含中文必须带 UTF-8 BOM（否则静默 exit 1）；`-match` 不区分大小写（排除 CamelCase 误报要用 `-cmatch`）
- **360 行为**：SYSTEM 计划任务会被静默删除且无恢复入口（所以登录自愈用启动文件夹项——安全软件对启动项给「恢复启动」按钮）；目录加入信任区可减少误报
- **自动延伸只锁"扫描时不存在"的候选**（预创建+上墙，墙先于第一次写入）；**绝不自动锁"扫描时已存在"的目录**（曾误锁 shell-snapshots 导致 ZCode shell 功能损坏）
- **快照墙副作用**：ZCode 时间线/回读功能失效属预期；聊天、补全、工具执行不受影响

### 密钥重建渠道

| 服务商 | 位置 | 说明 |
|---|---|---|
| DeepSeek | platform.deepseek.com → API Keys | 常规 sk- 键 |
| OpenRouter | openrouter.ai/settings/keys | 常规键 |
| 智谱开放平台 | open.bigmodel.cn → API Keys | 套餐键 |
| 智谱 ZCode 套餐 | ZCode 客户端内重新登录 | JWT 自动刷新进 credentials.json，**不要手动加密** |

## 工作原理（要点）

`app.asar` 逆向确认的关键结构：快照上传链路为 `POST /api/v1/snapshot/upload-credential`（zcode.z.ai 取凭证）→ 本地 tar.gz 打包 → AES-256-CTR 加密 → RSA-OAEP-SHA256 包裹对称密钥（私钥只在云端，用户无法解密自己的密文）→ PostObject 表单直传阿里云 OSS。产物必须先落盘 `checkpoints/<hash>/tmp/` 才能上传——**这就是墙的位置**。加密只在 manifest 信封层，文件本体按 4MB 分块内容寻址。

设置开关均不控制该管线：`optimizeAgentExperienceEnabled` 只管训练授权、`repoSnapshotIndexingEnabled` 只管服务端索引，sidecar 无条件实例化（唯一门槛是登录态 JWT）。触发点为每次 prompt 前（captureBeforePrompt）与任务完成时。

## 卸载

```
icacls "$env:USERPROFILE\.zcode\v2\checkpoints" /remove:d *S-1-1-0
icacls "$env:USERPROFILE\.zcode\git-checkpoint-index" /remove:d *S-1-1-0
schtasks /Delete /F /TN ZCodeGuard
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\ZCodeGuard-桌面入口维护.lnk"
# 删除目录、计划任务、快捷方式，并在 360 信任区移除
```
