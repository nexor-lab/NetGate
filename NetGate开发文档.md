# NetGate 开发文档

> 项目：NetGate 局域网代理 / 文件传输 / 群聊
> 文档整理：2026-11-13
> 对应源码：`源码\src\NetGate.cs`（约 14,383 行）
> 对应构建：`源码\build\NetGateAdmin.exe` / `NetGateClient.exe`（247,808 字节）
> 当前迭代文件：`NetGateAdmin.beta4.exe` / `NetGateClient.beta4.exe`

---

## 1. 项目概览

NetGate 是一套 Windows 局域网工具，由同一个 C# 单文件源码编译出两个程序：

| 程序 | 角色 | 作用 |
| --- | --- | --- |
| `NetGateAdmin.exe` | 控制端 | 在本机启动 HTTP 正向代理，管理允许上网的设备、限速、暂停、断开 |
| `NetGateClient.exe` | 用户端 | 自动发现控制端，在本机启动转发代理并把系统代理指向它 |

同一套源码还包含：

- 局域网文件传输
- 局域网群聊与聊天历史
- 设备发现、在线状态、限速、禁言
- 防火墙自动放行与自动修复
- 系统代理自动恢复
- BETA 水印

技术栈：

- C# 5 语法
- WinForms
- .NET Framework 4.8
- 不需要 Visual Studio，不需要 NuGet
- 支持 Windows 7 SP1 及以上
- 数据目录固定在程序所在目录的 `data\`

---

## 2. 目录结构

```text
F:\AAA软件\
├─ NetGateAdmin.exe                 正式控制端
├─ NetGateClient.exe                正式用户端
├─ NetGateAdmin.beta4.exe           当前迭代控制端（带 BETA 水印与最新修复）
├─ NetGateClient.beta4.exe          当前迭代用户端
├─ data\                            运行时数据目录
├─ backup-20261103\                 旧版本备份
└─ 源码\
   ├─ Build.ps1                     一键编译脚本
   ├─ Harness.cs                    引擎测试工具
   ├─ PeerTest.cs                   局域网发现/传输测试工具
   ├─ src\
   │  ├─ NetGate.cs                 全部产品源码
   │  ├─ app.manifest               应用清单（asInvoker + DPI aware）
   │  └─ netgate.ico                图标
   └─ build\                        编译产物
      ├─ NetGateAdmin.exe
      └─ NetGateClient.exe
```

注意：程序使用 `AppDomain.CurrentDomain.BaseDirectory\data` 作为数据目录。把 exe 放到 `F:\AAA软件\` 下运行时，配置和日志都在 `F:\AAA软件\data\`，与 exe 文件名无关。

---

## 3. 编译与运行

### 3.1 一键编译

在 `源码` 目录执行：

```powershell
powershell -ExecutionPolicy Bypass -File Build.ps1
```

`Build.ps1` 会调用系统自带的 `csc.exe`，分别用：

- `/define:ADMIN` 编译 `NetGateAdmin.exe`
- `/define:CLIENT` 编译 `NetGateClient.exe`

产物输出到 `源码\build\`。

### 3.2 手工编译

```powershell
csc /target:winexe /optimize+ /codepage:65001 /define:ADMIN ^
    /main:NetGateApp.Program /win32manifest:src\app.manifest ^
    /out:build\NetGateAdmin.exe src\NetGate.cs ^
    /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll
```

用户端把 `/define:ADMIN` 改成 `/define:CLIENT`，输出改为 `NetGateClient.exe`。

**必须带 `/codepage:65001`**，否则源码中的中文会乱码。

### 3.3 运行与权限

- 控制端需要管理员权限来配置防火墙。非管理员启动会自动通过 UAC 提权重启。
- 用户端普通权限即可运行；首次运行可能需要 UAC 放行防火墙端口。
- 控制端和用户端都使用单实例互斥体：
  - `Local\NetGateAdmin_<用户名>`
  - `Local\NetGateClient_<用户名>`
- `--lock`、`--selftest`、`--firewall-setup` 场景会跳过单实例检查。

---

## 4. 源码结构

文件仍保持反编译还原后的单文件结构。主要类型如下。

### 4.1 NetGateCore

| 类型 | 职责 |
| --- | --- |
| `EngineOptions` | 引擎参数：监听地址、端口、超时、DoH 服务器等 |
| `Device` | 设备实体：MAC、IP、名称、昵称、允许/暂停/禁言、流量、限速、在线状态 |
| `Peer` / `HttpHead` | 连接与 HTTP 头解析内部结构 |
| `NetGateServer` | 代理引擎主体：监听、鉴权、转发、隧道、统计、设备管理 |
| `DohClient` | DNS 解析与 DoH 回退 |

### 4.2 NetGateApp

| 类型 | 职责 |
| --- | --- |
| `Program` | 入口、提权、单实例、防火墙初始化、日志路径、运行模式 |
| `Util` | 网络工具、IP/MAC、格式化、JSON 解析、日志等 |
| `TrayIcon` | 托盘图标与菜单 |
| `AdminConfig` | 控制端配置 `data\admin.ini` |
| `ClientConfig` | 用户端配置 `data\client.ini` |
| `ProxyTalk` / `ProxyResult` | 控制端状态查询、密码验证、代理请求封装 |
| `AdminForm` | 控制端主界面 |
| `ClientForm` | 用户端主界面 |
| `FileTransferService` | 局域网发现、文件传输、聊天、历史记录 |
| `FileTransferForm` | 独立文件传输窗口 |
| `ChatForm` | 用户端群聊窗口 |
| `HubForm` | 控制端“文件传输 / 群聊”一体化窗口 |
| `LocalRelay` | 用户端本机转发代理 |
| `Firewall` / `FirewallRepairResult` | 防火墙规则、自动修复、结果描述 |
| `SystemProxy` | Windows 系统代理设置、备份与恢复 |
| `LocalLock` | 可选的“锁定本机网络” |
| `UiKit` | 统一 UI 主题、卡片、按钮、状态栏、占位符 |
| `BetaWatermarkForm` | 置顶分层 BETA 水印窗口 |
| `PasswordDialog` / `SpeedForm` / `NameDialog` / `IncomingDialog` | 各类对话框 |

源码为 C# 5 语法，不能使用字符串插值、`nameof`、表达式体成员等新语法。

---

## 5. 核心机制

### 5.1 代理与鉴权

控制端在本机启动 HTTP 正向代理，默认端口 `8899`。

客户端请求需要两个关键请求头：

```http
X-NetGate-Mac: 12位十六进制设备标识
Proxy-Authorization: Basic base64(":密码")
```

鉴权顺序：

1. 缺少设备标识：`407 no-device`
2. MAC 格式错误：`407 bad-device`
3. 密码错误：`407 auth`
4. 密码正确但设备未允许：`403 pending`
5. 已允许：`200 ok`，开始转发

浏览器本身不会发送这些请求头，所以用户端必须启动 `LocalRelay`：

1. 用户端在本机监听一个随机端口；
2. 把 Windows 系统代理指向 `127.0.0.1:本机端口`；
3. 浏览器请求先到 `LocalRelay`；
4. `LocalRelay` 补上 `X-NetGate-Mac` 和 `Proxy-Authorization`；
5. 再转发到控制端。

控制端设备状态支持：

- 允许上网
- 断开 / 禁止
- 暂停 / 恢复
- 上传/下载限速
- 聊天禁言

### 5.2 局域网发现与扫描

文件传输、群聊、用户端查找控制端都依赖局域网发现。

UDP 端口范围：`8895-8905`，默认从 `8895` 开始。

发现报文为纯文本、竖线分隔：

```text
请求：NETGATE_DISCOVER_V1|本机ID
应答：NETGATE_HERE_V1|ID|名称|TCP端口|Base64(用户名)|Base64(计算机名)
```

发送目标：

- 各网卡定向广播地址
- `255.255.255.255`
- 回环地址

扫描端每约 300 ms 发送一轮，最多 8 轮。

用户端 `ClientForm.DoScan` 查找控制端的策略：

1. 先探测上次保存的控制端地址；
2. 只优先扫描有默认网关的网段（`Util.LanPrefixes`）；
3. 使用最多 64 个工作线程并行探测；
4. 单次探测超时 600 ms；
5. 总扫描时间上限 9 秒；
6. 找到后立即停止其余探测。

该策略避免把虚拟网卡、VPN 网段全部扫一遍。

### 5.3 文件传输

文件传输与群聊共用 TCP 监听：`8896-8905`，取第一个可用端口。

私有文本命令协议：

```text
OFFER
ENTRY
YES
FILE
END
```

特性：

- 接收方确认后才写盘；
- 重名文件自动追加 ` (1)`；
- 文件不加密、无密码，仅适合可信局域网；
- 接收目录默认 `data\Received\`。

### 5.4 群聊与聊天历史

聊天和文件传输共用同一个 TCP 监听，不额外开端口。

消息格式：

```text
CHAT<TAB>发送方实例ID<TAB>Base64(名字)<TAB>Base64(计算机名)<TAB>Base64(正文)<TAB>发送方DateTime.Ticks
```

历史协议：

```text
请求：HIST<TAB>数量
响应：HIST<TAB>条数
      H<TAB>Base64(时间)<TAB>Base64(名字)<TAB>Base64(内容)
      HIST_END
```

历史记录实现：

1. 收到/发送的消息写入 `data\chat.log`；
2. 打开聊天窗口先读取本机最近 300 条；
3. 扫描到成员后，向最多 6 台在线成员各请求最近 60 条；
4. 用 `时间|名字|内容` 去重；
5. 合并后补写本机 `chat.log` 并显示；
6. 发送方时间使用 `DateTime.Ticks`，保证各机器记录时间一致。

聊天日志优化：

- `LoadChatLog` 只读取文件尾部 512 KB；
- 单文件超过 4 MB 自动滚动到 `chat.log.1`；
- 群聊窗口提供“清空历史”按钮（只清本机，联网时仍可能从其他电脑补回）；
- 写入使用无 BOM 的 UTF-8。

控制端的 `HubForm` 与用户端的 `ChatForm` 都支持补历史。

### 5.5 防火墙自动修复

核心入口：`Firewall.Repair(tag, ports)`

流程：

1. 删除本程序自己的入站阻止规则；
2. 删除并重建 TCP/UDP 端口规则；
3. 删除并重建按程序放行规则；
4. 校验规则是否存在；
5. 返回 `FirewallRepairResult`，包含：
   - `Ok`
   - `Ports`
   - `Program`
   - `Verified`
   - `BlockRulesRemoved`
   - `Message`

规则名称：

```text
NetGate_AllowInTCP_<tag>
NetGate_AllowInUDP_<tag>
NetGate_AllowApp_<tag>
```

防火墙自动维护：

- 控制端启动：
  - `CleanupLegacy`
  - `Repair("Main", 8899 + 8895-8905)`
- 控制端界面“修复防火墙”按钮：
  - `CleanupLegacy`
  - `Repair`
  - 弹窗显示结果
- 运行中看门狗：
  - 每 60 秒清除一次入站阻止规则；
  - 每 5 分钟检查端口/程序规则是否还在，缺失则自动重建。
- 用户端：
  - `EnsureClientFirewall` / `--firewall-setup` 也走 `Repair("File", 8895-8905)`
- 文件传输窗口的放行按钮同样走 `Repair`

防火墙规则使用 `profile=any`，避免网络被识别为“公用”后规则失效。

日志：

- `data\firewall.log`
- 成功标记：`data\firewall.ok`（客户端，带 v2 版本号）
- 失败标记：`data\firewall.fail`（24 小时内不重复弹 UAC）

无法自动解决的情况：

- 用户在 UAC 弹窗点“否”
- 组策略强制阻止
- 第三方安全软件接管防火墙
- 这些情况只能记录日志并提示用户处理。

### 5.6 系统代理自动恢复

用户端连接时：

1. 备份当前系统代理到 `data\proxy-backup.ini`；
2. 把系统代理设置为 `127.0.0.1:本机转发端口`；
3. 正常断开时恢复备份并删除备份文件。

异常退出处理：

- 用户端启动时调用 `SystemProxy.RecoverIfStale()`；
- 如果备份文件存在且当前系统代理指向 `127.0.0.1` / `localhost`，自动恢复；
- 如果当前代理已被用户手动改掉，则删除过期备份，避免下次连接覆盖用户设置；
- 注册 `ProcessExit` 兜底恢复代理。

单实例确保不会有两个用户端同时修改系统代理。

### 5.7 设备列表与“幽灵设备”治理

控制端设备列表只应显示真实出现过的设备。

规则：

- 扫描探测包（`GET /__netgate/hello`，没有 IP / 昵称）不再创建设备；
- 真实状态上报（带 IP / 昵称）、密码验证、实际代理请求才会建档；
- 已允许 MAC、限速 MAC、禁言 MAC 只保存在独立配置集合中，不预建设备；
- 设备真正出现时，再应用允许、限速、禁言状态；
- 60 秒没有上报自动判离线；
- 无 IP、未允许、非等待、超过 120 秒无活动的设备自动清理。

说明：

- “等待允许”的设备是真实电脑在请求上网，需要管理员手动允许或拒绝；
- 如果出现不认识的等待设备，直接选中点“断开 / 禁止”，并更换授权密码；
- 控制端无法判断“这台电脑是谁”，只能按 MAC、名称、IP、密码区分。

### 5.8 BETA 水印

实现类型：`BetaWatermarkForm`

特点：

- 独立顶层窗口，`Owner` 为主窗口；
- 分层窗口（`WS_EX_LAYERED`）+ 逐像素透明；
- `WS_EX_TRANSPARENT` / `WS_EX_NOACTIVATE` / `WS_EX_TOOLWINDOW`；
- 不抢焦点、不挡鼠标、不进入任务栏；
- 跟随主窗口移动、缩放、最小化、隐藏；
- 覆盖主窗口客户区（不含 Windows 标题栏）；
- 方向固定 `-24°`；
- `BETA` 平铺铺满整个客户区；
- 中心位置显示完整的：
  - `BUILD yyyy-MM-dd HH:mm:ss`
  - `by YanzheQu`
- 所有水印文字统一颜色和透明度；
- 时间戳与作者使用加粗字体，保证可读；
- 构建时间取自程序集文件的最后写入时间，每次重新编译自动更新。

---

## 6. 配置与数据文件

| 文件 | 作用 |
| --- | --- |
| `data\admin.ini` | 控制端配置：密码哈希、DPAPI 保护的明文密码、端口、自动允许、限速、允许列表、禁言、自定义名称 |
| `data\client.ini` | 用户端配置：控制端地址、端口、记住的密码、是否自动连接 |
| `data\transfer.ini` | 文件传输：本机显示名称、接收目录 |
| `data\chat.log` | 聊天记录：`时间<TAB>名字<TAB>内容` |
| `data\chat.log.1` | 聊天日志滚动备份 |
| `data\engine.log` | 代理引擎日志 |
| `data\firewall.log` | 防火墙规则执行结果 |
| `data\firewall.ok` | 客户端防火墙已放行标记（v2） |
| `data\firewall.fail` | 防火墙失败冷却标记（24 小时） |
| `data\client-error.log` | 用户端未处理异常 |
| `data\proxy-backup.ini` | 系统代理原始设置备份 |
| `data\peers.ini` | 上次扫描到的局域网电脑缓存 |
| `data\Received\` | 接收到的文件 |
| `data\locked.flag` | 本机网络锁定标记 |

安全提示：

- 控制端 `PasswordPlain` 使用 DPAPI（CurrentUser）保护；
- 用户端记住的密码目前只做 URL 转义，落盘近似明文；
- 文件传输和群聊没有认证、没有加密，仅适合可信局域网；
- 防火墙端口当前使用 `profile=any`，在公用网络也会生效，需要按实际环境评估。

---

## 7. 协议速查

### 7.1 代理状态查询

```http
GET /__netgate/hello?mac=<mac>&ip=<ip>&name=<name>&user=<user>&v=1.0&nick=<nick> HTTP/1.1
Host: x
Connection: close
```

扫描探测包只带 `mac/name/user/v`，不带 `ip/nick`，控制端不会为它创建设备。

### 7.2 密码验证

```http
GET /__netgate/auth?name=<name>&user=<user>&ip=<ip>&v=1.1&nick=<nick> HTTP/1.1
X-NetGate-Mac: <mac>
Proxy-Authorization: Basic <base64(":password")>
Connection: close
```

### 7.3 发现协议

```text
NETGATE_DISCOVER_V1|<本机ID>
NETGATE_HERE_V1|<ID>|<名称>|<TCP端口>|<Base64(用户名)>|<Base64(计算机名)>
```

### 7.4 聊天协议

```text
CHAT<TAB>FromId<TAB>Base64(Name)<TAB>Base64(Host)<TAB>Base64(Text)<TAB>Ticks
HIST<TAB>60
HIST<TAB>N
H<TAB>Base64(Time)<TAB>Base64(Name)<TAB>Base64(Text)
HIST_END
```

### 7.5 端口

| 端口 | 协议 | 用途 |
| --- | --- | --- |
| 8899 | TCP | HTTP 正向代理 |
| 8895-8899 | UDP | 局域网发现 |
| 8896-8905 | TCP | 文件传输、群聊、历史请求 |

---

## 8. 开发约定

1. 只使用 C# 5 语法。
2. 编译必须带 `/codepage:65001`。
3. 新 UI 使用 `UiKit`：
   - 卡片 `UiKit.CardPanel()`
   - 主按钮 `UiKit.PrimaryButton`
   - 次按钮 `UiKit.SecondaryButton`
   - 字段标签 `UiKit.FieldLabel`
   - 状态栏 `UiKit.StatusBar`
4. 不添加细小的提示标签；提示尽量使用占位符或 ToolTip。
5. 程序数据统一放 `data\`，不要写到 C 盘其他位置。
6. 修改协议必须考虑新旧版本兼容，并更新本文档。
7. 不要吞掉关键异常；至少写入日志。
8. 改动代理、发现、文件传输、聊天协议后，必须用 `Harness.cs` / `PeerTest.cs` 或真实双机验证。
9. 发布前必须重新编译两个 exe，并确认水印 BUILD 时间已更新。

---

## 9. 调试与验证

### 9.1 看日志

```text
data\engine.log        引擎监听、设备上线、允许/拒绝
data\firewall.log      防火墙规则是否成功
data\transfer.log      发现、文件传输、传输服务启动
data\chat.log          聊天记录
data\client-error.log  用户端异常
data\NetGateDebug.log  --debug 模式调试日志
```

### 9.2 用户端自检

```powershell
NetGateClient.exe --selftest --debug --client
```

自检会：

- 启动用户端窗口；
- 自动扫描局域网；
- 扫描完成后关闭；
- 输出 `SELFTEST-OK` 或超时日志。

### 9.3 测试工具

- `Harness.cs`：在临时端口启动引擎，验证转发。
- `PeerTest.cs`：验证局域网发现、按 IP 探测、发送文件、群聊。

编译示例：

```powershell
csc /r:NetGateAdmin.exe Harness.cs
csc /r:NetGateAdmin.exe PeerTest.cs
```

### 9.4 防火墙验证

- 启动控制端后执行界面“修复防火墙”；
- 查看 `data\firewall.log` 是否出现 `repair Main: ports=ok program=ok verify=ok`；
- 用另一台电脑扫描或在文件传输窗口点“重新扫描”。

### 9.5 设备列表验证

- 控制端启动后，设备列表不应出现“设备 xxxx”这类无 IP、无名称的离线幽灵；
- 只应有真实状态上报、密码验证或代理请求的设备；
- 等待允许的设备是真实请求，需要管理员确认；
- 如果仍有异常设备，查看 `data\engine.log` 的 `device online` 记录，核对 MAC、IP、名称。

---

## 10. 2026-11-13 改动记录

### 10.1 UI

- 新增 `UiKit` 统一主题：卡片、按钮、表格、状态栏、字体。
- 控制端、用户端、文件传输、群聊、局域网窗口全部重做。
- 去掉“①/②”编号、小字提示、底部小字说明。
- 控制端设备列表改为工具栏 + 标签页（设备 / 运行日志）。
- 局域网窗口改为“文件传输 / 群聊”分页。
- 对话框统一为现代按钮、加粗字段、回车确认。
- 文件传输、禁言按钮根据列表选中状态启用/禁用。
- 聊天窗口增加“清空历史”。

### 10.2 可靠性

- 新增单实例互斥体，避免重复监听、重复修改系统代理。
- 新增系统代理崩溃自愈：`SystemProxy.RecoverIfStale`。
- 新增 `ProcessExit` 代理恢复兜底。
- 控制端启动与运行中补全防火墙规则。
- 新增 `Firewall.Repair` 统一修复流程。
- `OpenProgram` 先删除旧规则再添加，避免重复规则。
- 看门狗每 60 秒清阻止规则、每 5 分钟校验并重建端口/程序规则。
- 用户端扫描改为网关网段优先 + 64 工作线程 + 9 秒上限。
- 聊天日志改为尾部 512 KB 读取、4 MB 滚动、可清空。
- 控制端 `HubForm` 补齐聊天历史同步。

### 10.3 设备列表治理

- 扫描 hello 不再创建设备。
- 已允许 MAC、限速 MAC、禁言 MAC 不再预建设备。
- 设备实际出现时再应用配置。
- 60 秒无上报判离线。
- 无 IP、未允许、非等待、长时间无活动的设备自动清理。
- 修复控制端出现未知离线设备的问题。

### 10.4 BETA 水印

- 新增 `BetaWatermarkForm` 顶层分层水印。
- `BETA` 平铺铺满客户区，方向 `-24°`。
- 中心显示 `BUILD 时间` 与 `by YanzheQu`。
- 统一颜色与透明度，时间戳和作者加粗可读。
- 水印置顶、不挡鼠标、不抢焦点。
- 构建时间自动取程序集最后写入时间。

---

## 11. 已知限制与后续建议

### 11.1 已知限制

- 只代理 HTTP/HTTPS，游戏、BT、UDP 语音不走代理。
- 用户端只支持 Windows。
- 文件传输不加密、无密码。
- 群聊不加密、不做离线消息。
- 不支持跨 /24、VLAN、访客网络，只能手动填 IP。
- 控制端与用户端的局域网窗口仍有部分重复逻辑。
- 源码仍是单文件，约 14,000 行，维护成本较高。
- 客户端记住的密码只做 URL 转义，安全性不足。
- 防火墙使用 `profile=any`，公用网络也会放行，需要按场景评估。
- 第三方安全软件或组策略拦截时，程序无法自动绕过。

### 11.2 建议

1. 把单文件拆分为：
   - `Engine.cs`
   - `Core.cs`
   - `AdminForm.cs`
   - `ClientForm.cs`
   - `LanForm.cs`
   - `Chat.cs`
   - `FileTransfer.cs`
   - `UiKit.cs`
2. 统一 `ChatForm` / `HubForm` / `FileTransferForm` 的重复逻辑。
3. 客户端密码改用 DPAPI。
4. 文件传输/群聊增加共享令牌或 HMAC。
5. 聊天日志增加清理策略、保留天数。
6. 增加“仅显示已允许/在线设备”等筛选，减少待批准设备对列表的干扰。
7. 增加拖拽发送、文件夹传输、取消/重试。
8. 增加自动化测试：历史合并、去重、配置解析、防火墙幂等。
9. 发布流程统一命名，避免长期保留多个 `.new/.latest/.betaN` 文件。

---

## 12. 迁移到新电脑

1. 拷贝整个 `源码` 文件夹。
2. 确认安装 .NET Framework 4.8。
3. 打开 PowerShell 执行：
   ```powershell
   powershell -ExecutionPolicy Bypass -File Build.ps1
   ```
4. 产物在 `build\`：
   - `NetGateAdmin.exe`
   - `NetGateClient.exe`
5. 把 exe 放到目标目录，首次运行接受 UAC 并放行防火墙。
6. 如果迁移配置，拷贝旧目录的 `data\` 到新目录同级。
7. 控制端和用户端必须在同一局域网；默认端口 8899。
8. 如果网络被识别为“公用”，确认防火墙规则已放行；必要时执行界面“修复防火墙”。

---

## 13. 发布检查清单

- [ ] `Build.ps1` 编译通过，两个 exe 大小一致。
- [ ] 用户端 `--selftest` 退出码为 0，无 `client-error.log`。
- [ ] 控制端启动后设备列表没有幽灵设备。
- [ ] 防火墙日志出现 `ports=ok program=ok verify=ok`。
- [ ] 文件传输、群聊、历史补拉双机验证通过。
- [ ] 水印 BUILD 时间已更新，显示 `BETA`、`BUILD`、`by YanzheQu`。
- [ ] 退出程序后系统代理已恢复。
- [ ] 正式发布文件名统一为 `NetGateAdmin.exe` / `NetGateClient.exe`，清理临时 `.betaN` 文件。
