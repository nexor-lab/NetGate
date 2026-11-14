# NetGate

NetGate 是一套 Windows 局域网代理、文件传输和群聊工具。

- `NetGateAdmin.exe`：控制端，启动 HTTP 正向代理，管理设备、限速、暂停、断开。
- `NetGateClient.exe`：用户端，自动发现控制端，在本机启动转发代理并把系统代理指向它。

## 功能

- 局域网 HTTP/HTTPS 正向代理
- 设备允许、断开、暂停、限速
- 局域网文件传输
- 局域网群聊与聊天历史同步
- 局域网自动发现
- 防火墙自动放行与自愈
- 系统代理崩溃自愈
- 单实例运行
- BETA 水印（显示编译时间和作者）

## 技术栈

- C# 5
- WinForms
- .NET Framework 4.8
- 单文件源码
- Windows 7 SP1 及以上

## 目录

```text
Build.ps1                 一键编译脚本
Harness.cs                引擎测试工具
PeerTest.cs               局域网发现/传输测试工具
NetGate开发文档.md        开发文档
使用说明.txt              使用说明
源码/
  Build.ps1
  Harness.cs
  PeerTest.cs
  src/NetGate.cs          全部产品源码
  src/app.manifest        应用清单
  src/netgate.ico         图标
```

## 编译

```powershell
cd 源码
powershell -ExecutionPolicy Bypass -File Build.ps1
```

产物在 `源码/build/`：

- `NetGateAdmin.exe`
- `NetGateClient.exe`

手工编译时必须带 `/codepage:65001`，否则中文会乱码。详见 `NetGate开发文档.md`。

## 运行

- 控制端需要管理员权限，用于配置防火墙。
- 用户端普通权限即可运行。
- 程序数据保存在 exe 所在目录的 `data/`。

## 注意

- 不要提交 `data/` 目录：里面包含密码、日志、防火墙状态和聊天记录。
- 文件传输和群聊不加密，仅适合可信局域网。
- 本仓库不包含编译生成的 exe，发布时自行编译。
