# NetGate 一键编译脚本
# 用法：powershell -ExecutionPolicy Bypass -File Build.ps1
#
# 目录结构（与本包一致）：
#   Build.ps1        本脚本
#   src\NetGate.cs   全部源码（引擎 + 控制端界面 + 用户端界面 + 文件传输）
#   src\app.manifest 兼容性清单（asInvoker，程序自己按需提权）
#   src\netgate.ico  图标（可选）
#
# 产物：build\NetGateAdmin.exe、build\NetGateClient.exe
# 环境：Windows 7+ / .NET Framework 4.8，不需要 Visual Studio

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$srcDir = Join-Path $root "src"
$outDir = Join-Path $root "build"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory $outDir | Out-Null }

# 找编译器
$candidates = @(
    "$env:windir\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    "$env:windir\Microsoft.NET\Framework\v4.0.30319\csc.exe"
)
$csc = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $csc) { throw "未找到 csc.exe，请安装 .NET Framework 4.x" }
Write-Host "编译器: $csc"

$source   = Join-Path $srcDir "NetGate.cs"
$manifest = Join-Path $srcDir "app.manifest"
$icon     = Join-Path $srcDir "netgate.ico"

foreach ($f in @($source, $manifest)) {
    if (-not (Test-Path $f)) { throw "缺少文件: $f" }
}

$refs = @("/r:System.dll", "/r:System.Core.dll", "/r:System.Drawing.dll", "/r:System.Windows.Forms.dll")
$iconArg = @()
if (Test-Path $icon) { $iconArg = @("/win32icon:$icon") }

# 两个版本由 /define 区分：
#   ADMIN  -> 控制端，client 默认 false
#   CLIENT -> 用户端，client 默认 true
foreach ($t in @(@{ N = "NetGateAdmin.exe";  D = "ADMIN" }, @{ N = "NetGateClient.exe"; D = "CLIENT" })) {
    $out = Join-Path $outDir $t.N
    $args = @(
        "/nologo", "/optimize+", "/target:winexe", "/codepage:65001",
        "/define:$($t.D)", "/main:NetGateApp.Program",
        "/win32manifest:$manifest", "/out:$out"
    ) + $iconArg + @($source) + $refs
    & $csc @args
    if ($LASTEXITCODE -ne 0) { throw "编译失败: $($t.N)" }
    $fi = Get-Item $out
    Write-Host ("OK  {0}  {1:N0} 字节" -f $fi.Name, $fi.Length)
}

Write-Host ""
Write-Host "完成：$outDir"