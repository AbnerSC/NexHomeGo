# =====================================================================
# NexHome｜联枢 绿联 NAS（UGOS Pro）UPK 打包辅助脚本（Windows / PowerShell 5.1+）
#
# 职责：构建双架构镜像 -> 导出 tar 到 rootfs_{arch}/images/ -> ugcli check
# 注意：上架/安装测试用的 UPK 必须在 Linux 执行 pack.sh 生成（Unix 文件权限
#       只在 Linux 打包时完整保留）。-Pack 仅产出 Windows 本地测试包，勿提交上架。
#
# 用法示例：
#   .\pack.ps1                    # 全流程：构建双架构镜像 + 导出 tar + check
#   .\pack.ps1 -SkipImageBuild    # 跳过镜像构建，直接使用已有 tar
#   .\pack.ps1 -Arch amd64        # 只处理 amd64 架构
#   .\pack.ps1 -Build 3           # 指定构建号（默认读 build_num.txt）
#   .\pack.ps1 -Pack              # 额外生成 Windows 本地测试包（勿上架）
#
# 前置条件：Docker Desktop（含 buildx）；ugcli.exe 在 PATH
#           （下载：https://developer.ugnas.com/doc/tools/ugcli.html）
#
# 环境变量：EXTRA_BUILD_ARGS —— 追加给 docker buildx 的参数，例：
#           $env:EXTRA_BUILD_ARGS='--build-arg GOPROXY=https://goproxy.cn,direct'; .\pack.ps1
# =====================================================================
param(
    [int]$Build = 0,
    [ValidateSet('all', 'amd64', 'arm64')]
    [string]$Arch = 'all',
    [switch]$SkipImageBuild,
    [switch]$Pack
)

$ErrorActionPreference = 'Stop'
$proj = $PSScriptRoot
$repo = Split-Path $proj -Parent
$composeFile = Join-Path $proj 'rootfs_common\docker-compose.yaml'

Write-Host "=== NexHomeGo UGOS 打包（方案 A：bridge + 15656 端口映射）===" -ForegroundColor Cyan

# ---------- 解析 project.yaml ----------
function Read-YamlValue([string]$Key) {
    $line = Select-String -Path (Join-Path $proj 'project.yaml') `
        -Pattern ("^\s*{0}:\s*(.+?)\s*$" -f $Key) | Select-Object -First 1
    if ($null -eq $line) { throw "project.yaml 中未找到字段: $Key" }
    return $line.Matches[0].Groups[1].Value.Trim('"')
}
$version = Read-YamlValue 'version'
$appId   = Read-YamlValue 'app_id'
$image   = "babyfly/nex-home:$version"   # 不带 docker.io 前缀：tar 内 tag 为归一化形式，ugcli 要求与 compose 字符串一致
Write-Host "应用: $appId  版本: $version  镜像: $image"

# ---------- 校验 compose 镜像 tag 与 version 一致 ----------
$compose = Get-Content $composeFile -Raw
if (-not $compose.Contains($image)) {
    throw "docker-compose.yaml 的 image 与 project.yaml version($version) 不一致，请先同步修改。"
}

# ---------- 依赖检查 ----------
if (-not (Get-Command ugcli -ErrorAction SilentlyContinue)) {
    throw "未找到 ugcli。请从 https://developer.ugnas.com/doc/tools/ugcli.html 下载 ugcli-windows-amd64.exe，重命名为 ugcli.exe 并加入 PATH。"
}
if (-not $SkipImageBuild -and -not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "未找到 docker。需要 Docker Desktop（含 buildx）构建多架构镜像，或使用 -SkipImageBuild 跳过。"
}

# ---------- 构建号 ----------
$buildNumFile = Join-Path $proj 'build_num.txt'
if ($Build -gt 0) {
    $buildNo = $Build
} elseif (Test-Path $buildNumFile) {
    $buildNo = [int](Get-Content $buildNumFile -Raw).Trim()
} else {
    $buildNo = 1
}
Write-Host "构建号: $buildNo （最终版本号: $version.$('0000') ，打包后由 ugcli 补零）"

# ---------- 构建镜像并导出 tar ----------
$archs = if ($Arch -eq 'all') { @('amd64', 'arm64') } else { @($Arch) }

if (-not $SkipImageBuild) {
    foreach ($a in $archs) {
        Write-Host "--- 构建 linux/$a 镜像（非本机架构走 QEMU 模拟，较慢）---" -ForegroundColor Cyan
        $extraArgs = @()
        if ($env:EXTRA_BUILD_ARGS) { $extraArgs = $env:EXTRA_BUILD_ARGS -split '\s+' }
        docker buildx build --platform "linux/$a" `
            --build-arg "VERSION=$version" `
            @extraArgs `
            -t $image --load $repo
        if ($LASTEXITCODE -ne 0) { throw "docker buildx 构建 linux/$a 失败" }

        $imgDir = Join-Path $proj "rootfs_$a\images"
        New-Item -ItemType Directory -Force -Path $imgDir | Out-Null
        # 清理旧版本 tar，确保目录内只有当前版本（官方要求 tar 与 compose tag 一致）
        Get-ChildItem $imgDir -Filter *.tar -ErrorAction SilentlyContinue | Remove-Item -Force
        $tarPath = Join-Path $imgDir "nex-home-$version-$a.tar"
        docker save -o $tarPath $image
        if ($LASTEXITCODE -ne 0) { throw "docker save 导出 $a 失败" }
        Write-Host "已导出: $tarPath ($([math]::Round((Get-Item $tarPath).Length/1MB,1)) MB)"
    }
}

# ---------- 校验 tar 就位 ----------
foreach ($a in $archs) {
    $imgDir = Join-Path $proj "rootfs_$a\images"
    $tars = @(Get-ChildItem $imgDir -Filter *.tar -ErrorAction SilentlyContinue)
    if ($tars.Count -eq 0) { throw "rootfs_$a/images/ 下没有镜像 tar，请先构建导出（去掉 -SkipImageBuild）。" }
}

# ---------- ugcli check ----------
Write-Host "--- ugcli check ---" -ForegroundColor Cyan
Push-Location $proj
try {
    ugcli check
    if ($LASTEXITCODE -ne 0) { throw "ugcli check 未通过，请根据上方输出修复。" }
} finally {
    Pop-Location
}

# ---------- ugcli pack（可选，仅本地测试包）----------
if ($Pack) {
    Write-Warning "Windows 打包不保留 Unix 文件权限，产物仅用于本地测试，严禁提交上架（上架包用 Linux 跑 pack.sh）。"
    Push-Location $proj
    try {
        ugcli pack --arch $Arch --build $buildNo
        if ($LASTEXITCODE -ne 0) { throw "ugcli pack 失败" }
    } finally {
        Pop-Location
    }
    # 成功后构建号自增写回（同一 x.y.z 下构建号必须递增）
    Set-Content -Path $buildNumFile -Value ($buildNo + 1) -Encoding ASCII
    Write-Host "构建号已写回 build_num.txt -> $($buildNo + 1)"
}

Write-Host "完成。产物目录: $proj\build_dir（-Pack 时生成）；上架请在 Linux 执行 ./pack.sh" -ForegroundColor Green
