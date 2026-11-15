#!/usr/bin/env bash
# =====================================================================
# NexHome｜联枢 绿联 NAS（UGOS Pro）UPK 一键打包（Linux / macOS）
#
# 上架包必须在本脚本（Linux 环境）生成：UPK 内 Unix 文件权限只在 Linux 打包
# 时完整保留，Windows 打包权限不可靠。
#
# 用法示例：
#   ./pack.sh                    # 使用 rootfs_{arch}/images/ 已有 tar：check + pack
#   ./pack.sh -b                 # 现场构建双架构镜像并导出 tar（需要 docker + buildx）
#   ./pack.sh --arch amd64       # 只打单架构
#   ./pack.sh --build 5          # 指定构建号（默认读 build_num.txt，成功后自增写回）
#
# 前置条件：ugcli 在 PATH（下载：https://developer.ugnas.com/doc/tools/ugcli.html）；
#           -b 时需要 docker + buildx（非本机架构走 QEMU 模拟）。
#
# 环境变量：EXTRA_BUILD_ARGS —— 追加给 docker buildx 的参数，例：
#           EXTRA_BUILD_ARGS="--build-arg GOPROXY=https://goproxy.cn,direct" ./pack.sh -b
# =====================================================================
set -euo pipefail

BUILD=0
ARCH=all
BUILD_IMAGES=0

usage() { grep -E '^#   \./pack' "$0" | sed 's/^# *//'; exit 0; }

while [ $# -gt 0 ]; do
    case "$1" in
        -b|--build-images) BUILD_IMAGES=1; shift ;;
        --arch)            ARCH="$2"; shift; shift ;;
        --build)           BUILD="$2"; shift; shift ;;
        -h|--help)         usage ;;
        *) echo "未知参数: $1"; usage ;;
    esac
done

proj=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$proj")
compose_file="$proj/rootfs_common/docker-compose.yaml"

echo "=== NexHomeGo UGOS 打包（方案 A：bridge + 15656 端口映射）==="

# ---------- 解析 project.yaml ----------
read_yaml() {
    grep -E "^[[:space:]]*$1:[[:space:]]*" "$proj/project.yaml" \
        | head -n1 | sed -E "s/^[[:space:]]*$1:[[:space:]]*\"?([^\"]+)\"?.*/\\1/"
}
version=$(read_yaml version)
app_id=$(read_yaml app_id)
image="babyfly/nex-home:$version"   # 不带 docker.io 前缀：tar 内 tag 为归一化形式，ugcli 要求与 compose 字符串一致
echo "应用: $app_id  版本: $version  镜像: $image"
[ -n "$version" ] || { echo "无法从 project.yaml 解析 version"; exit 1; }

# ---------- 校验 compose 镜像 tag 与 version 一致 ----------
grep -q -- "$image" "$compose_file" \
    || { echo "docker-compose.yaml 的 image 与 project.yaml version($version) 不一致，请先同步修改。"; exit 1; }

# ---------- 依赖检查 ----------
command -v ugcli >/dev/null 2>&1 \
    || { echo "未找到 ugcli。请下载并安装：https://developer.ugnas.com/doc/tools/ugcli.html"; exit 1; }

case "$ARCH" in
    all)  archs="amd64 arm64" ;;
    amd64|arm64) archs="$ARCH" ;;
    *) echo "--arch 仅支持 all/amd64/arm64"; exit 1 ;;
esac

# ---------- 构建号 ----------
build_num_file="$proj/build_num.txt"
if [ "$BUILD" -gt 0 ]; then
    build_no="$BUILD"
elif [ -f "$build_num_file" ]; then
    build_no=$(tr -d '[:space:]' < "$build_num_file")
else
    build_no=1
fi
echo "构建号: $build_no"

# ---------- 构建镜像并导出 tar ----------
if [ "$BUILD_IMAGES" = 1 ]; then
    command -v docker >/dev/null 2>&1 || { echo "未找到 docker，无法现场构建镜像（可预置 tar 后去掉 -b）。"; exit 1; }
    for a in $archs; do
        echo "--- 构建 linux/$a 镜像（非本机架构走 QEMU 模拟，较慢）---"
        # shellcheck disable=SC2086
        docker buildx build --platform "linux/$a" \
            --build-arg "VERSION=$version" \
            ${EXTRA_BUILD_ARGS:-} \
            -t "$image" --load "$repo"
        img_dir="$proj/rootfs_$a/images"
        mkdir -p "$img_dir"
        # 清理旧版本 tar，确保目录内只有当前版本（官方要求 tar 与 compose tag 一致）
        rm -f "$img_dir"/*.tar
        docker save -o "$img_dir/nex-home-$version-$a.tar" "$image"
        echo "已导出: $img_dir/nex-home-$version-$a.tar"
    done
fi

# ---------- 校验 tar 就位 ----------
for a in $archs; do
    ls "$proj/rootfs_$a/images/"*.tar >/dev/null 2>&1 \
        || { echo "rootfs_$a/images/ 下没有镜像 tar，请先构建导出（加 -b）或手工放置。"; exit 1; }
done

# ---------- ugcli check ----------
echo "--- ugcli check ---"
(cd "$proj" && ugcli check)

# ---------- ugcli pack ----------
echo "--- ugcli pack --arch $ARCH --build $build_no ---"
(cd "$proj" && ugcli pack --arch "$ARCH" --build "$build_no")

# ---------- 成功后构建号自增写回（同一 x.y.z 下构建号必须递增）----------
echo $((build_no + 1)) > "$build_num_file"
echo "构建号已写回 build_num.txt -> $((build_no + 1))"

echo "=== 完成，UPK 产物： ==="
find "$proj/build_dir" -name '*.upk' -printf '%p  (%s bytes)\n' 2>/dev/null || true
echo "提示：amd64/arm64_nasync_*.upk 安装测试后再提交上架（详见 docs/绿联NAS应用上架流程说明.md）"
