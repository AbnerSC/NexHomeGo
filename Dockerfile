# =====================================================================
# NexHomeGo(Go) 多架构镜像构建文件（linux/amd64 & linux/arm64）
#
# 与 Java 侧 NexHome Dockerfile 的差异（Go 迁移点）：
#   - CGO 必须开启（mattn/go-sqlite3 内嵌 SQLite amalgamation 源码，
#     与 Java 侧 SQLite 数据文件互操作），编译阶段需要 gcc；
#     产物二进制绑定目标架构，编译阶段不能像 Java 那样固定
#     --platform=$BUILDPLATFORM，arm64 依赖 QEMU 模拟
#     （由工作流 docker/setup-qemu-action 提供）
#   - 前端静态资源 / schema.sql / ip2region xdb 均已 go:embed 进单二进制，
#     运行阶段镜像只需二进制 + CA 证书 + 时区数据，无需 node/jdk
#
# 本地手动构建多架构镜像：
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -t nex-home:latest --push .
# 本机单架构调试可直接：docker build -t nex-home . && docker run -p 8090:8090 nex-home
# 模块代理默认不注入（GitHub Actions / 本地直连 Go 官方 proxy.golang.org）；
# 国内环境构建（Gitea Actions）显式注入加速依赖下载：
#   --build-arg GOPROXY=https://goproxy.cn,direct
# 同样可选的 apt 镜像源（加速运行阶段 ca-certificates/tzdata 安装）：
#   --build-arg APT_MIRROR=repo.huaweicloud.com
# =====================================================================

# ---------- 阶段一：Go 编译打包（golang 官方镜像自带 gcc，满足 CGO） ----------
ARG GO_IMAGE=golang:1.27-bookworm
# 运行时基础镜像：必须声明在第一个 FROM 之前（全局 ARG），否则后续 FROM 无法引用
ARG BASE_IMAGE=debian:bookworm-slim
# 可选：Debian apt 镜像源（仅运行阶段安装 ca-certificates/tzdata/curl 时生效）。
# 默认不注入，保持官方 deb.debian.org；国内环境由 Gitea Actions 经 build-arg
# 注入公共镜像源加速，为空时运行阶段跳过替换
ARG APT_MIRROR=
FROM ${GO_IMAGE} AS build
WORKDIR /build

# 可选：模块代理默认不注入，保持 Go 官方默认行为（proxy.golang.org + direct），
# 供 GitHub Actions / 本地直接构建；国内环境由 Gitea Actions 通过 build-arg
# 注入 Nexus 模块代理加速 go mod download
ARG GOPROXY
# GOFLAGS=-buildvcs=false：构建上下文已排除 .git，禁止 go 尝试嵌入 VCS 戳记
ENV GOFLAGS=-buildvcs=false CGO_ENABLED=1
# 仅在显式传入时才写入 go env（持久化到后续构建步骤），未传时完全不改动默认代理
RUN if [ -n "$GOPROXY" ]; then go env -w GOPROXY="$GOPROXY"; fi

# 先拷贝 go.mod/go.sum 预取依赖，源码变更时可复用 Docker 层缓存
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# 版本号注入：对齐 internal/core.Version 的 ldflags 约定
# （VERSION 为空时保留代码内默认值，与 Java 侧 Dockerfile 不带版本构建的行为一致）
ARG VERSION=
ARG TARGETOS
ARG TARGETARCH
RUN LDFLAGS="-s -w"; \
    if [ -n "$VERSION" ]; then LDFLAGS="$LDFLAGS -X 'NexHomeGo/internal/core.Version=$VERSION'"; fi; \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
        go build -trimpath -ldflags="$LDFLAGS" -o /out/nexhome ./cmd/nexhome

# ---------- 阶段二：运行时镜像 ----------
FROM ${BASE_IMAGE}
WORKDIR /app

ARG APT_MIRROR

# 二进制按编译阶段的 glibc 动态链接（与运行镜像同源发行版系列），
# 运行期仅需 CA 证书（ACME 签发/DDNS/通知等 HTTPS 出站）与时区数据（定时任务/日志时间）
# 动态替换镜像源（兼容 DEB822 格式与旧版 sources.list 格式；APT_MIRROR 为空则保持官方源）
RUN if [ -n "${APT_MIRROR}" ]; then \
        sed -i "s|deb.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; \
        sed -i "s|security.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources 2>/dev/null || true; \
        sed -i "s|deb.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list 2>/dev/null || true; \
    fi && \
    apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates tzdata curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /out/nexhome ./nexhome

# 运行期文件全部落在 WORK_DIR/data 下（见 core.LoadConfig，决策⑤），
# 部署时挂载数据卷持久化： -v /srv/nexhome/data:/app/data
RUN mkdir -p /app/data

EXPOSE 8090
ENTRYPOINT ["./nexhome"]
