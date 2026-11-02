#!/bin/sh
# ARTEX CI 发布脚本（ci.ktyun.cc docker runner）。
# 产物：oci.ktyun.cc/ktaiorg/ARTEX:prod-sha-<short>（amd64，webui embed）
# 注意：runner 的 daemon 看不见作业目录；容器构建一律 tar 进 tar 出。docker build 的
# context 由 docker CLI 客户端侧打包上传，不受影响。
set -eu
cd "$(dirname "$0")/.."

fail() { echo "!!! $*" >&2; exit 1; }

sha="${SOURCE_SHA:-}"
case "$sha" in *[!0-9a-f]*|"") fail "SOURCE_SHA required";; esac
short=$(printf '%s' "$sha" | cut -c1-12)
tag="prod-sha-${short}"
ref="oci.ktyun.cc/ktaiorg/ARTEX:${tag}"

echo "=== 1/4 web build $(date -u +%H:%M:%SZ)"
tar -cf - -C web --exclude=node_modules --exclude=out . \
  | docker run --rm -i -e npm_config_registry=https://registry.npmmirror.com \
    docker.m.daocloud.io/library/node:22-bookworm-slim \
    sh -ec 'set -eu; mkdir -p /src && tar xf - -C /src && cd /src && npm ci --no-audit --no-fund && npm run build:static && tar cf - out' \
  > /tmp/web-out.tar || fail "web build 失败"
rm -rf web/out && mkdir -p web/out && tar -xf /tmp/web-out.tar -C web/out --strip-components=1
[ -f web/out/index.html ] || fail "web/out/index.html 缺失"
rm -rf server/webui/dist && mkdir -p server/webui && cp -r web/out server/webui/dist

echo "=== 2/4 go build $(date -u +%H:%M:%SZ)"
mkdir -p dist/amd64
tar -cf - --exclude=.git --exclude=node_modules --exclude='dist/*-arm64' . \
  | docker run --rm -i -e CGO_ENABLED=0 -e GOFLAGS=-mod=mod -e GOPROXY=https://goproxy.cn,direct -e HOME=/tmp \
    docker.m.daocloud.io/library/golang:1.26-bookworm \
    sh -ec 'set -eu; mkdir -p /src && tar xf - -C /src && cd /src && go build -trimpath -tags embedui -o /out-artex ./cmd/artex && cat /out-artex' \
  > dist/amd64/artex || fail "go build 失败"
[ -s dist/amd64/artex ] || fail "二进制为空"
chmod +x dist/amd64/artex

echo "=== 3/4 docker build ${ref} $(date -u +%H:%M:%SZ)"
timeout 3600 docker build -t "${ref}" . || fail "docker build 失败"

echo "=== 4/4 push $(date -u +%H:%M:%SZ)"
work="${RUNNER_TEMP:-/tmp}/artex-image"
mkdir -p "${work}"
docker save -o "${work}/image.tar" "${ref}" || fail "docker save 失败"
digest=$(OCI_BEARER="$(cat /var/run/secrets/zot/token)" \
  python3 .forgejo/workflows/oci-push.py \
  --archive "${work}/image.tar" \
  --registry http://zot.kt-oci-registry.svc.cluster.local:5000 \
  --repository ktaiorg/ARTEX \
  --tag "${tag}" --kind docker) || fail "推 Zot 失败"
echo "DIGEST ${digest}"
echo "镜像: oci.ktyun.cc/ktaiorg/ARTEX:${tag}"
