#!/bin/sh
# ARTEX CI 发布脚本（在 ci.ktyun.cc docker runner 上执行）。
# 产物：oci.ktyun.cc/ktaiorg/ARTEX:prod-sha-<short>（amd64，含 webui embed）
set -eu
cd "$(dirname "$0")/.."

fail() { echo "!!! $*" >&2; exit 1; }

sha="${SOURCE_SHA:-}"
case "$sha" in *[!0-9a-f]*|"") fail "SOURCE_SHA required";; esac
short=$(printf '%s' "$sha" | cut -c1-12)
tag="prod-sha-${short}"
ref="oci.ktyun.cc/ktaiorg/ARTEX:${tag}"

echo "=== 1/4 web build $(date -u +%H:%M:%SZ)"
docker run --rm -v "$PWD:/src" -w /src/web -e npm_config_registry=https://registry.npmmirror.com \
  docker.m.daocloud.io/library/node:22-bookworm-slim \
  sh -ec 'npm ci --no-audit --no-fund && npm run build:static' || fail "web build 失败"
[ -d web/out ] || fail "web/out 缺失"
rm -rf server/webui/dist && mkdir -p server/webui && cp -r web/out server/webui/dist

echo "=== 2/4 go build $(date -u +%H:%M:%SZ)"
mkdir -p dist/amd64
docker run --rm -v "$PWD:/src" -w /src -e CGO_ENABLED=0 -e GOFLAGS=-mod=mod \
  -e GOPROXY=https://goproxy.cn,direct -e HOME=/tmp \
  docker.m.daocloud.io/library/golang:1.26-bookworm \
  go build -trimpath -tags embedui -o dist/amd64/artex ./cmd/artex || fail "go build 失败"
[ -x dist/amd64/artex ] || fail "二进制缺失"

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
