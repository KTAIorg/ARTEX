#!/bin/bash
# 双机滚动发布：rollout.sh <service> <image>
# service: vuln-api | vuln-web | artex-main | artex-partner | artex-both
set -euo pipefail
SERVICE="${1:?service required: vuln-api|vuln-web|artex-main|artex-partner|artex-both}"
IMAGE="${2:?image required (含 tag/digest)}"
MAIN=69.194.14.91
PARTNER=104.225.156.8
KEY="${DEPLOY_KEY:-$HOME/.ssh/id_ed25519_ktpub}"

run_remote() {
  local host="$1"; shift
  ssh -i "$KEY" -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new "root@${host}" "$@"
}

# 通用容器启动：env 清单在各主机 /opt/ktstack/<svc>.env（EnvironmentFile 形态），密钥已落盘
rollout_one() {
  local host="$1" svc="$2"
  echo "== ${host} ${svc} -> ${IMAGE}"
  run_remote "$host" "SVC='${svc}' IMAGE_REF='${IMAGE}' bash -s" <<'REMOTE'
set -e
svc="$SVC"; IMAGE="$IMAGE_REF"
ENVFILE="/opt/ktstack/env/${svc}.env"
if [ ! -f "$ENVFILE" ]; then echo "missing $ENVFILE" >&2; exit 1; fi
docker pull "$IMAGE" >/dev/null
docker rm -f "$svc" >/dev/null 2>&1 || true
NET=kt-vuln-net
if [ "$(hostname)" != "special-gig-2.localdomain" ] && [ "$svc" = "kt-artex" ]; then
  NET=kt-partner-net
fi
VOL=""
[ "$svc" = "kt-artex" ] && VOL="-v kt-artex-data:/app/data"
ENVS=""
while IFS= read -r line; do
  case "$line" in \#*|"") continue ;; esac
  k="${line%%=*}"
  ENVS="$ENVS -e $line"
done < "$ENVFILE"
eval docker run -d --name "$svc" --restart unless-stopped \
  --network "$NET" $VOL $ENVS "$IMAGE" >/dev/null
sleep 8
case "$svc" in
  kt-vuln-api) URL=http://127.0.0.1:44851/healthz ;;
  kt-vuln-web) URL=http://127.0.0.1:37419/ ;;
  kt-artex)
    # 主站 52913 / 伙伴站 48172（按主机名区分）
    if [ "$(hostname)" = "special-gig-2.localdomain" ]; then
      URL=http://127.0.0.1:52913/api/health
    else
      URL=http://127.0.0.1:48172/api/health
    fi ;;
  *) URL="" ;;
esac
if [ -n "$URL" ]; then
  for i in 1 2 3 4 5; do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$URL" || true)
    [ "$CODE" = "200" ] && echo "healthz OK ($URL)" && exit 0
    sleep 4
  done
  echo "health check failed: $URL (last=$CODE)" >&2; exit 1
fi
echo "started (no healthz probe)"
REMOTE
}

case "$SERVICE" in
  vuln-api)   rollout_one "$MAIN" kt-vuln-api ;;
  vuln-web)   rollout_one "$MAIN" kt-vuln-web ;;
  artex-main) rollout_one "$MAIN" kt-artex ;;
  artex-partner) rollout_one "$PARTNER" kt-artex ;;
  artex-both)
    rollout_one "$MAIN" kt-artex
    rollout_one "$PARTNER" kt-artex
    ;;
  *) echo "未知 service: $SERVICE" >&2; exit 1 ;;
esac
echo "== 发布完成: $SERVICE @ $IMAGE"
