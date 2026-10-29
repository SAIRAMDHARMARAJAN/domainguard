#!/usr/bin/env bash
# Run your own CertStream server (certstream-server-go) in Docker, so DomainGuard has a reliable live stream.
#
#   scripts/certstream.sh start     pull the image if needed and start the server (safe to run twice)
#   scripts/certstream.sh check     connect and print one real certificate message (proves it works)
#   scripts/certstream.sh status    is it running?
#   scripts/certstream.sh logs      follow the server log
#   scripts/certstream.sh stop      stop it (it uses bandwidth and CPU while running)
#   scripts/certstream.sh remove    stop and delete the container
#
# Then put this in .env:   CERTSTREAM_URL=ws://localhost:8080
# Needs Docker (Docker Desktop on Mac/Windows). Project: https://github.com/d-Rickyy-b/certstream-server-go (MIT).
set -euo pipefail

NAME="${CERTSTREAM_CONTAINER:-certstream}"
PORT="${CERTSTREAM_PORT:-8080}"
IMAGE="${CERTSTREAM_IMAGE:-0rickyy0/certstream-server-go}"

need_docker() {
  command -v docker >/dev/null || { echo "Docker is not installed. Install Docker Desktop: https://www.docker.com/products/docker-desktop/"; exit 1; }
  if ! docker info >/dev/null 2>&1; then
    if [[ "$(uname)" == "Darwin" ]]; then
      echo "Starting Docker Desktop..."; open -a Docker
      for _ in $(seq 1 45); do docker info >/dev/null 2>&1 && break; sleep 4; done
    fi
    docker info >/dev/null 2>&1 || { echo "Docker is installed but its daemon is not running. Start Docker and retry."; exit 1; }
  fi
}

state() {
  local s
  s="$(docker ps -a --filter "name=^/${NAME}$" --format '{{.State}}' 2>/dev/null | head -n1)"
  echo "${s:-absent}"
}

case "${1:-}" in
  start)
    need_docker
    case "$(state)" in
      running) echo "Already running on port $PORT." ;;
      absent)  docker run -d --name "$NAME" --restart unless-stopped -p "$PORT:8080" "$IMAGE" >/dev/null
               echo "Started. First certificates arrive within a minute (the server also catches up on recent ones)." ;;
      *)       docker start "$NAME" >/dev/null; echo "Restarted existing container." ;;
    esac
    echo "Use:  CERTSTREAM_URL=ws://localhost:$PORT   (verify with: scripts/certstream.sh check)"
    ;;
  check)
    PY_BIN="python3"
    if [[ -x "${VIRTUAL_ENV:-}/bin/python" ]]; then
      PY_BIN="$VIRTUAL_ENV/bin/python"
    elif [[ -x "$(dirname "$0")/../.venv/bin/python" ]]; then
      PY_BIN="$(dirname "$0")/../.venv/bin/python"
    fi
    "$PY_BIN" - "$PORT" <<'PY'
import asyncio, json, sys
try:
    import websockets
except ImportError:
    sys.exit("pip install websockets   (needed for this check and for live mode)")
async def main(port):
    try:
        async with websockets.connect(f"ws://localhost:{port}", open_timeout=10) as ws:
            msg = json.loads(await asyncio.wait_for(ws.recv(), 60))
        doms = msg["data"]["leaf_cert"]["all_domains"]
        print("OK: received a certificate update")
        print("  message_type:", msg["message_type"], "| domains in certificate:", doms[:3])
    except Exception as e:
        sys.exit(f"FAILED: {type(e).__name__} {e}\nIs it running? Try: scripts/certstream.sh status / logs")
asyncio.run(main(int(sys.argv[1])))
PY
    ;;
  status)  need_docker; echo "container '$NAME': $(state)"; docker ps --filter "name=$NAME" --format '  {{.Status}}  {{.Ports}}' ;;
  logs)    need_docker; docker logs -f --tail 30 "$NAME" ;;
  stop)    need_docker; docker stop "$NAME" >/dev/null && echo "Stopped." ;;
  remove)  need_docker; docker rm -f "$NAME" >/dev/null && echo "Removed." ;;
  *)       sed -n '2,12p' "$0"; exit 1 ;;
esac
