#!/bin/sh
set -e

lower() {
  printf '%s' "$1" | tr 'A-Z' 'a-z'
}

is_false() {
  case "$(lower "$1")" in
    false|0|no) return 0 ;;
    *) return 1 ;;
  esac
}

probe() {
  curl -fsS --max-time 4 "$1/api/tags" >/dev/null 2>&1
}

MODE=$(lower "${OLLAMA_MODE:-auto}")
AUTO_FLAG=$(lower "${OLLAMA_AUTO_START:-true}")
REMOTE_URL="${OLLAMA_REMOTE_URL%/}"
BASE_URL="${OLLAMA_BASE_URL%/}"
[ -n "$BASE_URL" ] || BASE_URL="http://127.0.0.1:11434"

if [ -n "$REMOTE_URL" ]; then
  if probe "$REMOTE_URL"; then
    export OLLAMA_BASE_URL="$REMOTE_URL"
    echo "Using remote Ollama at $REMOTE_URL"
    exec "$@"
  else
    echo "Remote Ollama at $REMOTE_URL unreachable." >&2
    if [ "$MODE" = "remote" ] && is_false "$AUTO_FLAG"; then
      echo "Remote mode enforced and embedded auto-start disabled." >&2
      exit 1
    fi
  fi
fi

if [ "$MODE" = "remote" ] && is_false "$AUTO_FLAG"; then
  if probe "$BASE_URL"; then
    export OLLAMA_BASE_URL="$BASE_URL"
    echo "Using explicitly provided Ollama base URL $BASE_URL"
    exec "$@"
  fi
  echo "Remote mode requested but no reachable Ollama endpoint found." >&2
  exit 1
fi

export OLLAMA_BASE_URL="$BASE_URL"

if probe "$BASE_URL"; then
  echo "Ollama already reachable at $BASE_URL"
else
  if is_false "$AUTO_FLAG"; then
    echo "Embedded Ollama auto-start disabled; continuing without launching the server."
  else
    echo "Starting embedded Ollama server at $BASE_URL..."
    /usr/local/bin/ollama serve >/tmp/ollama.log 2>&1 &
    OLLAMA_PID=$!
    trap 'if [ -n "$OLLAMA_PID" ]; then kill "$OLLAMA_PID" 2>/dev/null; fi' TERM INT
    for _ in $(seq 1 30); do
      if probe "$BASE_URL"; then
        echo "Embedded Ollama ready at $BASE_URL"
        break
      fi
      sleep 1
    done
  fi
fi

exec "$@"
