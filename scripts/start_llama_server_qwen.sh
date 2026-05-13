#!/usr/bin/env bash
set -euo pipefail
MODEL_PATH="${1:-models/qwen2.5-coder-0.5b-instruct-q4_k_m.gguf}"
SERVER_BINARY="${LLAMA_SERVER_BINARY:-llama-server}"
HOST="${LLAMA_SERVER_HOST:-127.0.0.1}"
PORT="${LLAMA_SERVER_PORT:-8080}"
CTX="${LLAMA_SERVER_CTX:-8192}"
NGL="${LLAMA_SERVER_NGL:--1}"

if [[ ! -f "$MODEL_PATH" ]]; then
  echo "Model not found at $MODEL_PATH"
  echo "Run a config with auto_download=true once, or put your GGUF file at this path."
  exit 1
fi

echo "Starting llama-server"
echo "  model: $MODEL_PATH"
echo "  url:   http://$HOST:$PORT/v1"
exec "$SERVER_BINARY" -m "$MODEL_PATH" -c "$CTX" -ngl "$NGL" --host "$HOST" --port "$PORT"
