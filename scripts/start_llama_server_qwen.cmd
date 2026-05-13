@echo off
setlocal
set MODEL_PATH=models\qwen2.5-coder-0.5b-instruct-q4_k_m.gguf
set HOST=127.0.0.1
set PORT=8080
set CTX=8192
set GPU=-1

if not "%~1"=="" set MODEL_PATH=%~1

python -m vuln_commit_kg start-llama-server --config configs/18_smallest_pair_llama_server_qwen_0_5b.yaml
