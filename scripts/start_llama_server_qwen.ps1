param(
  [string]$ModelPath = "models/qwen2.5-coder-0.5b-instruct-q4_k_m.gguf",
  [string]$ServerBinary = "llama-server",
  [string]$HostName = "127.0.0.1",
  [int]$Port = 8080,
  [int]$Context = 8192,
  [int]$GpuLayers = -1
)

if (-not (Test-Path $ModelPath)) {
  Write-Host "Model not found at $ModelPath"
  Write-Host "Run a config with auto_download=true once, or put your GGUF file at this path."
  exit 1
}

Write-Host "Starting llama-server"
Write-Host "  model: $ModelPath"
Write-Host "  url:   http://$HostName`:$Port/v1"
& $ServerBinary -m $ModelPath -c $Context -ngl $GpuLayers --host $HostName --port $Port
