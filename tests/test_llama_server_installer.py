from vuln_commit_kg.models.llama_server_installer import _score_executable_asset, _score_runtime_asset


def test_cuda_installer_prefers_executable_over_cudart_runtime_asset():
    alias = "windows-cuda12"
    runtime = "cudart-llama-bin-win-cuda-12.4-x64.zip"
    executable = "llama-b9080-bin-win-cuda-12.4-x64.zip"
    assert _score_executable_asset(executable, alias) > 0
    assert _score_executable_asset(runtime, alias) < 0
    assert _score_executable_asset(executable, alias) > _score_executable_asset(runtime, alias)


def test_cuda_runtime_companion_asset_is_detected_only_as_runtime():
    alias = "windows-cuda12"
    runtime = "cudart-llama-bin-win-cuda-12.4-x64.zip"
    executable = "llama-b9080-bin-win-cuda-12.4-x64.zip"
    assert _score_runtime_asset(runtime, alias, executable) > 0
    assert _score_runtime_asset(executable, alias, executable) < 0
