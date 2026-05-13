from pathlib import Path

from vuln_commit_kg.config import load_config


def test_qwen7b_configs_load():
    for name in [
        "configs/24_smallest_pair_llama_server_qwen7b_q8_agent_demo_strict.yaml",
        "configs/25_smallest_pair_managed_llama_server_qwen7b_q8_agent_demo_strict.yaml",
        "configs/26_estimate_cost_smallest_pair_qwen7b_q8_llama_tokenizer.yaml",
    ]:
        cfg = load_config(Path(name))
        assert cfg.model.repo_id == "bartowski/Qwen2.5-Coder-7B-Instruct-GGUF"
        assert cfg.model.gguf_filename == "Qwen2.5-Coder-7B-Instruct-Q8_0.gguf"
        assert cfg.model.local_path == "models/Qwen2.5-Coder-7B-Instruct-Q8_0.gguf"
        assert cfg.model.backend == "llama_server"
        assert cfg.model.auto_download is True
