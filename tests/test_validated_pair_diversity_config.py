from vuln_commit_kg.config import load_config


def test_five_pair_config_uses_project_diversity_and_no_probe():
    cfg = load_config("configs/32_five_pair_academiccloud_qwen397b.yaml")
    assert cfg.dataset.validation_aware_pair_selection is True
    assert cfg.dataset.validation_candidate_one_pair_per_project is True
    assert cfg.api_quota.provider_header_probe == "off"
    assert cfg.api_quota.retry_max_attempts <= 4
