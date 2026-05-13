from vuln_commit_kg.config import load_config


def test_five_pair_qwen_config_uses_validation_aware_selection_and_no_probe():
    cfg = load_config("configs/32_five_pair_academiccloud_qwen397b.yaml")
    assert cfg.dataset.validation_aware_pair_selection is True
    assert cfg.dataset.validated_pair_limit == 5
    assert cfg.dataset.candidate_pair_limit >= 5
    assert cfg.dataset.require_validated_pair_both_sides is True
    assert cfg.dataset.validation_candidate_stream_until_valid_pairs is True
    assert cfg.api_quota.provider_header_probe == "off"
    assert cfg.model.model_name == "qwen3.5-397b-a17b"


def test_five_pair_qwen_config_is_small_first_and_uses_repo_inventory():
    cfg = load_config("configs/32_five_pair_academiccloud_qwen397b.yaml")
    assert cfg.dataset.validation_candidate_order == "dataset_smallest_first"
    assert cfg.dataset.candidate_pair_limit >= 50
    assert cfg.dataset.validation_candidate_use_repo_inventory is True
    assert cfg.dataset.validation_candidate_one_pair_per_project is True
    assert cfg.dataset.validation_candidate_stream_until_valid_pairs is True
    assert cfg.api_quota.provider_header_probe == "off"


def test_cached_inventory_qwen_config_uses_persistent_pair_cache_and_no_probe():
    cfg = load_config("configs/34_five_pair_cached_inventory_qwen397b.yaml")
    assert cfg.dataset.validation_candidate_use_repo_inventory is True
    assert cfg.dataset.validation_candidate_require_repo_inventory_usable is True
    assert cfg.dataset.validation_candidate_stream_until_valid_pairs is True
    assert cfg.dataset.validation_candidate_one_pair_per_project is True
    assert cfg.dataset.validation_candidate_order == "cached_smallest_first"
    assert cfg.dataset.use_cached_pair_candidates is True
    assert cfg.dataset.pair_candidate_cache_path.endswith("pair_candidates_smallest_first.jsonl")
    assert cfg.repo.partial_clone is False
    assert cfg.repo.use_existing_mirror is True
    assert cfg.repo.clone_if_missing is False
    assert cfg.api_quota.provider_header_probe == "off"
    assert cfg.validation_cache.enabled is True
    assert cfg.validation_cache.reuse_negative_results is True
