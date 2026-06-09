from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator


class InputConfig(BaseModel):
    dataset_path: str = "data/raw/sec_vul_eval-train.arrow"
    dataset_mode: str = "file"
    base_vckg_config: str | None = "configs/45_curriculum_1_function_agentic_proof_qwen397b.yaml"
    repo_inventory_dir: str = "cache/repo_inventory"
    require_repo_inventory_usable: bool = False
    use_pair_candidate_cache: bool = True
    pair_candidate_cache_path: str = "cache/repo_inventory/pair_candidates_smallest_first.jsonl"
    clone_if_missing: bool = False
    # Optional override. Keep null to reuse the VCKG config worktree directory.
    # On Windows a very short path such as C:/vckg_wt or cache/wt may reduce
    # Filename-too-long failures for large repositories.
    worktree_dir: str | None = None
    git_timeout_seconds: int = 180


class SelectionConfig(BaseModel):
    seed: int = 42
    skip_projects: list[str] = Field(default_factory=list)
    skip_project_patterns: list[str] = Field(default_factory=lambda: [
        # These are commonly Windows-hostile or too large for classroom challenge creation.
        "chrome", "chromium", "android", "linux"
    ])
    max_projects: int | None = None
    max_functions_per_project: int = 2
    max_functions_per_label_per_project: int = 1
    prefer_validated_pair_cache: bool = True
    test_projects: int = 300
    test_functions: int = 600
    strict_test_size: bool = False
    include_projects_with_single_label_in_train: bool = True
    # Build order. Use cached inventory/stat files to try smaller projects first.
    # This makes long challenge creation useful even if interrupted early.
    order_by_project_size: bool = True
    unknown_size_last: bool = True
    body_match_threshold: float = 0.98
    min_function_chars: int = 20
    max_function_chars: int | None = None

    @field_validator("max_functions_per_project", "max_functions_per_label_per_project", "test_projects", "test_functions")
    @classmethod
    def _positive(cls, value: int) -> int:
        if value < 1:
            raise ValueError("value must be >= 1")
        return value


class KGBuildConfig(BaseModel):
    cache_dir: str = "cache/kg"
    backend: Literal["auto", "joern", "heuristic", "tree-sitter", "treesitter", "tree_sitter"] = "auto"
    joern_home: str | None = "tools/joern-cli"
    require_joern: bool = False
    joern_language: Literal["C", "CPP"] = "C"
    joern_timeout_seconds: int = 900
    force_rebuild: bool = False
    build_if_missing: bool = True
    copy_kg_artifacts: bool = True
    kg_store_mode: Literal["copy", "reference"] = "copy"


class APIConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8000
    api_key: str = "dev-key"
    require_api_key: bool = False
    max_nodes_per_query: int = 500
    max_queries_per_sample: int = 8
    max_queries_per_round: int = 2
    max_rounds: int = 5
    timeout_per_sample_seconds: int = 120
    allowed_query_kinds: list[str] = Field(default_factory=lambda: [
        "security_context", "evidence_slice", "function_context", "call_neighborhood",
        "variable_flow", "semantic_facts", "file_context", "shortest_path",
    ])


class OutputConfig(BaseModel):
    root: str = "outputs/student_challenge"
    challenge_name: str = "vckg_codekg_student_challenge"
    include_public_metadata: bool = False
    overwrite: bool = False
    make_raid_bundle: bool = True
    make_student_release_zip: bool = True
    make_organizer_private_zip: bool = False
    # Write public/private outputs periodically while building so Ctrl+C still leaves
    # a usable partial challenge package. Set to 0 to disable periodic writes.
    write_partial_every: int = 10


class ChallengeCreatorConfig(BaseModel):
    input: InputConfig = Field(default_factory=InputConfig)
    selection: SelectionConfig = Field(default_factory=SelectionConfig)
    kg: KGBuildConfig = Field(default_factory=KGBuildConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)

    @classmethod
    def load(cls, path: str | Path) -> "ChallengeCreatorConfig":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls.model_validate(data)

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(yaml.safe_dump(self.model_dump(mode="json"), sort_keys=False), encoding="utf-8")


def deep_update(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_update(out[k], v)
        else:
            out[k] = v
    return out
