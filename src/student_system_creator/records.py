from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from vuln_commit_kg.data.schema import SecVulEvalSample
from vuln_commit_kg.repos.commit_resolver import CommitResolution


@dataclass
class ChallengeRecord:
    sample_id: str
    project: str
    project_url: str | None
    repo_key: str
    filepath: str
    function_name: str
    function: str
    vulnerability: int
    dataset_commit: str | None
    resolved_commit: str
    resolved_label: str | None
    target_status: str | None
    target_similarity: float | None
    knowledge_graph_id: str
    graph_dir: str
    dashboard_path: str | None = None
    split: str = "train"
    cve_list: list[str] | None = None
    cwe_list: list[str] | None = None

    def public_row(self, *, include_label: bool, include_metadata: bool = False) -> dict[str, Any]:
        row: dict[str, Any] = {
            "sample_id": self.sample_id,
            "function_name": self.function_name,
            "function": self.function,
            "knowledge_graph_id": self.knowledge_graph_id,
        }
        if include_label:
            row["vulnerability"] = int(self.vulnerability)
        if include_metadata:
            row.update({
                "project": self.project,
                "filepath": self.filepath,
                "cwe_list": ";".join(self.cwe_list or []),
                "cve_list": ";".join(self.cve_list or []),
            })
        return row

    def private_row(self) -> dict[str, Any]:
        return asdict(self)


def make_kg_id(sample: SecVulEvalSample, repo_key: str, resolved_commit: str) -> str:
    from vuln_commit_kg.utils.hashing import safe_name, stable_hash

    base = "__".join([
        safe_name(sample.project or "project", 32),
        safe_name(repo_key, 24),
        safe_name((resolved_commit or sample.commit_id or "commit")[:12], 16),
        safe_name(sample.func_name or "function", 40),
        "vuln" if sample.is_vulnerable else "safe",
    ])
    suffix = stable_hash({
        "sample_id": sample.sample_id,
        "project": sample.project,
        "repo_key": repo_key,
        "commit": resolved_commit,
        "file": sample.filepath,
        "function": sample.func_name,
        "label": bool(sample.is_vulnerable),
    }, 10)
    return f"kg_{base}_{suffix}"
