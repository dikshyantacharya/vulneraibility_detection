from __future__ import annotations

from pydantic import BaseModel, Field


class EvidenceItem(BaseModel):
    evidence_id: str
    kind: str
    node_id: str | None = None
    relpath: str | None = None
    function: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    text: str
    score: float = 1.0
    scope: str | None = None
    matched_symbol: str | None = None
    match_type: str | None = None
    trust: str | None = None
    metadata: dict = Field(default_factory=dict)


class EvidencePack(BaseModel):
    sample_id: str
    dataset_commit_id: str | None = None
    resolved_commit_id: str | None = None
    resolved_commit_label: str | None = None
    target_validation_status: str | None = None
    target_validation_similarity: float | None = None
    target_node_id: str | None = None
    target_found: bool = False
    summary: str = ""
    items: list[EvidenceItem] = Field(default_factory=list)
    retrieval_diagnostics: dict = Field(default_factory=dict)

    def to_prompt_text(self, max_chars: int) -> str:
        parts = [self.summary]
        for item in self.items:
            loc = ""
            if item.relpath:
                loc = f"{item.relpath}:{item.line_start or '?'}-{item.line_end or '?'}"
            parts.append(
                f"\n[{item.evidence_id}] kind={item.kind} score={item.score:.2f} loc={loc} "
                f"scope={item.scope or 'unknown'} match={item.match_type or 'unspecified'} symbol={item.matched_symbol or ''}\n{item.text}"
            )
        text = "\n".join(parts)
        if len(text) > max_chars:
            text = text[:max_chars] + "\n... <evidence truncated>"
        return text
