from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from .sample_selector import find_vulnerable_fixed_pairs


def read_pair_candidate_cache(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    rows=[]
    if not p.exists():
        return rows
    for line in p.read_text(encoding='utf-8').splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def write_pair_candidate_cache(samples, cfg, cache_dir: str | Path, inventory_rows=None) -> dict[str, Any]:
    out_dir = Path(cache_dir); out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / 'pair_candidates_smallest_first.jsonl'
    pairs = find_vulnerable_fixed_pairs(samples, cfg)
    with path.open('w', encoding='utf-8') as f:
        for rank, p in enumerate(pairs, start=1):
            f.write(json.dumps({
                'rank': rank, 'project': p.project, 'project_url': p.project_url,
                'vulnerable_idx': p.vulnerable_idx, 'fixed_idx': p.fixed_idx,
                'vulnerable_sample_id': str(p.vulnerable_idx), 'fixed_sample_id': str(p.fixed_idx),
                'filepath': p.filepath, 'func_name': p.func_name,
                'patch_commit_id': p.patch_commit_id,
            }) + '\n')
    return {'path': str(path), 'pairs': len(pairs)}
