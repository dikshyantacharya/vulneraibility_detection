from __future__ import annotations

from vuln_commit_kg.data.schema import SecVulEvalSample
from vuln_commit_kg.kg.graph_store import KGNode, ProjectGraph
from vuln_commit_kg.utils.text import similarity


class TargetLocator:
    def locate(self, graph: ProjectGraph, sample: SecVulEvalSample) -> tuple[KGNode | None, dict]:
        funcs = graph.nodes_of_type("Function")
        candidates = []
        for node in funcs:
            props = node.properties
            name_ok = sample.func_name and props.get("name") == sample.func_name
            path_ok = sample.filepath and props.get("relpath") == sample.filepath
            if name_ok and path_ok:
                candidates.append((1.0, node, "name_path"))
            elif name_ok:
                candidates.append((0.7, node, "name_only"))
        if candidates:
            candidates.sort(key=lambda x: x[0], reverse=True)
            node = candidates[0][1]
            return node, {"method": candidates[0][2], "score": candidates[0][0], "num_candidates": len(candidates)}

        # Fallback: body preview similarity.
        best = (0.0, None)
        for node in funcs:
            sim = similarity(sample.func_body, node.properties.get("body_preview", ""))
            if sim > best[0]:
                best = (sim, node)
        if best[1] is not None and best[0] > 0.4:
            return best[1], {"method": "body_similarity", "score": best[0], "num_candidates": 1}
        return None, {"method": "not_found", "score": 0.0, "num_candidates": 0}
