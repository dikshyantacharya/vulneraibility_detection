from __future__ import annotations

import csv
import json
import shutil
import textwrap
from pathlib import Path
from typing import Any

from .config import ChallengeCreatorConfig
from .records import ChallengeRecord


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def make_registry(records: list[ChallengeRecord], *, root: Path, private_dir: Path) -> dict[str, Any]:
    entries = {}
    for rec in records:
        graph_dir = Path(rec.graph_dir)
        try:
            graph_dir_value = graph_dir.relative_to(private_dir).as_posix()
        except Exception:
            graph_dir_value = str(graph_dir)
        entries[rec.knowledge_graph_id] = {
            "knowledge_graph_id": rec.knowledge_graph_id,
            "sample_id": rec.sample_id,
            "project": rec.project,
            "project_url": rec.project_url,
            "repo_key": rec.repo_key,
            "filepath": rec.filepath,
            "function_name": rec.function_name,
            "split": rec.split,
            "label": int(rec.vulnerability),
            "dataset_commit": rec.dataset_commit,
            "resolved_commit": rec.resolved_commit,
            "resolved_label": rec.resolved_label,
            "target_status": rec.target_status,
            "target_similarity": rec.target_similarity,
            "graph_dir": graph_dir_value,
            "dashboard_path": str(Path(graph_dir_value) / "dashboard" / "index.html") if not Path(graph_dir_value).is_absolute() else str(Path(graph_dir_value) / "dashboard" / "index.html"),
            "cve_list": rec.cve_list or [],
            "cwe_list": rec.cwe_list or [],
        }
    return {
        "schema_version": 1,
        "description": "Private registry mapping public knowledge_graph_id values to CodeKG artifacts and hidden labels.",
        "entries": entries,
    }


def write_challenge_outputs(*, root: Path, cfg: ChallengeCreatorConfig, train: list[ChallengeRecord], test: list[ChallengeRecord], all_records: list[ChallengeRecord]) -> None:
    public_dir = root / "public"
    private_dir = root / "private"
    raid_dir = root / "raid"
    include_meta = bool(cfg.output.include_public_metadata)

    train_rows = [r.public_row(include_label=True, include_metadata=include_meta) for r in train]
    test_rows = [r.public_row(include_label=False, include_metadata=include_meta) for r in test]
    labels_rows = [{"sample_id": r.sample_id, "knowledge_graph_id": r.knowledge_graph_id, "vulnerability": int(r.vulnerability)} for r in test]
    sample_sub_rows = [{"sample_id": r.sample_id, "prediction": 0} for r in test]

    write_csv(public_dir / "train.csv", train_rows)
    write_csv(public_dir / "test.csv", test_rows)
    write_csv(public_dir / "sample_submission.csv", sample_sub_rows)
    write_csv(private_dir / "test_labels.csv", labels_rows)
    write_json(private_dir / "kg_registry_private.json", make_registry(all_records, root=root, private_dir=private_dir))
    write_json(private_dir / "dataset_manifest.json", {
        "schema_version": 1,
        "challenge_name": cfg.output.challenge_name,
        "train_rows": len(train),
        "test_rows": len(test),
        "total_records": len(all_records),
        "test_projects": len({r.repo_key for r in test}),
        "train_projects": len({r.repo_key for r in train}),
        "test_vulnerable": sum(1 for r in test if r.vulnerability == 1),
        "test_non_vulnerable": sum(1 for r in test if r.vulnerability == 0),
        "train_vulnerable": sum(1 for r in train if r.vulnerability == 1),
        "train_non_vulnerable": sum(1 for r in train if r.vulnerability == 0),
        "agent_limits": cfg.api.model_dump(mode="json"),
    })
    write_json(root / "build_summary.json", {
        "challenge_root": str(root),
        "public_dir": str(public_dir),
        "private_dir": str(private_dir),
        "raid_dir": str(raid_dir),
        "train_rows": len(train),
        "test_rows": len(test),
    })
    write_student_readme(public_dir / "README.md", cfg)
    write_student_kit(public_dir / "student_kit", cfg)
    if cfg.output.make_raid_bundle:
        write_raid_bundle(raid_dir, public_dir, private_dir, cfg)


def write_student_readme(path: Path, cfg: ChallengeCreatorConfig) -> None:
    text = f"""
# VCKG CodeKG Vulnerability Challenge - Student Package

You receive `train.csv` with labels and `test.csv` without labels.

## Your goal

For every row, predict whether the target function is vulnerable (`1`) or not vulnerable (`0`).
The source code of the target function is provided in the CSV, and the project-level Code Knowledge Graph is available through the challenge API using `knowledge_graph_id`.

## Files

- `train.csv`: training rows with labels.
- `test.csv`: final rows without labels.
- `sample_submission.csv`: expected submission shape.
- `student_kit/solution.py`: starter agent.
- `student_kit/kg_client.py`: helper for KG API requests.
- `student_kit/llm_client.py`: optional helper for OpenAI-compatible LLM API calls.

Columns:

- `sample_id`: unique challenge row id.
- `function_name`: target function name.
- `function`: target function source text from the benchmark row.
- `knowledge_graph_id`: id of the server-side Code Knowledge Graph snapshot.
- `vulnerability`: only in train; `1` means vulnerable and `0` means not vulnerable.

## Submission contract

Submit a single `solution.py` file exposing:

```python
def build_agent(config: dict):
    return MyAgent(config)
```

The returned agent must implement:

```python
def step(self, sample: dict, observation: dict, budget: dict) -> dict:
    ...
```

The evaluator controls the recursive loop. Your agent returns either KG queries:

```python
{{
    "action": "query",
    "reason": "why this evidence is needed",
    "queries": [
        {{"kind": "security_context", "target_function": sample["function_name"], "max_nodes": 400}}
    ],
}}
```

or a final prediction:

```python
{{"action": "final", "prediction": 0 or 1, "confidence": 0.0-1.0, "reason": "..."}}
```

## Limits enforced by the evaluator/API

- max rounds: {cfg.api.max_rounds}
- max KG queries per round: {cfg.api.max_queries_per_round}
- max KG queries per sample: {cfg.api.max_queries_per_sample}
- max nodes per query: {cfg.api.max_nodes_per_query}

Allowed query kinds:

{chr(10).join('- ' + k for k in cfg.api.allowed_query_kinds)}

Recommended first-pass query:

```python
{{
    "kind": "security_context",
    "target_function": sample["function_name"],
    "depth": 3,
    "call_depth": 2,
    "data_depth": 3,
    "include_headers": True,
    "include_globals": True,
    "include_joern": True,
    "max_nodes": 400,
}}
```

Use `evidence_slice` when you know a suspicious statement/expression, `variable_flow` for suspicious symbols, `call_neighborhood` for callers/callees, and `semantic_facts` for deterministic security facts.

## Optional LLM use

You may implement your agent with rules or with an LLM. The starter kit includes `llm_client.py` for OpenAI-compatible APIs. Set environment variables such as:

```bash
export OPENAI_BASE_URL="https://your-llm-endpoint/v1"
export OPENAI_API_KEY="..."
export OPENAI_MODEL="..."
```

Do not rely on labels from `test.csv`; they are hidden during final evaluation.
"""
    path.write_text(textwrap.dedent(text).strip() + "\n", encoding="utf-8")



STUDENT_KG_CLIENT_TEMPLATE = r"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import requests


class KGClient:
    def __init__(self, api_base: Optional[str] = None, timeout_seconds: int = 30):
        self.api_base = (api_base or os.environ.get("KG_API_BASE") or "http://127.0.0.1:8000").rstrip("/")
        self.timeout_seconds = int(timeout_seconds)

    def query(self, knowledge_graph_id: str, query: Dict[str, Any]) -> Dict[str, Any]:
        if not knowledge_graph_id:
            raise ValueError("knowledge_graph_id is required")
        if not isinstance(query, dict):
            raise TypeError("query must be a dictionary")
        url = f"{self.api_base}/api/v1/kgs/{knowledge_graph_id}/query"
        response = requests.post(url, json=query, timeout=self.timeout_seconds)
        response.raise_for_status()
        return response.json()

    def function_context(
        self,
        knowledge_graph_id: str,
        target_function: str,
        depth: int = 2,
        max_nodes: int = 300,
    ) -> Dict[str, Any]:
        return self.query(
            knowledge_graph_id,
            {
                "kind": "function_context",
                "target_function": target_function,
                "depth": depth,
                "max_nodes": max_nodes,
            },
        )

    def security_context(
        self,
        knowledge_graph_id: str,
        target_function: str,
        depth: int = 3,
        call_depth: int = 2,
        data_depth: int = 3,
        max_nodes: int = 400,
    ) -> Dict[str, Any]:
        return self.query(
            knowledge_graph_id,
            {
                "kind": "security_context",
                "target_function": target_function,
                "depth": depth,
                "call_depth": call_depth,
                "data_depth": data_depth,
                "include_callers": True,
                "include_headers": True,
                "include_globals": True,
                "include_joern": True,
                "max_nodes": max_nodes,
            },
        )

    def semantic_facts(
        self,
        knowledge_graph_id: str,
        target_function: str,
        max_nodes: int = 250,
    ) -> Dict[str, Any]:
        return self.query(
            knowledge_graph_id,
            {
                "kind": "semantic_facts",
                "target_function": target_function,
                "max_nodes": max_nodes,
            },
        )

    def evidence_slice(
        self,
        knowledge_graph_id: str,
        target_function: str,
        target_statement: Optional[str] = None,
        relation_depth: int = 3,
        data_depth: int = 3,
        control_depth: int = 2,
        call_depth: int = 2,
        max_nodes: int = 350,
    ) -> Dict[str, Any]:
        query = {
            "kind": "evidence_slice",
            "target_function": target_function,
            "relation_depth": relation_depth,
            "data_depth": data_depth,
            "control_depth": control_depth,
            "call_depth": call_depth,
            "include_defs": True,
            "include_uses": True,
            "include_guards": True,
            "include_callees": True,
            "include_headers": True,
            "include_globals": True,
            "include_joern": True,
            "max_nodes": max_nodes,
        }
        if target_statement:
            query["target_statement"] = target_statement
        return self.query(knowledge_graph_id, query)


def make_client(config: Optional[Dict[str, Any]] = None) -> KGClient:
    config = config or {}
    return KGClient(
        api_base=config.get("kg_api_base") or config.get("api_base"),
        timeout_seconds=int(config.get("query_timeout_seconds", 30)),
    )
"""




STUDENT_LLM_CLIENT_TEMPLATE = r"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import requests


class LLMClient:
    # Optional OpenAI-compatible LLM client for students.
    # The official evaluator does not require an LLM. Students may also
    # implement deterministic logic using only KG queries.

    def __init__(
        self,
        api_base: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout_seconds: int = 60,
    ):
        self.api_base = (api_base or os.environ.get("OPENAI_BASE_URL") or "").rstrip("/")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY") or ""
        self.model = model or os.environ.get("OPENAI_MODEL") or ""
        self.timeout_seconds = int(timeout_seconds)

    def available(self) -> bool:
        return bool(self.api_base and self.api_key and self.model)

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.0,
        max_tokens: int = 800,
    ) -> str:
        if not self.available():
            raise RuntimeError(
                "LLMClient is not configured. Set OPENAI_BASE_URL, OPENAI_API_KEY, and OPENAI_MODEL."
            )

        url = f"{self.api_base}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        response = requests.post(url, headers=headers, json=payload, timeout=self.timeout_seconds)
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]


def make_llm_client(config: Optional[Dict[str, Any]] = None) -> LLMClient:
    config = config or {}
    return LLMClient(
        api_base=config.get("llm_api_base") or config.get("openai_base_url"),
        api_key=config.get("llm_api_key") or config.get("openai_api_key"),
        model=config.get("llm_model") or config.get("model"),
        timeout_seconds=int(config.get("llm_timeout_seconds", 60)),
    )
"""

def write_student_kit(path: Path, cfg: ChallengeCreatorConfig) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "solution.py").write_text(STUDENT_SOLUTION_TEMPLATE, encoding="utf-8")
    (path / "kg_client.py").write_text(STUDENT_KG_CLIENT_TEMPLATE, encoding="utf-8")
    (path / "llm_client.py").write_text(STUDENT_LLM_CLIENT_TEMPLATE, encoding="utf-8")
    (path / "requirements.txt").write_text("requests>=2.31\n", encoding="utf-8")
    (path / "README.md").write_text(textwrap.dedent("""
    # Student Kit

    Implement `solution.py` and submit that file.

    The evaluator calls:

    ```python
    agent = build_agent(config)
    action = agent.step(sample, observation, budget)
    ```

    Your `step` method may request KG evidence by returning `action="query"`, or stop with `action="final"`.
    You do not call the KG API directly inside `solution.py` during official evaluation; the evaluator executes your requested queries and passes the returned evidence back in `observation`.

    `kg_client.py` is provided only for your own local experiments against the development KG API.
    `llm_client.py` is optional and supports OpenAI-compatible chat-completion APIs.
    """).strip() + "\n", encoding="utf-8")


def write_raid_bundle(raid_dir: Path, public_dir: Path, private_dir: Path, cfg: ChallengeCreatorConfig) -> None:
    raid_dir.mkdir(parents=True, exist_ok=True)
    data_dir = raid_dir / "data"
    data_dir.mkdir(exist_ok=True)
    shutil.copy2(public_dir / "train.csv", data_dir / "train.csv")
    shutil.copy2(public_dir / "test.csv", data_dir / "test.csv")
    shutil.copy2(public_dir / "sample_submission.csv", data_dir / "sample_submission.csv")
    # Private files are copied only into the organizer RAID bundle. They are used
    # by the API service container, not by the student evaluator container.
    if (private_dir / "kg_registry_private.json").exists():
        (raid_dir / "private").mkdir(exist_ok=True)
        shutil.copy2(private_dir / "kg_registry_private.json", raid_dir / "private" / "kg_registry_private.json")
        shutil.copy2(private_dir / "test_labels.csv", raid_dir / "private" / "test_labels.csv")
        if (private_dir / "kg_store").exists():
            dst = raid_dir / "private" / "kg_store"
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(private_dir / "kg_store", dst)
    (raid_dir / "solution.py").write_text(STUDENT_SOLUTION_TEMPLATE, encoding="utf-8")
    (raid_dir / "evaluate.py").write_text(EVALUATE_TEMPLATE, encoding="utf-8")
    (raid_dir / "api_client.py").write_text(API_CLIENT_TEMPLATE, encoding="utf-8")
    (raid_dir / "Dockerfile").write_text(DOCKERFILE_EVALUATOR, encoding="utf-8")
    (raid_dir / "Dockerfile.api").write_text(DOCKERFILE_API, encoding="utf-8")
    (raid_dir / "docker-compose.yml").write_text(DOCKER_COMPOSE, encoding="utf-8")
    (raid_dir / "build.sh").write_text("#!/bin/bash\ndocker compose build\n", encoding="utf-8")
    (raid_dir / "run.sh").write_text("#!/bin/bash\ndocker compose up --abort-on-container-exit --exit-code-from evaluator\n", encoding="utf-8")
    (raid_dir / "requirements.txt").write_text("requests>=2.31\n", encoding="utf-8")


STUDENT_SOLUTION_TEMPLATE = r'''from __future__ import annotations

from typing import Any


class StudentAgent:
    """Starter agent.

    Replace the heuristics with your own LLM-driven or rule-based strategy.
    The evaluator, not this file, controls the recursion and KG-query budget.
    """

    def __init__(self, config: dict[str, Any]):
        self.config = config

    def step(self, sample: dict[str, Any], observation: dict[str, Any], budget: dict[str, Any]) -> dict[str, Any]:
        fn = sample["function_name"]
        evidence_text = str(observation.get("evidence", [])).lower()

        if budget.get("force_final"):
            return self._final(evidence_text, "Forced final because query budget ended.")

        if budget["round"] == 1:
            return {
                "action": "query",
                "reason": "Start with broad security context and deterministic semantic facts.",
                "queries": [
                    {
                        "kind": "security_context",
                        "target_function": fn,
                        "depth": 3,
                        "call_depth": 2,
                        "data_depth": 3,
                        "include_headers": True,
                        "include_globals": True,
                        "include_joern": True,
                        "max_nodes": 400,
                        "risk_terms": ["pointer", "array", "bounds", "size", "copy", "read", "write", "allocation", "free", "null", "overflow", "guard"],
                    },
                    {"kind": "semantic_facts", "target_function": fn},
                ],
            }

        if any(t in evidence_text for t in ["overflow", "multiply", "allocation size", "bounds"]):
            return {
                "action": "query",
                "reason": "Potential size/bounds issue; inspect a focused evidence slice.",
                "queries": [
                    {
                        "kind": "evidence_slice",
                        "target_function": fn,
                        "target_statement": "size",
                        "relation_depth": 4,
                        "data_depth": 4,
                        "control_depth": 3,
                        "include_defs": True,
                        "include_uses": True,
                        "include_guards": True,
                        "max_nodes": 350,
                    }
                ],
            }

        if any(t in evidence_text for t in ["pointer", "buffer", "raw"]):
            return {
                "action": "query",
                "reason": "Pointer/buffer terms appeared; inspect variable flow if a relevant symbol is present.",
                "queries": [
                    {"kind": "variable_flow", "target_function": fn, "symbol": "raw", "data_depth": 4, "max_nodes": 250}
                ],
            }

        return self._final(evidence_text, "No more useful query trigger found.")

    def _final(self, evidence_text: str, reason_prefix: str) -> dict[str, Any]:
        risk_terms = [
            "unchecked", "overflow", "out of bounds", "missing guard", "buffer overflow",
            "null dereference", "use after free", "allocation size", "pointer arithmetic",
        ]
        score = sum(1 for t in risk_terms if t in evidence_text)
        return {
            "action": "final",
            "prediction": 1 if score >= 2 else 0,
            "confidence": min(0.95, 0.50 + 0.10 * score),
            "reason": f"{reason_prefix} risk_score={score}",
        }


def build_agent(config: dict[str, Any]) -> StudentAgent:
    return StudentAgent(config)
'''

API_CLIENT_TEMPLATE = r'''from __future__ import annotations

import json
import urllib.request
from typing import Any


class KGClient:
    def __init__(self, api_base: str, api_key: str | None = None, timeout: int = 60):
        self.api_base = api_base.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def query(self, kg_id: str, query: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.api_base}/api/v1/kgs/{kg_id}/query"
        data = json.dumps(query).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
'''

EVALUATE_TEMPLATE = r'''from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from api_client import KGClient


LIMITS = {
    "max_rounds": int(os.getenv("MAX_ROUNDS", "5")),
    "max_queries_per_round": int(os.getenv("MAX_QUERIES_PER_ROUND", "2")),
    "max_queries_per_sample": int(os.getenv("MAX_QUERIES_PER_SAMPLE", "8")),
    "max_nodes_per_query": int(os.getenv("MAX_NODES_PER_QUERY", "500")),
    "timeout_per_sample_seconds": int(os.getenv("TIMEOUT_PER_SAMPLE_SECONDS", "120")),
    "allowed_query_kinds": set(os.getenv("ALLOWED_QUERY_KINDS", "security_context,evidence_slice,function_context,call_neighborhood,variable_flow,semantic_facts,file_context,shortest_path").split(",")),
}


def read_csv(path: str | Path) -> list[dict[str, str]]:
    with Path(path).open("r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: str | Path, rows: list[dict[str, Any]]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["sample_id", "prediction"])
        writer.writeheader()
        writer.writerows(rows)


def load_solution(path: str | Path):
    spec = importlib.util.spec_from_file_location("student_solution", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load solution: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["student_solution"] = module
    spec.loader.exec_module(module)
    if not hasattr(module, "build_agent"):
        raise RuntimeError("solution.py must define build_agent(config)")
    return module.build_agent


def validate_query(q: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(q, dict):
        raise ValueError("query must be a dict")
    kind = str(q.get("kind") or "")
    if kind not in LIMITS["allowed_query_kinds"]:
        raise ValueError(f"unsupported query kind: {kind}")
    q = dict(q)
    if "max_nodes" in q:
        q["max_nodes"] = min(int(q["max_nodes"]), LIMITS["max_nodes_per_query"])
    else:
        q["max_nodes"] = LIMITS["max_nodes_per_query"]
    return q


def validate_final(action: dict[str, Any]) -> dict[str, Any]:
    pred = int(action.get("prediction", 0))
    pred = 1 if pred == 1 else 0
    try:
        confidence = float(action.get("confidence", 0.0))
    except Exception:
        confidence = 0.0
    return {
        "prediction": pred,
        "confidence": max(0.0, min(1.0, confidence)),
        "reason": str(action.get("reason") or "")[:1000],
    }


def run_agent_for_sample(agent, sample: dict[str, Any], kg_client: KGClient) -> dict[str, Any]:
    start = time.time()
    evidence: list[dict[str, Any]] = []
    query_history: list[dict[str, Any]] = []
    used_queries = 0

    for round_id in range(1, LIMITS["max_rounds"] + 1):
        if time.time() - start > LIMITS["timeout_per_sample_seconds"]:
            break
        budget = {
            "round": round_id,
            "max_rounds": LIMITS["max_rounds"],
            "used_queries": used_queries,
            "remaining_queries": LIMITS["max_queries_per_sample"] - used_queries,
            "max_queries_per_round": LIMITS["max_queries_per_round"],
            "max_nodes_per_query": LIMITS["max_nodes_per_query"],
            "allowed_query_kinds": sorted(LIMITS["allowed_query_kinds"]),
        }
        observation = {"round": round_id - 1, "evidence": evidence, "query_history": query_history}
        action = agent.step(sample, observation, budget)
        if not isinstance(action, dict):
            raise RuntimeError("agent.step must return a dict")
        if action.get("action") == "final":
            return validate_final(action)
        if action.get("action") != "query":
            raise RuntimeError("agent action must be 'query' or 'final'")
        queries = list(action.get("queries") or [])[: LIMITS["max_queries_per_round"]]
        if not queries:
            break
        for query in queries:
            if used_queries >= LIMITS["max_queries_per_sample"]:
                break
            safe_query = validate_query(query)
            result = kg_client.query(sample["knowledge_graph_id"], safe_query)
            compact = {
                "query": safe_query,
                "reason": str(action.get("reason") or ""),
                "result": result,
            }
            evidence.append(compact)
            query_history.append({"round": round_id, "query": safe_query, "reason": action.get("reason", "")})
            used_queries += 1
        if used_queries >= LIMITS["max_queries_per_sample"]:
            break

    forced = agent.step(
        sample,
        {"round": LIMITS["max_rounds"], "evidence": evidence, "query_history": query_history},
        {"force_final": True, "remaining_queries": 0, "round": LIMITS["max_rounds"], **LIMITS},
    )
    if isinstance(forced, dict) and forced.get("action") == "final":
        return validate_final(forced)
    return {"prediction": 0, "confidence": 0.0, "reason": "No final answer within budget."}


def score(labels_path: Path, prediction_rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not labels_path.exists():
        return {"score_available": False}
    labels = {r["sample_id"]: int(r["vulnerability"]) for r in read_csv(labels_path)}
    y_pred = {str(r["sample_id"]): int(r["prediction"]) for r in prediction_rows}
    ids = [sid for sid in labels if sid in y_pred]
    tp = sum(1 for sid in ids if labels[sid] == 1 and y_pred[sid] == 1)
    tn = sum(1 for sid in ids if labels[sid] == 0 and y_pred[sid] == 0)
    fp = sum(1 for sid in ids if labels[sid] == 0 and y_pred[sid] == 1)
    fn = sum(1 for sid in ids if labels[sid] == 1 and y_pred[sid] == 0)
    acc = (tp + tn) / len(ids) if ids else 0.0
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"score_available": True, "n": len(ids), "accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "tp": tp, "tn": tn, "fp": fp, "fn": fn}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--solution", default="solution.py")
    parser.add_argument("--train", default="data/train.csv")
    parser.add_argument("--input", default="data/test.csv")
    parser.add_argument("--labels", default="private/test_labels.csv")
    parser.add_argument("--output", default="predictions.csv")
    parser.add_argument("--api-base", default=os.getenv("KG_API_BASE", "http://kg_api:8000"))
    parser.add_argument("--api-key", default=os.getenv("KG_API_KEY", "dev-key-KG"))
    args = parser.parse_args()

    build_agent = load_solution(args.solution)
    train_rows = read_csv(args.train) if Path(args.train).exists() else []
    test_rows = read_csv(args.input)
    agent = build_agent({"train_rows": train_rows, "limits": {k: (sorted(v) if isinstance(v, set) else v) for k, v in LIMITS.items()}})
    if hasattr(agent, "fit"):
        agent.fit(train_rows)
    client = KGClient(args.api_base, args.api_key)
    out_rows = []
    for row in test_rows:
        ans = run_agent_for_sample(agent, row, client)
        out_rows.append({
            "sample_id": row["sample_id"],
            "prediction": int(ans["prediction"]),
            "confidence": ans.get("confidence", 0.0),
            "reason": ans.get("reason", ""),
        })
    write_csv(args.output, out_rows)
    metrics = score(Path(args.labels), out_rows)
    Path("score.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print("score:", json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
'''

DOCKERFILE_EVALUATOR = '''FROM python:3.11-slim
WORKDIR /work
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY data data/
COPY evaluate.py api_client.py solution.py ./
CMD ["python", "evaluate.py"]
'''

DOCKERFILE_API = '''FROM python:3.11-slim
WORKDIR /work
COPY private private/
# The full project package is not copied into this tiny template. For local RAID
# packaging, build this image from the project root or install the wheel first.
# In the generated full project ZIP, run the API directly with Python instead.
CMD ["python", "-m", "http.server", "8000"]
'''

DOCKER_COMPOSE = '''services:
  # Recommended production mode: run the KG API from the full VCKG project on the host
  # and set KG_API_BASE for evaluator. This compose file keeps the RAID template shape.
  evaluator:
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      KG_API_BASE: ${KG_API_BASE:-http://host.docker.internal:8000}
      KG_API_KEY: ${KG_API_KEY:-dev-key-KG}
      MAX_ROUNDS: ${MAX_ROUNDS:-5}
      MAX_QUERIES_PER_ROUND: ${MAX_QUERIES_PER_ROUND:-2}
      MAX_QUERIES_PER_SAMPLE: ${MAX_QUERIES_PER_SAMPLE:-8}
      MAX_NODES_PER_QUERY: ${MAX_NODES_PER_QUERY:-500}
'''
