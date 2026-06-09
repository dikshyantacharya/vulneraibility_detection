# Student System Creator

This folder adds a university/student challenge layer on top of the existing VCKG + CodeKG project.

It creates:

- public `train.csv` with labels;
- public `test.csv` without labels;
- `sample_submission.csv`;
- private `test_labels.csv`;
- private `kg_registry_private.json` mapping `knowledge_graph_id` to CodeKG graph artifacts;
- optional private self-contained `kg_store/` copied from `cache/kg`;
- a bounded KG retrieval API;
- a recursive evaluator that runs student `solution.py` through a fixed agent loop;
- a RAID-style bundle with evaluator template and student starter solution.

## Build the challenge

From the main project root:

```powershell
pip install -e .
student-system-creator build --config student_system_creator/configs/default.yaml
```

Output:

```text
outputs/student_challenge/vckg_codekg_student_challenge/
  public/
    train.csv
    test.csv
    sample_submission.csv
    README.md
    student_kit/
  private/
    test_labels.csv
    kg_registry_private.json
    kg_store/
  raid/
    Dockerfile
    evaluate.py
    solution.py
    data/train.csv
    data/test.csv
    private/kg_registry_private.json
```

## Start the private KG retrieval API

```powershell
student-system-creator serve `
  --registry outputs/student_challenge/vckg_codekg_student_challenge/private/kg_registry_private.json `
  --host 127.0.0.1 `
  --port 8000
```

Health check:

```powershell
curl http://127.0.0.1:8000/health
```

## Run a student solution locally

```powershell
student-system-creator evaluate `
  --solution outputs/student_challenge/vckg_codekg_student_challenge/public/student_kit/solution.py `
  --train outputs/student_challenge/vckg_codekg_student_challenge/public/train.csv `
  --input outputs/student_challenge/vckg_codekg_student_challenge/public/test.csv `
  --labels outputs/student_challenge/vckg_codekg_student_challenge/private/test_labels.csv `
  --api-base http://127.0.0.1:8000 `
  --out outputs/student_eval/demo
```

## Student `solution.py` contract

Students submit a `solution.py` file exposing:

```python
def build_agent(config: dict):
    return MyAgent(config)
```

The agent must implement:

```python
def step(self, sample: dict, observation: dict, budget: dict) -> dict:
    ...
```

At each recursive step, the student returns either a query action:

```python
{
  "action": "query",
  "reason": "Need pointer-flow evidence",
  "queries": [
    {"kind": "variable_flow", "target_function": sample["function_name"], "symbol": "raw"}
  ]
}
```

or a final answer:

```python
{"action": "final", "prediction": 1, "confidence": 0.82, "reason": "..."}
```

The evaluator controls the loop and enforces max rounds / query budget.

## Why this is safe and fair

Students can design dynamic LLM agents, but the platform controls:

- max reasoning rounds;
- max queries per round;
- max queries per function;
- allowed KG query kinds;
- max nodes per query;
- timeout per sample;
- hidden test labels;
- private graph registry.

The KG API never returns the vulnerability label.

## Smoke testing after installation

Use dry-run first. This must not create worktrees or build KGs:

```powershell
student-system-creator build --config student_system_creator/configs/default.yaml --dry-run --limit 20 --overwrite
```

Then run a very small structural build without Joern, useful for checking the RAID/public/private folder generation quickly:

```powershell
student-system-creator build --config student_system_creator/configs/default.yaml --limit 4 --backend heuristic --overwrite
```

Then run a small production-style build using the config backend, usually `auto`:

```powershell
student-system-creator build --config student_system_creator/configs/default.yaml --limit 20 --overwrite
```
