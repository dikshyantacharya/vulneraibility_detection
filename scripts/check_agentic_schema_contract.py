from __future__ import annotations
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from vckg_agentic_proof.parser import parse_json_answer
from vckg_agentic_proof.schemas import FinalDecision
GOOD = '<analysis>brief public audit</analysis><answer>{"prediction":"fixed/non-vulnerable","prediction_bool":false,"confidence":0.8,"local_risk_present":true,"confirmed_security_vulnerability":false,"final_hypothesis_statuses":[],"minimum_vulnerability_proof":null,"decisive_evidence_ids":[],"decisive_counter_evidence_ids":[],"explanation":"Suspicious code exists, but proof is incomplete.","limitations":[]}</answer>'
def main():
    parsed = parse_json_answer(GOOD)
    obj = FinalDecision.model_validate(parsed.parsed).normalize_prediction_bool()
    print("schema_ok")
    print(json.dumps(obj.model_dump(mode="json"), indent=2))
if __name__ == "__main__": main()
