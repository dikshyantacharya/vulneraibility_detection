from __future__ import annotations
import json, time
from pathlib import Path
from typing import Any, Dict
class LiveEventWriter:
    def __init__(self, run_dir: str | Path):
        self.run_dir = Path(run_dir); self.seq = 0
        self.events_path = self.run_dir / "live_dashboard" / "agent_events.jsonl"
        self.state_path = self.run_dir / "live_dashboard" / "agent_state.json"
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
    def write(self, event: Dict[str, Any]) -> None:
        self.seq += 1
        row = {"seq": self.seq, "time": time.time(), **event}
        with self.events_path.open("a", encoding="utf-8") as f: f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
        tmp = self.state_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"latest_seq": self.seq, "latest_event": row}, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        tmp.replace(self.state_path)
