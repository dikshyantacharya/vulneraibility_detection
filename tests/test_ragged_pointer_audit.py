from vuln_commit_kg.agents.agent_controller import AgentController
from vuln_commit_kg.agents.schemas import AgentTrace
from vuln_commit_kg.config import AgentConfig, ModelConfig, RetrievalConfig
from vuln_commit_kg.retrieval.evidence import EvidencePack


class DummyModel:
    pass


def _controller():
    return AgentController(AgentConfig(), RetrievalConfig(), ModelConfig(backend="mock"), DummyModel(), __import__("logging").getLogger("test"))


def test_ragged_pointer_audit_detects_prefix_unsafe():
    body = """int count_rows(void * raw, int raw_length, int length_power, int big_endian,
               int itemsize) {
  IntRead read = choose_int_read(length_power, big_endian);
  int rows = 0;
  void * end = raw + raw_length;
  while (raw <= end - (1 << length_power)) {
    uint64_t length = read(raw);
    raw += (1 << length_power);
    raw += length * itemsize;
    rows ++;
  }
  if (raw == end) return rows;
  return -1;
}"""
    audit = _controller()._source_ragged_pointer_audit_from_text(body)
    assert audit["present"] is True
    assert audit["verdict"] == "unsafe"
    assert "raw >= start" in audit["missing_facts"][0]


def test_ragged_pointer_audit_detects_postfix_safe_and_validator_enforces():
    body = """int count_rows(void * raw, int raw_length, int length_power, int big_endian,
               int itemsize) {
  IntRead read = choose_int_read(length_power, big_endian);
  int rows = 0;
  void * start = raw;
  void * end = raw + raw_length;
  while (raw <= end - (1 << length_power) && raw >= start) {
    uint64_t length = read(raw);
    raw += (1 << length_power);
    raw += length * itemsize;
    rows ++;
  }
  if (raw == end) return rows;
  return -1;
}"""
    c = _controller()
    trace = AgentTrace(sample_id="x", mode="iterative")
    evidence = EvidencePack(sample_id="x", summary="", items=[])
    trace.hypothesis_ledger.append({"stage": "source_snapshot_ragged_pointer_audit", "ragged_pointer_audit": c._source_ragged_pointer_audit_from_text(body)})
    data, notes = c._apply_source_ragged_pointer_contract({"is_vulnerable": True, "confidence": 0.75, "vuln_statements": []}, evidence, trace)
    assert data["decision_status"] == "non_vulnerable"
    assert data["is_vulnerable"] is False
    assert notes
