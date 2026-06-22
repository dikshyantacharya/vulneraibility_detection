from __future__ import annotations

"""
Full-stage agentic student solution for the VCKG student challenge evaluator.

Evaluator contract:
    def build_agent(config: dict): ...
    agent.step(sample: dict, observation: dict, budget: dict) -> dict

This solution intentionally mirrors the research pipeline as an internal state machine:
    01_source_only_hypothesis
    02_kg_query_planning
    04_hypothesis_verification
    04_evidence_gap_iterN
    04_hypothesis_verification_iterN
    05_counter_evidence_review
    05_counter_gap_iterN
    06_final_adjudication
    final_decision

Important limitation of the student evaluator interface:
    The evaluator usually accepts only two external actions from solution.py:
        {"action": "query", ...}
        {"action": "final", ...}
    Therefore the detailed stages below are executed inside solution.py and included as
    metadata fields such as `stage`, `agentic_trace`, `hypotheses`, `verification`, and
    `counter_review` in each action. If the frontend/evaluator records these extra fields,
    Student Agent Audit can display them. If it ignores unknown fields, the logic still runs.

This file does not use labels, commit messages, sample IDs, or benchmark metadata to decide.
It uses only target source and KG evidence returned by the evaluator.

Optional LLM mode is configured by the evaluator from env/config defaults, not by typing secrets in the terminal:
    STUDENT_AGENT_LLM=1
    STUDENT_LLM_API_BASE=https://chat-ai.academiccloud.de/v1
    STUDENT_LLM_API_KEY_ENV=ACADEMIC_CLOUD_API_KEY
    STUDENT_LLM_MODEL=mistral-large-3-675b-instruct-2512

The actual key value is read from the named environment variable in the backend subprocess.
When LLM mode is off or fails, deterministic family-aware logic is used.
"""

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request

STUDENT_AGENT_VERSION = "research_exact_like_v7_family_safe_20260619"

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _jsonable(x: Any) -> Any:
    try:
        json.dumps(x)
        return x
    except Exception:
        return str(x)


def _s(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, str):
        return x
    try:
        return json.dumps(x, ensure_ascii=False, sort_keys=True)
    except Exception:
        return str(x)


def _low(x: Any) -> str:
    return _s(x).lower()


def _compact(text: str, limit: int = 8000) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    half = max(1000, limit // 2)
    return text[:half] + "\n...<truncated>...\n" + text[-half:]


def _sample_id(sample: Dict[str, Any]) -> str:
    for key in ("sample_id", "id", "row_id"):
        if sample.get(key) is not None:
            return str(sample.get(key))
    basis = (_sample_function_name(sample) + "\n" + _sample_source(sample))[:2000]
    return hashlib.sha1(basis.encode("utf-8", "ignore")).hexdigest()[:16]


def _sample_function_name(sample: Dict[str, Any]) -> str:
    for key in ("function_name", "target_function", "function", "name", "target"):
        v = sample.get(key)
        if isinstance(v, str) and v.strip():
            # If function body is stored under "function", do not use it as name.
            if "\n" not in v and "{" not in v:
                return v.strip()
    return "target_function"


def _sample_source(sample: Dict[str, Any]) -> str:
    for key in ("target_function_source", "function_source", "source", "code", "body"):
        v = sample.get(key)
        if isinstance(v, str) and v.strip():
            return v
    # Some bundles use "function" as body.
    v = sample.get("function")
    if isinstance(v, str) and ("\n" in v or "{" in v):
        return v
    return ""


def _obs_evidence(observation: Dict[str, Any]) -> List[Any]:
    if not isinstance(observation, dict):
        return []
    ev = observation.get("evidence")
    if isinstance(ev, list):
        return ev
    if ev:
        return [ev]
    # Some evaluators return query_results/results/nodes.
    out: List[Any] = []
    for key in ("query_results", "results", "nodes", "last_result"):
        val = observation.get(key)
        if isinstance(val, list):
            out.extend(val)
        elif val:
            out.append(val)
    return out


def _obs_text(observation: Dict[str, Any], limit: int = 16000) -> str:
    return _compact(_s(_obs_evidence(observation)), limit)


def _budget_remaining(budget: Dict[str, Any]) -> int:
    for key in ("remaining_queries", "queries_remaining", "max_queries_remaining"):
        try:
            if budget.get(key) is not None:
                return int(budget.get(key))
        except Exception:
            pass
    return 3


def _budget_round(budget: Dict[str, Any]) -> int:
    for key in ("round", "round_no", "iteration"):
        try:
            if budget.get(key) is not None:
                return int(budget.get(key))
        except Exception:
            pass
    return 1


# ---------------------------------------------------------------------------
# Source facts and family detection
# ---------------------------------------------------------------------------


@dataclass
class SourceFacts:
    families: set[str] = field(default_factory=set)
    risks: set[str] = field(default_factory=set)
    safeties: set[str] = field(default_factory=set)
    variables: set[str] = field(default_factory=set)
    suspicious_statements: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def add_family(self, x: str) -> None:
        self.families.add(x)

    def add_risk(self, x: str, stmt: Optional[str] = None) -> None:
        self.risks.add(x)
        if stmt:
            s = " ".join(stmt.strip().split())
            if s and s not in self.suspicious_statements:
                self.suspicious_statements.append(s)

    def add_safety(self, x: str) -> None:
        self.safeties.add(x)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "families": sorted(self.families),
            "risks": sorted(self.risks),
            "safeties": sorted(self.safeties),
            "variables": sorted(self.variables),
            "suspicious_statements": self.suspicious_statements[:10],
            "notes": self.notes[:10],
        }


_ALLOC_RE = re.compile(r"\b(?P<var>[A-Za-z_][A-Za-z0-9_]*(?:->[A-Za-z_][A-Za-z0-9_]*)?)\s*=\s*(?P<func>malloc|calloc|realloc)\s*\((?P<args>[^;]*)\)", re.M)
_SAFE_ALLOC_RE = re.compile(r"\b(?P<var>[A-Za-z_][A-Za-z0-9_]*(?:->[A-Za-z_][A-Za-z0-9_]*)?)\s*=\s*(?P<func>safe_calloc|safe_malloc|xmalloc|xcalloc|g_malloc|g_new0)\s*\(", re.M)
_FIXED_BUF_RE = re.compile(r"\b(?:char|unsigned\s+char|uint8_t|BYTE)\s+(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*\[(?P<size>\d+)\]")


def _chunk_after(src: str, pos: int, lines: int = 10) -> str:
    return "\n".join(src[pos:].splitlines()[:lines])


def _has_check(chunk: str, var: str) -> bool:
    v = re.escape(var)
    patterns = [
        rf"if\s*\(\s*!\s*{v}\s*\)",
        rf"if\s*\(\s*{v}\s*==\s*NULL\s*\)",
        rf"if\s*\(\s*NULL\s*==\s*{v}\s*\)",
        rf"assert\s*\(\s*{v}\s*\)",
    ]
    return any(re.search(p, chunk) for p in patterns)


def _used_before_check(chunk: str, var: str) -> bool:
    v = re.escape(var)
    check_positions = [m.start() for m in re.finditer(rf"if\s*\([^\)]*{v}[^\)]*\)", chunk)]
    first_check = min(check_positions) if check_positions else None
    use_patterns = [
        rf"\bmemset\s*\(\s*{v}\b",
        rf"\bmemcpy\s*\(\s*{v}\b",
        rf"\bstrcpy\s*\(\s*{v}\b",
        rf"\bstrncpy\s*\(\s*{v}\b",
        rf"\bsprintf\s*\(\s*{v}\b",
        rf"\bsnprintf\s*\(\s*{v}\b",
        rf"\bfread\s*\(\s*{v}\b",
        rf"{v}\s*\[",
        rf"{v}\s*->",
        rf"\*\s*{v}\b",
    ]
    for p in use_patterns:
        m = re.search(p, chunk)
        if m and (first_check is None or m.start() < first_check):
            return True
    return False


def analyze_source(sample: Dict[str, Any]) -> SourceFacts:
    src = _sample_source(sample)
    low = src.lower()
    facts = SourceFacts()

    # Families.
    if any(t in low for t in ["malloc", "calloc", "realloc", "free(", "safe_calloc", "xmalloc"]):
        facts.add_family("allocation")
    if any(t in low for t in ["memcpy", "memmove", "strcpy", "strncpy", "sprintf", "snprintf", "fread", "read(", "recv", "recvfrom"]):
        facts.add_family("memory_bounds")
    if any(t in low for t in ["len", "length", "size", "offset", "idx", "index", "count", "total", "n_entries", "payload"]):
        facts.add_family("parser_state")
    if any(t in low for t in ["socket", "recvfrom", "sendto", "sockaddr", "hop", "ttl", "ndp", "icmp", "tcp", "udp"]):
        facts.add_family("protocol_validation")
    if any(t in low for t in ["auth", "permission", "uid", "gid", "daemon", "localhost", "127.0.0.1", "bind(", "listen("]):
        facts.add_family("access_control")
    if any(t in low for t in ["xor", "encrypt", "decrypt", "key", "hash", "crypto", "scramble"]):
        facts.add_family("crypto_algorithmic")
    if any(t in low for t in ["open(", "fopen", "path", "realpath", "getcwd", "unlink", "rename"]):
        facts.add_family("path_file")
    if any(t in low for t in ["mpz_", "point", "curve", "invert"]):
        facts.add_family("numeric_domain")

    # Allocation risks and safeties.
    for m in _ALLOC_RE.finditer(src):
        var, func, stmt = m.group("var"), m.group("func"), m.group(0)
        facts.variables.add(var.split("->")[-1])
        chunk = _chunk_after(src, m.start())
        if func in {"malloc", "calloc"}:
            if not _has_check(chunk, var) and _used_before_check(chunk, var):
                facts.add_risk(f"raw_{func}_without_null_check_before_use", stmt)
            elif not _has_check(chunk, var):
                facts.add_risk(f"raw_{func}_without_visible_failure_check", stmt)
        elif func == "realloc":
            facts.add_risk("raw_realloc_direct_assignment", stmt)

    # Dynamic growth guard: a buffer capacity check followed by realloc before indexed writes.
    if re.search(r"if\s*\([^)]*(?:>=|==)[^)]*(?:size|capacity|cap|allocated)[^)]*\).*?realloc\s*\(", src, re.I | re.S) and re.search(r"\[[^\]]+\]\s*=", src):
        facts.add_safety("dynamic_growth_guarded_buffer")

    for m in _SAFE_ALLOC_RE.finditer(src):
        facts.add_safety("safe_allocation_wrapper_used")
        facts.variables.add(m.group("var").split("->")[-1])

    # Fixed buffers and bounded reads.
    for m in _FIXED_BUF_RE.finditer(src):
        var, size = m.group("var"), int(m.group("size"))
        facts.variables.add(var)
        after = _chunk_after(src, m.end(), 25)
        if re.search(rf"\b(strcpy|sprintf|strcat|gets)\s*\([^;]*\b{re.escape(var)}\b", after):
            facts.add_risk("fixed_buffer_unbounded_write", m.group(0))
        if re.search(rf"\bfread\s*\(\s*{re.escape(var)}\s*,\s*1\s*,\s*{max(0, size - 1)}\s*,", src):
            facts.add_safety("bounded_read_within_fixed_buffer")

    # Pointer/integer/parser risks.
    if re.search(r"\+=\s*[A-Za-z_][A-Za-z0-9_]*\s*\*\s*[A-Za-z_][A-Za-z0-9_]*", src):
        facts.add_risk("pointer_advance_by_multiplication", "raw += length * itemsize style expression")
    if re.search(r"\bvoid\s*\*\s*start\s*=\s*raw\b|\bchar\s*\*\s*start\s*=", src) and "raw >= start" in low:
        facts.add_safety("saved_base_lower_bound_guard")
    if re.search(r"if\s*\([^\)]*==\s*end\s*\)", src) and re.search(r"return\s+-?1\s*;", src):
        facts.add_safety("exact_end_error_return")
    if any(t in low for t in ["idx++", "offset +=", "size +=", "total_sz +=", "length *", "count *"]):
        facts.add_risk("parser_length_or_offset_update")

    # Protocol/access/crypto signals.
    if "recvfrom" in low and not any(t in low for t in ["hop", "ttl", "linklocal", "link-local", "in6_is_addr_linklocal"]):
        facts.add_risk("network_receive_without_visible_source_invariant")
    if any(t in low for t in ["bind(", "listen("]) and not any(t in low for t in ["127.0.0.1", "localhost", "loopback"]):
        facts.add_risk("listening_surface_without_visible_localhost_restriction")
    if "xor" in low and any(t in low for t in ["key", "scramble", "coding", "decoding"]):
        facts.add_risk("deterministic_xor_or_scramble_algorithm")

    # Domain facts that suppress false positives.
    if "mpz_" in low:
        facts.add_safety("gmp_arbitrary_precision_not_c_integer_overflow")
    if re.search(r"sprintf\s*\([^;]*['\"]/proc/%d", src):
        facts.add_safety("proc_percent_d_not_path_traversal")

    return facts


# ---------------------------------------------------------------------------
# Full-stage state machine
# ---------------------------------------------------------------------------


@dataclass
class Hypothesis:
    hypothesis_id: str
    title: str
    vulnerability_class: str
    affected_code_region: str
    risk_summary: str
    family: str
    required_proof_questions: List[str]
    target_relevance: str = "medium"

    def as_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class Verification:
    hypothesis_id: str
    status: str
    local_risk_present: bool
    confirmed_security_vulnerability: bool
    proof: Dict[str, Any]
    missing_evidence: List[str]
    target_relevance: str
    explanation: str

    def as_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class CounterFinding:
    hypothesis_id: str
    refutes_or_weakens: str
    recommended_status: str
    strongest_counterargument: str
    counter_evidence_ids: List[str]

    def as_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class SampleState:
    sample_id: str
    fn: str
    source: str
    facts: SourceFacts
    stage: str = "01_source_only_hypothesis"
    iteration: int = 0
    counter_iteration: int = 0
    hypotheses: List[Hypothesis] = field(default_factory=list)
    verifications: List[Verification] = field(default_factory=list)
    counter_findings: List[CounterFinding] = field(default_factory=list)
    evidence_text: str = ""
    seen_query_keys: set[str] = field(default_factory=set)
    trace: List[Dict[str, Any]] = field(default_factory=list)
    last_evidence_len: int = 0
    pending_queries: List[Dict[str, Any]] = field(default_factory=list)
    pending_stage: str = ""
    pending_reason: str = ""
    pending_next_stage: str = ""

    def add_trace(self, stage: str, output: Any) -> None:
        self.trace.append({"stage": stage, "output": _jsonable(output), "ts": time.time()})


class FullStageAgenticStudent:
    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.states: Dict[str, SampleState] = {}
        self.max_evidence_iterations = int(self.config.get("max_evidence_iterations", 2))
        self.max_counter_iterations = int(self.config.get("max_counter_iterations", 1))
        self.llm_enabled = bool(self.config.get("llm_enabled")) or os.getenv("STUDENT_AGENT_LLM", "0").lower() in {"1", "true", "yes"}
        self.llm_api_base = str(self.config.get("llm_api_base") or os.getenv("STUDENT_LLM_API_BASE", "")).rstrip("/")
        self.llm_model = str(self.config.get("llm_model") or os.getenv("STUDENT_LLM_MODEL", ""))
        key_env = str(self.config.get("llm_api_key_env") or os.getenv("STUDENT_LLM_API_KEY_ENV", "STUDENT_LLM_API_KEY"))
        self.llm_api_key_env = key_env
        self.llm_api_key = os.getenv(key_env, os.getenv("STUDENT_LLM_API_KEY", ""))
        self.llm_call_count = 0
        print(f"student.solution.version | version={STUDENT_AGENT_VERSION} | mode=full_research_like_kg_loop", flush=True)

    def step(self, sample: Dict[str, Any], observation: Dict[str, Any], budget: Dict[str, Any]) -> Dict[str, Any]:
        sid = _sample_id(sample)
        if sid not in self.states:
            source = _sample_source(sample)
            fn = _sample_function_name(sample)
            facts = analyze_source(sample)
            self.states[sid] = SampleState(sample_id=sid, fn=fn, source=source, facts=facts)
        st = self.states[sid]

        # Update evidence on every step.
        st.evidence_text = _obs_text(observation)
        force_final = bool(budget.get("force_final")) or _budget_remaining(budget) <= 0
        if force_final:
            return self._final_action(st, reason="budget_force_final")

        # If a previous research stage planned more KG queries than the evaluator
        # can execute in one round, keep draining that exact queued plan before
        # moving to verification/final stages.  This mirrors Research Audit more
        # closely than returning 12 queries and letting the evaluator silently run
        # only the first 3.
        if st.pending_queries:
            return self._dequeue_query_action(st, budget)

        # Stage 01: hypothesis generation.
        if st.stage == "01_source_only_hypothesis":
            st.hypotheses = self._source_only_hypothesis(st)
            st.add_trace("01_source_only_hypothesis", {"hypotheses": [h.as_dict() for h in st.hypotheses], "source_facts": st.facts.as_dict()})
            st.stage = "02_kg_query_planning"

        # Stage 02: query planning returns the first external KG action.
        if st.stage == "02_kg_query_planning":
            queries = self._kg_query_planning(st)
            st.add_trace("02_kg_query_planning", {"queries": queries})
            return self._enqueue_query_action(st, "02_kg_query_planning", queries, "Initial KG retrieval for hypotheses.", "04_hypothesis_verification", budget)

        # Stage 04: verification after initial KG result.
        if st.stage == "04_hypothesis_verification":
            st.verifications = self._hypothesis_verification(st, iter_no=0)
            st.add_trace("04_hypothesis_verification", {"verifications": [v.as_dict() for v in st.verifications]})
            st.stage = "04_evidence_gap"

        # Stage 04 gap loop.
        if st.stage == "04_evidence_gap":
            if st.iteration < self.max_evidence_iterations:
                gap_queries = self._evidence_gap(st)
                st.add_trace(f"04_evidence_gap_iter{st.iteration + 1}", {"queries": gap_queries})
                if gap_queries:
                    st.iteration += 1
                    return self._enqueue_query_action(st, f"04_evidence_gap_iter{st.iteration}", gap_queries, "Retrieve missing evidence for unresolved hypotheses.", "04_hypothesis_verification_iter", budget)
            st.stage = "05_counter_evidence_review"

        # Stage 04 iter verification after gap query.
        if st.stage == "04_hypothesis_verification_iter":
            st.verifications = self._hypothesis_verification(st, iter_no=st.iteration)
            st.add_trace(f"04_hypothesis_verification_iter{st.iteration}", {"verifications": [v.as_dict() for v in st.verifications]})
            st.stage = "04_evidence_gap"
            # Allow another loop if budget remains; recursive one-step avoided by falling through next call.
            if st.iteration < self.max_evidence_iterations and _budget_remaining(budget) > 0:
                gap_queries = self._evidence_gap(st)
                st.add_trace(f"04_evidence_gap_iter{st.iteration + 1}", {"queries": gap_queries})
                if gap_queries:
                    st.iteration += 1
                    return self._enqueue_query_action(st, f"04_evidence_gap_iter{st.iteration}", gap_queries, "Retrieve additional missing evidence.", "04_hypothesis_verification_iter", budget)
            st.stage = "05_counter_evidence_review"

        # Stage 05 counter review.
        if st.stage == "05_counter_evidence_review":
            st.counter_findings = self._counter_evidence_review(st)
            st.add_trace("05_counter_evidence_review", {"findings": [c.as_dict() for c in st.counter_findings]})
            st.stage = "05_counter_gap"

        # Stage 05 counter gap loop.
        if st.stage == "05_counter_gap":
            if st.counter_iteration < self.max_counter_iterations:
                cq = self._counter_gap(st)
                st.add_trace(f"05_counter_gap_iter{st.counter_iteration + 1}", {"queries": cq})
                if cq:
                    st.counter_iteration += 1
                    return self._enqueue_query_action(st, f"05_counter_gap_iter{st.counter_iteration}", cq, "Retrieve counter-evidence or guard dominance evidence.", "05_counter_gap_after_query", budget)
            st.stage = "06_final_adjudication"

        if st.stage == "05_counter_gap_after_query":
            # Re-run counter review with new evidence.
            st.counter_findings = self._counter_evidence_review(st)
            st.add_trace(f"05_counter_evidence_review_iter{st.counter_iteration}", {"findings": [c.as_dict() for c in st.counter_findings]})
            st.stage = "06_final_adjudication"

        if st.stage == "06_final_adjudication":
            # Hard safety gate: a research-like student run must not finalize before
            # at least one KG-backed verification stage has happened.  If the
            # evaluator ever reaches final without evidence, force a KG action.
            if not any(str(t.get("stage", "")).startswith("04_hypothesis_verification") for t in st.trace) and _budget_remaining(budget) > 0:
                st.add_trace("kg_required_before_final_hard_gate", {"reason": "no verification trace before final; forcing KG retrieval"})
                return self._enqueue_query_action(st, "02_kg_query_planning_hard_gate", self._kg_query_planning(st), "KG evidence is required before final adjudication.", "04_hypothesis_verification", budget)
            return self._final_action(st, reason="completed_full_agentic_flow")

        return self._final_action(st, reason="fallback_unknown_stage")

    # ------------------------------------------------------------------
    # Internal stages
    # ------------------------------------------------------------------

    def _source_only_hypothesis(self, st: SampleState) -> List[Hypothesis]:
        facts = st.facts
        hyps: List[Hypothesis] = []

        def add(title: str, cls: str, region: str, summary: str, family: str, qs: List[str]) -> None:
            if len(hyps) >= 6:
                return
            hyps.append(Hypothesis(
                hypothesis_id=f"HYP-{len(hyps)+1:02d}",
                title=title,
                vulnerability_class=cls,
                affected_code_region=region,
                risk_summary=summary,
                family=family,
                required_proof_questions=qs,
            ))

        # Family-specific hypothesis templates.
        if "allocation" in facts.families:
            if any("raw_malloc" in r or "raw_calloc" in r for r in facts.risks):
                add(
                    "Raw allocation result used without visible failure check",
                    "Allocation Failure / NULL Dereference",
                    "; ".join(facts.suspicious_statements[:2]) or "malloc/calloc assignment",
                    "A raw allocator result may be used before checking for NULL, creating a reachable crash or memory-safety failure under allocation failure.",
                    "allocation",
                    ["Is the allocation result checked before first dereference/use?", "Can allocation size be influenced by input or file data?", "Does a safe wrapper handle allocation failure instead?"],
                )
            if "raw_realloc_direct_assignment" in facts.risks:
                add(
                    "Direct realloc assignment can lose original pointer or enable unchecked growth failure",
                    "Allocation Failure / Memory Management",
                    "realloc assignment",
                    "Assigning realloc directly back to the same pointer can lose the original allocation on failure and may be followed by unsafe use.",
                    "allocation",
                    ["Is realloc assigned to a temporary pointer first?", "Is the result checked before use?", "Can the growth path be triggered by untrusted input?"],
                )
            if "safe_allocation_wrapper_used" in facts.safeties:
                add(
                    "Allocation-wrapper safety check",
                    "Counter-Evidence Candidate",
                    "safe_calloc/xmalloc wrapper",
                    "A safe allocation wrapper may refute raw allocation-failure hypotheses if its semantics abort or handle NULL/zero-size safely.",
                    "allocation",
                    ["Does the wrapper check zero-size and allocation failure?", "Does the caller use the wrapper consistently on all relevant paths?"],
                )

        if "memory_bounds" in facts.families or "parser_state" in facts.families:
            if facts.risks.intersection({"fixed_buffer_unbounded_write", "pointer_advance_by_multiplication", "parser_length_or_offset_update"}):
                add(
                    "Input-controlled length/offset may reach unsafe memory operation",
                    "Buffer Bounds / Parser State",
                    "; ".join(facts.suspicious_statements[:3]) or "copy/read/offset update",
                    "The function updates an index/offset/length or performs a copy/read where safety depends on input-controlled bounds.",
                    "parser_state",
                    ["Where does the length/offset originate?", "Does a dominating guard bound the exact value used?", "What unsafe read/write/seek follows the update?"],
                )

        if "protocol_validation" in facts.families:
            add(
                "Missing protocol trust-boundary validation",
                "Protocol Validation",
                "network receive / message validation path",
                "The function appears to process network/protocol data; vulnerability may be a missing hop-limit, source, message-type, or trust-boundary check.",
                "protocol_validation",
                ["What protocol invariant must hold before accepting the message?", "Is source/hop-limit/link-local validation present?", "Does processing continue when validation is absent?"],
            )

        if "access_control" in facts.families:
            add(
                "Missing access-control or local-surface restriction",
                "Access Control",
                "daemon/listen/auth path",
                "A security-sensitive operation may be reachable without the required local-only or authorization restriction.",
                "access_control",
                ["What privileged operation is exposed?", "Is localhost/permission/authentication checked before use?", "Can untrusted input reach this path?"],
            )

        if "crypto_algorithmic" in facts.families:
            add(
                "Algorithmic or cryptographic transformation weakness",
                "Crypto/Algorithmic Weakness",
                "XOR/key/scramble path",
                "The weakness may be semantic rather than memory-safety: deterministic/key-reuse transformations can leak structure or be reversible.",
                "crypto_algorithmic",
                ["What attacker capability is assumed?", "Is there deterministic output or key reuse?", "Does the transformation preserve frequency/structure?"],
            )

        if "path_file" in facts.families:
            add(
                "Path/file operation missing validation",
                "Path/File Handling",
                "open/fopen/path operation",
                "The function may use file paths or filesystem operations without canonicalization, permission checks, or safe directory constraints.",
                "path_file",
                ["Is the path attacker-controlled?", "Is canonicalization or base-directory restriction present?", "What sensitive file operation follows?"],
            )

        if not hyps:
            add(
                "Generic source-level security hypothesis",
                "Unknown / Needs Evidence",
                st.fn,
                "No high-signal family pattern was found; retrieve semantic and caller context before deciding.",
                "unknown",
                ["What inputs reach this function?", "What guards dominate risky operations?", "What security impact is plausible?"],
            )

        # Optional LLM refinement can replace/augment deterministic hypotheses.
        if self.llm_enabled:
            llm_h = self._llm_hypotheses(st, hyps)
            if llm_h:
                return llm_h
        return hyps

    def _kg_query_planning(self, st: SampleState) -> List[Dict[str, Any]]:
        """Plan the first external KG action.

        This function must NEVER return an empty list for a normal sample with
        query budget available.  The evaluator can only execute KG when we
        return action='query'.  Earlier versions sometimes let LLM planning or
        stateful dedupe remove every query, causing the student agent to jump
        directly from 02_kg_query_planning to final_decision with queries=0.
        """
        fn = st.fn
        base_queries: List[Dict[str, Any]] = [
            {"kind": "security_context", "target_function": fn, "depth": 3, "call_depth": 2, "data_depth": 4, "max_nodes": 350},
            {"kind": "semantic_facts", "target_function": fn, "max_nodes": 300},
            {"kind": "call_neighborhood", "target_function": fn, "direction": "both", "call_depth": 2, "max_nodes": 300},
        ]
        for stmt in st.facts.suspicious_statements[:3]:
            base_queries.append({"kind": "evidence_slice", "target_function": fn, "target_statement": stmt[:240], "relation_depth": 4, "data_depth": 4, "control_depth": 3, "call_depth": 2, "max_nodes": 350})
        for v in sorted(st.facts.variables)[:4]:
            base_queries.append({"kind": "variable_flow", "target_function": fn, "symbol": v, "data_depth": 4, "max_nodes": 300})

        # Ask the LLM to refine/augment, but never let it erase deterministic
        # fallback queries.  LLM-normalized queries may update seen_query_keys;
        # therefore final dedupe is local-only and not stateful.
        llm_queries: List[Dict[str, Any]] = []
        if self.llm_enabled:
            llm_queries = self._llm_query_plan_no_mark(st, base_queries, "02_kg_query_planning")

        merged = self._merge_planned_queries(llm_queries, base_queries)
        scheduled = self._dedupe_queries(st, merged)

        # Absolute safety net: if stateful dedupe removed everything, still
        # return fresh fallback queries with harmless query_id salt so the
        # evaluator executes KG before any final decision.
        if not scheduled:
            fallback = [
                {"kind": "security_context", "target_function": fn, "depth": 3, "call_depth": 2, "data_depth": 4, "max_nodes": 350, "query_id": "forced_initial_security_context"},
                {"kind": "semantic_facts", "target_function": fn, "max_nodes": 300, "query_id": "forced_initial_semantic_facts"},
                {"kind": "call_neighborhood", "target_function": fn, "direction": "both", "call_depth": 2, "max_nodes": 300, "query_id": "forced_initial_call_neighborhood"},
            ]
            scheduled = fallback
        return scheduled

    def _hypothesis_verification(self, st: SampleState, iter_no: int) -> List[Verification]:
        text = (st.evidence_text + "\n" + st.source).lower()
        facts = st.facts
        out: List[Verification] = []
        for h in st.hypotheses:
            risk = False
            confirmed = False
            status = "plausible_but_unproven"
            missing: List[str] = []
            proof = {
                "input_control": "",
                "dangerous_operation": h.affected_code_region,
                "missing_or_failed_guard": "",
                "unsafe_use": "",
                "security_impact": "",
                "cited_evidence_ids": ["SRC-FACTS"],
            }

            if h.family == "allocation":
                if any(r in facts.risks for r in ["raw_malloc_without_null_check_before_use", "raw_calloc_without_null_check_before_use", "raw_realloc_direct_assignment"]):
                    risk = True
                    proof["missing_or_failed_guard"] = "raw allocator result lacks visible check before use or direct realloc assignment is present"
                    proof["unsafe_use"] = "allocation result appears used/dereferenced or growth path continues after allocation"
                    proof["security_impact"] = "NULL dereference, memory corruption, or denial of service under allocation failure"
                    if any(t in text for t in ["input", "file", "read", "parse", "network", "user", "untrusted", "attacker"]):
                        proof["input_control"] = "source/KG evidence suggests allocation path can be influenced by file, input, or parsed data"
                        confirmed = True
                        status = "confirmed_vulnerability"
                    else:
                        missing.append("input/control reachability for allocation-failure path")
                if "safe_allocation_wrapper_used" in facts.safeties:
                    if not risk:
                        status = "refuted_by_guard"
                    missing.append("wrapper semantics should be confirmed by KG if allocation is central")

            elif h.family in {"parser_state", "memory_bounds"}:
                if facts.risks.intersection({"fixed_buffer_unbounded_write", "pointer_advance_by_multiplication", "parser_length_or_offset_update"}):
                    risk = True
                    proof["missing_or_failed_guard"] = "exact length/offset dominance guard not proven"
                    proof["unsafe_use"] = "copy/read/offset/pointer update may use input-derived size"
                    proof["security_impact"] = "out-of-bounds read/write, parser confusion, or pointer wraparound"
                    if any(t in text for t in ["attacker", "untrusted", "file", "packet", "buffer", "input", "raw", "payload"]):
                        proof["input_control"] = "input/file/buffer source appears relevant in source or KG evidence"
                        confirmed = "saved_base_lower_bound_guard" not in facts.safeties and "bounded_read_within_fixed_buffer" not in facts.safeties
                        status = "confirmed_vulnerability" if confirmed else "refuted_by_guard"
                    else:
                        missing.append("input source or caller reachability")

            elif h.family == "protocol_validation":
                risk = "network_receive_without_visible_source_invariant" in facts.risks or any(t in text for t in ["recvfrom", "packet", "message"])
                proof["dangerous_operation"] = "accepting or processing protocol/network message"
                proof["missing_or_failed_guard"] = "required protocol invariant such as hop/source/message validation not proven"
                proof["unsafe_use"] = "message may be accepted or processed across trust boundary"
                proof["security_impact"] = "spoofing, unauthorized protocol action, or remote policy bypass"
                if risk and not any(t in text for t in ["hop limit", "link-local", "validated", "reject", "auth"]):
                    confirmed = True
                    status = "confirmed_vulnerability"
                else:
                    missing.append("proof that required protocol invariant is absent on all acceptance paths")

            elif h.family == "access_control":
                risk = "listening_surface_without_visible_localhost_restriction" in facts.risks or any(t in text for t in ["daemon", "listen", "privilege", "permission"])
                proof["dangerous_operation"] = "exposing or executing privileged/security-sensitive operation"
                proof["missing_or_failed_guard"] = "authorization/local-only/permission check not proven"
                proof["unsafe_use"] = "untrusted caller may reach privileged operation"
                proof["security_impact"] = "access-control bypass or privilege/security boundary violation"
                if risk and not any(t in text for t in ["localhost", "127.0.0.1", "permission", "authorized", "denied"]):
                    confirmed = True
                    status = "confirmed_vulnerability"
                else:
                    missing.append("security-boundary and missing-check proof")

            elif h.family == "crypto_algorithmic":
                risk = "deterministic_xor_or_scramble_algorithm" in facts.risks
                proof["dangerous_operation"] = "deterministic/keyed transformation"
                proof["missing_or_failed_guard"] = "no diversification/randomization or key separation proven"
                proof["unsafe_use"] = "predictable transformation may preserve structure"
                proof["security_impact"] = "frequency analysis or reversible/weak obfuscation"
                if risk:
                    confirmed = True
                    status = "confirmed_vulnerability"

            if not risk and status == "plausible_but_unproven":
                missing.append("no high-signal source or KG evidence for this hypothesis")
            out.append(Verification(
                hypothesis_id=h.hypothesis_id,
                status=status,
                local_risk_present=risk,
                confirmed_security_vulnerability=confirmed,
                proof=proof,
                missing_evidence=missing,
                target_relevance=h.target_relevance,
                explanation=f"{h.family} verification from source facts and KG evidence; status={status}",
            ))
        if self.llm_enabled:
            llm_verified = self._llm_verify(st, out, iter_no)
            if llm_verified:
                return llm_verified
        return out

    def _evidence_gap(self, st: SampleState) -> List[Dict[str, Any]]:
        queries: List[Dict[str, Any]] = []
        unresolved = [v for v in st.verifications if v.local_risk_present and not v.confirmed_security_vulnerability and v.status not in {"refuted_by_guard"}]
        if not unresolved:
            return []
        fn = st.fn
        # Family-specific gap queries.
        families = {h.family for h in st.hypotheses if any(v.hypothesis_id == h.hypothesis_id for v in unresolved)}
        if "allocation" in families:
            queries.append({"kind": "semantic_facts", "target_function": fn, "max_nodes": 350})
            for var in sorted(st.facts.variables)[:3]:
                queries.append({"kind": "variable_flow", "target_function": fn, "symbol": var, "data_depth": 4, "max_nodes": 300})
            for stmt in st.facts.suspicious_statements[:3]:
                if any(x in stmt for x in ["malloc", "calloc", "realloc"]):
                    queries.append({"kind": "evidence_slice", "target_function": fn, "target_statement": stmt[:240], "relation_depth": 4, "data_depth": 4, "control_depth": 3, "call_depth": 2, "max_nodes": 350})
        if families.intersection({"protocol_validation", "access_control"}):
            queries.append({"kind": "call_neighborhood", "target_function": fn, "direction": "both", "call_depth": 3, "max_nodes": 450})
            queries.append({"kind": "security_context", "target_function": fn, "depth": 4, "call_depth": 3, "data_depth": 4, "max_nodes": 450})
        if families.intersection({"parser_state", "memory_bounds"}):
            for stmt in st.facts.suspicious_statements[:3]:
                queries.append({"kind": "evidence_slice", "target_function": fn, "target_statement": stmt[:240], "relation_depth": 4, "data_depth": 4, "control_depth": 4, "call_depth": 2, "max_nodes": 350})
            for sym in ["len", "length", "size", "offset", "idx", "count", "total_sz", "raw"]:
                if sym in st.source.lower():
                    queries.append({"kind": "variable_flow", "target_function": fn, "symbol": sym, "data_depth": 4, "max_nodes": 300})
        deterministic = self._dedupe_queries(st, queries)
        if self.llm_enabled:
            llm_queries = self._llm_evidence_gap_queries(st, deterministic)
            if llm_queries:
                return self._merge_planned_queries(llm_queries, deterministic)
        return deterministic

    def _counter_evidence_review(self, st: SampleState) -> List[CounterFinding]:
        text = (st.evidence_text + "\n" + st.source).lower()
        findings: List[CounterFinding] = []
        for v in st.verifications:
            h = next((x for x in st.hypotheses if x.hypothesis_id == v.hypothesis_id), None)
            if not h:
                continue
            ref = "weakens"
            status = v.status
            arg = "No decisive counter-evidence found."
            ids = ["SRC-FACTS"]
            if h.family == "allocation" and "safe_allocation_wrapper_used" in st.facts.safeties and not any(r.startswith("raw_") for r in st.facts.risks):
                ref, status = "refutes", "refuted_by_guard"
                arg = "Safe allocation wrapper is used and no raw allocation-before-check pattern is visible."
            if h.family in {"parser_state", "memory_bounds"}:
                if "bounded_read_within_fixed_buffer" in st.facts.safeties:
                    ref, status = "refutes", "refuted_by_guard"
                    arg = "Read size appears bounded within the visible fixed allocation."
                if "saved_base_lower_bound_guard" in st.facts.safeties and "exact_end_error_return" in st.facts.safeties:
                    ref, status = "refutes", "refuted_by_guard"
                    arg = "Saved-base lower-bound guard plus exact-end error return refutes pointer-wraparound traversal."
            if h.family == "numeric_domain" and "gmp_arbitrary_precision_not_c_integer_overflow" in st.facts.safeties:
                ref, status = "refutes", "refuted_by_guard"
                arg = "GMP mpz arithmetic is arbitrary precision, so normal mpz_mul/mpz_sub is not C integer overflow/underflow."
            findings.append(CounterFinding(v.hypothesis_id, ref, status, arg, ids))
        if self.llm_enabled:
            llm_findings = self._llm_counter_review(st, findings)
            if llm_findings:
                return llm_findings
        return findings

    def _counter_gap(self, st: SampleState) -> List[Dict[str, Any]]:
        needs = [c for c in st.counter_findings if c.refutes_or_weakens == "weakens"]
        if not needs:
            return []
        queries = [
            {"kind": "semantic_facts", "target_function": st.fn, "max_nodes": 350},
            {"kind": "call_neighborhood", "target_function": st.fn, "direction": "both", "call_depth": 2, "max_nodes": 350},
        ]
        deterministic = self._dedupe_queries(st, queries)
        if self.llm_enabled:
            llm_queries = self._llm_counter_gap_queries(st, deterministic)
            if llm_queries:
                return self._merge_planned_queries(llm_queries, deterministic)
        return deterministic

    def _final_decision(self, st: SampleState, reason: str) -> Dict[str, Any]:
        confirmed = [v for v in st.verifications if v.confirmed_security_vulnerability and v.status == "confirmed_vulnerability"]
        refuted = {c.hypothesis_id for c in st.counter_findings if c.recommended_status == "refuted_by_guard" or c.refutes_or_weakens == "refutes"}
        high_risk = bool(st.facts.risks.intersection({
            "raw_malloc_without_null_check_before_use",
            "raw_calloc_without_null_check_before_use",
            "raw_realloc_direct_assignment",
            "fixed_buffer_unbounded_write",
            "pointer_advance_by_multiplication",
            "network_receive_without_visible_source_invariant",
            "listening_surface_without_visible_localhost_restriction",
            "deterministic_xor_or_scramble_algorithm",
        }))
        strong_safety = bool(st.facts.safeties.intersection({
            "safe_allocation_wrapper_used",
            "bounded_read_within_fixed_buffer",
            "saved_base_lower_bound_guard",
            "gmp_arbitrary_precision_not_c_integer_overflow",
            "proc_percent_d_not_path_traversal",
            "dynamic_growth_guarded_buffer",
        }))

        # Precision gate copied from the research-side behavior: dynamic capacity-growth
        # guards can downgrade raw allocator/realloc residual concerns when no stronger
        # target-relevant memory-bound signal remains.
        if "dynamic_growth_guarded_buffer" in st.facts.safeties and not st.facts.risks.intersection({"fixed_buffer_unbounded_write", "pointer_advance_by_multiplication", "network_receive_without_visible_source_invariant", "listening_surface_without_visible_localhost_restriction"}):
            high_risk = False

        def _verification_family(v: Verification) -> str:
            hyp = next((h for h in st.hypotheses if h.hypothesis_id == v.hypothesis_id), None)
            return (hyp.family if hyp else "unknown")

        if confirmed and not ("dynamic_growth_guarded_buffer" in st.facts.safeties and all(_verification_family(v) == "allocation" for v in confirmed)):
            pred = 1
            status = "confirmed_vulnerable"
            confidence = 0.80
            explanation = f"At least one target-relevant hypothesis has a complete or high-signal proof: {[v.hypothesis_id for v in confirmed]}"
        elif high_risk and not strong_safety:
            pred = 1
            status = "forced_binary_vulnerable"
            confidence = 0.62
            explanation = "No complete proof was obtained, but high-signal source facts remain unresolved and no strong same-path safety evidence was found."
        else:
            pred = 0
            status = "forced_binary_non_vulnerable" if high_risk else "confirmed_non_vulnerable"
            confidence = 0.65 if high_risk else 0.78
            explanation = "No complete target-relevant vulnerability proof remains after source facts, KG evidence, and counter-evidence review."

        return {
            "prediction": pred,
            "prediction_bool": bool(pred),
            "confidence": confidence,
            "decision_status": status,
            "reason": explanation,
            "explanation": explanation,
            "residual_uncertainty": self._residual_uncertainty(st),
            "source_facts": st.facts.as_dict(),
            "hypotheses": [h.as_dict() for h in st.hypotheses],
            "verifications": [v.as_dict() for v in st.verifications],
            "counter_evidence_review": [c.as_dict() for c in st.counter_findings],
            "agentic_stages_completed": [t["stage"] for t in st.trace],
            "finalization_reason": reason,
            "llm_enabled": bool(self.llm_enabled),
            "llm_call_count": int(self.llm_call_count),
            "llm_config": {
                "enabled": bool(self.llm_enabled),
                "api_base": self.llm_api_base,
                "model": self.llm_model,
                "api_key_env": self.llm_api_key_env,
                "api_key_present": bool(self.llm_api_key),
            },
        }

    def _residual_uncertainty(self, st: SampleState) -> List[str]:
        out = []
        if not st.evidence_text.strip():
            out.append("No KG evidence text was visible to the student agent; decision relies heavily on source facts.")
        if any(v.local_risk_present and not v.confirmed_security_vulnerability for v in st.verifications):
            out.append("Some local risks remained plausible but did not reach complete proof.")
        if st.iteration >= self.max_evidence_iterations:
            out.append("Evidence loop budget was exhausted.")
        return out

    # ------------------------------------------------------------------
    # Action wrappers
    # ------------------------------------------------------------------

    def _dedupe_queries(self, st: SampleState, queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out = []
        for q in queries:
            if not isinstance(q, dict) or not q.get("kind"):
                continue
            # Normalize direction aliases.
            if q.get("kind") == "call_neighborhood" and q.get("direction") in {"incoming", "caller", "callers"}:
                q = dict(q); q["direction"] = "in"
            if q.get("kind") == "call_neighborhood" and q.get("direction") in {"outgoing", "callee", "callees"}:
                q = dict(q); q["direction"] = "out"
            key = json.dumps(q, sort_keys=True, default=str)
            if key in st.seen_query_keys:
                continue
            st.seen_query_keys.add(key)
            out.append(q)
        return out

    def _merge_planned_queries(self, *query_lists: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Merge already-normalized/planned query lists without reusing the stateful
        seen_query_keys set.  This is important because _dedupe_queries marks
        queries as scheduled.  The previous version re-deduped llm+deterministic
        lists and accidentally removed every query, causing the student agent to
        jump directly to final_decision with queries=0.
        """
        out: List[Dict[str, Any]] = []
        seen: set[str] = set()
        for query_list in query_lists:
            for q in query_list or []:
                if not isinstance(q, dict) or not q.get("kind"):
                    continue
                key = json.dumps(q, sort_keys=True, default=str)
                if key in seen:
                    continue
                seen.add(key)
                out.append(q)
        return out


    def _normalize_direction_value(self, value: Any) -> str:
        d = str(value or "both").strip().lower().replace("-", "_").replace(" ", "_")
        aliases_in = {"in", "incoming", "inbound", "caller", "callers", "caller_constraints", "callers_of", "input", "source", "sources", "upstream", "predecessor", "predecessors"}
        aliases_out = {"out", "outgoing", "outbound", "callee", "callees", "callees_of", "sink", "sinks", "downstream", "successor", "successors"}
        aliases_both = {"both", "all", "either", "bidirectional", "neighbors", "neighborhood", "call_neighborhood"}
        if d in aliases_in:
            return "in"
        if d in aliases_out:
            return "out"
        if d in aliases_both:
            return "both"
        # Safe default: keep the query valid rather than letting the KG API abort the sample.
        return "both"

    def _sanitize_query_for_api(self, q: Dict[str, Any], st: SampleState) -> Optional[Dict[str, Any]]:
        if not isinstance(q, dict):
            return None
        nq = dict(q)
        kind = str(nq.get("kind") or "").strip()
        if kind not in {"security_context", "semantic_facts", "evidence_slice", "variable_flow", "call_neighborhood", "function_context"}:
            return None
        nq["kind"] = kind
        nq.setdefault("target_function", st.fn)
        nq.pop("query_text", None)
        if kind == "call_neighborhood":
            old = nq.get("direction")
            nq["direction"] = self._normalize_direction_value(old)
            if old != nq["direction"]:
                st.add_trace("query_direction_normalized", {"old": old, "new": nq["direction"], "query": {k: v for k, v in nq.items() if k != "evidence"}})
        if kind == "variable_flow" and not nq.get("symbol"):
            return None
        if kind == "evidence_slice" and not nq.get("target_statement"):
            if st.facts.suspicious_statements:
                nq["target_statement"] = st.facts.suspicious_statements[0][:240]
            else:
                return None
        nq.setdefault("max_nodes", 350)
        return nq

    def _enqueue_query_action(self, st: SampleState, stage: str, queries: List[Dict[str, Any]], reason: str, next_stage: str, budget: Dict[str, Any]) -> Dict[str, Any]:
        """Queue a full Research-Audit-style KG query plan and execute it across
        evaluator rounds.  The evaluator can cap queries per round; this method
        prevents the remaining planned queries from being silently discarded.
        """
        if not queries:
            queries = [
                {"kind": "security_context", "target_function": st.fn, "depth": 3, "call_depth": 2, "data_depth": 4, "max_nodes": 350, "query_id": f"fallback_{stage}_security_context"},
                {"kind": "semantic_facts", "target_function": st.fn, "max_nodes": 300, "query_id": f"fallback_{stage}_semantic_facts"},
                {"kind": "call_neighborhood", "target_function": st.fn, "direction": "both", "call_depth": 2, "max_nodes": 300, "query_id": f"fallback_{stage}_call_neighborhood"},
            ]
            st.add_trace(stage + "_fallback_queries", {"reason": "empty_query_plan_replaced_with_forced_fallback", "queries": queries})
        sanitized: List[Dict[str, Any]] = []
        seen_sanitized: set[str] = set()
        for q in queries:
            sq = self._sanitize_query_for_api(q, st)
            if not sq:
                continue
            key = json.dumps(sq, sort_keys=True, default=str)
            if key in seen_sanitized:
                continue
            seen_sanitized.add(key)
            sanitized.append(sq)
        if not sanitized:
            sanitized = [
                {"kind": "security_context", "target_function": st.fn, "depth": 3, "call_depth": 2, "data_depth": 4, "max_nodes": 350, "query_id": f"fallback_{stage}_security_context"},
                {"kind": "semantic_facts", "target_function": st.fn, "max_nodes": 300, "query_id": f"fallback_{stage}_semantic_facts"},
                {"kind": "call_neighborhood", "target_function": st.fn, "direction": "both", "call_depth": 2, "max_nodes": 300, "query_id": f"fallback_{stage}_call_neighborhood"},
            ]
            st.add_trace(stage + "_sanitized_fallback_queries", {"reason": "all_planned_queries_invalid_after_sanitization", "queries": sanitized})
        st.pending_queries = list(sanitized)
        st.pending_stage = stage
        st.pending_reason = reason
        st.pending_next_stage = next_stage
        st.add_trace(stage + "_query_queue", {"planned_queries": len(st.pending_queries), "next_stage": next_stage})
        return self._dequeue_query_action(st, budget)

    def _dequeue_query_action(self, st: SampleState, budget: Dict[str, Any]) -> Dict[str, Any]:
        per_round = int(budget.get("max_queries_per_round") or 1)
        remaining_budget = int(budget.get("remaining_queries") or per_round)
        n = max(1, min(per_round, remaining_budget, len(st.pending_queries)))
        raw_batch = st.pending_queries[:n]
        st.pending_queries = st.pending_queries[n:]
        queries = []
        for q in raw_batch:
            sq = self._sanitize_query_for_api(q, st)
            if sq:
                queries.append(sq)
        if not queries and st.pending_queries:
            # Try one more valid query from the remaining queue instead of returning an empty/invalid batch.
            while st.pending_queries and not queries:
                sq = self._sanitize_query_for_api(st.pending_queries.pop(0), st)
                if sq:
                    queries.append(sq)
        if not queries:
            queries = [{"kind": "semantic_facts", "target_function": st.fn, "max_nodes": 300, "query_id": f"fallback_empty_batch_{stage}"}]
        stage = st.pending_stage or "kg_query_batch"
        reason = st.pending_reason or "Execute queued KG queries."
        if not st.pending_queries:
            st.stage = st.pending_next_stage or st.stage
        else:
            st.stage = stage + "_drain"
        print(
            f"student.agent.query_action | version={STUDENT_AGENT_VERSION} | stage={stage} | batch={n} | remaining_queued={len(st.pending_queries)} | next_stage={st.pending_next_stage} | reason={reason[:100]}",
            flush=True,
        )
        return {
            "action": "query",
            "stage": stage,
            "reason": reason + (f" queued_remaining={len(st.pending_queries)}" if st.pending_queries else ""),
            "queries": queries,
            "agentic_trace": st.trace,
            "source_facts": st.facts.as_dict(),
            "hypotheses": [h.as_dict() for h in st.hypotheses],
        }

    def _query_action(self, st: SampleState, stage: str, queries: List[Dict[str, Any]], reason: str) -> Dict[str, Any]:
        # Compatibility wrapper for any legacy call sites.
        return self._enqueue_query_action(st, stage, queries, reason, st.stage, {"max_queries_per_round": len(queries) or 1, "remaining_queries": len(queries) or 1})

    def _final_action(self, st: SampleState, reason: str) -> Dict[str, Any]:
        decision = self._final_decision(st, reason)
        llm_decision = self._llm_final_decision(st, decision)
        if llm_decision:
            decision.update(llm_decision)
            decision["llm_reviewed_final_decision"] = True
        if "dynamic_growth_guarded_buffer" in st.facts.safeties and not st.facts.risks.intersection({"fixed_buffer_unbounded_write", "pointer_advance_by_multiplication", "network_receive_without_visible_source_invariant", "listening_surface_without_visible_localhost_restriction"}):
            decision.update({
                "prediction": 0,
                "prediction_bool": False,
                "confidence": min(float(decision.get("confidence", 0.7)), 0.75),
                "decision_status": "forced_binary_non_vulnerable",
                "reason": "LLM residual allocation concerns were downgraded by the deterministic precision gate: visible dynamic capacity-growth/realloc guard is present and no stronger target-relevant memory-bound signal remains.",
                "explanation": "LLM residual allocation concerns were downgraded by the deterministic precision gate: visible dynamic capacity-growth/realloc guard is present and no stronger target-relevant memory-bound signal remains.",
                "precision_gate_override": "dynamic_growth_guarded_buffer",
            })
        st.add_trace("06_final_adjudication", decision)
        st.add_trace("final_decision", {"prediction": decision["prediction"], "confidence": decision["confidence"], "decision_status": decision["decision_status"]})
        return {
            "action": "final",
            "prediction": decision["prediction"],
            "confidence": decision["confidence"],
            "reason": decision["reason"],
            "decision_status": decision["decision_status"],
            "stage": "final_decision",
            "student_solution_version": STUDENT_AGENT_VERSION,
            "agentic_trace": st.trace,
            "final_adjudication": decision,
            "llm_config": decision.get("llm_config"),
            "llm_call_count": decision.get("llm_call_count", 0),
        }

    # ------------------------------------------------------------------
    # Optional LLM helpers. They are intentionally non-fatal.
    # ------------------------------------------------------------------


    def _stage_contract(self, stage: str, required: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "return_format": "Return exactly one JSON object. Do not use markdown fences.",
            "stage": stage,
            "required": required,
        }

    def _normalize_llm_queries_no_mark(self, st: SampleState, raw_queries: Any) -> List[Dict[str, Any]]:
        """Normalize LLM query suggestions without touching st.seen_query_keys."""
        if isinstance(raw_queries, dict):
            raw_queries = [raw_queries]
        if not isinstance(raw_queries, list):
            return []
        out: List[Dict[str, Any]] = []
        fn = st.fn
        for q in raw_queries:
            if isinstance(q, str):
                sym = q.strip().strip('`"')
                if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", sym):
                    q = {"kind": "variable_flow", "target_function": fn, "symbol": sym, "data_depth": 4, "max_nodes": 300}
                else:
                    continue
            if not isinstance(q, dict):
                continue
            kind = str(q.get("kind") or q.get("query_kind") or q.get("type") or "").strip()
            qt = str(q.get("query_text") or "")
            if not kind and qt:
                if qt.startswith("security_context"):
                    kind = "security_context"
                elif qt.startswith("semantic_facts"):
                    kind = "semantic_facts"
                elif qt.startswith("evidence_slice"):
                    kind = "evidence_slice"
                    m = re.search(r'target_statement="([^"]+)"', qt)
                    if m:
                        q["target_statement"] = m.group(1)
                elif qt.startswith("variable_flow"):
                    kind = "variable_flow"
                    m = re.search(r'symbol="([^"]+)"', qt)
                    if m:
                        q["symbol"] = m.group(1)
                elif qt.startswith("call_neighborhood"):
                    kind = "call_neighborhood"
                    m = re.search(r'direction="([^"]+)"', qt)
                    if m:
                        q["direction"] = m.group(1)
                elif qt.startswith("function_context"):
                    kind = "function_context"
            if kind not in {"security_context", "semantic_facts", "evidence_slice", "variable_flow", "call_neighborhood", "function_context"}:
                continue
            nq = dict(q)
            nq["kind"] = kind
            nq.setdefault("target_function", fn)
            nq.pop("query_text", None)
            if kind == "variable_flow" and not nq.get("symbol"):
                continue
            if kind == "evidence_slice" and not nq.get("target_statement"):
                if st.facts.suspicious_statements:
                    nq["target_statement"] = st.facts.suspicious_statements[0][:240]
                else:
                    continue
            if kind == "call_neighborhood":
                nq["direction"] = self._normalize_direction_value(nq.get("direction") or "both")
            nq.setdefault("max_nodes", 350)
            out.append(nq)
        # local-only dedupe
        seen: set[str] = set()
        deduped: List[Dict[str, Any]] = []
        for q in out:
            key = json.dumps(q, sort_keys=True, default=str)
            if key not in seen:
                seen.add(key); deduped.append(q)
        return deduped

    def _llm_query_plan_no_mark(self, st: SampleState, deterministic_queries: List[Dict[str, Any]], stage: str = "02_kg_query_planning") -> List[Dict[str, Any]]:
        obj = self._llm_json({
            "stage": stage,
            "task": f"{stage}: plan deterministic KG queries for the target function.",
            "function": st.fn,
            "source_excerpt": _compact(st.source, 5000),
            "source_facts": st.facts.as_dict(),
            "hypotheses": [h.as_dict() for h in st.hypotheses],
            "existing_deterministic_queries": deterministic_queries,
            "allowed_query_kinds": ["security_context", "semantic_facts", "evidence_slice", "variable_flow", "call_neighborhood", "function_context"],
            "query_schema_examples": [
                {"kind": "security_context", "target_function": st.fn, "depth": 3, "call_depth": 2, "data_depth": 4, "max_nodes": 350},
                {"kind": "evidence_slice", "target_function": st.fn, "target_statement": "<exact suspicious statement>", "relation_depth": 4, "data_depth": 4, "control_depth": 3, "call_depth": 2, "max_nodes": 350},
                {"kind": "variable_flow", "target_function": st.fn, "symbol": "<variable>", "data_depth": 4, "max_nodes": 300},
                {"kind": "call_neighborhood", "target_function": st.fn, "direction": "both", "call_depth": 2, "max_nodes": 350},
            ],
            "rules": [
                "Use only allowed query kinds.",
                "Do not output free-form strings like length/raw/header; wrap variables as variable_flow queries.",
                "Prioritize caller/input-control evidence, exact guard dominance evidence, and counter-evidence for high-risk hypotheses.",
                "Do not use labels, commit messages, sample IDs, or benchmark metadata.",
            ],
            "output_schema": {"queries": "list of query objects", "reason": "short string"},
        })
        if not isinstance(obj, dict):
            return []
        qs = obj.get("queries") or obj.get("follow_up_queries") or []
        return self._normalize_llm_queries_no_mark(st, qs)

    def _llm_query_plan(self, st: SampleState, deterministic_queries: List[Dict[str, Any]], stage: str = "02_kg_query_planning") -> List[Dict[str, Any]]:
        obj = self._llm_json({
            "stage": stage,
            "task": f"{stage}: plan deterministic KG queries for the target function.",
            "function": st.fn,
            "source_excerpt": _compact(st.source, 5000),
            "source_facts": st.facts.as_dict(),
            "hypotheses": [h.as_dict() for h in st.hypotheses],
            "existing_deterministic_queries": deterministic_queries,
            "allowed_query_kinds": ["security_context", "semantic_facts", "evidence_slice", "variable_flow", "call_neighborhood", "function_context"],
            "query_schema_examples": [
                {"kind": "security_context", "target_function": st.fn, "depth": 3, "call_depth": 2, "data_depth": 4, "max_nodes": 350},
                {"kind": "evidence_slice", "target_function": st.fn, "target_statement": "<exact suspicious statement>", "relation_depth": 4, "data_depth": 4, "control_depth": 3, "call_depth": 2, "max_nodes": 350},
                {"kind": "variable_flow", "target_function": st.fn, "symbol": "<variable>", "data_depth": 4, "max_nodes": 300},
                {"kind": "call_neighborhood", "target_function": st.fn, "direction": "both", "call_depth": 2, "max_nodes": 350},
            ],
            "rules": [
                "Use only allowed query kinds.",
                "Do not output free-form strings like length/raw/header; wrap variables as variable_flow queries.",
                "Prioritize caller/input-control evidence, exact guard dominance evidence, and counter-evidence for high-risk hypotheses.",
                "Do not use labels, commit messages, sample IDs, or benchmark metadata.",
            ],
            "output_schema": {"queries": "list of query objects", "reason": "short string"},
        })
        if not isinstance(obj, dict):
            return []
        qs = obj.get("queries") or obj.get("follow_up_queries") or []
        return self._normalize_llm_queries(st, qs)

    def _llm_verify(self, st: SampleState, deterministic: List[Verification], iter_no: int) -> Optional[List[Verification]]:
        obj = self._llm_json({
            "stage": f"04_hypothesis_verification_iter{iter_no}",
            "task": f"04_hypothesis_verification_iter{iter_no}: verify each hypothesis using source facts and KG evidence.",
            "function": st.fn,
            "source_excerpt": _compact(st.source, 5000),
            "source_facts": st.facts.as_dict(),
            "kg_evidence_excerpt": _compact(st.evidence_text, 12000),
            "hypotheses": [h.as_dict() for h in st.hypotheses],
            "deterministic_verifications": [v.as_dict() for v in deterministic],
            "rules": [
                "Separate local risk from confirmed vulnerability.",
                "Confirmed vulnerability requires input/control evidence, exact dangerous operation, missing/failed guard, unsafe reachable use, and concrete impact.",
                "A guard refutes a hypothesis only if it protects the same variable/value and dominates the dangerous operation.",
                "Do not treat residual unrelated robustness issues as target-relevant vulnerabilities unless proof is complete.",
                "Do not use labels, commit messages, sample IDs, or benchmark metadata.",
            ],
            "output_schema": {"verifications": [{"hypothesis_id": "HYP-01", "status": "confirmed_vulnerability|plausible_but_unproven|refuted_by_guard|insufficient_evidence", "local_risk_present": True, "confirmed_security_vulnerability": False, "proof": {"input_control":"", "dangerous_operation":"", "missing_or_failed_guard":"", "unsafe_use":"", "security_impact":"", "cited_evidence_ids": []}, "missing_evidence": [], "target_relevance": "high|medium|low|unrelated", "explanation": ""}]},
        })
        if not isinstance(obj, dict) or not isinstance(obj.get("verifications"), list):
            return None
        out: List[Verification] = []
        valid_ids = {h.hypothesis_id for h in st.hypotheses}
        for item in obj.get("verifications", [])[:10]:
            if not isinstance(item, dict):
                continue
            hid = str(item.get("hypothesis_id") or "").strip()
            if hid not in valid_ids:
                continue
            proof = item.get("proof") if isinstance(item.get("proof"), dict) else {}
            proof.setdefault("input_control", "")
            proof.setdefault("dangerous_operation", "")
            proof.setdefault("missing_or_failed_guard", "")
            proof.setdefault("unsafe_use", "")
            proof.setdefault("security_impact", "")
            proof.setdefault("cited_evidence_ids", [])
            out.append(Verification(
                hypothesis_id=hid,
                status=str(item.get("status") or "plausible_but_unproven"),
                local_risk_present=bool(item.get("local_risk_present", False)),
                confirmed_security_vulnerability=bool(item.get("confirmed_security_vulnerability", False)),
                proof=proof,
                missing_evidence=[str(x) for x in item.get("missing_evidence", []) if x is not None][:8],
                target_relevance=str(item.get("target_relevance") or "medium"),
                explanation=str(item.get("explanation") or "LLM verification."),
            ))
        return out or None

    def _llm_evidence_gap_queries(self, st: SampleState, deterministic_queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        unresolved = [v.as_dict() for v in st.verifications if v.local_risk_present and not v.confirmed_security_vulnerability]
        obj = self._llm_json({
            "stage": "04_evidence_gap",
            "task": "04_evidence_gap: decide whether more KG evidence is needed and propose targeted follow-up queries.",
            "function": st.fn,
            "source_facts": st.facts.as_dict(),
            "hypotheses": [h.as_dict() for h in st.hypotheses],
            "verifications": [v.as_dict() for v in st.verifications],
            "unresolved_verifications": unresolved,
            "existing_deterministic_queries": deterministic_queries,
            "rules": [
                "If proof elements are missing and queryable, propose KG queries.",
                "Prefer caller/input-source, variable_flow for exact operands, evidence_slice for exact dangerous statements, and call_neighborhood for reachability.",
                "Do not output duplicate or free-form symbol queries.",
            ],
            "output_schema": {"needs_more_evidence": True, "queries": "list of query objects", "reason": "short string"},
        })
        if not isinstance(obj, dict):
            return []
        if obj.get("needs_more_evidence") is False and not obj.get("queries") and not obj.get("follow_up_queries"):
            return []
        return self._normalize_llm_queries(st, obj.get("queries") or obj.get("follow_up_queries") or [])

    def _llm_counter_review(self, st: SampleState, deterministic: List[CounterFinding]) -> Optional[List[CounterFinding]]:
        obj = self._llm_json({
            "task": "05_counter_evidence_review: review whether guards/counter-evidence truly refute each hypothesis.",
            "function": st.fn,
            "source_excerpt": _compact(st.source, 5000),
            "source_facts": st.facts.as_dict(),
            "kg_evidence_excerpt": _compact(st.evidence_text, 12000),
            "hypotheses": [h.as_dict() for h in st.hypotheses],
            "verifications": [v.as_dict() for v in st.verifications],
            "deterministic_counter_findings": [c.as_dict() for c in deterministic],
            "rules": [
                "Counter-evidence must be relevant to the same variable/value and dominate the dangerous operation.",
                "Do not treat a generic wrapper/guard as refuting an unrelated hypothesis.",
                "Distinguish refutes from weakens.",
            ],
            "output_schema": {"findings": [{"hypothesis_id": "HYP-01", "refutes_or_weakens": "refutes|weakens|none", "recommended_status": "refuted_by_guard|plausible_but_unproven|confirmed_vulnerability|insufficient_evidence", "strongest_counterargument": "", "counter_evidence_ids": []}]},
        })
        if not isinstance(obj, dict) or not isinstance(obj.get("findings"), list):
            return None
        valid_ids = {h.hypothesis_id for h in st.hypotheses}
        out: List[CounterFinding] = []
        for item in obj.get("findings", [])[:10]:
            if not isinstance(item, dict):
                continue
            hid = str(item.get("hypothesis_id") or "").strip()
            if hid not in valid_ids:
                continue
            out.append(CounterFinding(
                hypothesis_id=hid,
                refutes_or_weakens=str(item.get("refutes_or_weakens") or "weakens"),
                recommended_status=str(item.get("recommended_status") or "plausible_but_unproven"),
                strongest_counterargument=str(item.get("strongest_counterargument") or "No decisive counter-evidence found."),
                counter_evidence_ids=[str(x) for x in item.get("counter_evidence_ids", []) if x is not None][:8],
            ))
        return out or None

    def _llm_counter_gap_queries(self, st: SampleState, deterministic_queries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        obj = self._llm_json({
            "task": "05_counter_gap: propose KG queries to verify or falsify counter-evidence and guard dominance.",
            "function": st.fn,
            "source_facts": st.facts.as_dict(),
            "verifications": [v.as_dict() for v in st.verifications],
            "counter_evidence_review": [c.as_dict() for c in st.counter_findings],
            "existing_deterministic_queries": deterministic_queries,
            "rules": [
                "Query wrapper/callee semantics when a wrapper is used as safety evidence.",
                "Query caller/context when input control or reachability is disputed.",
                "Use valid KG query objects only.",
            ],
            "output_schema": {"needs_counter_evidence": True, "queries": "list of query objects", "reason": "short string"},
        })
        if not isinstance(obj, dict):
            return []
        if obj.get("needs_counter_evidence") is False and not obj.get("queries"):
            return []
        return self._normalize_llm_queries(st, obj.get("queries") or obj.get("follow_up_queries") or [])

    def _normalize_llm_queries(self, st: SampleState, raw_queries: Any) -> List[Dict[str, Any]]:
        if isinstance(raw_queries, dict):
            raw_queries = [raw_queries]
        if not isinstance(raw_queries, list):
            return []
        out: List[Dict[str, Any]] = []
        fn = st.fn
        for q in raw_queries:
            if isinstance(q, str):
                sym = q.strip().strip('`"')
                if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", sym):
                    q = {"kind": "variable_flow", "target_function": fn, "symbol": sym, "data_depth": 4, "max_nodes": 300}
                else:
                    continue
            if not isinstance(q, dict):
                continue
            kind = str(q.get("kind") or q.get("query_kind") or q.get("type") or "").strip()
            # Accept function-call-style query_text by lightweight parsing.
            qt = str(q.get("query_text") or "")
            if not kind and qt:
                if qt.startswith("security_context"):
                    kind = "security_context"
                elif qt.startswith("semantic_facts"):
                    kind = "semantic_facts"
                elif qt.startswith("evidence_slice"):
                    kind = "evidence_slice"
                    m = re.search(r'target_statement="([^"]+)"', qt)
                    if m:
                        q["target_statement"] = m.group(1)
                elif qt.startswith("variable_flow"):
                    kind = "variable_flow"
                    m = re.search(r'symbol="([^"]+)"', qt)
                    if m:
                        q["symbol"] = m.group(1)
                elif qt.startswith("call_neighborhood"):
                    kind = "call_neighborhood"
                    m = re.search(r'direction="([^"]+)"', qt)
                    if m:
                        q["direction"] = m.group(1)
                elif qt.startswith("function_context"):
                    kind = "function_context"
            if kind not in {"security_context", "semantic_facts", "evidence_slice", "variable_flow", "call_neighborhood", "function_context"}:
                continue
            nq = dict(q)
            nq["kind"] = kind
            nq.setdefault("target_function", fn)
            nq.pop("query_text", None)
            if kind == "variable_flow" and not nq.get("symbol"):
                continue
            if kind == "evidence_slice" and not nq.get("target_statement"):
                if st.facts.suspicious_statements:
                    nq["target_statement"] = st.facts.suspicious_statements[0][:240]
                else:
                    continue
            if kind == "call_neighborhood":
                nq["direction"] = self._normalize_direction_value(nq.get("direction") or "both")
            nq.setdefault("max_nodes", 350)
            out.append(nq)
        return self._dedupe_queries(st, out)

    def _llm_final_decision(self, st: SampleState, deterministic: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        prompt = {
            "stage": "06_final_adjudication",
            "task": "Review the student agent evidence and return a binary final vulnerability decision as JSON.",
            "function": st.fn,
            "source_excerpt": _compact(st.source, 5000),
            "source_facts": st.facts.as_dict(),
            "hypotheses": [h.as_dict() for h in st.hypotheses],
            "verifications": [v.as_dict() for v in st.verifications],
            "counter_evidence_review": [c.as_dict() for c in st.counter_findings],
            "deterministic_decision": deterministic,
            "required_output": {
                "prediction": "0 for safe/fixed-non-vulnerable, 1 for vulnerable",
                "confidence": "number between 0 and 1",
                "decision_status": "confirmed_vulnerable | confirmed_non_vulnerable | forced_binary_vulnerable | forced_binary_non_vulnerable",
                "reason": "concise evidence-grounded explanation",
            },
            "rules": [
                "Do not use labels, commit messages, sample IDs, or benchmark metadata.",
                "Prefer source/KG-grounded evidence over speculation.",
                "Do not call residual unrelated robustness concerns target vulnerabilities unless proof is complete.",
                "Return JSON only.",
            ],
        }
        obj = self._llm_json(prompt)
        if not isinstance(obj, dict):
            return None
        try:
            pred = 1 if int(obj.get("prediction", deterministic.get("prediction", 0))) == 1 else 0
        except Exception:
            return None
        try:
            conf = float(obj.get("confidence", deterministic.get("confidence", 0.5)))
        except Exception:
            conf = float(deterministic.get("confidence", 0.5))
        status = str(obj.get("decision_status") or deterministic.get("decision_status") or ("forced_binary_vulnerable" if pred else "forced_binary_non_vulnerable"))
        reason = str(obj.get("reason") or obj.get("explanation") or deterministic.get("reason") or "LLM-reviewed final decision.")
        return {
            "prediction": pred,
            "prediction_bool": bool(pred),
            "confidence": max(0.0, min(1.0, conf)),
            "decision_status": status,
            "reason": reason[:4000],
            "explanation": reason[:4000],
            "llm_final_decision_raw": obj,
        }

    def _llm_hypotheses(self, st: SampleState, fallback: List[Hypothesis]) -> Optional[List[Hypothesis]]:
        prompt = {
            "stage": "01_source_only_hypothesis",
            "task": "Generate 3-6 concise vulnerability hypotheses from source only.",
            "function": st.fn,
            "source": _compact(st.source, 6000),
            "source_facts": st.facts.as_dict(),
            "required_schema": "list of objects with title, vulnerability_class, affected_code_region, risk_summary, family, required_proof_questions",
            "families": ["allocation", "memory_bounds", "parser_state", "protocol_validation", "access_control", "crypto_algorithmic", "path_file", "numeric_domain"],
            "rule": "Do not use labels or commit messages. Do not confirm vulnerabilities here.",
        }
        obj = self._llm_json(prompt)
        if not obj:
            return None
        items = obj.get("hypotheses") if isinstance(obj, dict) else obj
        if not isinstance(items, list):
            return None
        out: List[Hypothesis] = []
        for item in items[:6]:
            if not isinstance(item, dict):
                continue
            out.append(Hypothesis(
                hypothesis_id=f"HYP-{len(out)+1:02d}",
                title=str(item.get("title") or "LLM hypothesis"),
                vulnerability_class=str(item.get("vulnerability_class") or "Unknown"),
                affected_code_region=str(item.get("affected_code_region") or st.fn),
                risk_summary=str(item.get("risk_summary") or "Potential vulnerability requiring KG evidence."),
                family=str(item.get("family") or "unknown"),
                required_proof_questions=[str(x) for x in item.get("required_proof_questions", [])][:5],
            ))
        return out or None

    def _extract_json_from_text(self, content: str) -> Optional[Any]:
        """Robustly extract one JSON value from common LLM formats.

        Supports:
        - <answer>{...}</answer>
        - ```json ... ``` fences
        - raw object or array
        - prose before/after JSON
        Uses json.JSONDecoder.raw_decode so extra prose after JSON does not cause
        JSONDecodeError: Extra data.
        """
        text = content or ""
        m = re.search(r"<answer>\s*(.*?)\s*</answer>", text, flags=re.I | re.S)
        if m:
            text = m.group(1)
        fence = re.search(r"```(?:json)?\s*(.*?)```", text, flags=re.I | re.S)
        if fence:
            text = fence.group(1)
        text = text.strip()
        dec = json.JSONDecoder()
        candidates = []
        if text:
            candidates.append(text)
        for m in re.finditer(r"[\{\[]", text):
            candidates.append(text[m.start():])
        for cand in candidates:
            cand = cand.strip()
            if not cand:
                continue
            try:
                obj, _idx = dec.raw_decode(cand)
                return obj
            except Exception:
                continue
        return None

    def _llm_json(self, payload: Dict[str, Any]) -> Optional[Any]:
        if not self.llm_enabled:
            return None
        base = self.llm_api_base
        key = self.llm_api_key
        model = self.llm_model
        task = str(payload.get("task") or "student_llm_call")[:96]
        stage = str(payload.get("stage") or str(payload.get("task") or "student_llm_call").split(":", 1)[0])[:64]
        if not base or not key or not model:
            print(f"student.llm.skipped | stage={stage} | task={task} | reason=missing_config | base_present={bool(base)} | model_present={bool(model)} | key_env={getattr(self, 'llm_api_key_env', '')} | key_present={bool(key)}", flush=True)
            return None
        body = {
            "model": model,
            "messages": [
                {"role": "system", "content": (
                    "You are a vulnerability-analysis stage inside a student agent. "
                    "Return exactly one JSON value. Prefer the requested schema. "
                    "Do not include labels, commit messages, sample IDs, or benchmark metadata."
                )},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
            ],
            "temperature": 0.0,
            "max_tokens": int(self.config.get("llm_max_tokens", os.getenv("STUDENT_LLM_MAX_TOKENS", "4096"))),
        }
        req = urllib.request.Request(
            base + "/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            method="POST",
        )
        t0 = time.time()
        print(f"student.llm.start | stage={stage} | task={task} | base={base} | model={model} | key_env={getattr(self, 'llm_api_key_env', '')}", flush=True)
        try:
            with urllib.request.urlopen(req, timeout=180) as resp:
                raw = resp.read().decode("utf-8", "replace")
                data = json.loads(raw)
            content = data["choices"][0]["message"]["content"]
            obj = self._extract_json_from_text(content)
            if obj is None:
                print(f"student.llm.done | stage={stage} | task={task} | ok=False | reason=no_parseable_json | time={time.time()-t0:.2f}s", flush=True)
                return None
            self.llm_call_count += 1
            print(f"student.llm.done | stage={stage} | task={task} | ok=True | time={time.time()-t0:.2f}s", flush=True)
            return obj
        except urllib.error.HTTPError as exc:
            body_text = ""
            try:
                body_text = exc.read().decode("utf-8", "replace")[:200]
            except Exception:
                pass
            print(f"student.llm.done | stage={stage} | task={task} | ok=False | http_status={exc.code} | error={body_text} | time={time.time()-t0:.2f}s", flush=True)
            return None
        except Exception as exc:
            print(f"student.llm.done | stage={stage} | task={task} | ok=False | error={type(exc).__name__}: {str(exc)[:200]} | time={time.time()-t0:.2f}s", flush=True)
            return None


# ---------------------------------------------------------------------------
# Evaluator entry point
# ---------------------------------------------------------------------------


def build_agent(config: Dict[str, Any]):
    return FullStageAgenticStudent(config or {})
