from __future__ import annotations

import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .base import Backend, BuildDiagnostics
from ..discovery import discover_source_files
from ..graph_store import GraphStore
from ..models import Edge, Node, stable_id
from ..semantic import semantic_findings_for_statement

CONTROL_KEYWORDS = {"if", "for", "while", "switch", "catch", "else", "do", "return", "sizeof"}
CALL_EXCLUDE = CONTROL_KEYWORDS | {"case", "typedef", "struct", "class", "enum", "defined"}
KNOWN_EXTERNAL_CALLS = {
    "abs", "assert", "atoi", "atol", "calloc", "close", "exit", "fclose", "feof", "ferror", "fflush",
    "fgets", "fopen", "fprintf", "fread", "free", "fseek", "ftell", "fwrite", "malloc", "memcmp",
    "memcpy", "memmove", "memset", "perror", "printf", "putchar", "puts", "realloc", "read",
    "snprintf", "sprintf", "sscanf", "strcasecmp", "strcat", "strchr", "strcmp", "strcpy",
    "strdup", "strlen", "strncmp", "strncpy", "strstr", "strtol", "strtoul", "write",
    "sizeof", "htonl", "htons", "ntohl", "ntohs", "be16toh", "be32toh", "be64toh",
    "htobe16", "htobe32", "htobe64", "le16toh", "le32toh", "le64toh", "htole16", "htole32", "htole64",
}
COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.DOTALL | re.MULTILINE)
IDENT_RE = re.compile(r"\b[A-Za-z_]\w*\b")

DECL_PREFIXES = {
    "const", "static", "extern", "volatile", "register", "auto", "inline", "restrict", "signed", "unsigned",
    "long", "short", "struct", "enum", "union",
}
BUILTIN_TYPES = {
    "void", "char", "int", "float", "double", "bool", "size_t", "ssize_t", "FILE", "uint8_t", "uint16_t",
    "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t", "uintptr_t", "intptr_t",
}


@dataclass
class FunctionSpan:
    name: str
    signature: str
    start_offset: int
    body_start_offset: int
    body_end_offset: int
    line_start: int
    line_end: int
    return_type: str
    parameters: List[dict]


def mask_comments_preserve_newlines(text: str) -> tuple[str, List[dict]]:
    comments: List[dict] = []
    chars = list(text)
    for m in COMMENT_RE.finditer(text):
        raw = m.group(0)
        line_start = text.count("\n", 0, m.start()) + 1
        line_end = text.count("\n", 0, m.end()) + 1
        comments.append({"text": raw, "start": m.start(), "end": m.end(), "line_start": line_start, "line_end": line_end})
        for i in range(m.start(), m.end()):
            if chars[i] != "\n":
                chars[i] = " "
    return "".join(chars), comments


def line_offsets(text: str) -> List[int]:
    offsets = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            offsets.append(i + 1)
    return offsets


def offset_to_line(offsets: List[int], pos: int) -> int:
    # binary search without importing bisect in hot path? bisect is fine.
    import bisect
    return bisect.bisect_right(offsets, pos)


def line_text(text: str, line_no: int) -> str:
    lines = text.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1]
    return ""


def snippet_lines(text: str, start: int, end: int, padding: int = 0) -> str:
    lines = text.splitlines()
    lo = max(1, start - padding)
    hi = min(len(lines), end + padding)
    return "\n".join(f"{i:5d} | {lines[i-1]}" for i in range(lo, hi + 1))


def _find_matching_brace(text: str, open_pos: int) -> Optional[int]:
    depth = 0
    i = open_pos
    while i < len(text):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _last_top_level_boundary(text: str, before: int) -> int:
    candidates = [text.rfind(";", 0, before), text.rfind("}", 0, before), text.rfind("{", 0, before)]
    b = max(candidates)
    if b < 0:
        return 0
    return b + 1


def _clean_signature(sig: str) -> str:
    sig = re.sub(r"#.*", " ", sig)
    sig = re.sub(r"\s+", " ", sig.strip())
    return sig


def parse_parameters(param_text: str) -> List[dict]:
    param_text = param_text.strip()
    if not param_text or param_text == "void":
        return []
    params: List[dict] = []
    depth = 0
    cur = []
    parts = []
    for ch in param_text:
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
        if ch in "([<":
            depth += 1
        elif ch in ")]>":
            depth = max(0, depth - 1)
    if cur:
        parts.append("".join(cur).strip())
    for idx, p in enumerate(parts):
        p = re.sub(r"\s*=.*$", "", p).strip()
        # function pointer parameter: int (*cb)(int)
        fp = re.search(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)", p)
        if fp:
            name = fp.group(1)
            ptype = p.replace(name, "").strip()
        else:
            m = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", p)
            name = m.group(1) if m else f"param_{idx}"
            ptype = p[: m.start(1)].strip() if m else p
        params.append({"name": name, "type": ptype or "unknown", "signature": p, "index": idx})
    return params


def find_functions(masked: str, raw: str) -> List[FunctionSpan]:
    offsets = line_offsets(masked)
    functions: List[FunctionSpan] = []
    depth = 0
    i = 0
    seen_ranges: List[Tuple[int, int]] = []
    while i < len(masked):
        ch = masked[i]
        if ch == "{":
            if depth == 0:
                sig_start = _last_top_level_boundary(masked, i)
                while sig_start < i and masked[sig_start].isspace():
                    sig_start += 1
                sig = _clean_signature(masked[sig_start:i])
                sig_raw = raw[sig_start:i].strip()
                if "(" in sig and ")" in sig and not sig.endswith(("=", ",")):
                    # Extract candidate name immediately before the last top-level '('
                    open_paren = sig.rfind("(")
                    before = sig[:open_paren].strip()
                    name_match = re.search(r"([A-Za-z_]\w*)\s*$", before)
                    name = name_match.group(1) if name_match else ""
                    if name and name not in CONTROL_KEYWORDS and not before.endswith(("typedef", "struct", "enum", "union", "class")):
                        close_paren = sig.rfind(")")
                        param_text = sig[open_paren + 1 : close_paren]
                        return_type = before[: name_match.start(1)].strip() if name_match else "unknown"
                        body_end = _find_matching_brace(masked, i)
                        if body_end is not None:
                            line_start = offset_to_line(offsets, sig_start)
                            line_end = offset_to_line(offsets, body_end)
                            # Avoid nested/duplicate spans.
                            if not any(a <= sig_start <= b for a, b in seen_ranges):
                                functions.append(
                                    FunctionSpan(
                                        name=name,
                                        signature=_clean_signature(sig_raw or sig),
                                        start_offset=sig_start,
                                        body_start_offset=i,
                                        body_end_offset=body_end,
                                        line_start=line_start,
                                        line_end=line_end,
                                        return_type=return_type or "unknown",
                                        parameters=parse_parameters(param_text),
                                    )
                                )
                                seen_ranges.append((sig_start, body_end))
                            # Consume the whole function body. Otherwise the closing brace
                            # is skipped while depth remains non-zero, causing subsequent
                            # top-level functions to be missed.
                            i = body_end + 1
                            continue
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
        i += 1
    return functions


def extract_includes(masked: str) -> List[dict]:
    items = []
    for m in re.finditer(r"^[ \t]*#[ \t]*include[ \t]+([<\"])([^>\"]+)[>\"]", masked, re.MULTILINE):
        items.append({"name": m.group(2).strip(), "system": m.group(1) == "<", "line": masked.count("\n", 0, m.start()) + 1})
    return items


def extract_macros(masked: str) -> List[dict]:
    items = []
    for m in re.finditer(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)(.*)$", masked, re.MULTILINE):
        body = m.group(2).strip()
        items.append({"name": m.group(1), "body": body, "line": masked.count("\n", 0, m.start()) + 1})
    return items


def extract_types(masked: str) -> List[dict]:
    """Extract top-level struct/class/union/enum declarations and simple fields.

    Struct/class fields are represented as Field nodes, not globals. This is
    essential for scope-correct graphs: a field such as RaggedArray.length must
    not be conflated with a local variable named length inside count_rows/load.
    """
    items = []
    type_re = re.compile(r"\b(?:typedef\s+)?(struct|class|union|enum)\s+([A-Za-z_]\w*)?\s*\{", re.MULTILINE)
    for m in type_re.finditer(masked):
        kind = m.group(1)
        name = m.group(2) or f"anonymous_{kind}_{m.start()}"
        end = _find_matching_brace(masked, m.end() - 1)
        line_start = masked.count("\n", 0, m.start()) + 1
        line_end = masked.count("\n", 0, end) + 1 if end else line_start
        fields: List[dict] = []
        if end is not None and kind in {"struct", "class", "union"}:
            body = masked[m.end():end]
            base_line = masked.count("\n", 0, m.end()) + 1
            for rel_line, raw_line in enumerate(body.splitlines(), start=0):
                line = raw_line.strip()
                if not line or line.startswith(("#", "//", "/*")):
                    continue
                if ";" not in line or "(" in line or ")" in line:
                    continue
                for fld in likely_local_declaration(line):
                    fields.append({
                        "name": fld["name"],
                        "type": fld.get("type", "unknown"),
                        "declaration": fld.get("declaration", line),
                        "line": base_line + rel_line,
                        "qualified_name": f"{name}.{fld['name']}",
                    })
        items.append({
            "kind": kind,
            "name": name,
            "line_start": line_start,
            "line_end": line_end,
            "start_offset": m.start(),
            "end_offset": end if end is not None else m.end(),
            "fields": fields,
        })
    return items

def likely_local_declaration(stmt: str) -> List[dict]:
    s = stmt.strip().rstrip(";")
    if not s or s.startswith(("return", "if", "for", "while", "switch", "case", "goto")):
        return []
    if "(" in s and not re.match(r"^(?:const\s+)?(?:struct\s+)?[A-Za-z_]\w+(?:\s+[\*A-Za-z_]\w*)+\s*[=;,]", s):
        return []
    # Match declarations such as: const char *p = x, buf[10]; struct foo bar;
    decl_re = re.compile(
        r"^(?P<type>(?:(?:const|static|volatile|register|unsigned|signed|long|short|struct|enum|union)\s+)*[A-Za-z_]\w*(?:\s*\*)*)\s+(?P<rest>[^;]+)$"
    )
    m = decl_re.match(s)
    if not m:
        return []
    typ = m.group("type").strip()
    first = typ.split()[0].replace("*", "")
    if first not in BUILTIN_TYPES and first not in DECL_PREFIXES and not typ.startswith(("struct ", "enum ", "union ")):
        # User-defined types are possible, but avoid treating arbitrary expressions as declarations.
        if not re.search(r"\b[A-Z][A-Za-z_0-9]*\b", typ):
            return []
    rest = m.group("rest")
    out = []
    for part in rest.split(","):
        part = part.strip()
        part = re.sub(r"=.*$", "", part).strip()
        nm = re.search(r"\*?\s*([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?$", part)
        if nm:
            out.append({"name": nm.group(1), "type": typ, "declaration": stmt.strip()})
    return out



def canonical_c_type(type_text: str) -> str:
    """Return a rough canonical C/C++ type name for scope-aware field resolution."""
    t = re.sub(r"\b(const|volatile|restrict|static|extern|register|signed|unsigned)\b", " ", type_text or "")
    t = t.replace("*", " ").replace("&", " ")
    t = re.sub(r"\b(struct|class|union|enum)\b", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    parts = [p for p in t.split() if p]
    return parts[-1] if parts else "unknown"


def extract_member_accesses(stmt: str) -> List[dict]:
    """Find C/C++ member accesses such as self->length or obj.length."""
    out: List[dict] = []
    assign_pos = stmt.find("=") if "=" in stmt else -1
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*(->|\.)\s*([A-Za-z_]\w*)\b", stmt):
        out.append({
            "base": m.group(1),
            "operator": m.group(2),
            "field": m.group(3),
            "span": (m.start(), m.end()),
            "is_lhs": assign_pos >= 0 and m.start() < assign_pos,
            "text": m.group(0),
        })
    return out

def statement_kind(stmt: str) -> str:
    s = stmt.strip()
    if re.match(r"^return\b", s):
        return "ReturnStatement"
    if re.match(r"^if\s*\(|^else\s+if\s*\(|^switch\s*\(", s):
        return "Condition"
    if re.match(r"^(for|while)\s*\(|^do\b", s):
        return "Loop"
    if re.search(r"(?<![=!<>])=(?!=)", s):
        return "Assignment"
    if re.search(r"[+\-*/%&|^]=|\+\+|--", s):
        return "OperatorExpression"
    return "Statement"


def split_statements(masked_body: str, raw_body: str, body_start_line: int) -> List[dict]:
    statements: List[dict] = []
    current = []
    raw_current = []
    depth_paren = 0
    depth_brace = 0
    start_line: Optional[int] = None
    line_no = body_start_line
    for masked_line, raw_line in zip(masked_body.splitlines(), raw_body.splitlines()):
        stripped = masked_line.strip()
        if start_line is None and stripped:
            start_line = line_no
        current.append(masked_line)
        raw_current.append(raw_line)
        depth_paren += masked_line.count("(") - masked_line.count(")")
        depth_brace += masked_line.count("{") - masked_line.count("}")
        boundary = False
        if stripped.endswith(";") and depth_paren <= 0:
            boundary = True
        if re.match(r"^(if|for|while|switch)\s*\(.*\)\s*\{?\s*$", stripped) and depth_paren <= 0:
            boundary = True
        if stripped in {"{", "}"}:
            boundary = True
        if boundary and start_line is not None:
            raw_stmt = "\n".join(raw_current).strip()
            masked_stmt = "\n".join(current).strip()
            if masked_stmt and masked_stmt not in {"{", "}"}:
                statements.append({
                    "masked": masked_stmt,
                    "raw": raw_stmt,
                    "line_start": start_line,
                    "line_end": line_no,
                    "kind": statement_kind(masked_stmt),
                })
            current = []
            raw_current = []
            start_line = None
            depth_paren = 0
        line_no += 1
    if start_line is not None:
        raw_stmt = "\n".join(raw_current).strip()
        masked_stmt = "\n".join(current).strip()
        if masked_stmt and masked_stmt not in {"{", "}"}:
            statements.append({"masked": masked_stmt, "raw": raw_stmt, "line_start": start_line, "line_end": line_no - 1, "kind": statement_kind(masked_stmt)})
    return statements


def extract_calls(stmt: str) -> List[str]:
    calls = []
    for name in re.findall(r"\b([A-Za-z_]\w*)\s*\(", stmt):
        if name not in CALL_EXCLUDE:
            calls.append(name)
    return calls


def mask_function_spans(text: str, fns: List[FunctionSpan]) -> str:
    return mask_spans(text, [(fn.start_offset, fn.body_end_offset + 1) for fn in fns])


def mask_spans(text: str, spans: Iterable[Tuple[int, int]]) -> str:
    chars = list(text)
    for start, end in spans:
        for i in range(max(0, start), min(len(chars), end)):
            if chars[i] != "\n":
                chars[i] = " "
    return "".join(chars)

def extract_global_declarations(masked: str, fns: List[FunctionSpan], types: Optional[List[dict]] = None) -> List[dict]:
    """Extract simple top-level global declarations outside function bodies.

    This is deliberately conservative. It avoids function prototypes and complex
    initializers but captures the important retrieval case where a target
    function uses file/header-scope state.
    """
    type_spans = [(int(t.get("start_offset", 0)), int(t.get("end_offset", 0)) + 1) for t in (types or [])]
    top = mask_spans(masked, [(fn.start_offset, fn.body_end_offset + 1) for fn in fns] + type_spans)
    out: List[dict] = []
    for line_no, raw_line in enumerate(top.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("typedef"):
            continue
        if ";" not in line or "(" in line or ")" in line:
            continue
        if line.startswith(("return ", "if ", "for ", "while ", "switch ", "case ")):
            continue
        for decl in likely_local_declaration(line):
            # Avoid enum/struct forward declarations without a variable name.
            if decl.get("name") and decl["name"] not in BUILTIN_TYPES:
                out.append({**decl, "line": line_no})
    return out


class HeuristicBackend(Backend):
    name = "heuristic"

    def __init__(self, backend_label: str = "heuristic") -> None:
        self.backend_label = backend_label

    def build(self, source_dir: Path, out_dir: Path, logger) -> tuple[GraphStore, BuildDiagnostics]:
        source_dir = source_dir.resolve()
        diagnostics = BuildDiagnostics(
            backend_requested=self.backend_label,
            backend_used=self.backend_label,
            parser_confidence="medium" if self.backend_label != "heuristic" else "medium-low",
            tool_versions={"python": sys.version.split()[0]},
        )
        graph = GraphStore()
        discovered = discover_source_files(source_dir)
        diagnostics.skipped_files.extend(discovered.skipped)
        logger.info("Source directory: %s", source_dir)
        logger.info("Discovered %d C/C++ source/header files", len(discovered.source_files))
        if discovered.skipped:
            logger.info("Skipped %d files (see manifest/build.log for reasons)", len(discovered.skipped))
            for item in discovered.skipped[:50]:
                logger.debug("Skipped %s: %s", item["path"], item["reason"])

        project_name = source_dir.name
        project_id = stable_id("project", str(source_dir))
        graph.add_node(Node(id=project_id, type="Project", label=project_name, name=project_name, attrs={"source_path": str(source_dir)}))

        all_functions_by_name: Dict[str, str] = {}
        global_nodes_by_name: Dict[str, str] = {}
        field_nodes_by_qualified: Dict[str, str] = {}
        field_nodes_by_name: Dict[str, List[str]] = defaultdict(list)
        type_nodes_by_name: Dict[str, str] = {}
        per_file_function_spans: Dict[str, List[FunctionSpan]] = {}
        file_nodes: Dict[str, str] = {}
        source_text_by_rel: Dict[str, str] = {}

        counters = Counter()

        # First pass: file-level nodes and function definitions.
        for idx, path in enumerate(discovered.source_files, start=1):
            rel = path.relative_to(source_dir).as_posix()
            logger.info("[%d/%d] Parsing %s", idx, len(discovered.source_files), rel)
            try:
                raw = path.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:
                diagnostics.parse_errors.append({"file": rel, "error": f"read failed: {exc}"})
                logger.warning("Parse error reading %s: %s", rel, exc)
                continue
            source_text_by_rel[rel] = raw
            masked, comments = mask_comments_preserve_newlines(raw)
            file_id = stable_id("file", rel)
            file_nodes[rel] = file_id
            graph.add_node(Node(id=file_id, type="File", label=rel, name=rel, file=rel, attrs={"path": rel, "bytes": len(raw)}))
            graph.add_edge(Edge(project_id, file_id, "PROJECT_HAS_FILE"))

            for inc in extract_includes(masked):
                node_id = stable_id("include", rel, inc["name"], inc["line"])
                graph.add_node(Node(id=node_id, type="Include", label=inc["name"], name=inc["name"], file=rel, line_start=inc["line"], line_end=inc["line"], code=line_text(raw, inc["line"]), attrs={"system": inc["system"]}))
                graph.add_edge(Edge(file_id, node_id, "FILE_INCLUDES_FILE"))
                counters["includes"] += 1

            for macro in extract_macros(masked):
                node_id = stable_id("macro", rel, macro["name"], macro["line"])
                graph.add_node(Node(id=node_id, type="Macro", label=macro["name"], name=macro["name"], file=rel, line_start=macro["line"], line_end=macro["line"], code=line_text(raw, macro["line"]), attrs={"body": macro["body"]}))
                graph.add_edge(Edge(file_id, node_id, "FILE_HAS_MACRO"))
                counters["macros"] += 1

            types = extract_types(masked)
            for typ in types:
                ntype = "Struct/Class" if typ["kind"] in {"struct", "class", "union"} else "Type"
                node_id = stable_id("type", rel, typ["kind"], typ["name"], typ["line_start"])
                type_nodes_by_name.setdefault(typ["name"], node_id)
                graph.add_node(Node(id=node_id, type=ntype, label=typ["name"], name=typ["name"], file=rel, line_start=typ["line_start"], line_end=typ["line_end"], code=snippet_lines(raw, typ["line_start"], typ["line_end"]), attrs={"kind": typ["kind"]}))
                graph.add_edge(Edge(file_id, node_id, "FILE_HAS_TYPE"))
                counters["types"] += 1
                for field in typ.get("fields", []):
                    qname = field.get("qualified_name") or f"{typ['name']}.{field['name']}"
                    field_id = stable_id("field", rel, typ["name"], field["name"], field["line"])
                    field_nodes_by_qualified.setdefault(qname, field_id)
                    field_nodes_by_name[field["name"]].append(field_id)
                    graph.add_node(Node(id=field_id, type="Field", label=qname, name=field["name"], file=rel, line_start=field["line"], line_end=field["line"], code=line_text(raw, field["line"]), attrs={"type": field.get("type", "unknown"), "declaration": field.get("declaration", ""), "qualified_name": qname, "owner_type": typ["name"], "scope_kind": "field"}))
                    graph.add_edge(Edge(node_id, field_id, "TYPE_HAS_FIELD"))
                    graph.add_edge(Edge(node_id, field_id, "AST_CHILD", attrs={"field": True}))
                    counters["fields"] += 1

            # Comments are stored as non-executable nodes and never parsed as statements/identifiers.
            for cidx, c in enumerate(comments):
                text = c["text"].strip()
                if not text:
                    continue
                cid = stable_id("comment", rel, cidx, c["line_start"], text[:60])
                graph.add_node(Node(id=cid, type="Comment", label=(text[:50] + "…") if len(text) > 50 else text, file=rel, line_start=c["line_start"], line_end=c["line_end"], code=text, attrs={"non_executable": True}))
                graph.add_edge(Edge(file_id, cid, "AST_CHILD", attrs={"comment_attachment": "file"}))
                counters["comments"] += 1

            try:
                fns = find_functions(masked, raw)
            except Exception as exc:
                diagnostics.parse_errors.append({"file": rel, "error": f"function extraction failed: {exc}"})
                logger.warning("Function extraction failed for %s: %s", rel, exc)
                fns = []
            per_file_function_spans[rel] = fns
            logger.info("    functions=%d includes=%d macros=%d comments=%d", len(fns), len(extract_includes(masked)), len(extract_macros(masked)), len(comments))
            for fn in fns:
                fid = stable_id("function", rel, fn.name, fn.line_start)
                all_functions_by_name.setdefault(fn.name, fid)
                graph.add_node(Node(id=fid, type="Function", label=fn.name, name=fn.name, file=rel, function=fn.name, line_start=fn.line_start, line_end=fn.line_end, code=snippet_lines(raw, fn.line_start, min(fn.line_end, fn.line_start + 30)), attrs={"signature": fn.signature, "return_type": fn.return_type, "defined": True}))
                graph.add_edge(Edge(file_id, fid, "FILE_HAS_FUNCTION"))
                graph.add_edge(Edge(file_id, fid, "AST_CHILD"))
                counters["functions"] += 1

            for gd in extract_global_declarations(masked, fns, types):
                gid = stable_id("global", rel, gd["name"], gd["line"], gd.get("declaration", ""))
                global_nodes_by_name.setdefault(gd["name"], gid)
                graph.add_node(Node(id=gid, type="GlobalVariable", label=gd["name"], name=gd["name"], file=rel, line_start=gd["line"], line_end=gd["line"], code=line_text(raw, gd["line"]), attrs={"type": gd.get("type", "unknown"), "declaration": gd.get("declaration", "")}))
                graph.add_edge(Edge(file_id, gid, "FILE_HAS_GLOBAL"))
                graph.add_edge(Edge(file_id, gid, "AST_CHILD", attrs={"global_scope": True}))
                counters["global_variables"] += 1

        # Second pass: function internals. Calls can now resolve against all defined functions.
        for rel, fns in per_file_function_spans.items():
            raw = source_text_by_rel[rel]
            masked, _comments = mask_comments_preserve_newlines(raw)
            offsets = line_offsets(raw)
            for fn in fns:
                fid = stable_id("function", rel, fn.name, fn.line_start)
                parameter_nodes: Dict[str, str] = {}
                parameter_types: Dict[str, str] = {}
                local_nodes_by_name: Dict[str, List[dict]] = defaultdict(list)
                variable_type_by_id: Dict[str, str] = {}
                last_def_stmt_by_varid: Dict[str, str] = {}

                def resolve_variable(symbol: str, at_line: int) -> Optional[str]:
                    defs = [d for d in local_nodes_by_name.get(symbol, []) if d["line"] <= at_line]
                    if defs:
                        return sorted(defs, key=lambda d: d["line"])[-1]["id"]
                    return parameter_nodes.get(symbol)

                def visible_symbol_names(at_line: int) -> Set[str]:
                    names = set(parameter_nodes)
                    for nm, defs in local_nodes_by_name.items():
                        if any(d["line"] <= at_line for d in defs):
                            names.add(nm)
                    return names

                for p in fn.parameters:
                    pid = stable_id("param", rel, fn.name, p["name"], p["index"], fn.line_start)
                    parameter_nodes[p["name"]] = pid
                    parameter_types[p["name"]] = p["type"]
                    variable_type_by_id[pid] = p["type"]
                    qname = f"{fn.name}::{p['name']}"
                    graph.add_node(Node(id=pid, type="FunctionParameter", label=p["name"], name=p["name"], file=rel, function=fn.name, line_start=fn.line_start, line_end=fn.line_start, code=p["signature"], attrs={"type": p["type"], "index": p["index"], "qualified_name": qname, "scope_kind": "parameter", "scope_owner": fn.name}))
                    graph.add_edge(Edge(fid, pid, "FUNCTION_HAS_PARAMETER"))
                    graph.add_edge(Edge(fid, pid, "AST_CHILD"))
                    owner_type = canonical_c_type(p["type"])
                    if owner_type in type_nodes_by_name:
                        graph.add_edge(Edge(pid, type_nodes_by_name[owner_type], "HAS_TYPE", attrs={"type_name": owner_type}))
                    counters["parameters"] += 1

                body_masked = masked[fn.body_start_offset + 1 : fn.body_end_offset]
                body_raw = raw[fn.body_start_offset + 1 : fn.body_end_offset]
                body_start_line = offset_to_line(line_offsets(masked), fn.body_start_offset) + 1
                statements = split_statements(body_masked, body_raw, body_start_line)
                previous_stmt_id: Optional[str] = None
                recent_raw_lines: List[str] = []
                logger.debug("Function %s:%s statements=%d", rel, fn.name, len(statements))
                for sidx, stmt in enumerate(statements):
                    stype = stmt["kind"]
                    sid = stable_id("stmt", rel, fn.name, stmt["line_start"], sidx, stmt["masked"][:80])
                    label = f"{stype}@{stmt['line_start']}"
                    graph.add_node(Node(id=sid, type=stype, label=label, file=rel, function=fn.name, line_start=stmt["line_start"], line_end=stmt["line_end"], code=stmt["raw"], attrs={"statement_index": sidx, "parser": self.backend_label}))
                    graph.add_edge(Edge(fid, sid, "FUNCTION_HAS_STATEMENT", attrs={"order": sidx}))
                    graph.add_edge(Edge(fid, sid, "AST_CHILD", attrs={"order": sidx}))
                    if previous_stmt_id:
                        graph.add_edge(Edge(previous_stmt_id, sid, "CFG_NEXT", attrs={"order": sidx}))
                    previous_stmt_id = sid
                    counters["statements"] += 1

                    if stype == "ReturnStatement":
                        graph.add_edge(Edge(fid, sid, "RETURNS"))
                    if stype in {"Condition", "Loop"}:
                        graph.add_edge(Edge(sid, fid, "CONTROLS", attrs={"control_scope": "heuristic_function_scope"}))

                    # Local variable definitions. Each declaration gets a scope-qualified identity.
                    # A local `length` in count_rows and a local `length` in load are different nodes;
                    # neither should resolve to RaggedArray.length merely because the spelling matches.
                    decls = likely_local_declaration(stmt["masked"])
                    for decl in decls:
                        lname = decl["name"]
                        lid = stable_id("local", rel, fn.name, lname, stmt["line_start"], stmt["masked"][:80])
                        if not any(d["id"] == lid for d in local_nodes_by_name[lname]):
                            local_nodes_by_name[lname].append({"id": lid, "line": stmt["line_start"], "type": decl["type"]})
                            variable_type_by_id[lid] = decl["type"]
                            qname = f"{fn.name}::{lname}@L{stmt['line_start']}"
                            graph.add_node(Node(id=lid, type="LocalVariable", label=lname, name=lname, file=rel, function=fn.name, line_start=stmt["line_start"], line_end=stmt["line_end"], code=decl["declaration"], attrs={"type": decl["type"], "qualified_name": qname, "scope_kind": "local", "scope_owner": fn.name, "declaration_line": stmt["line_start"]}))
                            graph.add_edge(Edge(fid, lid, "FUNCTION_HAS_LOCAL"))
                            graph.add_edge(Edge(sid, lid, "DEFINES_VARIABLE", attrs={"scope_resolved": True}))
                            owner_type = canonical_c_type(decl["type"])
                            if owner_type in type_nodes_by_name:
                                graph.add_edge(Edge(lid, type_nodes_by_name[owner_type], "HAS_TYPE", attrs={"type_name": owner_type}))
                            counters["local_variables"] += 1
                        last_def_stmt_by_varid[lid] = sid

                    # Assignment definitions for known variables. Global assignment is only used
                    # if no local/parameter shadows the name in the current function scope.
                    assign_m = re.match(r"\s*([A-Za-z_]\w*)\s*(?:[+\-*/%&|^]?=)", stmt["masked"])
                    if assign_m:
                        v = assign_m.group(1)
                        vid = resolve_variable(v, stmt["line_start"])
                        if vid:
                            graph.add_edge(Edge(sid, vid, "DEFINES_VARIABLE", attrs={"scope_resolved": True}))
                            last_def_stmt_by_varid[vid] = sid
                        elif v in global_nodes_by_name:
                            graph.add_edge(Edge(sid, global_nodes_by_name[v], "DEFINES_GLOBAL", attrs={"symbol": v, "scope_resolved": True}))

                    # Member/field access. These are distinct from globals. A plain identifier
                    # `length` is not the same as `self->length` or `RaggedArray.length`.
                    member_accesses = extract_member_accesses(stmt["masked"])
                    member_field_names = {m["field"] for m in member_accesses}
                    for macc in member_accesses:
                        base_id = resolve_variable(macc["base"], stmt["line_start"])
                        base_type = canonical_c_type(variable_type_by_id.get(base_id or "", parameter_types.get(macc["base"], "")))
                        target_field = None
                        resolution = "unresolved"
                        qname = f"{base_type}.{macc['field']}" if base_type and base_type != "unknown" else ""
                        if qname and qname in field_nodes_by_qualified:
                            target_field = field_nodes_by_qualified[qname]
                            resolution = "base_type"
                        elif len(field_nodes_by_name.get(macc["field"], [])) == 1:
                            target_field = field_nodes_by_name[macc["field"]][0]
                            resolution = "unique_field_name"
                        if target_field:
                            etype = "DEFINES_FIELD" if macc.get("is_lhs") else "USES_FIELD"
                            graph.add_edge(Edge(sid, target_field, etype, attrs={"base_symbol": macc["base"], "operator": macc["operator"], "base_type": base_type, "resolution": resolution, "scope_resolved": True}))
                            if base_id:
                                graph.add_edge(Edge(base_id, target_field, "ACCESSES_FIELD", attrs={"via_statement": sid, "base_type": base_type, "field": macc["field"]}))
                            counters["field_accesses"] += 1

                    # Uses and def-use are scope-aware. They only bind to visible parameters/locals.
                    identifiers = set(IDENT_RE.findall(stmt["masked"]))
                    for sym in visible_symbol_names(stmt["line_start"]):
                        if sym in identifiers:
                            vid = resolve_variable(sym, stmt["line_start"])
                            if not vid:
                                continue
                            graph.add_edge(Edge(sid, vid, "USES_VARIABLE", attrs={"scope_resolved": True}))
                            if vid in last_def_stmt_by_varid and last_def_stmt_by_varid[vid] != sid:
                                graph.add_edge(Edge(last_def_stmt_by_varid[vid], sid, "DEF_USE", attrs={"symbol": sym, "variable_id": vid, "scope_resolved": True}))
                                graph.add_edge(Edge(sid, last_def_stmt_by_varid[vid], "DATA_DEPENDS_ON", attrs={"symbol": sym, "variable_id": vid, "scope_resolved": True}))
                    for sym, gid in global_nodes_by_name.items():
                        if sym in identifiers:
                            if sym in visible_symbol_names(stmt["line_start"]):
                                counters["shadowed_global_name_suppressed"] += 1
                                continue
                            if sym in member_field_names:
                                counters["field_name_global_suppressed"] += 1
                                continue
                            graph.add_edge(Edge(sid, gid, "USES_GLOBAL", attrs={"symbol": sym, "scope_resolved": True}))

                    # Calls and call expression nodes. A call name that resolves to a visible
                    # local/parameter is modeled as an indirect function-pointer call, not as an
                    # external function merely because the spelling is e.g. `read`.
                    calls = extract_calls(stmt["masked"])
                    for cidx, call_name in enumerate(calls):
                        call_id = stable_id("call", rel, fn.name, stmt["line_start"], cidx, call_name)
                        callee_var = resolve_variable(call_name, stmt["line_start"])
                        call_attrs = {"callee": call_name}
                        if callee_var:
                            call_attrs.update({"callee_kind": "function_pointer_or_callable_variable", "callee_variable_id": callee_var, "scope_resolved": True})
                        graph.add_node(Node(id=call_id, type="CallExpression", label=call_name, name=call_name, file=rel, function=fn.name, line_start=stmt["line_start"], line_end=stmt["line_end"], code=stmt["raw"], attrs=call_attrs))
                        graph.add_edge(Edge(sid, call_id, "AST_CHILD"))
                        graph.add_edge(Edge(sid, call_id, "STATEMENT_CALLS"))
                        if callee_var:
                            graph.add_edge(Edge(call_id, callee_var, "CALLS_INDIRECT", attrs={"call_site_line": stmt["line_start"], "callee_symbol": call_name, "scope_resolved": True}))
                            graph.add_edge(Edge(fid, callee_var, "CALLS_INDIRECT", attrs={"call_site_line": stmt["line_start"], "via_statement": sid, "callee_symbol": call_name, "scope_resolved": True}))
                            counters["indirect_calls"] += 1
                            counters["calls"] += 1
                            continue
                        target = all_functions_by_name.get(call_name)
                        unresolved = False
                        known_external = False
                        if not target:
                            target = stable_id("external_function", call_name)
                            known_external = call_name in KNOWN_EXTERNAL_CALLS
                            unresolved = not known_external
                            status = "known_external" if known_external else "unresolved_project_or_external"
                            graph.add_node(Node(id=target, type="Function", label=call_name, name=call_name, attrs={"defined": False, "external_or_unresolved": True, "resolution_status": status}))
                        graph.add_edge(Edge(fid, target, "CALLS", attrs={"call_site_line": stmt["line_start"], "unresolved": unresolved, "known_external": known_external, "via_statement": sid, "scope_resolved": True}))
                        graph.add_edge(Edge(call_id, target, "CALLS", attrs={"call_site_line": stmt["line_start"], "unresolved": unresolved, "known_external": known_external, "scope_resolved": True}))
                        counters["calls"] += 1
                        if known_external:
                            counters["known_external_calls"] += 1
                        if unresolved:
                            counters["unresolved_calls"] += 1

                    # Literals.
                    for lidx, lit in enumerate(re.findall(r"\b\d+(?:u|U|l|L|ul|UL)?\b|\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'", stmt["masked"])):
                        lid = stable_id("literal", rel, fn.name, stmt["line_start"], lidx, lit)
                        graph.add_node(Node(id=lid, type="Literal", label=lit[:30], name=lit[:50], file=rel, function=fn.name, line_start=stmt["line_start"], line_end=stmt["line_end"], code=lit))
                        graph.add_edge(Edge(sid, lid, "AST_CHILD"))
                        counters["literals"] += 1

                    # Semantic overlays from non-comment masked statement.
                    findings = semantic_findings_for_statement(stmt["masked"], stmt["line_start"], recent_raw_lines[-3:], stype)
                    for fidx, finding in enumerate(findings):
                        fact_id = stable_id("semantic", rel, fn.name, stmt["line_start"], fidx, finding.rule_name, finding.evidence)
                        graph.add_node(Node(
                            id=fact_id,
                            type="SemanticFact",
                            label=finding.fact_type,
                            name=finding.rule_name,
                            file=rel,
                            function=fn.name,
                            line_start=finding.line_start,
                            line_end=finding.line_end,
                            code=finding.evidence,
                            attrs={
                                "rule_name": finding.rule_name,
                                "fact_type": finding.fact_type,
                                "severity": finding.severity,
                                "detail": finding.detail,
                                "confidence": finding.confidence,
                                "source_node_id": sid,
                            },
                        ))
                        graph.add_edge(Edge(sid, fact_id, "HAS_SEMANTIC_FACT", attrs={"rule_name": finding.rule_name}))
                        graph.add_edge(Edge(fid, fact_id, "SEMANTICALLY_RELATED", attrs={"rule_name": finding.rule_name}))
                        counters["semantic_facts"] += 1
                    recent_raw_lines.append(stmt["masked"])

        diagnostics.counters.update(counters)
        self._quality_diagnostics(graph, diagnostics)
        logger.info("Extraction summary: functions=%d statements=%d calls=%d locals=%d globals=%d semantic_facts=%d", counters["functions"], counters["statements"], counters["calls"], counters["local_variables"], counters["global_variables"], counters["semantic_facts"])
        logger.info("Graph summary: nodes=%d edges=%d", len(graph.nodes), len(graph.edges))
        return graph, diagnostics

    def _quality_diagnostics(self, graph: GraphStore, diagnostics: BuildDiagnostics) -> None:
        degree = graph.degree()
        unresolved = sum(1 for e in graph.edges.values() if e.type == "CALLS" and e.attrs.get("unresolved"))
        known_external = sum(1 for e in graph.edges.values() if e.type == "CALLS" and e.attrs.get("known_external"))
        source_optional = {"Project", "File", "Function", "Include"}
        no_source = sum(1 for n in graph.nodes.values() if n.type not in source_optional and not n.line_start)
        orphan_stmts = sum(1 for n in graph.nodes.values() if n.type in {"Statement", "Assignment", "ReturnStatement", "Condition", "Loop", "OperatorExpression"} and degree[n.id] <= 1)
        definition_like = {"Function", "Macro", "Struct/Class", "Type", "LocalVariable", "FunctionParameter", "GlobalVariable", "Field"}
        names = Counter((n.type, n.file, n.function, n.name) for n in graph.nodes.values() if n.name and n.type in definition_like and not n.attrs.get("external_or_unresolved"))
        dup = sum(1 for (_k, count) in names.items() if count > 1)
        self_calls = sum(1 for e in graph.edges.values() if e.type == "CALLS" and e.source == e.target)
        comment_facts = 0
        for n in graph.nodes.values():
            if n.type == "SemanticFact" and n.code and n.code.strip().startswith(("//", "/*")):
                comment_facts += 1
        diagnostics.counters.update({
            "unresolved_calls": unresolved,
            "known_external_call_edges": known_external,
            "nodes_without_source_lines": no_source,
            "orphan_statements": orphan_stmts,
            "duplicate_looking_names": dup,
            "self_call_artifacts": self_calls,
            "semantic_facts_generated_from_comments": comment_facts,
        })
        if self.backend_label == "heuristic":
            diagnostics.quality_warnings.append({"code": "fallback_parser_used", "message": "Heuristic fallback parser was used. Install Joern or tree-sitter optional dependencies for stronger parsing."})
        if unresolved:
            diagnostics.quality_warnings.append({"code": "unresolved_calls", "count": unresolved, "message": "Some calls did not resolve to in-project function definitions or known external APIs."})
        if comment_facts:
            diagnostics.quality_warnings.append({"code": "comment_semantic_facts", "count": comment_facts, "message": "Semantic facts appear to have been generated from comments; inspect parser masking."})
        if orphan_stmts:
            diagnostics.quality_warnings.append({"code": "orphan_statements", "count": orphan_stmts, "message": "Some statement nodes have weak connectivity."})
