from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ExtractedStatement:
    statement_id: str
    text: str
    line_start: int
    line_end: int
    calls: list[str] = field(default_factory=list)
    identifiers: list[str] = field(default_factory=list)
    defines_variables: list[str] = field(default_factory=list)
    uses_variables: list[str] = field(default_factory=list)


@dataclass
class ExtractedFunction:
    function_id: str
    name: str
    signature: str
    body: str
    relpath: str
    line_start: int
    line_end: int
    statements: list[ExtractedStatement] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    local_variables: dict[str, dict] = field(default_factory=dict)
    parameters: list[str] = field(default_factory=list)


CONTROL_WORDS = {"if", "for", "while", "switch", "return", "sizeof", "catch", "do"}
C_KEYWORDS = CONTROL_WORDS | {
    "int", "char", "short", "long", "float", "double", "void", "unsigned", "signed", "const", "static", "extern",
    "struct", "union", "enum", "typedef", "volatile", "register", "auto", "break", "continue", "case", "default", "goto",
    "else", "return", "switch", "sizeof", "NULL", "nullptr", "true", "false", "FILE", "size_t", "uint64_t", "uint32_t",
}
CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
IDENT_RE = re.compile(r"\b[A-Za-z_]\w*\b")
# Deliberately bounded and applied only to a short header candidate, never to the
# whole source file. The previous implementation used one large regex over the
# entire file, which could appear to hang on macro-heavy C/C++ headers.
FUNC_NAME_RE = re.compile(r"(?s)\b(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*$")
FUNC_CALLISH_RE = re.compile(r"(?s)\b(?P<name>[A-Za-z_]\w*)\s*\([^{}]*?\)")
MAX_HEADER_SCAN_CHARS = 1200
VAR_DECL_RE = re.compile(
    r"""
    ^\s*(?P<prefix>(?:const\s+|volatile\s+|static\s+|extern\s+|register\s+|unsigned\s+|signed\s+|struct\s+\w+\s+|enum\s+\w+\s+|union\s+\w+\s+|[A-Za-z_]\w*\s+)+)
    (?P<stars>[*\s]*)
    (?P<name>[A-Za-z_]\w*)
    (?:\s*\[[^\]]*\])?
    (?:\s*=|\s*;|\s*,)
    """,
    re.VERBOSE,
)


def _line_no(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def strip_comments(text: str) -> str:
    """Remove comments while preserving character positions as much as possible."""
    out: list[str] = []
    i = 0
    in_str: str | None = None
    escape = False
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_str:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in {'"', "'"}:
            in_str = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            out.extend([" ", " "])
            i += 2
            while i < len(text) and text[i] != "\n":
                out.append(" ")
                i += 1
            if i < len(text):
                out.append("\n")
                i += 1
            continue
        if ch == "/" and nxt == "*":
            out.extend([" ", " "])
            i += 2
            while i + 1 < len(text) and not (text[i] == "*" and text[i + 1] == "/"):
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            if i + 1 < len(text):
                out.extend([" ", " "])
                i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _find_matching_brace(text: str, open_pos: int) -> int | None:
    depth = 0
    i = open_pos
    in_str: str | None = None
    escape = False
    while i < len(text):
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_str:
                in_str = None
        else:
            if ch in {'"', "'"}:
                in_str = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return None


def _extract_calls(text: str) -> list[str]:
    calls: list[str] = []
    for m in CALL_RE.finditer(text):
        name = m.group(1)
        if name not in CONTROL_WORDS and name not in calls:
            calls.append(name)
    return calls


def _extract_identifiers(text: str) -> list[str]:
    out: list[str] = []
    for ident in IDENT_RE.findall(text):
        if ident not in C_KEYWORDS and not ident.isupper() and ident not in out:
            out.append(ident)
    return out


def _declared_variable(text: str) -> str | None:
    stripped = text.strip()
    # Avoid function signatures and control statements.
    if stripped.startswith(tuple(w + "(" for w in CONTROL_WORDS)):
        return None
    m = VAR_DECL_RE.match(stripped.replace("\n", " "))
    if not m:
        return None
    name = m.group("name")
    if name in C_KEYWORDS:
        return None
    # A declaration immediately followed by '(' is likely a function/cast-like fragment.
    after = stripped[m.end("name"):].lstrip()
    if after.startswith("("):
        return None
    return name


def _header_candidate(clean: str, open_pos: int) -> str:
    """Return a bounded candidate function header immediately before ``{``."""
    start = max(0, open_pos - MAX_HEADER_SCAN_CHARS)
    window = clean[start:open_pos]
    hard_cut = max(window.rfind("}"), window.rfind("{"))
    if hard_cut >= 0:
        window = window[hard_cut + 1 :]

    matches = list(FUNC_CALLISH_RE.finditer(window))
    if matches:
        m = matches[-1]
        line_start = window.rfind("\n", 0, m.start()) + 1
        prev_line_start = window.rfind("\n", 0, max(0, line_start - 1)) + 1
        prev_line = window[prev_line_start: max(0, line_start - 1)].strip()
        if prev_line and ";" not in prev_line and "(" not in prev_line and ")" not in prev_line:
            line_start = prev_line_start
        window = window[line_start:]
    else:
        cut = window.rfind(";")
        if cut >= 0:
            window = window[cut + 1 :]
    return window.strip()


def _function_name_from_header(header: str) -> str | None:
    if not header:
        return None
    # Drop preprocessor lines that may appear directly above a function
    # definition in the bounded header window. Keeping them made ordinary
    # one-file examples such as "#include ...\nint f(...) {" invisible to
    # the lightweight fallback parser.
    lines = [ln for ln in header.splitlines() if not ln.strip().startswith("#")]
    stripped = "\n".join(lines).strip()
    if not stripped:
        return None
    first_word = stripped.split(None, 1)[0] if stripped.split() else ""
    if first_word in CONTROL_WORDS:
        return None
    if "=" in stripped and stripped.rfind("=") > stripped.rfind(")"):
        return None

    if stripped.count("(") == stripped.count(")"):
        m = FUNC_NAME_RE.search(stripped)
        if m:
            name = m.group("name")
            if name not in CONTROL_WORDS:
                prefix = stripped[: m.start("name")].strip()
                if prefix or name.startswith("~"):
                    return name

    matches = list(FUNC_CALLISH_RE.finditer(stripped))
    for m in reversed(matches):
        name = m.group("name")
        if name in CONTROL_WORDS:
            continue
        prefix = stripped[: m.start("name")].strip()
        if prefix or "\n" in stripped[: m.start("name")]:
            return name
    return None


def _extract_parameters(signature: str) -> list[str]:
    start = signature.find("(")
    end = signature.rfind(")")
    if start < 0 or end <= start:
        return []
    params = signature[start + 1:end]
    out: list[str] = []
    for part in params.split(","):
        part = part.strip()
        if not part or part == "void":
            continue
        ids = [x for x in IDENT_RE.findall(part) if x not in C_KEYWORDS]
        if ids:
            name = ids[-1]
            if name not in out:
                out.append(name)
    return out


def split_statements(body: str, relpath: str, func_name: str, func_line_start: int) -> list[ExtractedStatement]:
    statements: list[ExtractedStatement] = []
    current: list[str] = []
    current_start_line = func_line_start
    line = func_line_start
    stmt_idx = 0
    declared_so_far: set[str] = set()
    for raw_line in body.splitlines():
        stripped = raw_line.strip()
        if stripped and not current:
            current_start_line = line
        current.append(raw_line)
        if ";" in raw_line or stripped.endswith("{") or stripped.endswith("}"):
            text = "\n".join(current).strip()
            if text:
                stmt_id = f"{relpath}:{func_name}:stmt:{stmt_idx}"
                calls = _extract_calls(text)
                identifiers = _extract_identifiers(text)
                defined = []
                decl = _declared_variable(text)
                if decl:
                    defined.append(decl)
                    declared_so_far.add(decl)
                uses = [i for i in identifiers if i not in calls and i not in defined]
                statements.append(
                    ExtractedStatement(
                        statement_id=stmt_id,
                        text=text,
                        line_start=current_start_line,
                        line_end=line,
                        calls=calls,
                        identifiers=identifiers,
                        defines_variables=defined,
                        uses_variables=uses,
                    )
                )
                stmt_idx += 1
            current = []
        line += 1
    text = "\n".join(current).strip()
    if text:
        identifiers = _extract_identifiers(text)
        calls = _extract_calls(text)
        decl = _declared_variable(text)
        statements.append(
            ExtractedStatement(
                statement_id=f"{relpath}:{func_name}:stmt:{stmt_idx}",
                text=text,
                line_start=current_start_line,
                line_end=line - 1,
                calls=calls,
                identifiers=identifiers,
                defines_variables=[decl] if decl else [],
                uses_variables=[i for i in identifiers if i not in calls and i != decl],
            )
        )
    return statements


def extract_functions_from_text(text: str, relpath: str) -> list[ExtractedFunction]:
    clean = strip_comments(text)
    functions: list[ExtractedFunction] = []
    i = 0
    text_len = len(clean)
    while i < text_len:
        open_pos = clean.find("{", i)
        if open_pos < 0:
            break
        header = _header_candidate(clean, open_pos)
        name = _function_name_from_header(header)
        if not name:
            i = open_pos + 1
            continue
        close_pos = _find_matching_brace(clean, open_pos)
        if close_pos is None:
            i = open_pos + 1
            continue
        header_start = clean.rfind(header, 0, open_pos) if header else -1
        if header_start < 0:
            header_start = max(0, open_pos - len(header))
        body = text[header_start : close_pos + 1]
        signature = header.strip()
        line_start = _line_no(clean, header_start)
        line_end = _line_no(clean, close_pos)
        statements = split_statements(body, relpath, name, line_start)
        calls = _extract_calls(body)
        params = _extract_parameters(signature)
        local_vars: dict[str, dict] = {}
        for p in params:
            local_vars[p] = {"name": p, "kind": "parameter", "line_start": line_start, "line_end": line_start}
        for stmt in statements:
            for var in stmt.defines_variables:
                local_vars.setdefault(var, {"name": var, "kind": "local", "line_start": stmt.line_start, "line_end": stmt.line_end})
        function_id = f"{relpath}:{name}:{line_start}"
        functions.append(
            ExtractedFunction(
                function_id=function_id,
                name=name,
                signature=signature,
                body=body,
                relpath=relpath,
                line_start=line_start,
                line_end=line_end,
                statements=statements,
                calls=calls,
                local_variables=local_vars,
                parameters=params,
            )
        )
        i = close_pos + 1
    return functions
