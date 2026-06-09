from __future__ import annotations

import difflib
import hashlib
import html
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from vuln_commit_kg.data.schema import SecVulEvalSample
from vuln_commit_kg.kg.extractors.c_like import ExtractedFunction, extract_functions_from_text


TOKEN_RE = re.compile(
    r"""
    [A-Za-z_]\w*                                      # identifiers / keywords
    |0[xX][0-9A-Fa-f]+[uUlL]*                         # hex integers
    |\d+\.\d+(?:[eE][+-]?\d+)?[fFlL]*               # floats
    |\d+(?:[eE][+-]?\d+)?[uUlLfF]*                   # integers / simple exponentials
    |"(?:\\.|[^"\\])*"                              # string literals
    |'(?:\\.|[^'\\])*'                               # char literals
    |==|!=|<=|>=|->|\+\+|--|&&|\|\||<<|>>|\+=|-=|\*=|/=|%=|&=|\|=|\^=|::|##|\.\.\.  # multi-char operators
    |[{}()\[\];,.:?~!+\-*/%<>=&|^#]                  # single-char operators / punctuation
    """,
    re.VERBOSE | re.DOTALL,
)


@dataclass
class TargetValidation:
    sample_id: str
    status: str
    filepath_exists: bool
    function_found: bool
    body_similarity: float
    resolved_file: str | None = None
    resolved_function: str | None = None
    error: str | None = None
    raw_similarity: float = 0.0
    whitespace_insensitive_similarity: float = 0.0
    token_sequence_similarity: float = 0.0
    raw_exact: bool = False
    whitespace_insensitive_exact: bool = False
    token_sequence_exact: bool = False
    dataset_content_sha256: str | None = None
    repo_content_sha256: str | None = None
    dataset_token_sha256: str | None = None
    repo_token_sha256: str | None = None
    dataset_chars: int = 0
    repo_chars: int = 0
    dataset_tokens: int = 0
    repo_tokens: int = 0
    artifact_dir: str | None = None


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def _ratio(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def _norm_repo_relpath(path: str | None) -> str:
    return (path or "").replace("\\", "/").strip().lstrip("/")


def _path_parts(path: str | None) -> list[str]:
    return [part for part in _norm_repo_relpath(path).split("/") if part and part not in {".", ".."}]


def _candidate_target_paths(snapshot_path: Path, sample: SecVulEvalSample, *, scan_limit: int = 200) -> list[Path]:
    """Return plausible target-file paths for dataset rows whose filepath may
    include a repository-name prefix or stale benchmark prefix.

    SecVulEval-style rows often contain paths such as
    ``project_name/src/file.c`` while the checked-out worktree contains
    ``src/file.c``.  Some rows also have stale prefixes after repository
    renames.  Validation should therefore try exact/suffix candidates before
    giving up with file_missing.
    """
    parts = _path_parts(sample.filepath)
    seen: set[str] = set()
    out: list[Path] = []

    def add(rel: str | Path) -> None:
        rel_s = _norm_repo_relpath(str(rel))
        if not rel_s or rel_s in seen:
            return
        seen.add(rel_s)
        out.append(snapshot_path / rel_s)

    if parts:
        add("/".join(parts))
        project = (sample.project or "").strip().lower()
        # Common case: dataset path starts with the project/repository name.
        if len(parts) > 1 and project and parts[0].lower() == project:
            add("/".join(parts[1:]))
        # General suffix attempts.  This is cheap and catches repository-root
        # prefix drift without scanning the tree.
        for i in range(1, min(len(parts), 5)):
            if len(parts[i:]) >= 1:
                add("/".join(parts[i:]))

    # If any direct/suffix candidate exists, do not scan the tree.
    existing = [path for path in out if path.exists() and path.is_file()]
    if existing:
        return existing + [path for path in out if path not in existing]

    # Last-resort filename scan.  Keep bounded because some challenge repos are
    # large.  Prefer candidate files whose suffix overlaps most with the dataset
    # path and that contain the target function name.
    filename = parts[-1] if parts else ""
    if not filename:
        return out

    suffixes = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
    if Path(filename).suffix.lower() not in suffixes:
        return out

    matches: list[tuple[int, int, Path]] = []
    scanned = 0
    try:
        for cand in snapshot_path.rglob(filename):
            if scanned >= scan_limit:
                break
            scanned += 1
            if not cand.is_file():
                continue
            rel_parts = cand.relative_to(snapshot_path).as_posix().split("/")
            # Ignore Git internals and common vendored binary/build trees.
            lowered = "/".join(rel_parts).lower()
            if "/.git/" in lowered or lowered.startswith(".git/"):
                continue
            tail_overlap = 0
            for a, b in zip(reversed(parts), reversed(rel_parts)):
                if a.lower() != b.lower():
                    break
                tail_overlap += 1
            contains_fn = 0
            if sample.func_name:
                try:
                    head = cand.read_text(encoding="utf-8", errors="ignore")[:250000]
                    contains_fn = 1 if re.search(r"\b" + re.escape(sample.func_name) + r"\b", head) else 0
                except Exception:
                    contains_fn = 0
            matches.append((contains_fn, tail_overlap, cand))
    except Exception:
        pass
    matches.sort(key=lambda item: (item[0], item[1], -len(str(item[2]))), reverse=True)
    for _, _, cand in matches[:25]:
        if str(cand) not in seen:
            seen.add(str(cand))
            out.append(cand)
    return out


def normalize_newlines(text: str | None) -> str:
    return (text or "").replace("\r\n", "\n").replace("\r", "\n")


def strip_comments_preserve_literals(text: str | None) -> str:
    """Remove C/C++ comments while preserving string and char literals.

    This is intentionally lexical rather than regex-only, so strings such as
    "http://example" or "/*not a comment*/" remain intact.
    """
    src = normalize_newlines(text)
    out: list[str] = []
    i = 0
    in_str: str | None = None
    escape = False
    while i < len(src):
        ch = src[i]
        nxt = src[i + 1] if i + 1 < len(src) else ""
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
        if ch in {"'", '"'}:
            in_str = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            i += 2
            while i < len(src) and src[i] != "\n":
                i += 1
            if i < len(src):
                out.append("\n")
                i += 1
            continue
        if ch == "/" and nxt == "*":
            i += 2
            newline_count = 0
            while i + 1 < len(src) and not (src[i] == "*" and src[i + 1] == "/"):
                if src[i] == "\n":
                    newline_count += 1
                i += 1
            i += 2 if i + 1 < len(src) else 0
            out.append("\n" * newline_count)
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def whitespace_insensitive_content(text: str | None) -> str:
    no_comments = strip_comments_preserve_literals(text)
    return re.sub(r"\s+", "", no_comments)


def code_tokens(text: str | None) -> list[str]:
    no_comments = strip_comments_preserve_literals(text)
    return [tok for m in TOKEN_RE.finditer(no_comments) if (tok := m.group(0).strip())]


def token_sequence_text(text: str | None) -> str:
    return " ".join(code_tokens(text))


def _side_by_side_lines(left: str, right: str, width: int = 92) -> str:
    left_lines = normalize_newlines(left).splitlines()
    right_lines = normalize_newlines(right).splitlines()
    rows = [f"{'DATASET func_body':<{width}} | REPOSITORY extracted function", f"{'-' * width}-+-{'-' * width}"]
    n = max(len(left_lines), len(right_lines))
    for i in range(n):
        l = left_lines[i] if i < len(left_lines) else ""
        r = right_lines[i] if i < len(right_lines) else ""
        rows.append(f"{l[:width]:<{width}} | {r[:width]}")
    return "\n".join(rows) + "\n"


class TargetValidator:
    def __init__(
        self,
        logger: logging.Logger,
        artifact_root: Path | None = None,
        save_artifacts: bool = True,
    ):
        self.logger = logger
        self.artifact_root = artifact_root
        self.save_artifacts = save_artifacts

    def validate(
        self,
        snapshot_path: Path | None,
        sample: SecVulEvalSample,
        *,
        candidate_commit_id: str | None = None,
        candidate_label: str | None = None,
    ) -> TargetValidation:
        if snapshot_path is None:
            return TargetValidation(sample.sample_id, "no_snapshot", False, False, 0.0, error="snapshot unavailable")
        if not sample.filepath:
            return TargetValidation(sample.sample_id, "missing_filepath", False, False, 0.0)
        target_candidates = _candidate_target_paths(snapshot_path, sample)
        target_file = next((p for p in target_candidates if p.exists() and p.is_file()), snapshot_path / sample.filepath)
        if not target_file.exists():
            return TargetValidation(sample.sample_id, "file_missing", False, False, 0.0, str(target_file))
        try:
            resolved_relpath = target_file.relative_to(snapshot_path).as_posix()
            text = target_file.read_text(encoding="utf-8", errors="ignore")
            funcs = extract_functions_from_text(text, relpath=resolved_relpath)
            candidates = [fn for fn in funcs if sample.func_name and fn.name == sample.func_name]
            function_found = bool(candidates)
            if not function_found and sample.func_name:
                pattern = re.compile(r"\b" + re.escape(sample.func_name) + r"\b")
                function_found = bool(pattern.search(text))

            best_fn: ExtractedFunction | None = None
            best: TargetValidation | None = None
            for fn in candidates:
                result = self._compare(sample, target_file, fn, function_found=True)
                if best is None or result.body_similarity > best.body_similarity:
                    best = result
                    best_fn = fn

            if best is None:
                status = "function_name_only" if function_found else "function_missing"
                result = TargetValidation(
                    sample_id=sample.sample_id,
                    status=status,
                    filepath_exists=True,
                    function_found=function_found,
                    body_similarity=0.0,
                    resolved_file=str(target_file),
                    resolved_function=sample.func_name,
                )
            else:
                result = best

            if self.save_artifacts and self.artifact_root and best_fn is not None:
                artifact_dir = self._write_artifacts(
                    sample=sample,
                    target_file=target_file,
                    repo_function=best_fn,
                    validation=result,
                    candidate_commit_id=candidate_commit_id,
                    candidate_label=candidate_label,
                )
                result.artifact_dir = str(artifact_dir)
            return result
        except Exception as exc:
            return TargetValidation(sample.sample_id, "validation_error", True, False, 0.0, str(target_file), error=str(exc))

    def _compare(
        self,
        sample: SecVulEvalSample,
        target_file: Path,
        fn: ExtractedFunction,
        *,
        function_found: bool,
    ) -> TargetValidation:
        dataset_raw = normalize_newlines(sample.func_body)
        repo_raw = normalize_newlines(fn.body)
        dataset_content = whitespace_insensitive_content(dataset_raw)
        repo_content = whitespace_insensitive_content(repo_raw)
        dataset_tokens = token_sequence_text(dataset_raw)
        repo_tokens = token_sequence_text(repo_raw)

        raw_sim = _ratio(dataset_raw, repo_raw)
        content_sim = _ratio(dataset_content, repo_content)
        token_sim = _ratio(dataset_tokens, repo_tokens)

        # Main validation score: token sequence first, content sequence second.
        # This makes whitespace-only and comment-only differences score exactly 1.0
        # while still preserving code-token order and string/operator identity.
        main_sim = max(token_sim, content_sim)

        token_exact = bool(dataset_tokens and repo_tokens and dataset_tokens == repo_tokens)
        content_exact = bool(dataset_content and repo_content and dataset_content == repo_content)
        raw_exact = bool(dataset_raw and repo_raw and dataset_raw == repo_raw)

        if token_exact or content_exact:
            status = "match_exact"
            main_sim = 1.0
        elif main_sim >= 0.98:
            status = "match_near_exact"
        elif main_sim >= 0.82:
            status = "match_approximate"
        elif main_sim > 0:
            status = "body_mismatch"
        else:
            status = "function_name_only" if function_found else "function_missing"

        return TargetValidation(
            sample_id=sample.sample_id,
            status=status,
            filepath_exists=True,
            function_found=function_found,
            body_similarity=main_sim,
            resolved_file=str(target_file),
            resolved_function=fn.name,
            raw_similarity=raw_sim,
            whitespace_insensitive_similarity=content_sim,
            token_sequence_similarity=token_sim,
            raw_exact=raw_exact,
            whitespace_insensitive_exact=content_exact,
            token_sequence_exact=token_exact,
            dataset_content_sha256=_sha256(dataset_content),
            repo_content_sha256=_sha256(repo_content),
            dataset_token_sha256=_sha256(dataset_tokens),
            repo_token_sha256=_sha256(repo_tokens),
            dataset_chars=len(dataset_raw),
            repo_chars=len(repo_raw),
            dataset_tokens=len(dataset_tokens.split()) if dataset_tokens else 0,
            repo_tokens=len(repo_tokens.split()) if repo_tokens else 0,
        )

    def _write_artifacts(
        self,
        *,
        sample: SecVulEvalSample,
        target_file: Path,
        repo_function: ExtractedFunction,
        validation: TargetValidation,
        candidate_commit_id: str | None,
        candidate_label: str | None,
    ) -> Path:
        commit = (candidate_commit_id or "unknown_commit")[:12]
        label = re.sub(r"[^A-Za-z0-9_.-]+", "_", candidate_label or "candidate")
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", f"sample_{sample.sample_id}_{label}_{commit}_{sample.func_name or 'func'}")
        out = self.artifact_root / safe_name
        out.mkdir(parents=True, exist_ok=True)

        dataset_raw = normalize_newlines(sample.func_body)
        repo_raw = normalize_newlines(repo_function.body)
        dataset_content = whitespace_insensitive_content(dataset_raw)
        repo_content = whitespace_insensitive_content(repo_raw)
        dataset_tokens = token_sequence_text(dataset_raw)
        repo_tokens = token_sequence_text(repo_raw)

        (out / "dataset_func_body.c").write_text(dataset_raw, encoding="utf-8")
        (out / "repo_extracted_func_body.c").write_text(repo_raw, encoding="utf-8")
        (out / "dataset_content_sequence.txt").write_text(dataset_content, encoding="utf-8")
        (out / "repo_content_sequence.txt").write_text(repo_content, encoding="utf-8")
        (out / "dataset_token_sequence.txt").write_text(dataset_tokens, encoding="utf-8")
        (out / "repo_token_sequence.txt").write_text(repo_tokens, encoding="utf-8")

        content_diff = difflib.unified_diff(
            [dataset_content[i : i + 100] + "\n" for i in range(0, len(dataset_content), 100)],
            [repo_content[i : i + 100] + "\n" for i in range(0, len(repo_content), 100)],
            fromfile="dataset_content_sequence",
            tofile="repo_content_sequence",
        )
        token_diff = difflib.unified_diff(
            dataset_tokens.split(),
            repo_tokens.split(),
            fromfile="dataset_token_sequence",
            tofile="repo_token_sequence",
            lineterm="",
        )
        raw_diff = difflib.unified_diff(
            dataset_raw.splitlines(),
            repo_raw.splitlines(),
            fromfile="dataset_func_body.c",
            tofile="repo_extracted_func_body.c",
            lineterm="",
        )
        (out / "content_sequence_diff.txt").write_text("".join(content_diff), encoding="utf-8")
        (out / "token_sequence_diff.txt").write_text("\n".join(token_diff) + "\n", encoding="utf-8")
        (out / "raw_unified_diff.txt").write_text("\n".join(raw_diff) + "\n", encoding="utf-8")
        (out / "side_by_side.txt").write_text(_side_by_side_lines(dataset_raw, repo_raw), encoding="utf-8")

        html_text = f"""<!doctype html>
<html><head><meta charset=\"utf-8\"><title>Target validation {html.escape(sample.sample_id)}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 1.5rem; }}
pre {{ white-space: pre-wrap; border: 1px solid #ccc; padding: 1rem; overflow-x: auto; }}
.grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }}
.good {{ color: #067a00; font-weight: 700; }} .bad {{ color: #9b0000; font-weight: 700; }}
</style></head><body>
<h1>Target validation: sample {html.escape(sample.sample_id)}</h1>
<p><b>Project:</b> {html.escape(sample.project)}<br>
<b>File:</b> {html.escape(sample.filepath)}<br>
<b>Function:</b> {html.escape(sample.func_name)}<br>
<b>Dataset commit:</b> {html.escape(sample.commit_id)}<br>
<b>Candidate commit:</b> {html.escape(candidate_commit_id or '')}<br>
<b>Candidate label:</b> {html.escape(candidate_label or '')}<br>
<b>Status:</b> {html.escape(validation.status)}<br>
<b>Main/body similarity:</b> {validation.body_similarity:.6f}<br>
<b>Raw similarity:</b> {validation.raw_similarity:.6f}<br>
<b>Whitespace-insensitive similarity:</b> {validation.whitespace_insensitive_similarity:.6f}<br>
<b>Token-sequence similarity:</b> {validation.token_sequence_similarity:.6f}</p>
<div class=\"grid\"><div><h2>Dataset func_body</h2><pre>{html.escape(dataset_raw)}</pre></div>
<div><h2>Repository extracted function</h2><pre>{html.escape(repo_raw)}</pre></div></div>
<h2>Raw diff</h2><pre>{html.escape((out / 'raw_unified_diff.txt').read_text(encoding='utf-8'))}</pre>
<h2>Token sequence diff</h2><pre>{html.escape((out / 'token_sequence_diff.txt').read_text(encoding='utf-8'))}</pre>
</body></html>"""
        (out / "side_by_side.html").write_text(html_text, encoding="utf-8")
        return out
