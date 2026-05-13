from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

API_BASE = os.getenv("ACADEMICCLOUD_API_BASE", "https://chat-ai.academiccloud.de/v1").rstrip("/")
MODEL = os.getenv("ACADEMICCLOUD_MODEL", "qwen3.5-397b-a17b")
API_KEY = os.getenv("ACADEMICCLOUD_API_KEY")
OUT = Path("outputs/api_debug") / time.strftime("%Y%m%d_%H%M%S")


def post(payload: dict, timeout: int = 120) -> dict:
    if not API_KEY:
        raise SystemExit("ACADEMICCLOUD_API_KEY is not set")
    req = Request(
        f"{API_BASE}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def summarize(name: str, data: dict, elapsed: float) -> None:
    choice = (data.get("choices") or [{}])[0]
    msg = choice.get("message") or {}
    content = msg.get("content")
    reasoning = msg.get("reasoning") or msg.get("reasoning_content")
    print("=" * 100)
    print(f"CASE: {name}")
    print(f"elapsed_seconds: {elapsed:.2f}")
    print(f"finish_reason: {choice.get('finish_reason')!r}")
    print(f"message keys: {sorted(msg.keys())}")
    print(f"content_chars: {len(content or '')}")
    print(f"reasoning_chars: {len(reasoning or '')}")
    print(f"usage: {json.dumps(data.get('usage'), indent=2)}")
    print("assistant.content:")
    print(content if content is not None else "<NULL>")
    print()


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    cases = [
        ("without_enable_thinking_false", {
            "model": MODEL,
            "messages": [{"role": "user", "content": "Return exactly: OK"}],
            "temperature": 0,
            "max_tokens": 512,
        }),
        ("with_enable_thinking_false", {
            "model": MODEL,
            "messages": [{"role": "user", "content": "Return exactly: OK"}],
            "temperature": 0,
            "max_tokens": 512,
            "chat_template_kwargs": {"enable_thinking": False},
        }),
        ("tagged_json_with_enable_thinking_false", {
            "model": MODEL,
            "messages": [
                {"role": "system", "content": "Return <analysis>brief audit</analysis> then <answer>JSON</answer>."},
                {"role": "user", "content": "Return verdict ok as JSON."},
            ],
            "temperature": 0,
            "max_tokens": 512,
            "chat_template_kwargs": {"enable_thinking": False},
        }),
    ]
    print(f"url: {API_BASE}/chat/completions")
    print(f"model: {MODEL}")
    for name, payload in cases:
        print("-" * 100)
        print(f"Sending {name} with keys={sorted(payload.keys())}")
        start = time.perf_counter()
        try:
            data = post(payload)
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            print(f"HTTPError {exc.code}: {body}")
            continue
        except URLError as exc:
            print(f"URLError: {exc}")
            continue
        elapsed = time.perf_counter() - start
        (OUT / f"{name}.json").write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        summarize(name, data, elapsed)
    print("=" * 100)
    print(f"Saved raw responses to: {OUT}")


if __name__ == "__main__":
    main()
