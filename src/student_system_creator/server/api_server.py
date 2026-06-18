from __future__ import annotations

import argparse
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .retrieval_api import KGChallengeRegistry, RegistryError, run_registry_query


def _short(text: object, limit: int = 72) -> str:
    s = str(text or "")
    return s if len(s) <= limit else s[: limit - 1] + "…"


def make_handler(
    registry: KGChallengeRegistry,
    *,
    api_key: str | None,
    require_api_key: bool,
    max_nodes: int,
    allowed_kinds: set[str],
    slow_query_seconds: float = 10.0,
    verbose: bool = True,
):
    class Handler(BaseHTTPRequestHandler):
        server_version = "VCKGChallengeAPI/0.2"

        def _json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            if not require_api_key:
                return True
            auth = self.headers.get("Authorization", "")
            token = auth.removeprefix("Bearer ").strip()
            return bool(api_key) and token == api_key

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/health":
                return self._json(200, {"ok": True, "graphs": len(registry.entries)})
            if path.startswith("/api/v1/kgs/") and path.endswith("/metadata"):
                if not self._authorized():
                    return self._json(401, {"error": "unauthorized"})
                kg_id = path.split("/")[4]
                try:
                    return self._json(200, registry.public_metadata(kg_id))
                except RegistryError as exc:
                    return self._json(404, {"error": str(exc)})
            return self._json(404, {"error": "not found"})

        def do_POST(self):
            path = urlparse(self.path).path
            if not self._authorized():
                return self._json(401, {"error": "unauthorized"})
            try:
                length = int(self.headers.get("Content-Length", "0") or "0")
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            except Exception as exc:
                return self._json(400, {"error": f"invalid json: {exc}"})

            if path.startswith("/api/v1/kgs/") and path.endswith("/query"):
                kg_id = path.split("/")[4]
                kind = payload.get("kind") if isinstance(payload, dict) else None
                target = payload.get("target_function") if isinstance(payload, dict) else None
                start = time.time()
                if verbose:
                    print(f"api.query.start | kg={_short(kg_id, 56)} | kind={kind} | target={target} | max_nodes={payload.get('max_nodes') if isinstance(payload, dict) else None}", flush=True)
                try:
                    result = run_registry_query(registry, kg_id, payload, max_nodes=max_nodes, allowed_kinds=allowed_kinds)
                    elapsed = time.time() - start
                    timing = result.get("timing") or {}
                    line = (
                        f"api.query.done | kg={_short(kg_id, 56)} | kind={kind} | target={result.get('query', {}).get('target_function')} "
                        f"| nodes={result.get('retrieved_node_count')} | edges={result.get('retrieved_edge_count')} "
                        f"| engine_cache_hit={timing.get('engine_cache_hit')} | engine_load={timing.get('engine_load_seconds')}s | time={elapsed:.2f}s"
                    )
                    print(line, flush=True)
                    if elapsed >= slow_query_seconds:
                        print(f"api.query.slow | kg={_short(kg_id, 56)} | kind={kind} | time={elapsed:.2f}s", flush=True)
                    return self._json(200, result)
                except RegistryError as exc:
                    print(f"api.query.error | kg={_short(kg_id, 56)} | kind={kind} | status=404 | error={exc}", flush=True)
                    return self._json(404, {"error": str(exc)})
                except Exception as exc:
                    print(f"api.query.error | kg={_short(kg_id, 56)} | kind={kind} | status=400 | error={exc}", flush=True)
                    return self._json(400, {"error": str(exc)})

            if path.startswith("/api/v1/kgs/") and path.endswith("/batch_query"):
                kg_id = path.split("/")[4]
                queries = payload.get("queries") if isinstance(payload, dict) else None
                if not isinstance(queries, list):
                    return self._json(400, {"error": "batch_query expects {queries: [...]}"})
                out = []
                for q in queries[:8]:
                    try:
                        out.append({"ok": True, "result": run_registry_query(registry, kg_id, q, max_nodes=max_nodes, allowed_kinds=allowed_kinds)})
                    except Exception as exc:
                        out.append({"ok": False, "error": str(exc)})
                return self._json(200, {"results": out})
            return self._json(404, {"error": "not found"})

        def log_message(self, fmt: str, *args) -> None:
            # Keep HTTP access logging compact; detailed timing is printed above.
            if verbose:
                print("api.http", self.address_string(), fmt % args, flush=True)

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve private CodeKG challenge graphs through a bounded retrieval API.")
    parser.add_argument("--registry", default="outputs/student_challenge/vckg_codekg_student_challenge/private/kg_registry_private.json")
    parser.add_argument("--host", default=os.getenv("KG_API_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("KG_API_PORT", "8000")))
    parser.add_argument("--api-key", default=os.getenv("KG_API_KEY", "dev-key-KG"))
    parser.add_argument("--require-api-key", action="store_true")
    parser.add_argument("--max-nodes", type=int, default=int(os.getenv("MAX_NODES_PER_QUERY", "500")))
    parser.add_argument("--engine-cache-size", type=int, default=int(os.getenv("KG_ENGINE_CACHE_SIZE", "8")))
    parser.add_argument("--slow-query-seconds", type=float, default=float(os.getenv("KG_SLOW_QUERY_SECONDS", "10")))
    parser.add_argument("--quiet", action="store_true", help="Disable per-query API timing logs")
    parser.add_argument("--allowed-query-kinds", default=os.getenv("ALLOWED_QUERY_KINDS", "security_context,evidence_slice,function_context,call_neighborhood,variable_flow,semantic_facts,file_context,shortest_path"))
    args = parser.parse_args(argv)

    registry = KGChallengeRegistry(args.registry, engine_cache_size=args.engine_cache_size)
    handler = make_handler(
        registry,
        api_key=args.api_key,
        require_api_key=args.require_api_key,
        max_nodes=args.max_nodes,
        allowed_kinds={x.strip() for x in args.allowed_query_kinds.split(",") if x.strip()},
        slow_query_seconds=args.slow_query_seconds,
        verbose=not args.quiet,
    )
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(
        f"Serving KG challenge API at http://{args.host}:{args.port} using registry {args.registry} "
        f"| graphs={len(registry.entries)} | engine_cache_size={args.engine_cache_size} | max_nodes={args.max_nodes}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping KG challenge API", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
