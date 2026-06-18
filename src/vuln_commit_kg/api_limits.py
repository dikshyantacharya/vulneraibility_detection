from __future__ import annotations

import os
import time
import json
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin


_RATE_LIMIT_HEADER_NAMES = {
    "minute": ("x-ratelimit-limit-minute", "x-ratelimit-remaining-minute"),
    "hour": ("x-ratelimit-limit-hour", "x-ratelimit-remaining-hour"),
    "day": ("x-ratelimit-limit-day", "x-ratelimit-remaining-day"),
    "month": ("x-ratelimit-limit-month", "x-ratelimit-remaining-month"),
}


def _to_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except Exception:
        return None


def _lower_headers(headers: Any) -> dict[str, str]:
    try:
        items = headers.items()
    except Exception:
        return {}
    return {str(k).lower(): str(v) for k, v in items}


def parse_rate_limit_headers(headers: Any) -> dict[str, Any]:
    """Parse SAIA/OpenAI-compatible provider rate-limit headers."""
    h = _lower_headers(headers)
    usage: dict[str, dict[str, Any]] = {}
    raw: dict[str, str] = {}
    for k, v in h.items():
        if k.startswith("x-ratelimit-") or k.startswith("ratelimit-"):
            raw[k] = v

    for window, (limit_name, remaining_name) in _RATE_LIMIT_HEADER_NAMES.items():
        limit = _to_int(h.get(limit_name))
        remaining = _to_int(h.get(remaining_name))
        if limit is None and remaining is None:
            continue
        used = None
        if limit is not None and remaining is not None:
            used = max(0, limit - remaining)
        usage[window] = {
            "limit": limit,
            "remaining": remaining,
            "used": used,
            "source": "provider_header",
        }

    generic_limit = _to_int(h.get("ratelimit-limit"))
    generic_remaining = _to_int(h.get("ratelimit-remaining"))
    reset_seconds = _to_int(h.get("ratelimit-reset"))
    if generic_limit is not None or generic_remaining is not None:
        usage.setdefault("generic", {
            "limit": generic_limit,
            "remaining": generic_remaining,
            "used": (max(0, generic_limit - generic_remaining) if generic_limit is not None and generic_remaining is not None else None),
            "source": "provider_header",
        })

    return {
        "source": "provider_headers",
        "timestamp": time.time(),
        "headers_present": bool(raw),
        "usage": usage,
        "reset_seconds": reset_seconds,
        "raw_headers": raw,
    }


def quota_probe_url(api_base: str | None, override_url: str | None = None) -> str | None:
    if override_url:
        return override_url
    if not api_base:
        return None
    base = api_base.rstrip("/") + "/"
    return urljoin(base, "chat/completions")


def fetch_provider_quota_headers(model_cfg: Any, quota_cfg: Any) -> dict[str, Any]:
    """Fetch provider quota headers once for dashboard display."""
    enabled = bool(getattr(quota_cfg, "provider_headers_enabled", False))
    policy = str(getattr(quota_cfg, "provider_header_probe", "off") or "off")
    result: dict[str, Any] = {
        "source": "provider_headers",
        "enabled": enabled,
        "probe_policy": policy,
        "timestamp": time.time(),
    }
    if not enabled or policy == "off":
        result.update({"headers_present": False, "skipped": True, "skip_reason": "disabled"})
        return result

    try:
        import requests
    except Exception as exc:  # pragma: no cover
        result.update({"headers_present": False, "error": f"requests import failed: {exc}"})
        return result

    key_env = str(getattr(model_cfg, "api_key_env", "") or "")
    api_key = os.environ.get(key_env) if key_env else None
    if not api_key:
        result.update({"headers_present": False, "error": f"API key env var not set: {key_env}"})
        return result

    url = quota_probe_url(getattr(model_cfg, "api_base", None), getattr(quota_cfg, "provider_probe_url", None))
    if not url:
        result.update({"headers_present": False, "error": "No api_base/provider_probe_url configured"})
        return result

    method = str(getattr(quota_cfg, "provider_probe_method", "GET") or "GET").upper()
    timeout = float(getattr(quota_cfg, "provider_probe_timeout_seconds", 10.0) or 10.0)
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    result.update({
        "probe_url": url,
        "probe_method": method,
        "counts_against_quota_unknown": True,
        "note": "Startup-only by default because providers may count quota probes.",
    })
    try:
        if method == "POST":
            resp = requests.post(url, headers=headers, timeout=timeout)
        else:
            resp = requests.get(url, headers=headers, timeout=timeout)
        parsed = parse_rate_limit_headers(resp.headers)
        parsed.update(result)
        parsed["http_status"] = getattr(resp, "status_code", None)
        return parsed
    except Exception as exc:
        result.update({"headers_present": False, "error": f"{type(exc).__name__}: {exc}"})
        return result


class RateLimiter:
    """Thread-safe local API request scheduler with live-dashboard events.

    It enforces configured max concurrency and sliding-window request ceilings.
    The provider remains the source of truth for real quota headers; this class
    prevents accidental local bursts and makes waits visible in the dashboard.
    """

    def __init__(self, cfg: Any):
        import threading
        self.cfg = cfg
        self._lock = threading.RLock()
        self._semaphore = threading.BoundedSemaphore(max(1, int(getattr(cfg, "max_concurrent_requests", 1) or 1)))
        self._request_times: list[float] = []
        self._inflight = 0
        self._event_sink: Callable[[str, dict[str, Any]], None] | None = None
        self._state_path = Path(str(getattr(cfg, "state_dir", "cache/api_rate_limits") or "cache/api_rate_limits")) / "local_request_times.json"
        self._load_state_locked()

    def set_event_sink(self, sink: Callable[[str, dict[str, Any]], None] | None) -> None:
        self._event_sink = sink

    def _emit(self, kind: str, data: dict[str, Any]) -> None:
        if self._event_sink is None:
            return
        try:
            self._event_sink(kind, data)
        except Exception:
            pass

    def _load_state_locked(self) -> None:
        try:
            if self._state_path.exists():
                data = json.loads(self._state_path.read_text(encoding="utf-8"))
                vals = data.get("request_times", []) if isinstance(data, dict) else []
                now = time.time()
                self._request_times = [float(x) for x in vals if float(x) >= now - 30 * 86400]
        except Exception:
            self._request_times = []

    def _save_state_locked(self) -> None:
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._state_path.with_suffix(".tmp")
            tmp.write_text(json.dumps({"request_times": self._request_times[-10000:]}, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self._state_path)
        except Exception:
            pass

    def _limits(self) -> list[tuple[str, int, int | None]]:
        return [
            ("minute", 60, _to_int(getattr(self.cfg, "requests_per_minute", None))),
            ("hour", 3600, _to_int(getattr(self.cfg, "requests_per_hour", None))),
            ("day", 86400, _to_int(getattr(self.cfg, "requests_per_day", None))),
            ("month", 30 * 86400, _to_int(getattr(self.cfg, "requests_per_month", None))),
        ]

    def _prune_locked(self) -> None:
        now = time.time()
        max_window = 30 * 86400
        self._request_times = [t for t in self._request_times if t >= now - max_window]

    def _usage_locked(self) -> dict[str, Any]:
        now = time.time()
        usage: dict[str, Any] = {}
        for name, seconds, limit in self._limits():
            if limit is None:
                continue
            used = sum(1 for t in self._request_times if t >= now - seconds)
            usage[name] = {
                "limit": limit,
                "used": used,
                "remaining": max(0, int(limit) - used),
                "source": "local_scheduler",
            }
        return usage

    def _required_wait_locked(self) -> tuple[float, dict[str, Any] | None]:
        now = time.time()
        self._prune_locked()
        worst_wait = 0.0
        worst: dict[str, Any] | None = None
        safety = float(getattr(self.cfg, "safety_margin_seconds", 1.0) or 0.0)
        for name, seconds, limit in self._limits():
            if not limit or limit <= 0:
                continue
            times = sorted(t for t in self._request_times if t >= now - seconds)
            if len(times) >= int(limit):
                wait = max(0.0, times[0] + seconds - now + safety)
                if wait > worst_wait:
                    worst_wait = wait
                    worst = {"window": name, "limit": limit, "used": len(times), "required_wait_seconds": wait}
        return worst_wait, worst

    def acquire(self, context: dict[str, Any] | None = None) -> dict[str, Any]:
        ctx = dict(context or {})
        queued_at = time.time()
        self._emit("api.request.queued", {**ctx, "usage": self.snapshot().get("usage", {})})

        # Concurrency gate.
        if not self._semaphore.acquire(blocking=False):
            self._emit("api.concurrency_waiting", {**ctx, "max_concurrent_requests": getattr(self.cfg, "max_concurrent_requests", None)})
            self._semaphore.acquire()
        self._emit("api.concurrency_acquired", {**ctx})

        # Sliding-window gates.
        while True:
            with self._lock:
                wait, detail = self._required_wait_locked()
                if wait <= 0:
                    self._request_times.append(time.time())
                    self._save_state_locked()
                    self._inflight += 1
                    usage = self._usage_locked()
                    break
            if detail:
                self._emit("api.rate_limit_waiting", {**ctx, **detail, "usage": self.snapshot().get("usage", {})})
            time.sleep(min(float(wait), 60.0))

        token = {"context": ctx, "queued_at": queued_at, "started_at": time.time()}
        self._emit("api.request.in_flight", {**ctx, "waited_seconds": token["started_at"] - queued_at, "usage": usage})
        return token

    def release(self, token: dict[str, Any] | None, *, success: bool, response_chars: int | None = None, error: str | None = None, will_retry: bool = False, provider_rate_limit: dict[str, Any] | None = None, extra: dict[str, Any] | None = None) -> None:
        ctx = dict((token or {}).get("context") or {})
        data = {**ctx, **(extra or {})}
        if response_chars is not None:
            data["response_chars"] = response_chars
        if error:
            data["error"] = error
        if will_retry:
            data["will_retry"] = True
        if provider_rate_limit:
            data["provider_rate_limit"] = provider_rate_limit
        try:
            with self._lock:
                self._inflight = max(0, self._inflight - 1)
                data["usage"] = self._usage_locked()
        finally:
            try:
                self._semaphore.release()
            except ValueError:
                pass
        self._emit("api.request.done" if success else "api.request.error", data)

    def snapshot(self) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            self._prune_locked()
            return {
                "enabled": bool(getattr(self.cfg, "enabled", False)),
                "inflight": self._inflight,
                "requests_last_minute": sum(1 for t in self._request_times if t >= now - 60),
                "requests_last_hour": sum(1 for t in self._request_times if t >= now - 3600),
                "usage": self._usage_locked(),
                "configured": {
                    "requests_per_minute": getattr(self.cfg, "requests_per_minute", None),
                    "requests_per_hour": getattr(self.cfg, "requests_per_hour", None),
                    "requests_per_day": getattr(self.cfg, "requests_per_day", None),
                    "requests_per_month": getattr(self.cfg, "requests_per_month", None),
                    "max_concurrent_requests": getattr(self.cfg, "max_concurrent_requests", None),
                },
            }
