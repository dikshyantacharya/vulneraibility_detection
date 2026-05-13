from pathlib import Path

from vuln_commit_kg.analysis_outputs.live_dashboard import LiveDashboard


class DummyCfg:
    dirname = "live_dashboard"
    host = "127.0.0.1"
    port = 8765
    serve = False
    keep_recent_events = 20


def test_provider_quota_projected_after_real_request(tmp_path: Path):
    dash = LiveDashboard(tmp_path, DummyCfg())
    dash.event("api.provider_quota_probe", {
        "source": "provider_headers",
        "headers_present": True,
        "usage": {
            "minute": {"limit": 10, "remaining": 9, "used": 1, "source": "provider_header"},
            "hour": {"limit": 200, "remaining": 199, "used": 1, "source": "provider_header"},
        },
        "reset_seconds": 30,
        "http_status": 400,
    })
    dash.event("api.request.done", {"sample_id": "1", "stage": "final_decision", "attempt": "primary"})
    provider = dash.state["api"]["provider_rate_limit"]
    assert provider["locally_projected"] is True
    assert provider["usage"]["minute"]["remaining"] == 8
    assert provider["usage"]["minute"]["used"] == 2
    assert provider["usage"]["hour"]["remaining"] == 198
