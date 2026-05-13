from vuln_commit_kg.api_limits import parse_rate_limit_headers


def test_parse_saia_rate_limit_headers():
    parsed = parse_rate_limit_headers({
        "x-ratelimit-limit-minute": "1000",
        "x-ratelimit-remaining-minute": "999",
        "x-ratelimit-limit-hour": "10000",
        "x-ratelimit-remaining-hour": "9999",
        "x-ratelimit-limit-day": "50002",
        "x-ratelimit-remaining-day": "50001",
        "ratelimit-limit": "1000",
        "ratelimit-remaining": "999",
        "ratelimit-reset": "1",
    })
    assert parsed["headers_present"] is True
    assert parsed["usage"]["minute"]["limit"] == 1000
    assert parsed["usage"]["minute"]["remaining"] == 999
    assert parsed["usage"]["minute"]["used"] == 1
    assert parsed["reset_seconds"] == 1
