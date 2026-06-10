"""Dashboard control-plane for the student-system-creator workflow.

This package adds a browser-controllable layer (REST + WebSocket) on top of the
existing CLI commands (build / validate-challenge / evaluate / package-raid /
serve). It does NOT replace or modify any existing behaviour: every long-running
job is executed by invoking the same CLI entry points as a subprocess, with
structured progress parsed from their logs.
"""

from __future__ import annotations

__all__ = ["events", "log_parser", "inventory", "jobs", "app"]
