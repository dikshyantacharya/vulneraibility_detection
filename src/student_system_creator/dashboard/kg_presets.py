"""Canonical KG backend preset definitions for the dashboard.

The dashboard UI exposes higher-level *presets* (e.g. "Joern plus / semantic
overlay") which are NOT themselves valid ``kg.backend`` values in AppConfig.
This module is the single source of truth that maps each UI preset to the actual
validated config keys written into ``effective_config.yaml``.

AppConfig (``src/vuln_commit_kg/config.py`` :: ``KGConfig``) only accepts these
``kg.backend`` literals::

    auto, lightweight, heuristic, joern, tree-sitter, treesitter, tree_sitter

"Joern plus" is backed by REAL config fields: ``backend: joern`` plus the
semantic-enrichment overlay (``semantic_enrichment_enabled`` /
``semantic_enrichment_mode``), both defined on ``KGConfig``. It is therefore a
preset that maps to a valid backend, not a new backend literal.
"""

from __future__ import annotations

from typing import Any

# Mirror of KGConfig.backend Literal in src/vuln_commit_kg/config.py.
# Kept in sync manually; tests assert the UI never writes a value outside this.
ALLOWED_BACKEND_VALUES: tuple[str, ...] = (
    "auto",
    "lightweight",
    "heuristic",
    "joern",
    "tree-sitter",
    "treesitter",
    "tree_sitter",
)

# Each preset declares the full ``kg`` override block it contributes. The
# ``backend`` value inside every preset MUST be a member of
# ALLOWED_BACKEND_VALUES (asserted in tests).
KG_PRESETS: list[dict[str, Any]] = [
    {
        "id": "heuristic",
        "label": "Heuristic / lightweight",
        "description": "Fast fallback graph builder. Lower precision and coverage.",
        "requires_joern": False,
        "speed": "fast",
        "accuracy": "low",
        "recommended": False,
        "config": {"kg": {"backend": "heuristic"}},
    },
    {
        "id": "tree_sitter",
        "label": "Tree-sitter syntax parser",
        "description": "Syntax-level graph extraction. Medium speed and accuracy.",
        "requires_joern": False,
        "speed": "medium",
        "accuracy": "medium",
        "recommended": False,
        "config": {"kg": {"backend": "tree_sitter"}},
    },
    {
        "id": "joern",
        "label": "Joern CPG",
        "description": "Joern CPG-based graph builder. High quality, slower and disk-heavy.",
        "requires_joern": True,
        "speed": "slow",
        "accuracy": "high",
        "recommended": False,
        "config": {"kg": {"backend": "joern"}},
    },
    {
        "id": "joern_plus",
        "label": "Joern plus / semantic overlay",
        "description": (
            "Joern CPG plus the integrated semantic-enrichment overlay. "
            "Recommended final graph mode. Maps to kg.backend=joern with "
            "semantic_enrichment_enabled (a real AppConfig field), so the "
            "effective config never contains an invalid backend literal."
        ),
        "requires_joern": True,
        "speed": "slow",
        "accuracy": "very high",
        "recommended": True,
        "config": {
            "kg": {
                "backend": "joern",
                "semantic_enrichment_enabled": True,
                "semantic_enrichment_mode": "heuristic",
            }
        },
    },
]

# Legacy / alternate UI identifiers that older payloads may still send. They all
# resolve to one of the canonical preset ids above.
_PRESET_ALIASES: dict[str, str] = {
    "simple_heuristic": "heuristic",
    "lightweight": "heuristic",
    "syntax": "tree_sitter",
    "treesitter": "tree_sitter",
    "tree-sitter": "tree_sitter",
    "joern_plus_heuristic": "joern_plus",
    "joern-plus": "joern_plus",
    "semantic_overlay": "joern_plus",
    "integrated": "joern_plus",
}

_PRESET_BY_ID: dict[str, dict[str, Any]] = {p["id"]: p for p in KG_PRESETS}


def resolve_preset_id(value: str | None) -> str | None:
    """Resolve a raw UI value (preset id or legacy alias) to a canonical id."""
    if not value:
        return None
    v = str(value).strip()
    if v in _PRESET_BY_ID:
        return v
    return _PRESET_ALIASES.get(v)


def get_preset(value: str | None) -> dict[str, Any] | None:
    """Return the canonical preset dict for a raw UI value, or None."""
    pid = resolve_preset_id(value)
    if pid is None:
        return None
    return _PRESET_BY_ID[pid]


def kg_overrides_for(value: str | None) -> dict[str, Any]:
    """Return the validated ``kg`` override block for a raw UI value.

    Resolution order:
    1. Known preset id or alias -> the preset's declared kg overrides.
    2. A raw, already-valid backend literal -> ``{"backend": <value>}``.
    3. Anything else -> ValueError (we never write an invalid backend).
    """
    preset = get_preset(value)
    if preset is not None:
        return dict(preset["config"].get("kg", {}))
    raw = (value or "").strip()
    if raw in ALLOWED_BACKEND_VALUES:
        return {"backend": raw}
    raise ValueError(
        f"Unsupported KG backend/preset '{value}'. "
        f"Allowed backend values: {', '.join(ALLOWED_BACKEND_VALUES)}."
    )


def preset_options() -> dict[str, Any]:
    """Payload for ``GET /api/kg/backends`` consumed by the frontend."""
    options = []
    for p in KG_PRESETS:
        kg_block = p["config"].get("kg", {})
        extra = {k: v for k, v in kg_block.items() if k != "backend"}
        options.append(
            {
                "id": p["id"],
                "label": p["label"],
                "description": p["description"],
                "requires_joern": p["requires_joern"],
                "speed": p["speed"],
                "accuracy": p["accuracy"],
                "recommended": p["recommended"],
                "effective_backend": kg_block.get("backend"),
                "config": {"kg": kg_block},
                "extra_config": {"kg": extra} if extra else {},
            }
        )
    return {
        "options": options,
        "allowed_backend_values": list(ALLOWED_BACKEND_VALUES),
    }
