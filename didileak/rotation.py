"""Rotation cheat-sheet keyed by rule_id. Powering `didileak rotation`."""
from __future__ import annotations

from didileak.detectors import RULES

# Lazy-build from the rules themselves so the CLI never drifts from detectors.
GUIDE: dict[str, str] = {r.rule_id: (r.rotation_guide or "No specific rotation guide. Identify the system and rotate per its documentation.") for r in RULES}


def get_guide(rule_id: str) -> str:
    return GUIDE.get(rule_id, "Unknown rule. See https://github.com/gitleaks/gitleaks for context.")
