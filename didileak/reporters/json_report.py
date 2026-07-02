"""JSON report renderer."""
from __future__ import annotations

import json

from didileak.models import ScanResult


def render_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent, ensure_ascii=False, default=str)
