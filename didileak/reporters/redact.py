"""Shared redaction helpers for reporters.

Every finding embeds a ``context`` window around the match. By construction
that window contains the full secret of the finding itself, and when findings
overlap (e.g. an AWS access key id sitting right next to its secret key) a
window can also contain the full secret of *another* finding.

Reporters that are meant to be safe to share (Markdown, HTML) must therefore
run every context through :func:`redact_context` with the pairs collected
from **all** findings, not just the finding currently being rendered. This
module centralizes that logic so both reporters redact identically.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence

# Accepts Finding objects (attributes) or their to_dict() form (mapping keys).
FindingLike = object


def mask_pairs(findings: Iterable[FindingLike]) -> list[tuple[str, str]]:
    """Collect (matched_value, masked_value) pairs from all findings.

    Works with both ``Finding`` dataclass instances and ``to_dict()`` dicts.
    Duplicates are removed and pairs are sorted longest-value-first so that,
    if one secret is a substring of another, the longer one is replaced first
    and no partially-masked remainder is left behind.
    """
    pairs: list[tuple[str, str]] = []
    for f in findings:
        if isinstance(f, dict):
            mv = f.get("matched_value")
            mask = f.get("masked_value") or "***"
        else:
            mv = getattr(f, "matched_value", None)
            mask = getattr(f, "masked_value", None) or "***"
        if not mv:
            continue
        pair = (mv, mask)
        if pair not in pairs:
            pairs.append(pair)
    pairs.sort(key=lambda p: len(p[0]), reverse=True)
    return pairs


def redact_context(context: str | None, pairs: Sequence[tuple[str, str]]) -> str:
    """Replace every known matched_value inside ``context`` with its mask.

    Non-string / empty contexts are returned as an empty string, mirroring the
    previous behavior of reporters.
    """
    if not context:
        return context or ""
    for mv, mask in pairs:
        if mv and mv in context:
            context = context.replace(mv, mask)
    return context
