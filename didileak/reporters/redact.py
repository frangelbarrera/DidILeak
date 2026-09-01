"""Shared redaction helpers for reporters.

Every finding embeds a ``context`` window around the match. By construction
that window contains the full secret of the finding itself, and when findings
overlap (e.g. an AWS access key id sitting right next to its secret key) a
window can also contain the full secret - or a TRUNCATED FRAGMENT cut at the
window edge - of *another* finding.

Reporters that are meant to be safe to share (Markdown, HTML) therefore use
:class:`Redactor`, which combines two passes:

1. Span surgery: for every finding of the SAME message whose span intersects
   the context window, the visible slice is replaced by its mask - however
   the ±60 window cut it. This is exact: the window is reconstructed from
   ``span_start`` so partial overlaps are caught deterministically, with no
   string guessing.
2. Whole-value replacement of every known ``matched_value`` and of the secret
   "core" extracted from prefixed matches (``password = X``, ``Bearer X``,
   ``scheme://user:pass@host``) anywhere in the text, so bare repetitions of
   a value survive nowhere.

:func:`mask_pairs` and :func:`redact_context` (whole-value replacement only)
stay exported: they are pinned by the regression suite and remain the right
tool for short free-text fields.
"""
from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Iterable, Sequence

# Accepts Finding objects (attributes) or their to_dict() form (mapping keys).
FindingLike = object

# Must match the default radius of Message.context().
_CTX_RADIUS = 60
# Cores shorter than this are not worth a pair (masks already reveal 4+4 chars).
_MIN_CORE = 8

# Secret cores hidden inside prefixed matched values. Each pattern mirrors the
# corresponding detector rule so it only fires on values that rule produced.
_CORE_PATTERNS = (
    # generic-api-key: "password = VALUE", "api_key: VALUE"
    re.compile(r"[:=]\s*[\"']?([A-Za-z0-9_\-]{16,})[\"']?\s*$"),
    # bearer-token: "Bearer VALUE"
    re.compile(r"(?i)\bbearer\s+([A-Za-z0-9_\-\.=]{20,})\s*$"),
    # connection-string: "scheme://user:PASSWORD@host"
    re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://[^:/@\s]+:([^@\s]+)@"),
)


def _fget(f: FindingLike, name: str):
    if isinstance(f, dict):
        return f.get(name)
    return getattr(f, name, None)


def _msg_key(f: FindingLike):
    mid = _fget(f, "message_id")
    return mid if isinstance(mid, str) and mid else "\x00anon"


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


def _core_value(mv: str) -> str | None:
    for pat in _CORE_PATTERNS:
        m = pat.search(mv)
        if m:
            core = m.group(1)
            if len(core) >= _MIN_CORE:
                return core
    return None


def redaction_pairs(findings: Iterable[FindingLike]) -> list[tuple[str, str]]:
    """mask_pairs plus derived (core, mask) pairs for prefixed matches.

    ``password = hunter2secret`` only redacts as a whole, so a bare
    ``hunter2secret`` repeated elsewhere would survive; adding the core as
    its own pair closes that hole. Longest-first, deduplicated.
    """
    pairs = mask_pairs(findings)
    known = {mv for mv, _ in pairs}
    extra: list[tuple[str, str]] = []
    for f in findings:
        mv = _fget(f, "matched_value")
        mask = _fget(f, "masked_value") or "***"
        if not mv:
            continue
        core = _core_value(mv)
        if core and core not in known and len(core) >= _MIN_CORE:
            known.add(core)
            extra.append((core, mask))
    pairs = pairs + extra
    pairs.sort(key=lambda p: len(p[0]), reverse=True)
    return pairs


def redact_context(context: str | None, pairs: Sequence[tuple[str, str]]) -> str:
    """Replace every known matched_value inside ``context`` with its mask.

    Non-string / empty contexts are returned as an empty string, mirroring
    the previous behavior of reporters.
    """
    if not context:
        return context or ""
    for mv, mask in pairs:
        if mv and mv in context:
            context = context.replace(mv, mask)
    return context


class Redactor:
    """Span-aware redaction for share-safe reporters (HTML, Markdown).

    Works with Finding dataclasses or their ``to_dict()`` dicts - the web
    boundary feeds it the JSON form. Never mutates the input findings.
    """

    def __init__(self, findings: Iterable[FindingLike] | None):
        findings = list(findings or [])
        self.pairs = redaction_pairs(findings)
        # Whole-value pass, indexed by value length: one left-to-right scan
        # per text field (try every distinct secret length at each position,
        # longest first) instead of one substring search per known pair. The
        # cost per field is len(text) x distinct lengths, independent of how
        # many findings the scan produced - replacing N pairs per context
        # made an N-finding report O(N^2) and a CPU-DoS vector.
        self._buckets: dict[int, dict[str, str]] = {}
        for mv, mask in self.pairs:
            self._buckets.setdefault(len(mv), {})[mv] = mask
        self._lengths = sorted(self._buckets, reverse=True)
        # Findings grouped by message: span coordinates are only comparable
        # inside one message, so span surgery only ever crosses that border.
        groups: dict[str, list[FindingLike]] = {}
        for f in findings:
            groups.setdefault(_msg_key(f), []).append(f)
        # Per group: spans sorted by start plus a running max(end) so a
        # context window can find its neighbours with a binary search and
        # stop as soon as no earlier span can still reach the window.
        self._groups: dict[str, tuple[list[int], list[int], list[int], list[str]]] = {}
        for key, members in groups.items():
            members.sort(key=lambda f: _fget(f, "span_start") or 0)
            starts, ends, maxends, masks = [], [], [], []
            running = 0
            for f in members:
                s = _fget(f, "span_start") or 0
                e = _fget(f, "span_end") or 0
                running = max(running, e)
                starts.append(s)
                ends.append(e)
                maxends.append(running)
                masks.append(_fget(f, "masked_value") or "***")
            self._groups[key] = (starts, ends, maxends, masks)

    # -- whole-value pass -------------------------------------------------- #

    def text(self, value) -> str:
        """Redact full values and cores from any free-text field."""
        if not value:
            return value or ""
        if not isinstance(value, str):
            value = str(value)
        if not self._lengths:
            return value
        buckets = self._buckets
        lengths = self._lengths
        n = len(value)
        out: list[str] = []
        i = 0
        replaced = False
        while i < n:
            hit = False
            # Binary search over the descending list: skip every length
            # that cannot fit in the remaining text instead of walking
            # past it.
            remaining = n - i
            lo, hi = 0, len(lengths)
            while lo < hi:
                mid = (lo + hi) // 2
                if lengths[mid] > remaining:
                    lo = mid + 1
                else:
                    hi = mid
            for k in range(lo, len(lengths)):
                mask = buckets[lengths[k]].get(value[i:i + lengths[k]])
                if mask is not None:
                    out.append(mask)
                    i += lengths[k]
                    replaced = True
                    hit = True
                    break
            if not hit:
                out.append(value[i])
                i += 1
        return "".join(out) if replaced else value

    # -- span-aware context pass ------------------------------------------- #

    def context(self, finding: FindingLike) -> str:
        """Redact a finding's context window, edge fragments included."""
        ctx = _fget(finding, "context")
        if not isinstance(ctx, str) or not ctx:
            return ctx or ""

        span_s = _fget(finding, "span_start") or 0
        s = max(0, span_s - _CTX_RADIUS)
        if s > 0:
            # A clipped window always starts with the "..." marker that
            # Message.context() prepends; if it does not, the geometry is
            # not ours to reason about - fall back to whole-value redaction.
            if not ctx.startswith("..."):
                return self.text(ctx)
            body = ctx[3:]
        else:
            body = ctx
        tail = ""
        if body.endswith("..."):
            # Assume the trailing marker. If the export text itself ended in
            # dots the worst case is a sub-threshold 3-char residue at the
            # very end of the window.
            tail, body = "...", body[:-3]
        if not body:
            return ("..." if s > 0 else "") + tail

        cuts = self._window_cuts(finding, s, s + len(body))
        # Merge overlapping cuts first: two rules can match the same text
        # (e.g. the 40-char rule inside a ghp_ token) and splicing their
        # cuts one by one would leave raw residue in between.
        merged: list[list] = []
        for rel_s, rel_e, mask in sorted(cuts):
            if merged and rel_s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], rel_e)
            else:
                merged.append([rel_s, rel_e, mask])
        # Right-to-left keeps earlier offsets valid while we splice.
        for rel_s, rel_e, mask in sorted(merged, reverse=True):
            if rel_s < len(body):
                rel_e = min(rel_e, len(body))
                if rel_e > rel_s:
                    body = body[:rel_s] + mask + body[rel_e:]

        body = self.text(body)
        return ("..." if s > 0 else "") + body + tail

    def _window_cuts(self, finding: FindingLike, s: int, e: int):
        """Visible slices of same-message findings inside window [s, e)."""
        group = self._groups.get(_msg_key(finding))
        if not group:
            return []
        starts, ends, maxends, masks = group
        out = []
        i = bisect_right(starts, e - 1)
        while i > 0:
            i -= 1
            if maxends[i] <= s:
                break  # nothing at or before i can reach the window
            lo = max(starts[i], s)
            hi = min(ends[i], e)
            if hi > lo:
                out.append((lo - s, hi - s, masks[i]))
        return out
