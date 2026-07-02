"""Claude (Anthropic) export parser.

Anthropic's data export (Settings -> Export data) ships a ZIP that contains one
of:

  1. `conversations.json` - JSON array of conversation objects with shape:
        [
          {
            "uuid": "...",
            "name": "...",
            "created_at": "2024-01-01T00:00:00.000Z",
            "updated_at": "...",
            "chat_messages": [
              {
                "uuid": "...",
                "text": "...",
                "sender": "human"|"assistant",
                "created_at": "...",
                "attachments": [...]
              }
            ]
          }
        ]

  2. An HTML archive (`conversations.html` or similar) - we extract the visible
     text via a forgiving regex-based scrape (no external deps).

This parser handles both. If the input is HTML, the HTML branch runs; otherwise
we try JSON.
"""
from __future__ import annotations

import html as html_lib
import json
import re
from collections.abc import Iterator
from datetime import datetime

from didileak.models import Message
from didileak.parsers.base import Parser

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_BLOCK_RE = re.compile(
    r'<div[^>]*data-testid="user-message"[^>]*>(.*?)</div>\s*'
    r'<div[^>]*data-testid="ai-message"[^>]*>(.*?)</div>',
    re.DOTALL,
)


def _strip_html(s: str) -> str:
    s = html_lib.unescape(s)
    s = _TAG_RE.sub("", s)
    return _WS_RE.sub(" ", s).strip()


def _parse_iso(s: str | None) -> float | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


class ClaudeParser(Parser):
    provider = "claude"

    def parse(self) -> Iterator[Message]:
        raw = self.path.read_bytes()
        head = raw[:4096].lstrip()
        if head.startswith(b"<") or b"<!DOCTYPE" in head[:512].upper():
            yield from self._parse_html(raw.decode("utf-8", errors="replace"))
        else:
            yield from self._parse_json(raw.decode("utf-8-sig", errors="replace"))

    # --- JSON path -------------------------------------------------------- #
    def _parse_json(self, text: str) -> Iterator[Message]:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            self.warnings.append(f"Claude export is not valid JSON: {e}")
            return
        if isinstance(data, dict):
            # Some exports wrap in {"conversations": [...]}
            data = data.get("conversations") or data.get("data") or []
        if not isinstance(data, list):
            self.warnings.append("Claude JSON export is not an array")
            return

        self._conversation_count = len(data)
        convos = sorted(data, key=lambda c: c.get("created_at") or "")

        for conv in convos:
            conv_id = conv.get("uuid") or conv.get("id")
            title = conv.get("name") or "(untitled)"
            msgs = conv.get("chat_messages") or conv.get("messages") or []
            for idx, m in enumerate(msgs):
                body = m.get("text") or m.get("content") or ""
                if isinstance(body, list):
                    body = "\n".join(str(b) for b in body)
                body = (body or "").strip()
                if not body:
                    continue
                sender = (m.get("sender") or m.get("role") or "unknown").lower()
                role = {"human": "user", "assistant": "assistant"}.get(sender, sender)
                yield Message(
                    role=role or "unknown",
                    content=body,
                    timestamp=_parse_iso(m.get("created_at")),
                    message_id=m.get("uuid") or m.get("id"),
                    conversation_id=conv_id,
                    conversation_title=title,
                    provider=self.provider,
                    index=idx,
                )

    # --- HTML path -------------------------------------------------------- #
    def _parse_html(self, html: str) -> Iterator[Message]:
        # Try a structured extraction first; fall back to a generic sweep.
        found_any = False
        for m in _BLOCK_RE.finditer(html):
            user_text = _strip_html(m.group(1))
            ai_text = _strip_html(m.group(2))
            if user_text:
                found_any = True
                yield Message(
                    role="user",
                    content=user_text,
                    provider=self.provider,
                    index=0,
                )
            if ai_text:
                found_any = True
                yield Message(
                    role="assistant",
                    content=ai_text,
                    provider=self.provider,
                    index=1,
                )

        if not found_any:
            # Last resort: split by headers and yield everything that looks like text
            # This is lossy but at least lets detectors run.
            self.warnings.append(
                "Claude HTML structure not recognized; falling back to plain-text sweep"
            )
            text = _strip_html(html)
            # Yield as one giant user message so detectors still see it
            if text:
                yield Message(role="unknown", content=text, provider=self.provider, index=0)
