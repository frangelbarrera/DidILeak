"""ChatGPT export parser.

ChatGPT's data export (Settings -> Data controls -> Export) produces a ZIP that
contains `conversations.json`. The file is a JSON array of conversations:

    [
      {
        "title": "...",
        "create_time": 1699999999.0,
        "update_time": 1700000000.0,
        "mapping": {
          "<uuid>": {
            "id": "<uuid>",
            "message": {
              "id": "<uuid>",
              "author": {"role": "user"|"assistant"|"system"|"tool"},
              "content": {"content_type": "text", "parts": ["..."]},
              "create_time": 1699999999.0
            },
            "parent": "<uuid>"|null,
            "children": ["<uuid>"]
          },
          ...
        }
      },
      ...
    ]

Some messages have `content.parts` items that are dicts (e.g. DALL-E images);
we coerce anything non-string to its repr and move on.
"""
from __future__ import annotations

import json
from collections.abc import Iterator

from didileak.models import Message
from didileak.parsers.base import Parser


def _coerce_part(part) -> str:
    if isinstance(part, str):
        return part
    if isinstance(part, dict):
        # Common shapes: {"text": "..."} (tts), {"content_type": "image", ...}
        for k in ("text", "content", "markdown", "value"):
            v = part.get(k)
            if isinstance(v, str):
                return v
        return json.dumps(part, ensure_ascii=False)
    if isinstance(part, (list, tuple)):
        return "\n".join(_coerce_part(p) for p in part)
    return str(part)


class ChatGPTParser(Parser):
    provider = "chatgpt"

    def parse(self) -> Iterator[Message]:
        with self.path.open("r", encoding="utf-8-sig") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError as e:
                self.warnings.append(f"ChatGPT export is not valid JSON: {e}")
                return

        if not isinstance(data, list):
            self.warnings.append("ChatGPT export root is not a JSON array")
            return

        self._conversation_count = len(data)
        # Sort conversations by create_time so output is chronological
        convos = sorted(
            data,
            key=lambda c: c.get("create_time") or 0,
        )

        for conv in convos:
            conv_id = conv.get("id") or None
            title = conv.get("title") or "(untitled)"
            mapping = conv.get("mapping") or {}
            # Walk the tree in parent->child order to recover message order
            ordered = self._ordered_messages(mapping)
            for idx, node in enumerate(ordered):
                msg = node.get("message") or {}
                if not isinstance(msg, dict):
                    continue
                author = msg.get("author") or {}
                role = author.get("role") or "unknown"
                content = msg.get("content") or {}
                parts = content.get("parts") or []
                if not parts and isinstance(content.get("text"), str):
                    # Some tool messages use content.text instead
                    parts = [content["text"]]
                text = "\n".join(_coerce_part(p) for p in parts).strip()
                if not text:
                    continue
                yield Message(
                    role=role,
                    content=text,
                    timestamp=msg.get("create_time"),
                    message_id=msg.get("id"),
                    conversation_id=conv_id,
                    conversation_title=title,
                    provider=self.provider,
                    index=idx,
                )

    @staticmethod
    def _ordered_messages(mapping: dict) -> list[dict]:
        """Return nodes in topological order from the root parent."""
        if not mapping:
            return []
        # Find the root (node with no parent)
        roots = [n for n in mapping.values() if not n.get("parent")]
        if not roots:
            # Fall back to insertion order
            return list(mapping.values())
        seen: set[str] = set()
        ordered: list[dict] = []
        # DFS from each root
        for root in roots:
            stack = [root]
            while stack:
                node = stack.pop()
                nid = node.get("id")
                if nid in seen:
                    continue
                seen.add(nid)
                ordered.append(node)
                for child_id in reversed(node.get("children") or []):
                    child = mapping.get(child_id)
                    if child and child.get("id") not in seen:
                        stack.append(child)
        return ordered
