"""Generic JSON parser.

Accepts any JSON file and recursively extracts string values that look like
message content. Recognized shapes:

  - {"messages": [{"role": "...", "content": "..."}, ...]}
  - {"conversations": [{"messages": [...]}]}
  - [{"role": "user", "content": "..."}, ...]
  - Arbitrary nested dict/list: every string >= 4 chars is yielded as a
    standalone message (role=unknown) so detectors still run.
"""
from __future__ import annotations

import json
from collections.abc import Iterator

from didileak.models import Message
from didileak.parsers.base import Parser


def _walk_strings(obj, path=""):
    if isinstance(obj, str):
        if len(obj) >= 4:
            yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_strings(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_strings(v, f"{path}[{i}]")


def _looks_like_message(d) -> bool:
    if not isinstance(d, dict):
        return False
    keys = {k.lower() for k in d}
    return bool(
        keys & {"content", "text", "message", "body"}
        and keys & {"role", "sender", "author", "from"}
    )


def _extract_role(d) -> str:
    for k in ("role", "sender", "author", "from"):
        v = d.get(k)
        if isinstance(v, str):
            return v.lower()
    return "unknown"


def _extract_content(d) -> str:
    for k in ("content", "text", "message", "body", "value"):
        v = d.get(k)
        if isinstance(v, str):
            return v
        if isinstance(v, list) and v and isinstance(v[0], str):
            return "\n".join(v)
        if isinstance(v, dict):
            for sk in ("text", "value", "parts"):
                sv = v.get(sk)
                if isinstance(sv, str):
                    return sv
                if isinstance(sv, list):
                    return "\n".join(str(x) for x in sv)
    return ""


class GenericJSONParser(Parser):
    provider = "generic"

    def parse(self) -> Iterator[Message]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as e:
            self.warnings.append(f"Generic JSON is invalid: {e}")
            return

        # Shape 1: {messages: [...]}
        if isinstance(data, dict) and isinstance(data.get("messages"), list):
            self._conversation_count = 1
            for idx, m in enumerate(data["messages"]):
                if isinstance(m, dict) and _looks_like_message(m):
                    body = _extract_content(m).strip()
                    if body:
                        yield Message(
                            role=_extract_role(m),
                            content=body,
                            message_id=str(m.get("id") or m.get("uuid")) if isinstance(m, dict) else None,
                            conversation_title=data.get("title"),
                            provider=self.provider,
                            index=idx,
                        )
            return

        # Shape 2: {conversations: [{messages: [...]}]}
        if isinstance(data, dict) and isinstance(data.get("conversations"), list):
            self._conversation_count = len(data["conversations"])
            for conv in data["conversations"]:
                if not isinstance(conv, dict):
                    continue
                title = conv.get("title") or "(untitled)"
                conv_id = conv.get("id") or conv.get("uuid")
                for idx, m in enumerate(conv.get("messages") or []):
                    if isinstance(m, dict) and _looks_like_message(m):
                        body = _extract_content(m).strip()
                        if body:
                            yield Message(
                                role=_extract_role(m),
                                content=body,
                                message_id=str(m.get("id") or m.get("uuid")) if isinstance(m, dict) else None,
                                conversation_id=str(conv_id) if conv_id else None,
                                conversation_title=title,
                                provider=self.provider,
                                index=idx,
                            )
            return

        # Shape 3: top-level array of message-like dicts
        if isinstance(data, list) and data and _looks_like_message(data[0]):
            self._conversation_count = 1
            for idx, m in enumerate(data):
                if isinstance(m, dict) and _looks_like_message(m):
                    body = _extract_content(m).strip()
                    if body:
                        yield Message(
                            role=_extract_role(m),
                            content=body,
                            provider=self.provider,
                            index=idx,
                        )
            return

        # Shape 4: walk every string and yield it
        self.warnings.append(
            "Generic JSON shape not recognized; scanning every string value"
        )
        idx = 0
        for _path, text in _walk_strings(data):
            yield Message(role="unknown", content=text, provider=self.provider, index=idx)
            idx += 1  # noqa: SIM113 -- explicit counter is clearer here
        self._conversation_count = 1
