"""LLM export parsers. Each parser yields `Message` objects."""
from __future__ import annotations

from didileak.parsers.base import Parser
from didileak.parsers.chatgpt import ChatGPTParser
from didileak.parsers.claude import ClaudeParser
from didileak.parsers.cursor import CursorParser
from didileak.parsers.generic import GenericJSONParser

__all__ = [
    "Parser",
    "ChatGPTParser",
    "ClaudeParser",
    "CursorParser",
    "GenericJSONParser",
    "detect_provider",
    "get_parser",
]


def detect_provider(path: str, content_hint: bytes | None = None) -> str:
    """Best-effort detection of which LLM provider an export came from.

    Structure wins over filename. Both ChatGPT and Claude exports are commonly
    named ``conversations.json`` (the Anthropic export default), so when a
    content hint is available the JSON shape is inspected first; filename
    keywords are only the fallback. This prevents silent false negatives where
    a Claude export is handed to the ChatGPT parser, yields 0 messages, and
    the user is told the export is clean.
    """
    import os

    name = os.path.basename(path).lower()

    # 1) File-type signals (cheap, unambiguous).
    if name.endswith(".html") or name.endswith(".htm"):
        # Claude exports are often HTML
        return "claude"

    # 2) Structure sniffing: content beats filename. Only unambiguous,
    #    format-specific keys are used, so generic JSON logs that merely
    #    happen to carry fields like "uuid"/"sender" keep routing to the
    #    generic parser instead of silently yielding zero messages.
    if content_hint:
        head = content_hint[:65536].lower()
        if b'"mapping"' in head and b'"author"' in head:
            return "chatgpt"
        if b'"chat_messages"' in head:
            return "claude"
        if b'"chats"' in head and b'"messages"' in head:
            return "cursor"

    # 3) Filename keywords (fallback when no/unknown content).
    if "gpt" in name or "openai" in name or "conversations" in name:
        return "chatgpt"
    if "claude" in name or "anthropic" in name:
        return "claude"
    if "cursor" in name:
        return "cursor"

    # 4) Last-resort content sniffing.
    if content_hint:
        head = content_hint[:65536].lower()
        if b"<html" in head or b"claude" in head:
            return "claude"
    return "generic"


def get_parser(provider: str) -> type[Parser]:
    return {
        "chatgpt": ChatGPTParser,
        "claude": ClaudeParser,
        "cursor": CursorParser,
        "generic": GenericJSONParser,
    }.get(provider, GenericJSONParser)
