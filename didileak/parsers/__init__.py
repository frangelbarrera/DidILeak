"""LLM export parsers. Each parser yields `Message` objects."""
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
    """Best-effort detection of which LLM provider an export came from."""
    import os

    name = os.path.basename(path).lower()
    if "gpt" in name or "openai" in name or "conversations" in name:
        return "chatgpt"
    if "claude" in name or "anthropic" in name:
        return "claude"
    if "cursor" in name:
        return "cursor"
    if name.endswith(".html") or name.endswith(".htm"):
        # Claude exports are often HTML
        return "claude"
    # Fall back to content sniffing
    if content_hint:
        head = content_hint[:8192].lower()
        if b'"mapping"' in head and b'"author"' in head:
            return "chatgpt"
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
