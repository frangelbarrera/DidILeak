"""Tests for the parsers."""
from __future__ import annotations

from didileak.parsers import (
    ChatGPTParser,
    ClaudeParser,
    CursorParser,
    GenericJSONParser,
    detect_provider,
)


def test_chatgpt_parser_yields_messages_in_order(chatgpt_export):
    p = ChatGPTParser(chatgpt_export)
    msgs = list(p.parse())
    assert len(msgs) == 2
    assert msgs[0].role == "user"
    assert msgs[1].role == "assistant"
    assert msgs[0].conversation_title == "Debug .env"
    assert "AKIAIOSFODNN7EXAMPLE" in msgs[0].content


def test_chatgpt_parser_handles_non_text_parts(chatgpt_with_non_text_parts):
    p = ChatGPTParser(chatgpt_with_non_text_parts)
    msgs = list(p.parse())
    assert len(msgs) == 1
    assert "Here you go:" in msgs[0].content


def test_chatgpt_parser_empty_mapping(tmp_path):
    import json
    data = [{"title": "x", "create_time": 1.0, "update_time": 1.0, "mapping": {}}]
    p = tmp_path / "empty.json"
    p.write_text(json.dumps(data))
    msgs = list(ChatGPTParser(p).parse())
    assert msgs == []


def test_chatgpt_parser_invalid_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("not json at all")
    parser = ChatGPTParser(p)
    msgs = list(parser.parse())
    assert msgs == []
    assert parser.warnings  # at least one warning


def test_claude_json_parser(claude_json_export):
    msgs = list(ClaudeParser(claude_json_export).parse())
    assert len(msgs) == 2
    assert msgs[0].role == "user"
    assert msgs[1].role == "assistant"
    assert "AIzaSyD-9tSrke72PouQMnMXr7wZ3pK1MfTQw7oX" in msgs[0].content


def test_claude_html_parser(claude_html_export):
    msgs = list(ClaudeParser(claude_html_export).parse())
    assert len(msgs) >= 2
    # Both user and assistant messages should appear
    roles = {m.role for m in msgs}
    assert "user" in roles
    assert "assistant" in roles
    assert any("xoxb-" in m.content for m in msgs)


def test_cursor_json_parser(cursor_json_export):
    msgs = list(CursorParser(cursor_json_export).parse())
    assert len(msgs) == 2
    assert msgs[0].role == "user"
    assert "sk_live_" in msgs[0].content


def test_cursor_parser_missing_chats_field(tmp_path):
    import json
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"foo": []}))
    parser = CursorParser(p)
    msgs = list(parser.parse())
    assert msgs == []
    assert parser.warnings


def test_generic_parser_messages_shape(generic_messages_export):
    msgs = list(GenericJSONParser(generic_messages_export).parse())
    assert len(msgs) == 2
    assert "ya29." in msgs[0].content


def test_generic_parser_conversations_shape(tmp_path):
    import json
    data = {"conversations": [{"id": "c1", "title": "T", "messages": [
        {"role": "user", "content": "hello"}, {"role": "assistant", "content": "hi"}]}]}
    p = tmp_path / "conv.json"
    p.write_text(json.dumps(data))
    msgs = list(GenericJSONParser(p).parse())
    assert len(msgs) == 2
    assert msgs[0].conversation_title == "T"


def test_generic_parser_array_of_messages(tmp_path):
    import json
    data = [{"role": "user", "content": "x"}, {"role": "assistant", "content": "y"}]
    p = tmp_path / "arr.json"
    p.write_text(json.dumps(data))
    msgs = list(GenericJSONParser(p).parse())
    assert len(msgs) == 2


def test_generic_parser_walks_unknown_structure(tmp_path):
    import json
    data = {"foo": {"bar": ["some secret text here", "another string"]}}
    p = tmp_path / "weird.json"
    p.write_text(json.dumps(data))
    parser = GenericJSONParser(p)
    msgs = list(parser.parse())
    assert len(msgs) == 2
    assert parser.warnings  # warned about unknown shape


def test_detect_provider_by_filename():
    assert detect_provider("conversations.json") == "chatgpt"
    assert detect_provider("claude_export.html") == "claude"
    assert detect_provider("cursor_export.json") == "cursor"
    assert detect_provider("random.json") == "generic"


def test_detect_provider_by_content(tmp_path):
    p = tmp_path / "data.json"
    p.write_bytes(b'{"mapping": {"m1": {"message": {"author": {"role": "user"}}}}}')
    with p.open("rb") as fh:
        head = fh.read(8192)
    assert detect_provider(str(p), head) == "chatgpt"
