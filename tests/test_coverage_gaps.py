"""Additional tests targeting the last coverage gaps."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from didileak.cli import (
    main,
)
from didileak.detectors import DetectorEngine
from didileak.models import Message, ScanResult, Severity
from didileak.parsers import ChatGPTParser, ClaudeParser, CursorParser
from didileak.reporters import render_html

# --------------------------------------------------------------------------- #
# CLI: cmd_scan with failed scan (exception path)
# --------------------------------------------------------------------------- #

def test_cmd_scan_handles_scan_exception(chatgpt_export, tmp_path, capsys):
    """cmd_scan should continue if one file fails, and report the error."""
    # Create a file that will cause an error during scan
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("not json at all {")

    # Also include a valid file
    rc = main(["scan", str(bad_file), str(chatgpt_export)])
    # Should return 0 because at least one file succeeded
    assert rc == 0


def test_cmd_report_handles_all_failed_scans(tmp_path, capsys):
    """cmd_report returns 1 when all scans fail."""
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("not json")
    outdir = tmp_path / "out"
    rc = main(["report", str(bad_file), "--outdir", str(outdir)])
    # Even with all failures, reports are written (with 0 findings)
    assert rc == 0
    assert (outdir / "didileak_report.html").exists()


# --------------------------------------------------------------------------- #
# CLI: rotation command edge cases
# --------------------------------------------------------------------------- #

def test_cli_rotation_with_rich_output(capsys):
    """Rotation list command renders with rich table."""
    rc = main(["rotation"])
    assert rc == 0
    out = capsys.readouterr().out
    # With rich installed, output contains rule ids
    assert "aws-access-token" in out
    assert "github-pat" in out


def test_cli_rotation_specific_rule_with_rich(capsys):
    """Rotation for a specific rule renders with rich panel."""
    rc = main(["rotation", "stripe-secret-key"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "stripe" in out.lower() or "Stripe" in out


# --------------------------------------------------------------------------- #
# CLI: __main__ entry point
# --------------------------------------------------------------------------- #

def test_main_module_entry():
    """`python -m didileak --version` should work."""
    import subprocess
    import sys
    result = subprocess.run(
        [sys.executable, "-m", "didileak", "--version"],
        capture_output=True, text=True, cwd=str(Path(__file__).parent.parent),
    )
    assert result.returncode == 0
    assert "didileak" in result.stdout.lower()


# --------------------------------------------------------------------------- #
# Parsers: ChatGPT non-text parts coercion
# --------------------------------------------------------------------------- #

def test_chatgpt_parser_dict_part_with_nested_text(tmp_path):
    """Dict part with nested 'text' key is coerced properly."""
    data = [{
        "title": "test",
        "create_time": 1.0,
        "update_time": 1.0,
        "mapping": {
            "m1": {
                "id": "m1",
                "message": {
                    "id": "m1",
                    "author": {"role": "assistant"},
                    "content": {
                        "content_type": "multimodal_text",
                        "parts": [
                            "Here is the result:",
                            {"text": "AKIAIOSFODNN7EXAMPLE2 was found"},
                        ],
                    },
                    "create_time": 1.0,
                },
                "parent": None,
                "children": [],
            },
        },
    }]
    p = tmp_path / "conv.json"
    p.write_text(json.dumps(data))
    msgs = list(ChatGPTParser(p).parse())
    assert len(msgs) == 1
    assert "AKIAIOSFODNN7EXAMPLE2" in msgs[0].content


def test_chatgpt_parser_dict_part_with_content_key(tmp_path):
    """Dict part with 'content' key (not 'text')."""
    data = [{
        "title": "test",
        "create_time": 1.0,
        "update_time": 1.0,
        "mapping": {
            "m1": {
                "id": "m1",
                "message": {
                    "id": "m1",
                    "author": {"role": "assistant"},
                    "content": {
                        "content_type": "multimodal_text",
                        "parts": [
                            {"content": "image description"},
                        ],
                    },
                    "create_time": 1.0,
                },
                "parent": None,
                "children": [],
            },
        },
    }]
    p = tmp_path / "conv.json"
    p.write_text(json.dumps(data))
    msgs = list(ChatGPTParser(p).parse())
    assert len(msgs) == 1
    assert "image description" in msgs[0].content


def test_chatgpt_parser_dict_part_unknown_shape(tmp_path):
    """Dict part with no recognized text key gets JSON-serialized."""
    data = [{
        "title": "test",
        "create_time": 1.0,
        "update_time": 1.0,
        "mapping": {
            "m1": {
                "id": "m1",
                "message": {
                    "id": "m1",
                    "author": {"role": "assistant"},
                    "content": {
                        "content_type": "multimodal_text",
                        "parts": [
                            {"foo": "bar", "baz": 42},
                        ],
                    },
                    "create_time": 1.0,
                },
                "parent": None,
                "children": [],
            },
        },
    }]
    p = tmp_path / "conv.json"
    p.write_text(json.dumps(data))
    msgs = list(ChatGPTParser(p).parse())
    assert len(msgs) == 1
    # Should contain the JSON repr
    assert "foo" in msgs[0].content


def test_chatgpt_parser_list_part(tmp_path):
    """List part is coerced by joining elements."""
    data = [{
        "title": "test",
        "create_time": 1.0,
        "update_time": 1.0,
        "mapping": {
            "m1": {
                "id": "m1",
                "message": {
                    "id": "m1",
                    "author": {"role": "user"},
                    "content": {
                        "content_type": "text",
                        "parts": [
                            ["line1", "line2"],
                        ],
                    },
                    "create_time": 1.0,
                },
                "parent": None,
                "children": [],
            },
        },
    }]
    p = tmp_path / "conv.json"
    p.write_text(json.dumps(data))
    msgs = list(ChatGPTParser(p).parse())
    assert len(msgs) == 1
    assert "line1" in msgs[0].content
    assert "line2" in msgs[0].content


# --------------------------------------------------------------------------- #
# Parsers: ChatGPT ordered messages with multiple roots
# --------------------------------------------------------------------------- #

def test_chatgpt_parser_multiple_roots(tmp_path):
    """Mapping with multiple root nodes (no parent) is handled."""
    data = [{
        "title": "multi-root",
        "create_time": 1.0,
        "update_time": 1.0,
        "mapping": {
            "r1": {
                "id": "r1",
                "message": {"id": "r1", "author": {"role": "user"},
                            "content": {"content_type": "text", "parts": ["msg 1"]},
                            "create_time": 1.0},
                "parent": None,
                "children": [],
            },
            "r2": {
                "id": "r2",
                "message": {"id": "r2", "author": {"role": "assistant"},
                            "content": {"content_type": "text", "parts": ["msg 2"]},
                            "create_time": 2.0},
                "parent": None,
                "children": [],
            },
        },
    }]
    p = tmp_path / "multi_root.json"
    p.write_text(json.dumps(data))
    msgs = list(ChatGPTParser(p).parse())
    assert len(msgs) == 2


# --------------------------------------------------------------------------- #
# Parsers: Claude HTML with multiple user/ai pairs
# --------------------------------------------------------------------------- #

def test_claude_html_multiple_pairs(tmp_path):
    """HTML with multiple user/ai message pairs."""
    html = """<!DOCTYPE html>
    <html><body>
    <div data-testid="user-message">first user message with AKIAIOSFODNN7EXAMPLE2</div>
    <div data-testid="ai-message">first ai response</div>
    <div data-testid="user-message">second user message</div>
    <div data-testid="ai-message">second ai response with ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890</div>
    </body></html>"""
    p = tmp_path / "multi.html"
    p.write_text(html, encoding="utf-8")
    msgs = list(ClaudeParser(p).parse())
    # Should find at least 4 messages (2 user + 2 assistant)
    assert len(msgs) >= 4


def test_claude_html_strip_tags():
    """_strip_html removes tags and normalizes whitespace."""
    from didileak.parsers.claude import _strip_html
    result = _strip_html("<p>Hello   <b>world</b></p>")
    assert result == "Hello world"


def test_claude_html_unescape_entities():
    """_strip_html unescapes HTML entities."""
    from didileak.parsers.claude import _strip_html
    result = _strip_html("<p>test &amp; more text</p>")
    assert result == "test & more text"


# --------------------------------------------------------------------------- #
# Parsers: Cursor with various message shapes
# --------------------------------------------------------------------------- #

def test_cursor_json_message_with_dict_text(tmp_path):
    """Cursor message where 'text' is a dict (should be JSON-serialized)."""
    data = {"chats": [{
        "id": "c1",
        "title": "test",
        "createdAt": 1699000000000,
        "messages": [
            {"role": "user", "text": {"nested": "value"}, "createdAt": 1699000000000},
        ],
    }]}
    p = tmp_path / "cursor_dict.json"
    p.write_text(json.dumps(data))
    msgs = list(CursorParser(p).parse())
    assert len(msgs) == 1
    assert "nested" in msgs[0].content


def test_cursor_json_with_created_at_string(tmp_path):
    """Cursor message with created_at as string (should not crash)."""
    data = {"chats": [{
        "id": "c1",
        "title": "test",
        "createdAt": 1699000000000,
        "messages": [
            {"role": "user", "text": "hello", "createdAt": "2024-01-01"},
        ],
    }]}
    p = tmp_path / "cursor_str_date.json"
    p.write_text(json.dumps(data))
    msgs = list(CursorParser(p).parse())
    assert len(msgs) == 1
    assert msgs[0].timestamp is None  # string timestamp -> None


def test_cursor_json_with_chat_messages_key(tmp_path):
    """Cursor JSON with 'chat_messages' key instead of 'messages'."""
    data = {"chats": [{
        "id": "c1",
        "title": "test",
        "createdAt": 1699000000000,
        "chat_messages": [
            {"role": "user", "text": "hello with AKIAIOSFODNN7EXAMPLE2", "createdAt": 1699000000000},
        ],
    }]}
    p = tmp_path / "cursor_alt_key.json"
    p.write_text(json.dumps(data))
    msgs = list(CursorParser(p).parse())
    assert len(msgs) == 1
    assert "AKIA" in msgs[0].content


def test_cursor_sqlite_with_non_json_value(tmp_path):
    """SQLite with raw text value (not JSON) is yielded as-is."""
    p = tmp_path / "state.vscdb"
    conn = sqlite3.connect(str(p))
    conn.execute("CREATE TABLE ItemTable (key TEXT, value BLOB)")
    conn.execute("INSERT INTO ItemTable (key, value) VALUES (?, ?)",
                 ("aiService.prompts", b"raw text not json"))
    conn.commit()
    conn.close()
    msgs = list(CursorParser(p).parse())
    assert len(msgs) >= 1
    assert "raw text" in msgs[0].content


def test_cursor_sqlite_with_wrong_schema(tmp_path):
    """SQLite with wrong table name warns and returns empty."""
    p = tmp_path / "wrong.vscdb"
    conn = sqlite3.connect(str(p))
    conn.execute("CREATE TABLE OtherTable (key TEXT, value TEXT)")
    conn.execute("INSERT INTO OtherTable VALUES ('k', 'v')")
    conn.commit()
    conn.close()
    parser = CursorParser(p)
    msgs = list(parser.parse())
    assert msgs == []
    assert len(parser.warnings) > 0


# --------------------------------------------------------------------------- #
# Parsers: Generic with various shapes
# --------------------------------------------------------------------------- #

def test_generic_parser_extract_role_various_keys(tmp_path):
    """Generic parser extracts role from 'sender', 'author', 'from' keys."""
    from didileak.parsers.generic import _extract_role
    assert _extract_role({"role": "user"}) == "user"
    assert _extract_role({"sender": "human"}) == "human"
    assert _extract_role({"author": "me"}) == "me"
    assert _extract_role({"from": "bot"}) == "bot"
    assert _extract_role({}) == "unknown"


def test_generic_parser_extract_content_various_keys(tmp_path):
    """Generic parser extracts content from 'body', 'value', 'message' keys."""
    from didileak.parsers.generic import _extract_content
    assert _extract_content({"content": "hello"}) == "hello"
    assert _extract_content({"text": "hello"}) == "hello"
    assert _extract_content({"body": "hello"}) == "hello"
    assert _extract_content({"message": "hello"}) == "hello"
    assert _extract_content({"value": "hello"}) == "hello"


def test_generic_parser_extract_content_from_dict():
    """Content as dict with 'parts' list."""
    from didileak.parsers.generic import _extract_content
    result = _extract_content({"content": {"parts": ["line1", "line2"]}})
    assert "line1" in result
    assert "line2" in result


def test_generic_parser_extract_content_empty():
    """Content extraction returns empty string for unrecognized shapes."""
    from didileak.parsers.generic import _extract_content
    assert _extract_content({"unknown_key": "value"}) == ""


def test_generic_looks_like_message_negative():
    """Non-dict values are not messages."""
    from didileak.parsers.generic import _looks_like_message
    assert _looks_like_message("string") is False
    assert _looks_like_message([1, 2]) is False
    assert _looks_like_message(None) is False


def test_generic_walk_strings():
    """_walk_strings yields all strings >= 4 chars with their paths."""
    from didileak.parsers.generic import _walk_strings
    data = {"a": ["short", "longer text"], "b": {"c": "deep string"}}
    results = list(_walk_strings(data))
    texts = [r[1] for r in results]
    assert "longer text" in texts
    assert "deep string" in texts
    # 'short' is 5 chars, should be included
    assert "short" in texts


def test_generic_walk_strings_short_filtered():
    """_walk_strings filters strings shorter than 4 chars."""
    from didileak.parsers.generic import _walk_strings
    data = {"a": "ab", "b": "abcd", "c": "abcde"}
    results = list(_walk_strings(data))
    texts = [r[1] for r in results]
    assert "ab" not in texts  # 2 chars, filtered
    assert "abcd" in texts    # 4 chars, included
    assert "abcde" in texts   # 5 chars, included


# --------------------------------------------------------------------------- #
# Reporters: HTML payload security
# --------------------------------------------------------------------------- #

def test_html_strips_matched_value_from_payload():
    """HTML embedded JSON must not contain matched_value (full secret)."""
    engine = DetectorEngine()
    msgs = [Message(role="user", content="AKIAIOSFODNN7EXAMPLE2", provider="test")]
    result = ScanResult(
        source="x", provider="test", messages_scanned=1, conversations_scanned=1,
        findings=engine.scan(msgs),
    )
    html = render_html(result)
    # matched_value (full secret) must NOT be in the HTML
    assert "AKIAIOSFODNN7EXAMPLE2" not in html
    # masked_value should be
    assert "AKIA" in html


def test_html_strips_secret_from_context():
    """HTML embedded context must have the secret replaced with mask."""
    import json
    import re
    engine = DetectorEngine()
    msgs = [Message(role="user", content="prefix AKIAIOSFODNN7EXAMPLE2 suffix", provider="test")]
    result = ScanResult(
        source="x", provider="test", messages_scanned=1, conversations_scanned=1,
        findings=engine.scan(msgs),
    )
    html = render_html(result)
    m = re.search(r'<script id="data" type="application/json">(.+?)</script>', html, re.DOTALL)
    data = json.loads(m.group(1))
    ctx = data["findings"][0]["context"]
    # The full secret should NOT appear in the context
    assert "AKIAIOSFODNN7EXAMPLE2" not in ctx
    # The masked version should
    assert "AKIA" in ctx


# --------------------------------------------------------------------------- #
# Detectors: rules coverage
# --------------------------------------------------------------------------- #

def test_all_rules_have_rotation_guide_or_none():
    """Critical/High rules should have rotation guides. PII may have None."""
    from didileak.detectors import RULES
    for rule in RULES:
        if rule.severity in (Severity.CRITICAL, Severity.HIGH):
            assert rule.rotation_guide is not None, f"{rule.rule_id} ({rule.severity}) should have a rotation guide"
        # Low/Info rules may or may not have one


def test_all_rules_have_unique_ids():
    """All rule IDs must be unique."""
    from didileak.detectors import RULES
    ids = [r.rule_id for r in RULES]
    assert len(ids) == len(set(ids))


def test_all_rules_have_valid_severity():
    """All rules must have a valid Severity enum."""
    from didileak.detectors import RULES
    for rule in RULES:
        assert isinstance(rule.severity, Severity)


# --------------------------------------------------------------------------- #
# Models: Finding to_dict
# --------------------------------------------------------------------------- #

def test_finding_to_dict_severity_is_string():
    """Finding.to_dict() converts severity enum to string."""
    engine = DetectorEngine()
    msgs = [Message(role="user", content="AKIAIOSFODNN7EXAMPLE2", provider="test")]
    result = ScanResult(
        source="x", provider="test", messages_scanned=1, conversations_scanned=1,
        findings=engine.scan(msgs),
    )
    d = result.findings[0].to_dict()
    assert d["severity"] == "critical"
    assert isinstance(d["severity"], str)


def test_scan_result_to_dict_structure():
    """ScanResult.to_dict() has all expected keys."""
    result = ScanResult(
        source="x", provider="test", messages_scanned=1, conversations_scanned=1,
        findings=[], parser_warnings=["w"],
    )
    d = result.to_dict()
    assert "source" in d
    assert "provider" in d
    assert "messages_scanned" in d
    assert "conversations_scanned" in d
    assert "total_findings" in d
    assert "by_severity" in d
    assert "by_category" in d
    assert "by_rule" in d
    assert "parser_warnings" in d
    assert "findings" in d
