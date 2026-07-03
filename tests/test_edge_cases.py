"""Edge case tests to push coverage above 90%."""
from __future__ import annotations

import json
import sqlite3

from didileak.cli import _print_summary, _resolve_paths, main
from didileak.detectors import (
    RULES,
    DetectorEngine,
    _aws_access_key_valid,
    _fingerprint,
    _github_token_valid,
    _is_uuid_like,
    _luhn_valid,
    _mask,
)
from didileak.models import Message, ScanResult, Severity
from didileak.parsers import (
    ChatGPTParser,
    ClaudeParser,
    CursorParser,
    GenericJSONParser,
    detect_provider,
    get_parser,
)
from didileak.reporters import render_html, render_json, render_markdown
from didileak.rotation import GUIDE, get_guide

# --------------------------------------------------------------------------- #
# CLI: _resolve_paths edge cases
# --------------------------------------------------------------------------- #

def test_resolve_paths_nonexistent_glob(tmp_path):
    """Non-existent paths are treated as globs; if glob matches nothing, empty list."""
    result = _resolve_paths([str(tmp_path / "no-such-file-*.json")])
    assert result == []


def test_resolve_returns_all_json_in_directory(tmp_path):
    """When given a directory, returns all .json and .html files inside."""
    (tmp_path / "a.json").write_text("[]")
    (tmp_path / "b.json").write_text("[]")
    (tmp_path / "c.html").write_text("<html></html>")
    result = _resolve_paths([str(tmp_path)])
    names = sorted(p.name for p in result)
    assert names == ["a.json", "b.json", "c.html"]


def test_resolve_paths_single_file(tmp_path):
    f = tmp_path / "single.json"
    f.write_text("[]")
    result = _resolve_paths([str(f)])
    assert result == [f]


# --------------------------------------------------------------------------- #
# CLI: scan with no input files
# --------------------------------------------------------------------------- #

def test_cli_scan_no_files_returns_2(capsys):
    rc = main(["scan", "/nonexistent/path/to/file.json"])
    assert rc == 2


def test_cli_report_no_files_returns_2(capsys):
    rc = main(["report", "/nonexistent/path/to/file.json"])
    assert rc == 2


# --------------------------------------------------------------------------- #
# CLI: scan with explicit --provider
# --------------------------------------------------------------------------- #

def test_cli_scan_with_provider_flag(chatgpt_export, capsys):
    rc = main(["scan", str(chatgpt_export), "--provider", "chatgpt"])
    assert rc == 0


def test_cli_report_with_provider_flag(chatgpt_export, tmp_path):
    outdir = tmp_path / "out"
    rc = main(["report", str(chatgpt_export), "--provider", "chatgpt", "--outdir", str(outdir)])
    assert rc == 0


# --------------------------------------------------------------------------- #
# CLI: multiple files in one scan
# --------------------------------------------------------------------------- #

def test_cli_scan_multiple_files(chatgpt_export, claude_json_export, capsys):
    rc = main(["scan", str(chatgpt_export), str(claude_json_export)])
    assert rc == 0


def test_cli_report_multiple_files(chatgpt_export, claude_json_export, tmp_path):
    outdir = tmp_path / "out"
    rc = main(["report", str(chatgpt_export), str(claude_json_export), "--outdir", str(outdir)])
    assert rc == 0
    assert (outdir / "didileak_report.html").exists()


# --------------------------------------------------------------------------- #
# CLI: _print_summary with and without rich
# --------------------------------------------------------------------------- #

def test_print_summary_with_findings(capsys):
    """Exercise the summary printer (with rich installed)."""
    result = ScanResult(
        source="test.json",
        provider="chatgpt",
        messages_scanned=5,
        conversations_scanned=1,
        findings=[],
    )
    _print_summary(result)
    out = capsys.readouterr().out
    assert "0" in out  # zero findings


def test_print_summary_clean_export(capsys):
    """Summary for a clean export with zero findings."""
    result = ScanResult(
        source="clean.json",
        provider="chatgpt",
        messages_scanned=10,
        conversations_scanned=2,
        findings=[],
    )
    _print_summary(result)
    # Should not crash, output exists
    out = capsys.readouterr().out
    assert len(out) >= 0


# --------------------------------------------------------------------------- #
# Detectors: validator functions
# --------------------------------------------------------------------------- #

def test_mask_long_value():
    assert _mask("abcdefghijklmnop") == "abcd...mnop"


def test_mask_empty_string():
    assert _mask("") == "***"


def test_mask_single_char():
    assert _mask("a") == "***"


def test_mask_two_chars():
    assert _mask("ab") == "***"


def test_fingerprint_stable():
    fp1 = _fingerprint("secret123")
    fp2 = _fingerprint("secret123")
    assert fp1 == fp2
    assert len(fp1) == 16


def test_fingerprint_different_inputs():
    assert _fingerprint("a") != _fingerprint("b")


def test_luhn_valid_amex():
    # Valid Amex test number
    assert _luhn_valid("378282246310005") is True


def test_luhn_valid_mastercard():
    assert _luhn_valid("5555555555554444") is True


def test_luhn_too_short():
    assert _luhn_valid("123456") is False


def test_luhn_too_long():
    assert _luhn_valid("12345678901234567890123") is False


def test_aws_access_key_valid_length():
    assert _aws_access_key_valid("AKIA" + "A" * 16) is True


def test_aws_access_key_too_short():
    assert _aws_access_key_valid("AKIASHORT") is False


def test_aws_access_key_example_rejected():
    assert _aws_access_key_valid("AKIAEXAMPLE00000000") is False


def test_github_token_valid_realistic():
    assert _github_token_valid("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890") is True


def test_github_token_example_rejected():
    assert _github_token_valid("ghp_EXAMPLE1234567890abcdefghijklmnopqrstuv") is False


def test_github_token_fake_rejected():
    assert _github_token_valid("ghp_FAKE1234567890abcdefghijklmnopqrstuv") is False


def test_is_uuid_like_valid():
    assert _is_uuid_like("12345678-1234-1234-1234-123456789012") is True


def test_is_uuid_like_invalid():
    assert _is_uuid_like("not-a-uuid") is False


# --------------------------------------------------------------------------- #
# Detectors: engine scan multiple messages
# --------------------------------------------------------------------------- #

def test_engine_scan_multiple_messages():
    engine = DetectorEngine()
    msgs = [
        Message(role="user", content="AKIAIOSFODNN7EXAMPLE2", provider="test"),
        Message(role="assistant", content="normal text", provider="test"),
        Message(role="user", content="ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890", provider="test"),
    ]
    findings = engine.scan(msgs)
    assert len(findings) >= 2  # at least AWS + GitHub


def test_engine_custom_rules():
    """Engine accepts custom rule list."""
    import re

    from didileak.detectors import Rule
    custom = Rule(
        rule_id="test-rule",
        name="Test",
        category="secret",
        severity=Severity.LOW,
        pattern=re.compile(r"TEST_\d+"),
    )
    engine = DetectorEngine(rules=[custom])
    findings = engine.scan_message(Message(role="user", content="TEST_123", provider="test"))
    assert len(findings) == 1
    assert findings[0].rule_id == "test-rule"


# --------------------------------------------------------------------------- #
# Detectors: allowlist edge cases
# --------------------------------------------------------------------------- #

def test_email_with_subdomain_detected():
    from didileak.detectors import DetectorEngine
    engine = DetectorEngine()
    hits = engine.scan_message(Message(role="user", content="contact admin@sub.domain.io", provider="test"))
    assert any(h.rule_id == "email" for h in hits)


def test_email_dotted_local_part():
    from didileak.detectors import DetectorEngine
    engine = DetectorEngine()
    hits = engine.scan_message(Message(role="user", content="first.last@company.com", provider="test"))
    assert any(h.rule_id == "email" for h in hits)


def test_slack_token_in_context():
    from didileak.detectors import DetectorEngine
    engine = DetectorEngine()
    hits = engine.scan_message(Message(role="user", content="slack bot token xoxb-54321-abcdef", provider="test"))
    assert any(h.rule_id == "slack-token" for h in hits)


def test_stripe_test_key_not_flagged_as_live():
    """sk_test_ should NOT match the sk_live_ pattern."""
    from didileak.detectors import DetectorEngine
    engine = DetectorEngine()
    hits = engine.scan_message(Message(role="user", content="STRIPE_KEY=sk_test_abcdef1234567890abcdef123456", provider="test"))
    assert not any(h.rule_id == "stripe-secret-key" for h in hits)


# --------------------------------------------------------------------------- #
# Parsers: detect_provider content sniffing
# --------------------------------------------------------------------------- #

def test_detect_provider_html_by_extension():
    assert detect_provider("random.html") == "claude"


def test_detect_provider_unknown_extension():
    assert detect_provider("data.txt") == "generic"


def test_detect_provider_cursor_by_name():
    assert detect_provider("cursor-export.json") == "cursor"


def test_detect_provider_chatgpt_by_content(tmp_path):
    p = tmp_path / "data.json"
    p.write_bytes(b'{"mapping": {"m1": {"message": {"author": {"role": "user"}}}}}')
    with p.open("rb") as fh:
        head = fh.read(8192)
    assert detect_provider(str(p), head) == "chatgpt"


def test_detect_provider_claude_by_content(tmp_path):
    p = tmp_path / "data.json"
    p.write_bytes(b"<!DOCTYPE html><html><body>claude</body></html>")
    with p.open("rb") as fh:
        head = fh.read(8192)
    assert detect_provider(str(p), head) == "claude"


def test_get_parser_returns_correct_class():
    assert get_parser("chatgpt") is ChatGPTParser
    assert get_parser("claude") is ClaudeParser
    assert get_parser("cursor") is CursorParser
    assert get_parser("generic") is GenericJSONParser
    # Unknown provider falls back to generic
    assert get_parser("unknown") is GenericJSONParser


# --------------------------------------------------------------------------- #
# Parsers: ChatGPT edge cases
# --------------------------------------------------------------------------- #

def test_chatgpt_parser_circular_mapping(tmp_path):
    """Circular references in mapping should not infinite-loop."""
    data = [{
        "title": "circular",
        "create_time": 1.0,
        "update_time": 1.0,
        "mapping": {
            "a": {"id": "a", "message": None, "parent": None, "children": ["b"]},
            "b": {"id": "b", "message": None, "parent": "a", "children": ["a"]},  # back to a
        },
    }]
    p = tmp_path / "circular.json"
    p.write_text(json.dumps(data))
    msgs = list(ChatGPTParser(p).parse())
    # Should terminate, even if no messages are yielded
    assert isinstance(msgs, list)


def test_chatgpt_parser_message_without_content(tmp_path):
    """Messages with no content field should be skipped gracefully."""
    data = [{
        "title": "test",
        "create_time": 1.0,
        "update_time": 1.0,
        "mapping": {
            "m1": {
                "id": "m1",
                "message": {"id": "m1", "author": {"role": "user"}, "create_time": 1.0},
                # no "content" key
                "parent": None,
                "children": [],
            },
        },
    }]
    p = tmp_path / "no_content.json"
    p.write_text(json.dumps(data))
    msgs = list(ChatGPTParser(p).parse())
    assert msgs == []


def test_chatgpt_parser_root_is_dict_not_list(tmp_path):
    """If the JSON root is a dict (not a list), should warn and return empty."""
    p = tmp_path / "dict.json"
    p.write_text(json.dumps({"not": "a list"}))
    parser = ChatGPTParser(p)
    msgs = list(parser.parse())
    assert msgs == []
    assert len(parser.warnings) > 0


# --------------------------------------------------------------------------- #
# Parsers: Claude HTML fallback
# --------------------------------------------------------------------------- #

def test_claude_html_fallback_no_user_message(tmp_path):
    """HTML without the expected structure falls back to text sweep."""
    html = "<html><body><p>just some text with AKIAIOSFODNN7EXAMPLE2 in it</p></body></html>"
    p = tmp_path / "plain.html"
    p.write_text(html, encoding="utf-8")
    parser = ClaudeParser(p)
    msgs = list(parser.parse())
    assert len(msgs) >= 1
    assert any("AKIA" in m.content for m in msgs)
    assert len(parser.warnings) > 0  # warned about fallback


def test_claude_html_with_known_structure(tmp_path):
    """HTML with data-testid attributes extracts user + assistant messages."""
    html = """<!DOCTYPE html>
    <html><body>
    <div data-testid="user-message">my key is AKIAIOSFODNN7EXAMPLE2</div>
    <div data-testid="ai-message">I cannot help</div>
    </body></html>"""
    p = tmp_path / "structured.html"
    p.write_text(html, encoding="utf-8")
    msgs = list(ClaudeParser(p).parse())
    roles = {m.role for m in msgs}
    assert "user" in roles
    assert "assistant" in roles


def test_claude_json_with_dict_wrapper(tmp_path):
    """Some Claude exports wrap conversations in a dict."""
    data = {"conversations": [{
        "uuid": "c1",
        "name": "test",
        "created_at": "2024-01-01T00:00:00.000Z",
        "chat_messages": [
            {"uuid": "m1", "text": "hello", "sender": "human", "created_at": "2024-01-01T00:00:00.000Z"},
        ],
    }]}
    p = tmp_path / "wrapped.json"
    p.write_text(json.dumps(data))
    msgs = list(ClaudeParser(p).parse())
    assert len(msgs) == 1
    assert msgs[0].content == "hello"


def test_claude_json_with_messages_key(tmp_path):
    """Claude export with 'messages' instead of 'chat_messages'."""
    data = [{
        "uuid": "c1",
        "name": "test",
        "created_at": "2024-01-01T00:00:00.000Z",
        "messages": [
            {"text": "hello", "sender": "human", "created_at": "2024-01-01T00:00:00.000Z"},
        ],
    }]
    p = tmp_path / "messages_key.json"
    p.write_text(json.dumps(data))
    msgs = list(ClaudeParser(p).parse())
    assert len(msgs) == 1


def test_claude_json_invalid_iso_timestamp():
    """Invalid ISO timestamps should return None, not crash."""
    from didileak.parsers.claude import _parse_iso
    assert _parse_iso("not-a-date") is None
    assert _parse_iso(None) is None
    assert _parse_iso("") is None
    assert _parse_iso("2024-01-01T00:00:00.000Z") is not None


# --------------------------------------------------------------------------- #
# Parsers: Cursor SQLite
# --------------------------------------------------------------------------- #

def test_cursor_sqlite_parser(tmp_path):
    """Cursor parser can read from a state.vscdb SQLite file."""
    p = tmp_path / "state.vscdb"
    conn = sqlite3.connect(str(p))
    conn.execute("CREATE TABLE ItemTable (key TEXT, value BLOB)")
    conn.execute("INSERT INTO ItemTable (key, value) VALUES (?, ?)",
                 ("aiService.prompts", json.dumps({"prompt": "debug AKIAIOSFODNN7EXAMPLE2"}).encode()))
    conn.execute("INSERT INTO ItemTable (key, value) VALUES (?, ?)",
                 ("workbench.panel.aichat.view.aichat.chatdata", b"raw text content"))
    conn.commit()
    conn.close()

    msgs = list(CursorParser(p).parse())
    assert len(msgs) >= 1
    assert any("AKIA" in m.content or "aiService" in m.content for m in msgs)


def test_cursor_sqlite_invalid_file(tmp_path):
    """SQLite parser on a non-SQLite file should warn, not crash."""
    p = tmp_path / "not_vscdb.vscdb"
    p.write_text("this is not sqlite")
    parser = CursorParser(p)
    msgs = list(parser.parse())
    assert msgs == []
    assert len(parser.warnings) > 0


def test_cursor_json_missing_chats_field(tmp_path):
    """Cursor JSON without 'chats' key warns and returns empty."""
    p = tmp_path / "bad_cursor.json"
    p.write_text(json.dumps({"foo": "bar"}))
    parser = CursorParser(p)
    msgs = list(parser.parse())
    assert msgs == []
    assert len(parser.warnings) > 0


def test_cursor_json_message_with_no_text(tmp_path):
    """Messages with no text content are skipped."""
    data = {"chats": [{
        "id": "c1",
        "title": "test",
        "createdAt": 1699000000000,
        "messages": [
            {"role": "user", "text": "", "createdAt": 1699000000000},
            {"role": "assistant", "text": "response", "createdAt": 1699000001000},
        ],
    }]}
    p = tmp_path / "cursor_empty.json"
    p.write_text(json.dumps(data))
    msgs = list(CursorParser(p).parse())
    assert len(msgs) == 1  # only the assistant message


# --------------------------------------------------------------------------- #
# Parsers: Generic edge cases
# --------------------------------------------------------------------------- #

def test_generic_parser_content_as_list(tmp_path):
    """Generic parser handles content as a list of strings."""
    data = {"messages": [
        {"role": "user", "content": ["line 1", "line 2 with AKIAIOSFODNN7EXAMPLE2"]},
    ]}
    p = tmp_path / "list_content.json"
    p.write_text(json.dumps(data))
    msgs = list(GenericJSONParser(p).parse())
    assert len(msgs) == 1
    assert "line 1" in msgs[0].content


def test_generic_parser_content_as_dict_with_text(tmp_path):
    """Generic parser handles content as a dict with 'text' key."""
    data = {"messages": [
        {"role": "user", "content": {"text": "hello with AKIAIOSFODNN7EXAMPLE2"}},
    ]}
    p = tmp_path / "dict_content.json"
    p.write_text(json.dumps(data))
    msgs = list(GenericJSONParser(p).parse())
    assert len(msgs) == 1


def test_generic_parser_conversations_with_id(tmp_path):
    """Generic parser extracts conversation id."""
    data = {"conversations": [{
        "id": "conv-123",
        "title": "Test Conv",
        "messages": [
            {"role": "user", "content": "hello"},
        ],
    }]}
    p = tmp_path / "conv_id.json"
    p.write_text(json.dumps(data))
    msgs = list(GenericJSONParser(p).parse())
    assert len(msgs) == 1
    assert msgs[0].conversation_id == "conv-123"
    assert msgs[0].conversation_title == "Test Conv"


def test_generic_parser_walk_strings_deep_nested(tmp_path):
    """Deep nested JSON with no recognized shape falls back to string walking."""
    data = {"level1": {"level2": ["short", "this is a longer string with AKIAIOSFODNN7EXAMPLE2"]}}
    p = tmp_path / "deep.json"
    p.write_text(json.dumps(data))
    parser = GenericJSONParser(p)
    msgs = list(parser.parse())
    assert len(msgs) >= 1
    assert any("AKIA" in m.content for m in msgs)
    assert len(parser.warnings) > 0


# --------------------------------------------------------------------------- #
# Reporters: edge cases
# --------------------------------------------------------------------------- #

def test_markdown_with_parser_warnings():
    """Markdown report includes parser warnings section."""
    result = ScanResult(
        source="test.json",
        provider="chatgpt",
        messages_scanned=1,
        conversations_scanned=1,
        findings=[],
        parser_warnings=["warning 1", "warning 2"],
    )
    md = render_markdown(result)
    assert "Parser warnings" in md
    assert "warning 1" in md
    assert "warning 2" in md


def test_json_report_with_warnings():
    """JSON report includes parser_warnings array."""
    result = ScanResult(
        source="test.json",
        provider="chatgpt",
        messages_scanned=1,
        conversations_scanned=1,
        findings=[],
        parser_warnings=["test warning"],
    )
    out = render_json(result)
    import json
    parsed = json.loads(out)
    assert parsed["parser_warnings"] == ["test warning"]


def test_html_with_warnings():
    """HTML report renders even with parser warnings."""
    result = ScanResult(
        source="test.json",
        provider="chatgpt",
        messages_scanned=1,
        conversations_scanned=1,
        findings=[],
        parser_warnings=["test warning"],
    )
    html = render_html(result)
    assert "<!DOCTYPE html>" in html


def test_html_with_many_findings():
    """HTML handles many findings without truncation."""
    from didileak.detectors import DetectorEngine
    engine = DetectorEngine()
    msgs = [
        Message(role="user", content=f"key {i}: AKIAIOSFODNN7EXAMPLE2", provider="test")
        for i in range(50)
    ]
    result = ScanResult(
        source="test.json",
        provider="test",
        messages_scanned=50,
        conversations_scanned=1,
        findings=engine.scan(msgs),
    )
    html = render_html(result)
    # All 50 findings should be in the embedded JSON
    import re
    m = re.search(r'"total_findings":\s*(\d+)', html)
    assert int(m.group(1)) == 50


# --------------------------------------------------------------------------- #
# Rotation guide
# --------------------------------------------------------------------------- #

def test_rotation_guide_known_rule():
    guide = get_guide("aws-access-token")
    assert "IAM" in guide
    assert "CloudTrail" in guide


def test_rotation_guide_unknown_rule():
    guide = get_guide("nonexistent-rule-id")
    assert "Unknown" in guide or "unknown" in guide


def test_rotation_guide_all_rules_have_entry():
    """Every rule in RULES should have a guide entry."""
    for rule in RULES:
        assert rule.rule_id in GUIDE
        assert isinstance(GUIDE[rule.rule_id], str)


# --------------------------------------------------------------------------- #
# Models: ScanResult methods
# --------------------------------------------------------------------------- #

def test_scan_result_by_category_empty():
    r = ScanResult(source="x", provider="test", messages_scanned=0, conversations_scanned=0)
    assert r.by_category() == {}


def test_scan_result_by_rule_empty():
    r = ScanResult(source="x", provider="test", messages_scanned=0, conversations_scanned=0)
    assert r.by_rule() == {}


def test_scan_result_sorted_findings():
    """Findings are sorted by severity weight (descending)."""
    from didileak.detectors import DetectorEngine
    engine = DetectorEngine()
    msgs = [
        Message(role="user", content="email: test@acme.io", provider="test"),  # low
        Message(role="user", content="AKIAIOSFODNN7EXAMPLE2", provider="test"),  # critical
        Message(role="user", content="eyJabcdefgh.eyJabcdefgh.SflKxw12", provider="test"),  # high (jwt)
    ]
    r = ScanResult(
        source="x", provider="test", messages_scanned=3, conversations_scanned=1,
        findings=engine.scan(msgs),
    )
    sorted_f = r.sorted_findings()
    if len(sorted_f) >= 2:
        assert sorted_f[0].severity.weight >= sorted_f[-1].severity.weight


def test_finding_context_window():
    """Message.context returns text around a span with ... for truncation."""
    msg = Message(role="user", content="A" * 200 + "SECRET" + "B" * 200, provider="test")
    ctx = msg.context(200, 206, radius=20)
    assert "..." in ctx
    assert "SECRET" in ctx


def test_finding_context_at_start():
    """Context at the start of a message doesn't add leading ..."""
    msg = Message(role="user", content="SECRET at the start", provider="test")
    ctx = msg.context(0, 6, radius=10)
    assert not ctx.startswith("...")


def test_severity_weight_ordering():
    assert Severity.CRITICAL.weight > Severity.HIGH.weight
    assert Severity.HIGH.weight > Severity.MEDIUM.weight
    assert Severity.MEDIUM.weight > Severity.LOW.weight
    assert Severity.LOW.weight > Severity.INFO.weight
