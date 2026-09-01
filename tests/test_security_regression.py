"""Security regression tests for the reporting pipeline, web contract,
parser autodetection and CLI report handling.

Each test reproduces the original bug's precondition with synthetic fixtures
or documented example credentials (AWS docs: AKIAIOSFODNN7EXAMPLE /
wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY) and asserts the patched behavior.
They are written to FAIL if any of the regressions is reintroduced.
"""
from __future__ import annotations

import json
import os
import re
import stat
import sys
from pathlib import Path

import pytest

from didileak.cli import main, scan_path
from didileak.detectors import DetectorEngine
from didileak.models import Message, ScanResult
from didileak.parsers import detect_provider
from didileak.reporters import render_html, render_json, render_markdown
from didileak.reporters.redact import mask_pairs, redact_context, redaction_pairs

# Documented example credentials (public AWS documentation), not real secrets.
AWS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def _result(msgs: list[Message]) -> ScanResult:
    engine = DetectorEngine()
    return ScanResult(
        source="synthetic.json", provider="chatgpt",
        messages_scanned=len(msgs), conversations_scanned=1,
        findings=engine.scan(msgs),
    )


def _extract_payload(html: str) -> dict:
    m = re.search(
        r'<script id="data" type="application/json">(.+?)</script>', html, re.DOTALL
    )
    assert m, "data payload script element not found"
    return json.loads(m.group(1))


# --------------------------------------------------------------------------- #
# Stored XSS via </script> breakout in the HTML reporter
# --------------------------------------------------------------------------- #

def test_html_script_breakout():
    malicious = "title </script><script>window.__didileak_pwned=1</script>"
    msgs = [Message(
        role="user", content=f"AWS_ACCESS_KEY_ID={AWS_KEY_ID}",
        provider="chatgpt", conversation_title=malicious,
    )]
    html = render_html(_result(msgs))
    # The breakout sequence must NOT appear literally anywhere in the document.
    assert "</script><script>" not in html
    assert "window.__didileak_pwned=1</script>" not in html
    # The escape must be lossless: the payload still parses and round-trips.
    data = _extract_payload(html)
    assert data["findings"][0]["conversation_title"] == malicious


def test_html_escapes_line_separators():
    malicious = "title with u2028 and u2029 separators"
    msgs = [Message(
        role="user", content=f"AWS_ACCESS_KEY_ID={AWS_KEY_ID}",
        provider="chatgpt", conversation_title=malicious,
    )]
    html = render_html(_result(msgs))
    m = re.search(
        r'<script id="data" type="application/json">(.+?)</script>', html, re.DOTALL
    )
    payload = m.group(1)
    assert " " not in payload  # raw U+2028 must be escaped
    assert " " not in payload  # raw U+2029 must be escaped
    assert json.loads(payload)["findings"][0]["conversation_title"] == malicious


# --------------------------------------------------------------------------- #
# Markdown reporter leaks full secrets via context
# --------------------------------------------------------------------------- #

def test_markdown_context_redacted():
    synthetic = "SYNTHETIC_SECRET_123456789"
    msgs = [Message(
        role="user",
        content=f"deploy notes: api_key = {synthetic} , rotate quarterly",
        provider="chatgpt", conversation_title="ops",
    )]
    result = _result(msgs)
    assert result.findings, "fixture must produce at least one finding"
    md = render_markdown(result)
    assert synthetic not in md, "full secret leaked into the Markdown context"
    assert result.findings[0].masked_value in md, "masked value should be present"
    # The context line survives, redacted — not dropped.
    assert "deploy notes:" in md
    assert "rotate quarterly" in md


def test_markdown_hint_no_ghost_flag():
    msgs = [Message(role="user", content=f"AWS_ACCESS_KEY_ID={AWS_KEY_ID}", provider="chatgpt")]
    md = render_markdown(_result(msgs))
    assert "## Findings" in md
    # The old hint recommended `didileak report --format json`, which the CLI
    # never supported (`--format` does not exist in any subcommand).
    assert "--format" not in md
    assert "--json" in md


# --------------------------------------------------------------------------- #
# Cross-finding context leak in the HTML reporter
# --------------------------------------------------------------------------- #

def _two_overlapping_findings() -> ScanResult:
    # Access key id and secret key in the same message: their ±60 context
    # windows overlap, so each finding's context contains the other's secret.
    msgs = [Message(
        role="user", content=f"{AWS_KEY_ID} {AWS_SECRET}", provider="chatgpt",
    )]
    result = _result(msgs)
    assert len(result.findings) >= 2, "fixture must produce two findings"
    return result


def test_html_cross_finding_redaction():
    html = render_html(_two_overlapping_findings())
    assert AWS_KEY_ID not in html
    assert AWS_SECRET not in html
    # Both masked values must survive.
    for f in _two_overlapping_findings().findings:
        assert f.masked_value in html


def test_markdown_cross_finding_redaction():
    md = render_markdown(_two_overlapping_findings())
    assert AWS_KEY_ID not in md
    assert AWS_SECRET not in md


def test_secret_in_finding_metadata_redacted():
    # A secret that also appears in a finding's own metadata fields (role,
    # ids) must be masked there too — those fields are free text from the
    # export and can embed values matched elsewhere.
    msgs = [Message(
        role=AWS_KEY_ID,
        content=f"creds: {AWS_KEY_ID} {AWS_SECRET}",
        provider="chatgpt",
    )]
    result = _result(msgs)
    html = render_html(result)
    md = render_markdown(result)
    for out in (html, md):
        assert AWS_KEY_ID not in out
        assert AWS_SECRET not in out


# --------------------------------------------------------------------------- #
# matched_value must never reach the HTML payload / web contract
# --------------------------------------------------------------------------- #

def test_html_payload_has_no_matched_value_key():
    html = render_html(_two_overlapping_findings())
    assert "matched_value" not in html
    data = _extract_payload(html)
    assert "matched_value" not in data["findings"][0]


def test_cli_json_keeps_matched_value_by_design():
    # The CLI JSON report intentionally keeps full values for incident
    # response (documented in CHANGELOG and SECURITY.md); the web contract is
    # the sanitized one (dashboard/lib/sanitize.ts). This pins the split.
    out = render_json(_two_overlapping_findings())
    parsed = json.loads(out)
    assert all("matched_value" in f for f in parsed["findings"])


# --------------------------------------------------------------------------- #
# Claude exports named conversations.json misdetected as ChatGPT
# --------------------------------------------------------------------------- #

CLAUDE_HINT = json.dumps([{
    "uuid": "c1", "name": "t", "created_at": "2024-01-01T00:00:00Z",
    "chat_messages": [{"uuid": "m1", "text": "x", "sender": "human",
                       "created_at": "2024-01-01T00:00:00Z"}],
}]).encode()

CHATGPT_HINT = json.dumps([{
    "title": "t", "mapping": {"m1": {"message": {
        "author": {"role": "user"},
        "content": {"parts": ["x"]},
    }}},
}]).encode()


def test_detect_provider_structure_beats_filename():
    # Anthropic's default export name is conversations.json (see
    # parsers/claude.py docstring); content must win over the name.
    assert detect_provider("conversations.json", CLAUDE_HINT) == "claude"
    assert detect_provider("conversations.json", CHATGPT_HINT) == "chatgpt"
    # Symmetric case: a ChatGPT export renamed with a Claude-ish name.
    assert detect_provider("claude-backup.json", CHATGPT_HINT) == "chatgpt"
    # Cursor structure detected by shape too.
    cursor_hint = b'{"chats": [{"id": "c1", "messages": [{"role": "user", "text": "x"}]}]}'
    assert detect_provider("conversations.json", cursor_hint) == "cursor"


def test_detect_provider_filename_fallback_unchanged():
    # No content hint: legacy name-based behavior is the frozen contract
    # (tests/test_parsers.py::test_detect_provider_by_filename).
    assert detect_provider("conversations.json") == "chatgpt"
    assert detect_provider("claude_export.html") == "claude"
    assert detect_provider("cursor_export.json") == "cursor"
    assert detect_provider("random.json") == "generic"


def test_claude_named_conversations_end_to_end(tmp_path: Path):
    # The original repro: a Claude export named conversations.json that
    # contains a secret must NOT report clean.
    p = tmp_path / "conversations.json"
    p.write_text(CLAUDE_HINT.decode().replace(
        '"text": "x"',
        '"text": "my key is AKIAIOSFODNN7EXAMPLE ok"',
    ), encoding="utf-8")
    result = scan_path(p)
    assert result.provider == "claude"
    assert result.messages_scanned >= 1
    assert result.total_findings >= 1, "silent false negative reintroduced"


def test_generic_json_with_uuid_sender_not_misrouted(tmp_path: Path):
    # A generic JSON log whose messages carry "uuid"/"sender" fields must
    # stay with the generic parser (string walker), not be claimed by the
    # Claude parser and silently produce zero findings.
    p = tmp_path / "dump.json"
    p.write_text(json.dumps({"messages": [
        {"uuid": "m1", "sender": "user", "text": f"key = {AWS_KEY_ID}"}
    ]}), encoding="utf-8")
    result = scan_path(p)
    assert result.provider == "generic"
    assert result.total_findings >= 1, "generic export misrouted to a zero-yield parser"


def test_zero_message_scan_warns_about_possible_misroute(tmp_path: Path):
    # If a dedicated parser yields nothing, the result must say so instead
    # of silently reporting a clean export.
    p = tmp_path / "conversations.json"
    p.write_text('{"chats": [], "messages": [{"text": "x"}]}',
                 encoding="utf-8")
    result = scan_path(p)
    assert result.messages_scanned == 0
    assert any("parsed 0 messages" in w for w in result.parser_warnings)


# --------------------------------------------------------------------------- #
# Report files must be owner-only (0600)
# --------------------------------------------------------------------------- #

@pytest.fixture
def chatgpt_file(tmp_path: Path) -> Path:
    data = [{
        "title": "Debug", "create_time": 1699000000.0, "mapping": {
            "m1": {"message": {
                "id": "m1", "author": {"role": "user"},
                "content": {"content_type": "text",
                            "parts": [f"AWS_ACCESS_KEY_ID={AWS_KEY_ID}"]},
                "create_time": 1699000000.0,
            }, "parent": None, "children": []},
        },
    }]
    p = tmp_path / "conversations.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_scan_reports_owner_only(chatgpt_file: Path, tmp_path: Path):
    old_umask = os.umask(0o022)  # the classic worst case: 0644 default
    try:
        rc = main([
            "scan", str(chatgpt_file),
            "--json", str(tmp_path / "r.json"),
            "--markdown", str(tmp_path / "r.md"),
            "--html", str(tmp_path / "r.html"),
        ])
    finally:
        os.umask(old_umask)
    assert rc == 0
    for name in ("r.json", "r.md", "r.html"):
        assert _mode(tmp_path / name) == 0o600, f"{name} must be 0600"


def test_report_outdir_owner_only(chatgpt_file: Path, tmp_path: Path):
    outdir = tmp_path / "reports"
    rc = main(["report", str(chatgpt_file), "--outdir", str(outdir)])
    assert rc == 0
    for name in ("didileak_report.json", "didileak_report.md",
                 "didileak_report.html"):
        assert _mode(outdir / name) == 0o600, f"{name} must be 0600"


def test_report_tightens_preexisting_file(chatgpt_file: Path, tmp_path: Path):
    out = tmp_path / "r.json"
    out.write_text("old world-readable report", encoding="utf-8")
    os.chmod(out, 0o644)
    rc = main(["scan", str(chatgpt_file), "--json", str(out)])
    assert rc == 0
    assert _mode(out) == 0o600, "pre-existing 0644 report must be re-tightened"


def test_report_refuses_symlink_path(chatgpt_file: Path, tmp_path: Path):
    victim = tmp_path / "victim.txt"
    victim.write_text("sentinel", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(victim)
    rc = main(["scan", str(chatgpt_file), "--json", str(link)])
    assert rc == 2, "writing a secret-laden report through a symlink must fail"
    assert victim.read_text(encoding="utf-8") == "sentinel"


# --------------------------------------------------------------------------- #
# Multi-input scan must not overwrite its own output
# --------------------------------------------------------------------------- #

def _chatgpt_file_with(tmp_path: Path, name: str, secret: str) -> Path:
    data = [{
        "title": "t", "create_time": 1.0, "mapping": {
            "m1": {"message": {
                "author": {"role": "user"},
                "content": {"content_type": "text", "parts": [f"key = {secret}"]},
            }},
        },
    }]
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def test_multi_input_keeps_both_results(tmp_path: Path):
    # Distinct 16-char key bodies so both files yield distinct matched values.
    a = _chatgpt_file_with(tmp_path, "a.json", AWS_KEY_ID)
    b = _chatgpt_file_with(tmp_path, "b.json", "AKIAIOSFODNN7EXAMPL9")
    out = tmp_path / "report.json"
    rc = main(["scan", str(a), str(b), "--json", str(out)])
    assert rc == 0
    parsed = json.loads(out.read_text(encoding="utf-8"))
    assert parsed["total_findings"] == 2, "one input's findings were lost"
    values = {f["matched_value"] for f in parsed["findings"]}
    assert AWS_KEY_ID in values and "AKIAIOSFODNN7EXAMPL9" in values


def test_single_input_contract_unchanged(tmp_path: Path):
    a = _chatgpt_file_with(tmp_path, "a.json", AWS_KEY_ID)
    out = tmp_path / "report.json"
    rc = main(["scan", str(a), "--json", str(out)])
    assert rc == 0
    parsed = json.loads(out.read_text(encoding="utf-8"))
    # Byte-compatible with the pre-patch single-file behavior.
    assert parsed["source"] == str(a)
    assert parsed["provider"] == "chatgpt"
    assert parsed["total_findings"] == 1


def test_multi_input_all_formats(tmp_path: Path):
    a = _chatgpt_file_with(tmp_path, "a.json", AWS_KEY_ID)
    b = _chatgpt_file_with(tmp_path, "b.json", "AKIAIOSFODNN7EXAMPL9")
    j = tmp_path / "r.json"
    m = tmp_path / "r.md"
    h = tmp_path / "r.html"
    rc = main(["scan", str(a), str(b),
               "--json", str(j), "--markdown", str(m), "--html", str(h)])
    assert rc == 0
    parsed = json.loads(j.read_text(encoding="utf-8"))
    assert parsed["total_findings"] == 2
    assert parsed["source"] == "2 files"
    assert parsed["provider"] == "multi"
    md = m.read_text(encoding="utf-8")
    assert md.count("### ") == 2, "Markdown must list both inputs' findings"
    html = h.read_text(encoding="utf-8")
    assert '"total_findings": 2' in html


# --------------------------------------------------------------------------- #
# Shared redaction helpers (unit level)
# --------------------------------------------------------------------------- #

def test_mask_pairs_longest_first_and_dict_support():
    findings = [
        {"matched_value": "short", "masked_value": "sh***"},
        {"matched_value": "muchlongersecre", "masked_value": "mu***re"},
    ]
    pairs = mask_pairs(findings)
    assert pairs[0][0] == "muchlongersecre"  # longest first
    ctx = "prefix muchlongersecre with short inside"
    out = redact_context(ctx, pairs)
    assert "muchlongersecre" not in out
    assert "short" not in out


def test_mask_pairs_skips_empty_and_dedupes():
    findings = [
        {"matched_value": "", "masked_value": "x"},
        {"matched_value": "s", "masked_value": "m"},
        {"matched_value": "s", "masked_value": "m"},
    ]
    assert mask_pairs(findings) == [("s", "m")]


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main([__file__]))


# --------------------------------------------------------------------------- #
# Round 2: truncated fragments and bare core values surviving redaction
# --------------------------------------------------------------------------- #

AWS_SECRET_40 = "wJalrXUtnFEMIK7AAbCdEfGhIjKlMnOpQrStUvWx"


def _adjacent_creds_result() -> ScanResult:
    # The canonical adjacent-credentials layout: access key id on one line,
    # secret key on the next. Each finding's ±60 context window cuts the
    # other's secret mid-value at the window edge.
    content = (
        f"AWS_ACCESS_KEY_ID={AWS_KEY_ID}\n"
        f"aws_secret_access_key={AWS_SECRET_40}\n"
        "end of message"
    )
    return _result([Message(role="user", content=content, provider="chatgpt")])


def _longest_fragment(secret: str, text: str) -> int:
    """Longest prefix or suffix of `secret` present in `text` (>= 5 chars)."""
    for k in range(len(secret), 4, -1):
        if secret[:k] in text or secret[-k:] in text:
            return k
    return 0


def test_html_context_redacts_truncated_neighbor():
    payload = _extract_payload(render_html(_adjacent_creds_result()))
    for f in payload["findings"]:
        assert _longest_fragment(AWS_SECRET_40, f["context"]) <= 4, (
            "truncated secret fragment survived in HTML context"
        )
        assert _longest_fragment(AWS_KEY_ID, f["context"]) <= 4


def test_markdown_context_redacts_truncated_neighbor():
    md = render_markdown(_adjacent_creds_result())
    assert _longest_fragment(AWS_SECRET_40, md) <= 4, (
        "truncated secret fragment survived in Markdown"
    )
    assert _longest_fragment(AWS_KEY_ID, md) <= 4


def test_bare_value_repetition_redacted():
    # Rules whose matched_value includes a prefix (generic-api-key: the
    # keyword and separator) used to leave bare repetitions of the value
    # untouched in contexts and titles.
    secret = "VeryS3cretVal1234567"
    content = (
        f"password = {secret} ok; padding padding; people also paste "
        f"{secret} bare in slack channels all the time"
    )
    msgs = [Message(
        role="user", content=content, provider="chatgpt",
        conversation_title=f"{secret} bare in title",
    )]
    result = _result(msgs)
    assert result.findings, "fixture must produce at least one finding"
    for out in (render_html(result), render_markdown(result)):
        assert secret not in out, "bare secret value survived redaction"
        assert result.findings[0].masked_value in out


def test_bearer_and_uri_core_values_redacted():
    bearer = "SuperBearerToken123456789"
    dbpass = "Hunter2Pass9Xyz"
    content = (
        f"Authorization: Bearer {bearer} accepted; token {bearer} was reused; "
        f"db is postgres://admin:{dbpass}@db.internal/app and the password "
        f"{dbpass} is also written on the whiteboard"
    )
    msgs = [Message(role="user", content=content, provider="chatgpt")]
    result = _result(msgs)
    assert result.findings, "fixture must produce at least one finding"
    for out in (render_html(result), render_markdown(result)):
        assert bearer not in out, "bare bearer token survived redaction"
        assert dbpass not in out, "bare connection-string password survived redaction"


def test_redaction_pairs_add_secret_cores():
    findings = [{"matched_value": f"password = {AWS_SECRET_40}",
                 "masked_value": "pass...UvWx"}]
    pairs = redaction_pairs(findings)
    raws = [mv for mv, _ in pairs]
    assert f"password = {AWS_SECRET_40}" in raws
    assert AWS_SECRET_40 in raws, "core value missing from redaction pairs"
    # Longest first still holds with the derived pair included.
    assert raws == sorted(raws, key=len, reverse=True)


# --------------------------------------------------------------------------- #
# Round 2: conversation titles printed raw to stdout / TUI
# --------------------------------------------------------------------------- #

def test_stdout_summary_redacts_titles(tmp_path: Path, capsys):
    # ChatGPT auto-generates titles from the first message, so a secret
    # pasted as the first message ends up in the title - and used to be
    # printed raw by the rich preview table.
    title = f"creds {AWS_KEY_ID} inline"
    data = [{
        "title": title, "create_time": 1.0, "mapping": {
            "m1": {"message": {
                "author": {"role": "user"},
                "content": {"content_type": "text",
                            "parts": [f"AWS_ACCESS_KEY_ID={AWS_KEY_ID}"]},
            }},
        },
    }]
    p = tmp_path / "conversations.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    rc = main(["scan", str(p)])
    captured = capsys.readouterr()
    assert rc == 0
    flat = "".join(captured.out.split())
    assert AWS_KEY_ID not in flat, "secret leaked to stdout via the title"
    assert "Traceback" not in captured.err


# --------------------------------------------------------------------------- #
# Round 2: exports containing lone surrogates crash the CLI
# --------------------------------------------------------------------------- #

def test_cli_survives_lone_surrogates(tmp_path: Path, capsys):
    # A JSON escape like \ud800 decodes to a lone surrogate: valid inside a
    # Python str, invalid in UTF-8. It used to raise UnicodeEncodeError in
    # the rich console and abort the scan before any report was written.
    p = tmp_path / "conversations.json"
    p.write_text(json.dumps([{
        "uuid": "c1", "name": "surro \ud800 gate",
        "created_at": "2026-01-01T00:00:00Z",
        "chat_messages": [{
            "uuid": "m1", "sender": "human",
            "created_at": "2026-01-01T00:00:00Z",
            "text": "password = LoneSurrogateVal1234 \ud800 end",
        }],
    }]), encoding="utf-8")
    out = tmp_path / "r.json"
    html = tmp_path / "r.html"
    rc = main(["scan", str(p), "--json", str(out), "--html", str(html)])
    captured = capsys.readouterr()
    assert rc == 0, "surrogate in export must not abort the scan"
    assert "UnicodeEncodeError" not in captured.err
    parsed = json.loads(out.read_text(encoding="utf-8"))
    ctx = parsed["findings"][0]["context"]
    assert "\N{REPLACEMENT CHARACTER}" in ctx, (
        "lone surrogate should be mapped to U+FFFD, not crash or vanish"
    )


# --------------------------------------------------------------------------- #
# Round 2: multi-input scans with a failed input exited green
# --------------------------------------------------------------------------- #

def test_scan_partial_failure_exits_nonzero(tmp_path: Path):
    good = _chatgpt_file_with(tmp_path, "a.json", AWS_KEY_ID)
    bad = tmp_path / "unreadable.json"
    bad.write_text("{}", encoding="utf-8")
    bad.chmod(0)
    out = tmp_path / "report.json"
    try:
        rc = main(["scan", str(good), str(bad), "--json", str(out)])
    finally:
        bad.chmod(0o644)
    assert rc == 2, "partially failed scan must not exit green"
    parsed = json.loads(out.read_text(encoding="utf-8"))
    assert parsed["total_findings"] == 1, "the readable input must still report"


def test_report_partial_failure_exits_nonzero(tmp_path: Path):
    good = _chatgpt_file_with(tmp_path, "a.json", AWS_KEY_ID)
    bad = tmp_path / "unreadable.json"
    bad.write_text("{}", encoding="utf-8")
    bad.chmod(0)
    outdir = tmp_path / "reports"
    try:
        rc = main(["report", str(good), str(bad), "--outdir", str(outdir)])
    finally:
        bad.chmod(0o644)
    assert rc == 2
    assert (outdir / "didileak_report.json").exists()


# --------------------------------------------------------------------------- #
# Round 2: markdown injection in the shared report
# --------------------------------------------------------------------------- #

def test_markdown_neutralizes_injection():
    secret = "PhishySecretVal12345"
    # Secret at the END so the injection payloads above it fall inside the
    # ±60 context window of the match.
    content = (
        "[phish](https://evil.example/steal) <img src=x onerror=alert(1)>\n"
        "second line\n"
        f"password = {secret}"
    )
    msgs = [Message(
        role="user", content=content, provider="chatgpt",
        conversation_title="title with `backticks` and [phish](https://evil.example)",
    )]
    md = render_markdown(_result(msgs))
    assert secret not in md
    # Links/images are defused: brackets survive only escaped.
    assert "[phish](https://evil.example/steal)" not in md
    assert "\\[phish\\]" in md
    # Raw HTML tags are entity-escaped.
    assert "<img src=x" not in md
    assert "&lt;img" in md
    # Context newlines are flattened so nothing escapes the blockquote line.
    assert "\nsecond line" not in md
    assert "second line" in md
    # Backticks in titles cannot open a code span that swallows report
    # structure; the title line stays a single line.
    assert "title with \\`backticks\\`" in md


def test_markdown_source_survives_backticks(tmp_path: Path):
    # A source path containing a backtick must not break out of the code
    # span on the Source line.
    result = _result([Message(
        role="user", content=f"AWS_ACCESS_KEY_ID={AWS_KEY_ID}", provider="chatgpt",
    )])
    result.source = "we`ird path.json"
    md = render_markdown(result)
    assert "`we`ird path.json`" not in md
    assert "we'ird path.json" in md


def test_overlapping_spans_redact_cleanly():
    # The 40-char aws-secret rule can match INSIDE a ghp_ token; their
    # window cuts overlap and must merge into one mask instead of splicing
    # each other into raw residue (found via the demo sample regeneration).
    inner = "1234f1234567890abcdef1234567890abcdef"
    token = f"ghp_{inner}"
    content = (
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        f"GITHUB_TOKEN={token}\n"
        "the end"
    )
    result = _result([Message(role="user", content=content, provider="chatgpt")])
    rules = {f.rule_id for f in result.findings}
    assert "github-pat" in rules and "aws-secret-access-key" in rules
    for out in (render_html(result), render_markdown(result)):
        assert token not in out
        assert inner not in out
        # No long raw run of the token survives anywhere in the report.
        assert _longest_fragment(inner, out) <= 4


def _big_email_result(n: int) -> ScanResult:
    # Distinct low-severity matches (emails) are the cheapest way to get
    # many distinct pairs; the allowlist ignores example.com/.org/.net.
    content = ", ".join(f"user{i}@domain{i}.io" for i in range(n))
    msgs = [Message(role="user", content=content, provider="chatgpt")]
    return _result(msgs)


def test_report_rendering_stays_subquadratic():
    # Redaction used to replace every known pair inside every context
    # field, so an N-finding report paid O(N^2) - a CPU-DoS on the
    # dashboard. Ratio-based bound: machine-independent (quadratic growth
    # is a 16x step per doubling, linear ~4x; 12 leaves headroom for noise).
    import time as _time

    def _render(n: int) -> float:
        result = _big_email_result(n)
        t0 = _time.perf_counter()
        render_html(result)
        render_markdown(result)
        return _time.perf_counter() - t0

    t_small = _render(400)
    t_big = _render(1600)
    assert t_big / max(t_small, 1e-9) < 12, (
        f"rendering grew superlinearly: {t_small:.3f}s -> {t_big:.3f}s "
        "for a 4x finding count"
    )


def test_markdown_neutralizes_role_injection():
    # The role field is free text from the export (author.role) and used to
    # reach the Markdown report unescaped, so raw HTML and link forgery
    # could survive in the shared report.
    secret = "InlineAttackVal12345"
    msgs = [Message(
        role="user\n<img src=x onerror=alert(1)> [phish](https://evil.example)",
        content=f"password = {secret}", provider="chatgpt",
    )]
    md = render_markdown(_result(msgs))
    assert secret not in md
    assert "<img src=x" not in md, "raw HTML survived via the role field"
    assert "[phish](https://evil.example)" not in md, "link forgery survived via the role field"
    assert "&lt;img" in md
