"""Tests for the reporters."""
from __future__ import annotations

import json

from didileak.detectors import DetectorEngine
from didileak.models import Message, ScanResult
from didileak.reporters import render_html, render_json, render_markdown


def _result_with_findings() -> ScanResult:
    engine = DetectorEngine()
    msgs = [
        Message(role="user", content="AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE2", provider="chatgpt",
                conversation_id="c1", conversation_title="Test"),
        Message(role="assistant", content="ok", provider="chatgpt"),
    ]
    return ScanResult(
        source="test.json", provider="chatgpt", messages_scanned=2,
        conversations_scanned=1, findings=engine.scan(msgs),
    )


def test_markdown_includes_summary_and_findings():
    r = _result_with_findings()
    md = render_markdown(r)
    assert "# didileak report" in md
    assert "AWS Access Key" in md
    assert "Rotation guide" in md
    assert "AKIA" in md


def test_markdown_clean_export():
    r = ScanResult(source="clean.json", provider="chatgpt", messages_scanned=10,
                   conversations_scanned=2, findings=[])
    md = render_markdown(r)
    assert "No secrets or PII detected" in md


def test_json_is_valid_and_has_fields():
    r = _result_with_findings()
    out = render_json(r)
    parsed = json.loads(out)
    assert parsed["total_findings"] >= 1
    assert parsed["by_severity"]["critical"] >= 1
    assert len(parsed["findings"]) >= 1
    assert "masked_value" in parsed["findings"][0]
    # JSON report keeps the full matched_value for incident response
    assert "matched_value" in parsed["findings"][0]


def test_html_is_self_contained():
    r = _result_with_findings()
    html = render_html(r)
    assert "<!DOCTYPE html>" in html
    assert "</html>" in html
    # Embedded JSON data
    assert '<script id="data" type="application/json">' in html
    # Findings present
    assert "AWS Access Key" in html
    # Mask, not full value
    assert "AKIAIOSFODNN7EXAMPLE2" not in html


def test_html_clean_export():
    r = ScanResult(source="clean.json", provider="chatgpt", messages_scanned=10,
                   conversations_scanned=2, findings=[])
    html = render_html(r)
    assert "Clean" in html
    assert '"findings": []' in html or '"findings":[]' in html


def test_finding_to_dict_round_trip():
    r = _result_with_findings()
    d = r.findings[0].to_dict()
    assert d["severity"] == "critical"
    assert d["rule_id"] == "aws-access-token"
    assert isinstance(d["span_start"], int)
