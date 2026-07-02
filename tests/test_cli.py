"""End-to-end CLI tests."""
from __future__ import annotations

import json

import pytest

from didileak.cli import main, scan_path


def test_scan_path_chatgpt(chatgpt_export):
    r = scan_path(chatgpt_export)
    assert r.provider == "chatgpt"
    assert r.messages_scanned == 2
    assert r.total_findings >= 3
    assert r.by_severity()["critical"] >= 1


def test_scan_path_claude_json(claude_json_export):
    r = scan_path(claude_json_export)
    assert r.provider == "claude"
    assert r.messages_scanned == 2
    assert r.total_findings >= 1


def test_scan_path_cursor(cursor_json_export):
    r = scan_path(cursor_json_export)
    assert r.provider == "cursor"
    assert r.total_findings >= 1


def test_scan_path_generic(generic_messages_export):
    r = scan_path(generic_messages_export)
    assert r.provider == "generic"
    assert r.total_findings >= 1


def test_scan_path_clean(clean_export):
    r = scan_path(clean_export)
    assert r.total_findings == 0


def test_scan_path_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        scan_path(tmp_path / "does-not-exist.json")


def test_cli_scan_writes_html(chatgpt_export, tmp_path):
    out = tmp_path / "report.html"
    rc = main(["scan", str(chatgpt_export), "--html", str(out)])
    assert rc == 0
    assert out.exists()
    assert "<!DOCTYPE html>" in out.read_text(encoding="utf-8")


def test_cli_scan_writes_json_and_md(chatgpt_export, tmp_path):
    j = tmp_path / "r.json"
    m = tmp_path / "r.md"
    rc = main(["scan", str(chatgpt_export), "--json", str(j), "--markdown", str(m)])
    assert rc == 0
    assert j.exists() and m.exists()
    parsed = json.loads(j.read_text())
    assert parsed["total_findings"] >= 1


def test_cli_report_writes_all_three(chatgpt_export, tmp_path):
    outdir = tmp_path / "out"
    rc = main(["report", str(chatgpt_export), "--outdir", str(outdir)])
    assert rc == 0
    assert (outdir / "didileak_report.md").exists()
    assert (outdir / "didileak_report.json").exists()
    assert (outdir / "didileak_report.html").exists()


def test_cli_rotation_list(capsys):
    rc = main(["rotation"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "aws-access-token" in out


def test_cli_rotation_specific_rule(capsys):
    rc = main(["rotation", "github-pat"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Revoke" in out or "Revoke immediately" in out


def test_cli_rotation_unknown_rule_returns_2(capsys):
    rc = main(["rotation", "no-such-rule"])
    assert rc == 2


def test_cli_scan_directory(chatgpt_export, tmp_path):
    # Move the file into a dir
    d = tmp_path / "exports"
    d.mkdir()
    target = d / chatgpt_export.name
    chatgpt_export.replace(target)
    rc = main(["scan", str(d)])
    assert rc == 0
