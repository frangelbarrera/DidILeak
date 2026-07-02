"""Test fixtures: synthetic exports with known secrets."""
import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def chatgpt_export(tmp_path: Path) -> Path:
    """Minimal ChatGPT conversations.json with one real-ish secret."""
    data = [{
        "title": "Debug .env",
        "create_time": 1699000000.0,
        "update_time": 1699000100.0,
        "mapping": {
            "m1": {
                "id": "m1",
                "message": {
                    "id": "m1",
                    "author": {"role": "user"},
                    "content": {"content_type": "text", "parts": [
                        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE "
                        "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz1234 "
                        "JWT=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123def456ghi789"
                    ]},
                    "create_time": 1699000000.0,
                },
                "parent": None,
                "children": ["m2"],
            },
            "m2": {
                "id": "m2",
                "message": {
                    "id": "m2",
                    "author": {"role": "assistant"},
                    "content": {"content_type": "text", "parts": ["ok"]},
                    "create_time": 1699000010.0,
                },
                "parent": "m1",
                "children": [],
            },
        },
    }]
    p = tmp_path / "conversations.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


@pytest.fixture
def chatgpt_with_non_text_parts(tmp_path: Path) -> Path:
    """A DALL-E image attachment part should not crash the parser."""
    data = [{
        "title": "Image",
        "create_time": 1699000000.0,
        "update_time": 1699000000.0,
        "mapping": {
            "m1": {
                "id": "m1",
                "message": {
                    "id": "m1",
                    "author": {"role": "assistant"},
                    "content": {
                        "content_type": "multimodal_text",
                        "parts": [
                            "Here you go:",
                            {"content_type": "image_asset_pointer", "asset_pointer": "file-abc"},
                        ],
                    },
                    "create_time": 1699000000.0,
                },
                "parent": None,
                "children": [],
            }
        },
    }]
    p = tmp_path / "conv.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


@pytest.fixture
def claude_json_export(tmp_path: Path) -> Path:
    data = [{
        "uuid": "c1",
        "name": "Quick question",
        "created_at": "2024-01-01T00:00:00.000Z",
        "updated_at": "2024-01-01T00:01:00.000Z",
        "chat_messages": [
            {"uuid": "m1", "text": "whats my google api key AIzaSyD-9tSrke72PouQMnMXr7wZ3pK1MfTQw7oX", "sender": "human", "created_at": "2024-01-01T00:00:00.000Z"},
            {"uuid": "m2", "text": "I cant help with that", "sender": "assistant", "created_at": "2024-01-01T00:00:30.000Z"},
        ],
    }]
    p = tmp_path / "claude.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


@pytest.fixture
def claude_html_export(tmp_path: Path) -> Path:
    html = """<!DOCTYPE html>
<html><body>
<div data-testid="user-message">slack token xoxb-1234567890-abcdefghij</div>
<div data-testid="ai-message">sorry, can't help</div>
</body></html>"""
    p = tmp_path / "claude.html"
    p.write_text(html, encoding="utf-8")
    return p


@pytest.fixture
def cursor_json_export(tmp_path: Path) -> Path:
    data = {
        "chats": [{
            "id": "chat1",
            "title": "Refactor",
            "createdAt": 1699000000000,
            "messages": [
                {"role": "user", "text": "STRIPE_KEY=sk_live_abcdef1234567890abcdef123456", "createdAt": 1699000000000},
                {"role": "assistant", "text": "rotating now", "createdAt": 1699000001000},
            ],
        }]
    }
    p = tmp_path / "cursor.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


@pytest.fixture
def generic_messages_export(tmp_path: Path) -> Path:
    data = {
        "messages": [
            {"role": "user", "content": "Bearer ya29.a0ARrdaM-abcdefghij1234567890"},
            {"role": "assistant", "content": "ack"},
        ]
    }
    p = tmp_path / "generic.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


@pytest.fixture
def clean_export(tmp_path: Path) -> Path:
    """Export with no secrets; should produce 0 findings."""
    data = [{
        "title": "Hi",
        "create_time": 1.0,
        "update_time": 1.0,
        "mapping": {
            "m1": {
                "id": "m1",
                "message": {
                    "id": "m1",
                    "author": {"role": "user"},
                    "content": {"content_type": "text", "parts": ["hello world"]},
                    "create_time": 1.0,
                },
                "parent": None,
                "children": [],
            }
        },
    }]
    p = tmp_path / "clean.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p
