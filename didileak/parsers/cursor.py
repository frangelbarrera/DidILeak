"""Cursor session log parser.

Cursor stores session state under the user profile. Useful locations:

  - macOS:    ~/Library/Application Support/Cursor/User/workspaceStorage/
  - Linux:    ~/.config/Cursor/User/workspaceStorage/
  - Windows:  %APPDATA%/Cursor/User/workspaceStorage/

Each workspace folder has a `workspace.json` with the folder path, and a
`state.vscdb` (SQLite) that contains keys like `aiService.prompts` and
`workbench.panel.aichat.view.aichat.chatdata`.

Cursor also exports an AI chat log to JSON when users click "Export" in the chat
panel. That JSON typically has the shape:

    {
      "chats": [
        {
          "id": "...",
          "title": "...",
          "createdAt": 1699999999000,
          "messages": [
            {"role": "user", "text": "...", "createdAt": 1699999999000},
            ...
          ]
        }
      ]
    }

This parser handles the JSON export directly. If you point it at a `state.vscdb`
file we try to read the `aiService.prompts` and `ItemTable` keys.
"""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator

from didileak.models import Message
from didileak.parsers.base import Parser


class CursorParser(Parser):
    provider = "cursor"

    def parse(self) -> Iterator[Message]:
        path_str = str(self.path).lower()
        if path_str.endswith(".vscdb") or path_str.endswith(".sqlite") or path_str.endswith(".db"):
            yield from self._parse_sqlite()
        else:
            yield from self._parse_json()

    def _parse_json(self) -> Iterator[Message]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as e:
            self.warnings.append(f"Cursor JSON export is invalid: {e}")
            return

        chats = data.get("chats") if isinstance(data, dict) else data
        if not isinstance(chats, list):
            self.warnings.append("Cursor JSON has no `chats` array")
            return

        self._conversation_count = len(chats)
        chats = sorted(chats, key=lambda c: c.get("createdAt") or c.get("created_at") or 0)

        for conv in chats:
            conv_id = conv.get("id") or conv.get("uuid")
            title = conv.get("title") or "(untitled)"
            msgs = conv.get("messages") or conv.get("chat_messages") or []
            for idx, m in enumerate(msgs):
                body = m.get("text") or m.get("content") or m.get("message") or ""
                if not isinstance(body, str):
                    body = json.dumps(body, ensure_ascii=False)
                body = body.strip()
                if not body:
                    continue
                ts = m.get("createdAt") or m.get("created_at")
                if isinstance(ts, str):
                    ts = None
                yield Message(
                    role=(m.get("role") or "unknown").lower(),
                    content=body,
                    timestamp=float(ts) if isinstance(ts, (int, float)) else None,
                    message_id=m.get("id") or m.get("uuid"),
                    conversation_id=conv_id,
                    conversation_title=title,
                    provider=self.provider,
                    index=idx,
                )

    def _parse_sqlite(self) -> Iterator[Message]:
        try:
            conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        except sqlite3.Error as e:
            self.warnings.append(f"Could not open Cursor vscdb: {e}")
            return
        try:
            cur = conn.cursor()
            # Cursor stores state in `ItemTable` (key TEXT, value BLOB)
            try:
                cur.execute("SELECT key, value FROM ItemTable WHERE key LIKE 'aiService%' OR key LIKE 'workbench.panel.aichat%'")
            except sqlite3.Error as e:
                self.warnings.append(f"vscdb schema not Cursor-like: {e}")
                return
            idx = 0
            for key, value in cur.fetchall():
                text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
                # Try to parse as JSON; otherwise treat as raw text
                try:
                    parsed = json.loads(text)
                    rendered = json.dumps(parsed, ensure_ascii=False, indent=2)
                except json.JSONDecodeError:
                    rendered = text
                if not rendered.strip():
                    continue
                yield Message(
                    role="unknown",
                    content=rendered,
                    message_id=key,
                    conversation_id=str(self.path),
                    conversation_title=f"cursor-state:{key}",
                    provider=self.provider,
                    index=idx,
                )
                idx += 1
            self._conversation_count = 1
        finally:
            conn.close()
