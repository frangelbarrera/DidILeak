"""Core data models for didileak findings and messages."""
from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any


class Severity(str, enum.Enum):
    """Risk severity of a finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]


@dataclass
class Message:
    """A single chat message extracted from an LLM export."""

    role: str  # "user" | "assistant" | "system" | "unknown"
    content: str
    timestamp: float | None = None
    message_id: str | None = None
    conversation_id: str | None = None
    conversation_title: str | None = None
    provider: str = "unknown"
    # 1-indexed position inside the conversation, helps triage
    index: int | None = None

    def context(self, span_start: int, span_end: int, radius: int = 60) -> str:
        """Return a window of text around [span_start, span_end)."""
        s = max(0, span_start - radius)
        e = min(len(self.content), span_end + radius)
        prefix = "..." if s > 0 else ""
        suffix = "..." if e < len(self.content) else ""
        return f"{prefix}{self.content[s:e]}{suffix}"


@dataclass
class Finding:
    """A detected secret / PII hit inside a message."""

    rule_id: str
    rule_name: str
    category: str  # "secret" | "pii" | "key"
    severity: Severity
    provider: str  # which LLM provider the message came from
    conversation_id: str | None
    conversation_title: str | None
    message_id: str | None
    message_index: int | None
    role: str
    timestamp: float | None
    # match details
    matched_value: str
    masked_value: str  # masked for safe display
    span_start: int
    span_end: int
    context: str
    rotation_guide: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanResult:
    """Aggregate result of a full scan."""

    source: str  # path or identifier of what was scanned
    provider: str
    messages_scanned: int
    conversations_scanned: int
    findings: list[Finding] = field(default_factory=list)
    parser_warnings: list[str] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def by_category(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.category] = out.get(f.category, 0) + 1
        return out

    def by_rule(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.rule_id] = out.get(f.rule_id, 0) + 1
        return out

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: -f.severity.weight)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "provider": self.provider,
            "messages_scanned": self.messages_scanned,
            "conversations_scanned": self.conversations_scanned,
            "total_findings": self.total_findings,
            "by_severity": self.by_severity(),
            "by_category": self.by_category(),
            "by_rule": self.by_rule(),
            "parser_warnings": self.parser_warnings,
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
