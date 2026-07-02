"""Base parser interface."""
from __future__ import annotations

import abc
from collections.abc import Iterator
from pathlib import Path

from didileak.models import Message


class Parser(abc.ABC):
    """Each parser turns an export file into a stream of `Message` objects."""

    provider: str = "unknown"

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.warnings: list[str] = []

    @abc.abstractmethod
    def parse(self) -> Iterator[Message]:
        """Yield messages in chronological order (best effort)."""
        raise NotImplementedError

    @property
    def conversation_count(self) -> int:
        """Set by subclasses during `parse()` if known."""
        return getattr(self, "_conversation_count", 0)
