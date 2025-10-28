"""State persistence helpers used across the agent."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import json


@dataclass
class JsonStore:
    """Simple JSON-backed store with automatic persistence."""

    path: Path
    default: Any
    _data: Any | None = field(default=None, init=False, repr=False)

    def load(self) -> Any:
        if self._data is None:
            self._data = self._read()
        return self._data

    def clear(self) -> None:
        self._data = self.default() if callable(self.default) else self.default
        self.save()

    def _read(self) -> Any:
        if not self.path.exists():
            return self.default() if callable(self.default) else self.default
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        except json.JSONDecodeError:
            return self.default() if callable(self.default) else self.default

    def save(self) -> None:
        if self._data is None:
            return
        with self.path.open("w", encoding="utf-8") as handle:
            data = self._data
            json.dump(data, handle, indent=2, sort_keys=isinstance(data, dict))


def load(store: JsonStore) -> Any:
    return store.load()
