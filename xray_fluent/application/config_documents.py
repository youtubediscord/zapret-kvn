from __future__ import annotations

from pathlib import Path

from ..engines.singbox import SingboxDocumentState, inspect_singbox_document_text


class SingboxDocumentCache:
    def __init__(self) -> None:
        self._state: SingboxDocumentState | None = None

    def clear(self) -> None:
        self._state = None

    def cache_state(self, path: Path, text: str) -> SingboxDocumentState:
        state = inspect_singbox_document_text(path, text)
        try:
            stat = path.stat()
        except OSError:
            stat = None
        if stat is not None:
            state.file_mtime_ns = int(getattr(stat, "st_mtime_ns", 0))
            state.file_size = int(getattr(stat, "st_size", 0))
        self._state = state
        return state

    def get_state(self, path: Path) -> SingboxDocumentState:
        if self._state is not None and self._state.source_path == path:
            try:
                stat = path.stat()
            except OSError:
                stat = None
            if stat is not None:
                current_mtime_ns = int(getattr(stat, "st_mtime_ns", 0))
                current_size = int(getattr(stat, "st_size", 0))
                if self._state.file_mtime_ns == current_mtime_ns and self._state.file_size == current_size:
                    return self._state
        text = path.read_text(encoding="utf-8")
        return self.cache_state(path, text)
