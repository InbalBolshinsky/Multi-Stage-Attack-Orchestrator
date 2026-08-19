"""
Session: what you get back once an attack chain completes successfully.

Wraps read_file(path) (the one primitive the assignment guarantees you get)
and builds extract_all() on top of it.

Design decision worth calling out (see README): "extract everything" can't
mean anything without either (a) an explicit manifest of paths you already
care about, or (b) the device also exposing directory listing. We use (b)
here (Protocol.list_files()) since Part 2 is ours to design, but extract()
also accepts an explicit path list, so extraction still works against a
device/profile that can only do single-file reads and a known manifest.
Extraction is a per-file best-effort operation, not all-or-nothing: one
missing/unreadable file shouldn't discard everything else that succeeded.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .context import AttackContext
from .errors import DeviceLockedError, FileNotFoundOnDevice, OrchestratorError


@dataclass
class ExtractionResult:
    files: dict[str, bytes] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def succeeded(self) -> list[str]:
        return list(self.files.keys())

    @property
    def failed(self) -> list[str]:
        return list(self.errors.keys())


class Session:
    def __init__(self, context: AttackContext) -> None:
        self._context = context

    def read_file(self, path: str) -> bytes:
        return self._context.protocol.read_file(path)

    def list_files(self) -> list[str]:
        return self._context.protocol.list_files()

    def extract(self, paths: list[str]) -> ExtractionResult:
        """Extract a specific, caller-provided set of paths."""
        result = ExtractionResult()
        for path in paths:
            try:
                result.files[path] = self.read_file(path)
            except (FileNotFoundOnDevice, DeviceLockedError, OrchestratorError) as exc:
                result.errors[path] = str(exc)
        return result

    def extract_all(self) -> ExtractionResult:
        """Discover every extractable path via the device and pull all of them."""
        paths = self.list_files()
        return self.extract(paths)

    def close(self) -> None:
        """Release the underlying connection. Call when done with the session."""
        self._context.protocol.close()

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
