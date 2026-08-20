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

That per-file leniency only applies to per-file logical failures
(FileNotFoundOnDevice, DeviceLockedError) -- a transport-level failure
(ConnectionDropped, DeviceCrashed) is not a verdict on any individual path,
it means every *remaining* path is unreachable too. Treating it as just
another per-file error would misreport each remaining path as individually
"failed" for a reason that has nothing to do with that path, and would keep
retrying reads against a connection that's already dead. So extract() stops
at the first one and records it once, in `ExtractionResult.aborted`,
leaving already-collected files/errors intact and remaining paths simply
unattempted.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .context import AttackContext
from .errors import ConnectionDropped, DeviceCrashed, OrchestratorError


@dataclass
class ExtractionResult:
    files: dict[str, bytes] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    aborted: str | None = None
    """Set when extraction stopped early because the connection dropped or
    the device crashed mid-extraction, rather than running out of paths to
    try. None means extraction ran to completion (individual files may
    still have failed logically -- see `errors`)."""

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
        """
        Extract a specific, caller-provided set of paths.

        Per-path failures (not found, locked) are recorded in `.errors` and
        extraction keeps going. A connection drop or device crash is not a
        per-path failure -- it means the channel itself is gone -- so it
        stops the loop immediately and is recorded once in `.aborted`,
        rather than being misattributed to whichever path happened to be
        in flight and then repeated for every path after it.
        """
        result = ExtractionResult()
        for path in paths:
            try:
                result.files[path] = self.read_file(path)
            except (ConnectionDropped, DeviceCrashed) as exc:
                result.aborted = str(exc)
                break
            except OrchestratorError as exc:
                result.errors[path] = str(exc)
        return result

    def extract_all(self) -> ExtractionResult:
        """Discover every extractable path via the device and pull all of them."""
        try:
            paths = self.list_files()
        except (ConnectionDropped, DeviceCrashed) as exc:
            return ExtractionResult(aborted=str(exc))
        return self.extract(paths)

    def close(self) -> None:
        """Release the underlying connection. Call when done with the session."""
        self._context.protocol.close()

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
