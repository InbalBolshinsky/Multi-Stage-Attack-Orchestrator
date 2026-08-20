"""
Session: what you get back once an attack chain completes successfully.

Wraps read_file(path) and builds extract_all() on top of it, using
Protocol.list_files() to discover paths (see README). extract() also
accepts an explicit path list, for devices that only support single-file
reads against a known manifest. See extract() for how failures are handled.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .context import AttackContext
from .device import DeviceState
from .errors import ConnectionDropped, DeviceCrashed, OrchestratorError


@dataclass
class ExtractionResult:
    files: dict[str, bytes] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    aborted: str | None = None
    """Set when extraction stopped early (see extract()). None means it ran
    to completion."""

    @property
    def succeeded(self) -> list[str]:
        return list(self.files.keys())

    @property
    def failed(self) -> list[str]:
        return list(self.errors.keys())


class Session:
    def __init__(self, context: AttackContext) -> None:
        self._context = context

    @property
    def device(self) -> DeviceState:
        """The device state from the connection this session actually runs
        on, reflecting any reconnect that happened during the attack."""
        return self._context.device

    def read_file(self, path: str) -> bytes:
        return self._context.protocol.read_file(path)

    def list_files(self) -> list[str]:
        return self._context.protocol.list_files()

    def extract(self, paths: list[str]) -> ExtractionResult:
        """
        Extract a specific, caller-provided set of paths.

        Per-path failures (not found, locked) are recorded in `.errors` and
        extraction keeps going. A connection drop or device crash means the
        channel itself is gone, so it stops the loop immediately and is
        recorded once in `.aborted` instead.
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
