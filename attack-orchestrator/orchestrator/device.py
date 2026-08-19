"""
DeviceState: the snapshot of device attributes attacks check themselves
against before running.

Field choice is grounded in how real mobile-forensic tooling gates exploits
(see README "Device state fields" for sources/reasoning) rather than picked
arbitrarily:

- model / chipset generation: exploits target specific hardware generations
- ios_version: point releases matter, not just major version (an exploit
  patched in 16.0 may still work on 15.7)
- battery: insufficient charge is a real, commonly-cited reason a low-level
  attack attempt can't even be started
- locked: whether the device currently requires unlocking at all
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import total_ordering


@total_ordering
@dataclass(frozen=True)
class IOSVersion:
    """
    Comparable representation of an iOS version string like "15.7" or "14.4.1".

    A plain string comparison would sort "9.0" after "15.0" lexicographically,
    which is wrong -- version comparisons need numeric tuple comparison.
    """

    raw: str

    @property
    def parts(self) -> tuple[int, ...]:
        out = []
        for chunk in self.raw.split("."):
            digits = "".join(c for c in chunk if c.isdigit())
            out.append(int(digits) if digits else 0)
        return tuple(out)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IOSVersion):
            return NotImplemented
        return self._padded(self.parts) == self._padded(other.parts)

    def __lt__(self, other: "IOSVersion") -> bool:
        if not isinstance(other, IOSVersion):
            return NotImplemented
        return self._padded(self.parts) < self._padded(other.parts)

    def __hash__(self) -> int:
        return hash(self._padded(self.parts))

    @staticmethod
    def _padded(parts: tuple[int, ...], length: int = 4) -> tuple[int, ...]:
        return parts + (0,) * (length - len(parts))

    def __str__(self) -> str:
        return self.raw


@dataclass(frozen=True)
class DeviceState:
    """Immutable snapshot of a device's reported attributes."""

    model: str
    ios_version: IOSVersion
    battery: int  # 0-100
    locked: bool

    @classmethod
    def from_wire(cls, model: str, ios_version: str, battery: int, locked: bool) -> "DeviceState":
        """Build from the raw values the protocol layer parses off the wire."""
        return cls(model=model, ios_version=IOSVersion(ios_version), battery=battery, locked=locked)
