"""
AttackContext: what gets passed to Stage.run(), instead of a bare Protocol.

Built once per attack attempt and threaded through every stage in the
chain. Bundles:
  - protocol: the Bridge implementation actually talking to the device
  - device: the DeviceState snapshot from before this attempt started
  - scratch: a shared dict stages can use to pass data forward (e.g. stage 1
    discovers an offset or token that stage 3 needs) without stages knowing
    about each other directly

This is the "second option" from planning: stages depend on one stable
context object, not directly on Protocol, which keeps every Stage
implementation insulated from how the attack composes them together.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .device import DeviceState
from .protocol import Protocol


@dataclass
class AttackContext:
    protocol: Protocol
    device: DeviceState
    scratch: dict[str, Any] = field(default_factory=dict)
