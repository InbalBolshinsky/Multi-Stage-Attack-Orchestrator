"""
AttackContext: what gets passed to Stage.run(), instead of a bare Protocol.

Built once per attack attempt and threaded through every stage in the
chain. Includes:
  - protocol: the Bridge implementation actually talking to the device
  - device: the DeviceState snapshot from before this attempt started
  - scratch: a shared dict for passing data between stages. Unused by the
    current example attacks, but available for a future stage that needs it

Stages depend on this one stable object instead of on Protocol directly,
so a Stage never needs to know how the attack composes them together.
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
