"""
Multi-stage attack orchestrator.

Public surface: the pieces a caller (or a test) actually needs to import.
Internal wiring (context construction, etc.) stays inside orchestrator.py.
"""

from .device import DeviceState
from .errors import (
    OrchestratorError,
    ConnectionDropped,
    DeviceCrashed,
    DeviceLockedError,
    FileNotFoundOnDevice,
    NoViableAttackError,
    ProtocolError,
)
from .protocol import Protocol, FakeProtocol, TCPProtocol
from .context import AttackContext
from .stage import Stage, StageResult
from .attack import Attack, AttackResult
from .selector import AttackSelector
from .session import Session
from .orchestrator import Orchestrator

__all__ = [
    "DeviceState",
    "OrchestratorError",
    "ConnectionDropped",
    "DeviceCrashed",
    "DeviceLockedError",
    "FileNotFoundOnDevice",
    "NoViableAttackError",
    "ProtocolError",
    "Protocol",
    "FakeProtocol",
    "TCPProtocol",
    "AttackContext",
    "Stage",
    "StageResult",
    "Attack",
    "AttackResult",
    "AttackSelector",
    "Session",
    "Orchestrator",
]
