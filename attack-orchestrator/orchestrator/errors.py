"""
This is an exception hierarchy.

Each error is specific on purpose, instead of reusing generic exceptions:
the orchestrator's retry/abort/fallback logic (see README) depends on
knowing WHY something failed, not just that it did.
"""


class OrchestratorError(Exception):
    """Base class for every error this package raises on purpose."""


class ConnectionDropped(OrchestratorError):
    """
    The connection to the device died mid-conversation.

    Not a stage failure but a transport problem, not a verdict on whether
    the exploit works (see README).
    """


class DeviceCrashed(OrchestratorError):
    """
    The device reported a crash caused by the stage just run, before the
    connection closed.

    A sibling of ConnectionDropped, not a subclass: a drop is worth
    retrying, a crash isn't. Keeping them separate stops one from ever
    being handled as if it were the other.
    """


class DeviceLockedError(OrchestratorError):
    """Tried a locked-only operation (e.g. read_file) before any attack
    chain unlocked the device."""


class FileNotFoundOnDevice(OrchestratorError):
    """The device reported that a requested path doesn't exist."""


class NoViableAttackError(OrchestratorError):
    """No registered attack was compatible with the device, or every
    compatible attack was attempted and failed."""


class ProtocolError(OrchestratorError):
    """The device sent a reply the protocol layer couldn't parse, or an
    error with no more specific exception."""
