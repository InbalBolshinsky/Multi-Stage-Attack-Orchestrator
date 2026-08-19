"""
Exception hierarchy.

Kept flat and specific rather than reusing generic exceptions, because the
orchestrator's control flow (retry vs. abort vs. fall back to the next
attack, see README "Stage failure handling") depends on distinguishing
*why* something failed, not just that it did.
"""


class OrchestratorError(Exception):
    """Base class for every error this package raises on purpose."""


class ConnectionDropped(OrchestratorError):
    """
    The connection to the device died mid-conversation (e.g. mid-chain).

    This is deliberately distinct from a stage reporting failure: a dropped
    connection is a transport-layer/environmental problem, not a signal that
    the exploit itself doesn't apply to this device. See README section on
    retry-vs-fallback for why that distinction drives different handling.
    """


class DeviceLockedError(OrchestratorError):
    """Attempted a locked-only operation (e.g. read_file) before any
    attack chain completed successfully."""


class FileNotFoundOnDevice(OrchestratorError):
    """The device reported that a requested path doesn't exist."""


class NoViableAttackError(OrchestratorError):
    """No registered attack was compatible with the device, or every
    compatible attack was attempted and failed."""


class ProtocolError(OrchestratorError):
    """The device sent something the protocol layer couldn't parse, or
    responded with an error we don't have a more specific exception for."""
