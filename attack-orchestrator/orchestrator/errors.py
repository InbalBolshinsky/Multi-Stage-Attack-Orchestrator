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


class DeviceCrashed(OrchestratorError):
    """
    The device explicitly reported that it crashed as a result of the
    stage just run, before the connection closed.

    Deliberately a *sibling* of ConnectionDropped, not a subclass. The two
    look similar at the socket level (the connection ends up dead either
    way) but mean opposite things for retry policy: a plain drop is
    transport-layer noise unrelated to the exploit, so it's worth
    reconnecting and retrying the same attack; a crash is a verdict on the
    exploit itself -- this stage broke the device -- so retrying it again
    isn't expected to end differently, same as an ordinary stage-logic
    failure. Making DeviceCrashed a subclass of ConnectionDropped would let
    any `except ConnectionDropped` handler silently catch crashes too and
    apply the reconnect-and-retry policy to them by accident; keeping them
    as siblings forces every catch site to decide on purpose which failure
    mode it's handling.
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
