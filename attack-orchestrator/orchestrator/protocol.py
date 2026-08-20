"""
Protocol: the Bridge between "what an attack/stage needs to do" and "how
that actually gets done on the wire."

Stages and Attacks only ever depend on this interface. They never know or
care whether they're talking to a real TCP connection (Part 2, TCPProtocol)
or an in-memory fake (Part 1 tests, FakeProtocol). That's the whole point of
pulling this out as its own abstraction rather than letting each Attack
implement its own communication -- see README "Why Bridge" for the reasoning
that led here.

Deliberately a *high-level* interface (hello / run_stage / read_file), not a
thin wrapper around raw socket bytes. Stages should reason in terms of
device operations, not wire format -- the wire format is TCPProtocol's
private concern (see PROTOCOL.md for the actual length-prefixed framing it
speaks).
"""

from __future__ import annotations

import base64
import random
import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from .device import DeviceState
from .errors import ConnectionDropped, DeviceCrashed, DeviceLockedError, FileNotFoundOnDevice, ProtocolError


class Protocol(ABC):
    """Abstract communication channel to a device."""

    @abstractmethod
    def connect(self) -> None:
        """Establish the channel. Must be called before anything else."""

    @abstractmethod
    def hello(self) -> DeviceState:
        """Ask the device for its current state."""

    @abstractmethod
    def run_stage(self, stage_id: int) -> bool:
        """
        Ask the device to execute one attack stage.

        Returns True/False for success/failure. Raises ConnectionDropped if
        the channel dies before a response arrives, or DeviceCrashed if the
        device explicitly reports (before the channel dies) that this stage
        crashed it -- callers must not conflate "stage failed" with
        "connection dropped" with "device crashed"; each gets different
        handling (see README).
        """

    @abstractmethod
    def unlock(self) -> None:
        """Mark the device as unlocked. Called once an attack's stages all succeed."""

    @abstractmethod
    def read_file(self, path: str) -> bytes:
        """Read a single file from the (now unlocked) device."""

    @abstractmethod
    def list_files(self) -> list[str]:
        """Enumerate extractable file paths, for extract_all()."""

    @abstractmethod
    def close(self) -> None:
        """Tear down the channel."""

    def __enter__(self) -> "Protocol":
        self.connect()
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


# ---------------------------------------------------------------------------
# FakeProtocol -- in-memory implementation for Part 1 unit tests.
# No sockets, no C process. Configure exactly which stages fail / drop the
# connection / which files exist, and test the framework's decision-making
# in complete isolation from Part 2.
# ---------------------------------------------------------------------------


@dataclass
class FakeProtocol(Protocol):
    model: str = "iPhone12,1"
    ios_version: str = "14.4"
    battery: int = 80
    after_first_unlock: bool = True
    jailbroken: bool = False
    fail_stages: frozenset[int] = field(default_factory=frozenset)
    drop_at_stage: int | None = None
    crash_at_stage: int | None = None
    drop_on_read: str | None = None  # path that raises ConnectionDropped when read
    crash_on_read: str | None = None  # path that raises DeviceCrashed when read
    drop_on_list: bool = False  # raise ConnectionDropped from list_files()
    files: dict[str, bytes] = field(default_factory=dict)
    success_probabilities: dict[int, float] = field(default_factory=dict)
    rng: random.Random = field(default_factory=random.Random)

    _connected: bool = field(default=False, init=False)
    _locked: bool = field(default=True, init=False)

    def connect(self) -> None:
        self._connected = True
        self._locked = True

    def hello(self) -> DeviceState:
        return DeviceState.from_wire(
            self.model,
            self.ios_version,
            self.battery,
            self._locked,
            self.after_first_unlock,
            self.jailbroken,
        )

    def run_stage(self, stage_id: int) -> bool:
        if not self._connected:
            raise ProtocolError("run_stage called before connect()")
        if self.crash_at_stage == stage_id:
            # Deliberately does NOT touch _connected: unlike drop_at_stage,
            # a crash isn't modeling transport death here, just the
            # protocol-level signal a real device would send before the
            # socket happens to close -- see DeviceCrashed's docstring.
            raise DeviceCrashed(f"device crashed at stage {stage_id}")
        if self.drop_at_stage == stage_id:
            self._connected = False
            raise ConnectionDropped(f"connection dropped at stage {stage_id}")
        if stage_id in self.fail_stages:
            return False
        prob = self.success_probabilities.get(stage_id)
        if prob is not None:
            return self.rng.random() < prob
        return True

    def unlock(self) -> None:
        self._locked = False

    def read_file(self, path: str) -> bytes:
        if self._locked:
            raise DeviceLockedError(f"cannot read {path!r}: device is locked")
        if self.crash_on_read == path:
            raise DeviceCrashed(f"device crashed while reading {path}")
        if self.drop_on_read == path:
            self._connected = False
            raise ConnectionDropped(f"connection dropped while reading {path}")
        if path not in self.files:
            raise FileNotFoundOnDevice(path)
        return self.files[path]

    def list_files(self) -> list[str]:
        if self._locked:
            raise DeviceLockedError("cannot list files: device is locked")
        if self.drop_on_list:
            self._connected = False
            raise ConnectionDropped("connection dropped while listing files")
        return list(self.files.keys())

    def close(self) -> None:
        self._connected = False


# ---------------------------------------------------------------------------
# TCPProtocol -- Part 2 implementation. Speaks the length-prefixed protocol
# documented in PROTOCOL.md to the C simulator (or, unmodified, to a real
# device that spoke the same protocol).
#
# Every message either direction is one frame: a 4-byte big-endian length,
# then exactly that many payload bytes. Framing never depends on scanning
# for a delimiter, so payload content -- including READ's file bytes --
# can safely contain '\n' or anything else.
# ---------------------------------------------------------------------------

MAX_FRAME_BYTES = 64 * 1024  # sanity bound on a declared frame length; matches simulator.c's MAX_FRAME


class TCPProtocol(Protocol):
    def __init__(self, host: str, port: int, timeout: float = 5.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._buf = b""

    def connect(self) -> None:
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._buf = b""

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._send_frame(b"QUIT")
            except Exception:
                pass  # best-effort; we're closing regardless
            self._sock.close()
            self._sock = None

    # -- wire helpers --------------------------------------------------

    def _send_frame(self, payload: bytes) -> None:
        if self._sock is None:
            raise ProtocolError("not connected")
        try:
            self._sock.sendall(len(payload).to_bytes(4, "big") + payload)
        except OSError as exc:
            raise ConnectionDropped(str(exc)) from exc

    def _read_exact(self, n: int) -> bytes:
        if self._sock is None:
            raise ProtocolError("not connected")
        while len(self._buf) < n:
            try:
                chunk = self._sock.recv(4096)
            except OSError as exc:
                raise ConnectionDropped(str(exc)) from exc
            if not chunk:
                raise ConnectionDropped("connection closed by peer")
            self._buf += chunk
        data, self._buf = self._buf[:n], self._buf[n:]
        return data

    def _read_frame(self) -> bytes:
        length = int.from_bytes(self._read_exact(4), "big")
        if length > MAX_FRAME_BYTES:
            raise ProtocolError(f"frame too large: {length} bytes")
        return self._read_exact(length)

    # -- protocol operations ---------------------------------------------

    def hello(self) -> DeviceState:
        self._send_frame(b"HELLO")
        reply = self._read_frame().decode("utf-8")
        fields = _parse_kv_reply(reply, expect_prefix="OK HELLO")
        return DeviceState.from_wire(
            model=fields["model"],
            ios_version=fields["ios"],
            battery=int(fields["battery"]),
            locked=fields["locked"] == "1",
            after_first_unlock=fields["afu"] == "1",
            jailbroken=fields["jailbroken"] == "1",
        )

    def run_stage(self, stage_id: int) -> bool:
        self._send_frame(f"STAGE {stage_id}".encode("utf-8"))
        reply = self._read_frame().decode("utf-8")  # raises ConnectionDropped if the sim closed on us
        # A crash means the read itself SUCCEEDS -- the device answers
        # before its connection dies -- unlike a silent drop, where this
        # _read_frame() call above is the thing that fails. That's the
        # actual distinguishing signal between the two failure modes.
        if reply.startswith("ERR CRASH"):
            raise DeviceCrashed(f"device crashed during stage {stage_id}")
        parts = reply.split()
        if len(parts) >= 4 and parts[0] == "OK" and parts[1] == "STAGE":
            return parts[3] == "SUCCESS"
        raise ProtocolError(f"unexpected reply to STAGE {stage_id}: {reply!r}")

    def unlock(self) -> None:
        self._send_frame(b"UNLOCK")
        reply = self._read_frame().decode("utf-8")
        if not reply.startswith("OK UNLOCK"):
            raise ProtocolError(f"unexpected reply to UNLOCK: {reply!r}")

    def read_file(self, path: str) -> bytes:
        self._send_frame(f"READ {path}".encode("utf-8"))
        payload = self._read_frame()
        if payload.startswith(b"ERR LOCKED"):
            raise DeviceLockedError(path)
        if payload.startswith(b"ERR NOTFOUND"):
            raise FileNotFoundOnDevice(path)
        # Header text, one embedded '\n', then raw content -- split on the
        # FIRST '\n' only and take the rest by length, not by scanning for
        # another delimiter, so embedded '\n' bytes in content are safe.
        header, sep, content = payload.partition(b"\n")
        if not sep:
            raise ProtocolError(f"unexpected reply to READ {path}: {payload!r}")
        header_text = header.decode("utf-8")
        # Split from the right for the length: `path` may itself contain
        # spaces (see simulator.c's sscanf, which captures it verbatim), so
        # parts[2] isn't reliably "the path" -- but the length is always
        # the last whitespace-separated token, since it's a plain integer.
        parts = header_text.split()
        if len(parts) < 3 or parts[0] != "OK" or parts[1] != "READ":
            raise ProtocolError(f"unexpected reply to READ {path}: {header_text!r}")
        try:
            declared_len = int(parts[-1])
        except ValueError:
            raise ProtocolError(f"unexpected reply to READ {path}: {header_text!r}")
        if declared_len != len(content):
            raise ProtocolError(
                f"READ {path}: header declared {declared_len} content bytes, got {len(content)}"
            )
        return content

    def list_files(self) -> list[str]:
        self._send_frame(b"LIST")
        payload = self._read_frame()
        if payload.startswith(b"ERR LOCKED"):
            raise DeviceLockedError("cannot list files: device is locked")
        lines = payload.decode("utf-8").split("\n")
        parts = lines[0].split()
        if len(parts) != 3 or parts[0] != "OK" or parts[1] != "LIST":
            raise ProtocolError(f"unexpected reply to LIST: {lines[0]!r}")
        n = int(parts[2])
        return lines[1 : 1 + n]


def _parse_kv_reply(reply: str, expect_prefix: str) -> dict[str, str]:
    if not reply.startswith(expect_prefix):
        raise ProtocolError(f"expected reply starting with {expect_prefix!r}, got {reply!r}")
    fields: dict[str, str] = {}
    for token in reply[len(expect_prefix):].split():
        if "=" in token:
            k, v = token.split("=", 1)
            fields[k] = v
    return fields
