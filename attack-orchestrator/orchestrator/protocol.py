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
private concern (see PROTOCOL.md for the actual line protocol it speaks).
"""

from __future__ import annotations

import base64
import random
import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from .device import DeviceState
from .errors import ConnectionDropped, DeviceLockedError, FileNotFoundOnDevice, ProtocolError


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
        the channel dies before a response arrives -- callers must not
        conflate "stage failed" with "connection dropped"; they get
        different handling (see README).
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
    fail_stages: frozenset[int] = field(default_factory=frozenset)
    drop_at_stage: int | None = None
    files: dict[str, bytes] = field(default_factory=dict)
    success_probabilities: dict[int, float] = field(default_factory=dict)
    rng: random.Random = field(default_factory=random.Random)

    _connected: bool = field(default=False, init=False)
    _locked: bool = field(default=True, init=False)

    def connect(self) -> None:
        self._connected = True
        self._locked = True

    def hello(self) -> DeviceState:
        return DeviceState.from_wire(self.model, self.ios_version, self.battery, self._locked)

    def run_stage(self, stage_id: int) -> bool:
        if not self._connected:
            raise ProtocolError("run_stage called before connect()")
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
        if path not in self.files:
            raise FileNotFoundOnDevice(path)
        return self.files[path]

    def list_files(self) -> list[str]:
        if self._locked:
            raise DeviceLockedError("cannot list files: device is locked")
        return list(self.files.keys())

    def close(self) -> None:
        self._connected = False


# ---------------------------------------------------------------------------
# TCPProtocol -- Part 2 implementation. Speaks the line protocol documented
# in PROTOCOL.md to the C simulator (or, unmodified, to a real device that
# spoke the same protocol).
# ---------------------------------------------------------------------------


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
                self._send_line("QUIT")
            except Exception:
                pass  # best-effort; we're closing regardless
            self._sock.close()
            self._sock = None

    # -- wire helpers --------------------------------------------------

    def _send_line(self, line: str) -> None:
        if self._sock is None:
            raise ProtocolError("not connected")
        try:
            self._sock.sendall((line + "\n").encode("utf-8"))
        except OSError as exc:
            raise ConnectionDropped(str(exc)) from exc

    def _read_line(self) -> str:
        if self._sock is None:
            raise ProtocolError("not connected")
        while b"\n" not in self._buf:
            try:
                chunk = self._sock.recv(4096)
            except OSError as exc:
                raise ConnectionDropped(str(exc)) from exc
            if not chunk:
                raise ConnectionDropped("connection closed by peer")
            self._buf += chunk
        line, self._buf = self._buf.split(b"\n", 1)
        return line.decode("utf-8").rstrip("\r")

    # -- protocol operations ---------------------------------------------

    def hello(self) -> DeviceState:
        self._send_line("HELLO")
        reply = self._read_line()
        fields = _parse_kv_reply(reply, expect_prefix="OK HELLO")
        return DeviceState.from_wire(
            model=fields["model"],
            ios_version=fields["ios"],
            battery=int(fields["battery"]),
            locked=fields["locked"] == "1",
        )

    def run_stage(self, stage_id: int) -> bool:
        self._send_line(f"STAGE {stage_id}")
        reply = self._read_line()  # raises ConnectionDropped if the sim closed on us
        parts = reply.split()
        if len(parts) >= 4 and parts[0] == "OK" and parts[1] == "STAGE":
            return parts[3] == "SUCCESS"
        raise ProtocolError(f"unexpected reply to STAGE {stage_id}: {reply!r}")

    def unlock(self) -> None:
        self._send_line("UNLOCK")
        reply = self._read_line()
        if not reply.startswith("OK UNLOCK"):
            raise ProtocolError(f"unexpected reply to UNLOCK: {reply!r}")

    def read_file(self, path: str) -> bytes:
        self._send_line(f"READ {path}")
        reply = self._read_line()
        if reply.startswith("ERR LOCKED"):
            raise DeviceLockedError(path)
        if reply.startswith("ERR NOTFOUND"):
            raise FileNotFoundOnDevice(path)
        parts = reply.split()
        if len(parts) < 3 or parts[0] != "OK" or parts[1] != "READ":
            raise ProtocolError(f"unexpected reply to READ {path}: {reply!r}")
        payload_line = self._read_line()
        return payload_line.encode("utf-8")

    def list_files(self) -> list[str]:
        self._send_line("LIST")
        reply = self._read_line()
        if reply.startswith("ERR LOCKED"):
            raise DeviceLockedError("cannot list files: device is locked")
        parts = reply.split()
        if len(parts) != 3 or parts[0] != "OK" or parts[1] != "LIST":
            raise ProtocolError(f"unexpected reply to LIST: {reply!r}")
        n = int(parts[2])
        return [self._read_line() for _ in range(n)]


def _parse_kv_reply(reply: str, expect_prefix: str) -> dict[str, str]:
    if not reply.startswith(expect_prefix):
        raise ProtocolError(f"expected reply starting with {expect_prefix!r}, got {reply!r}")
    fields: dict[str, str] = {}
    for token in reply[len(expect_prefix):].split():
        if "=" in token:
            k, v = token.split("=", 1)
            fields[k] = v
    return fields
