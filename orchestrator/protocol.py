"""
Protocol: the Bridge between "what an attack/stage needs to do" and "how
that actually gets done on the wire" (see README "Why Bridge").

Stages and Attacks only depend on this interface - they never know or care
whether they're talking to a real TCP connection (TCPProtocol) or an
in-memory fake (FakeProtocol, used in unit tests).

It's a high-level interface (hello / run_stage / read_file).
Stages reason in terms of device operations;
the wire format itself is TCPProtocol's own concern.
"""

from __future__ import annotations

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
        device reports the stage crashed it. Each case gets different
        handling upstream (see README), so callers must not conflate them.
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
# FakeProtocol - in-memory implementation for unit tests.
# Configure which stages fail/drop the connection and which files
# exist, to test the framework's decision-making in isolation.
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
            # Unlike drop_at_stage, a crash doesn't mean the transport died -
            # it's the device reporting a crash before the connection closes.
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
# TCPProtocol - speaks the length-prefixed protocol documented in
# README.md to the C simulator.
#
# Every message is one frame: a 4-byte length prefix, then that many
# payload bytes. Framing never depends on scanning for a delimiter, so
# payload content can safely contain '\n' or anything else.
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
        reply = _decode(self._read_frame())
        fields = _parse_kv_reply(reply, expect_prefix="OK HELLO")
        # model/ios/battery/locked are required by every is_compatible()
        # check, so a missing/malformed value is a ProtocolError.
        # afu/jailbroken fall back to DeviceState's own defaults, 
        # so older simulators without those fields still work.
        try:
            model = fields["model"]
            ios_version = fields["ios"]
            battery = int(fields["battery"])
            locked = fields["locked"] == "1"
        except KeyError as exc:
            raise ProtocolError(f"HELLO reply missing required field {exc}: {reply!r}") from exc
        except ValueError as exc:
            raise ProtocolError(f"HELLO reply had a non-numeric battery: {reply!r}") from exc
        return DeviceState.from_wire(
            model=model,
            ios_version=ios_version,
            battery=battery,
            locked=locked,
            after_first_unlock=fields.get("afu", "1") == "1",
            jailbroken=fields.get("jailbroken", "0") == "1",
        )

    def run_stage(self, stage_id: int) -> bool:
        self._send_frame(f"STAGE {stage_id}".encode("utf-8"))
        reply = _decode(self._read_frame())  # raises ConnectionDropped if the sim closes
        # A crash means the read succeeds - the device answers before its
        # connection dies, while a silent drop fails the read above instead.
        if reply.startswith("ERR CRASH"):
            raise DeviceCrashed(f"device crashed during stage {stage_id}")
        parts = reply.split()
        if len(parts) >= 4 and parts[0] == "OK" and parts[1] == "STAGE":
            return parts[3] == "SUCCESS"
        raise ProtocolError(f"unexpected reply to STAGE {stage_id}: {reply!r}")

    def unlock(self) -> None:
        self._send_frame(b"UNLOCK")
        reply = _decode(self._read_frame())
        if not reply.startswith("OK UNLOCK"):
            raise ProtocolError(f"unexpected reply to UNLOCK: {reply!r}")

    def read_file(self, path: str) -> bytes:
        self._send_frame(f"READ {path}".encode("utf-8"))
        payload = self._read_frame()
        if payload.startswith(b"ERR LOCKED"):
            raise DeviceLockedError(path)
        if payload.startswith(b"ERR NOTFOUND"):
            raise FileNotFoundOnDevice(path)
        # Header text -> '\n' -> raw content. Split on the first '\n'
        # only; content is taken by length so embedded '\n' bytes are safe.
        header, sep, content = payload.partition(b"\n")
        if not sep:
            raise ProtocolError(f"unexpected reply to READ {path}: {payload!r}")
        header_text = _decode(header)
        # `path` may itself contain spaces, so we can't assume parts[2] is
        # the path, but the length is always the last token.
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
        lines = _decode(payload).split("\n")
        parts = lines[0].split()
        if len(parts) != 3 or parts[0] != "OK" or parts[1] != "LIST":
            raise ProtocolError(f"unexpected reply to LIST: {lines[0]!r}")
        try:
            n = int(parts[2])
        except ValueError as exc:
            raise ProtocolError(f"unexpected reply to LIST: {lines[0]!r}") from exc
        return lines[1 : 1 + n]


def _decode(payload: bytes) -> str:
    """Decodes a reply, turning invalid UTF-8 into a ProtocolError instead
    of a raw crash."""
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError(f"reply was not valid utf-8: {payload!r}") from exc


def _parse_kv_reply(reply: str, expect_prefix: str) -> dict[str, str]:
    if not reply.startswith(expect_prefix):
        raise ProtocolError(f"expected reply starting with {expect_prefix!r}, got {reply!r}")
    fields: dict[str, str] = {}
    for token in reply[len(expect_prefix):].split():
        if "=" in token:
            k, v = token.split("=", 1)
            fields[k] = v
    return fields
