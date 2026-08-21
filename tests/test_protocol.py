"""
Unit tests for TCPProtocol's wire-parsing logic, isolated from any real
socket by replacing the frame-level send/receive helpers with stubs.
These don't need the compiled simulator - they exercise what TCPProtocol
does with a given (possibly malformed) frame, independent of who sent it.
"""

import pytest

from orchestrator.errors import ProtocolError
from orchestrator.protocol import TCPProtocol


def make_protocol(reply: bytes) -> TCPProtocol:
    proto = TCPProtocol("127.0.0.1", 0)
    proto._sock = object()  # bypass the "not connected" guard; never actually used
    proto._send_frame = lambda payload: None
    proto._read_frame = lambda: reply
    return proto


class TestReadFileLengthValidation:
    def test_accepts_matching_declared_length(self):
        proto = make_protocol(b"OK READ /a 5\nhello")
        assert proto.read_file("/a") == b"hello"

    @pytest.mark.parametrize(
        "reply",
        [b"OK READ /a 2\nhello", b"OK READ /a 999\nhello"],
        ids=["declared_shorter_than_actual", "declared_longer_than_actual"],
    )
    def test_rejects_mismatched_declared_length(self, reply):
        proto = make_protocol(reply)
        with pytest.raises(ProtocolError):
            proto.read_file("/a")

    def test_length_is_read_from_the_last_token_not_the_third(self):
        # a path containing spaces pushes the length further right in the
        # whitespace-split header: parts[-1], not parts[2], is the length
        proto = make_protocol(b"OK READ /var/mobile/My File.db 5\nhello")
        assert proto.read_file("/var/mobile/My File.db") == b"hello"


class TestHelloFieldValidation:
    """
    hello() feeds every attack's is_compatible() check, so a malformed or
    non-UTF-8 reply must surface as a ProtocolError -- not a raw
    KeyError/ValueError/UnicodeDecodeError.
    """

    def test_accepts_full_reply(self):
        proto = make_protocol(
            b"OK HELLO model=iPhone8,1 ios=14.4 battery=60 locked=1 afu=1 jailbroken=0"
        )
        device = proto.hello()
        assert device.model == "iPhone8,1"
        assert device.battery == 60
        assert device.locked is True
        assert device.after_first_unlock is True
        assert device.jailbroken is False

    def test_defaults_afu_and_jailbroken_when_omitted(self):
        # an older simulator without afu/jailbroken fields should still work
        proto = make_protocol(b"OK HELLO model=iPhone8,1 ios=14.4 battery=60 locked=1")
        device = proto.hello()
        assert device.after_first_unlock is True
        assert device.jailbroken is False

    @pytest.mark.parametrize(
        "reply",
        [
            b"OK HELLO ios=14.4 battery=60 locked=1",  # missing model=
            b"OK HELLO model=iPhone8,1 ios=14.4 battery=full locked=1",
            b"\xff\xfe not utf-8",
        ],
        ids=["missing_required_field", "non_numeric_battery", "invalid_utf8"],
    )
    def test_rejects_malformed_reply(self, reply):
        proto = make_protocol(reply)
        with pytest.raises(ProtocolError):
            proto.hello()


class TestListFilesValidation:
    def test_non_numeric_count_raises_protocol_error(self):
        proto = make_protocol(b"OK LIST many\n/a\n/b")
        with pytest.raises(ProtocolError):
            proto.list_files()
