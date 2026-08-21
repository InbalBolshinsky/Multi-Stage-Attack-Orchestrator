import pytest

from orchestrator import AttackContext, FakeProtocol, Session
from orchestrator.errors import DeviceLockedError, FileNotFoundOnDevice


def make_session(**fake_kwargs) -> tuple[Session, FakeProtocol]:
    proto = FakeProtocol(**fake_kwargs)
    proto.connect()
    proto.unlock()
    ctx = AttackContext(protocol=proto, device=proto.hello())
    return Session(ctx), proto


class TestReadFile:
    def test_reads_unlocked_file(self):
        session, _ = make_session(files={"/a": b"hello"})
        assert session.read_file("/a") == b"hello"

    def test_raises_on_missing_file(self):
        session, _ = make_session(files={})
        with pytest.raises(FileNotFoundOnDevice):
            session.read_file("/nope")

    def test_locked_device_refuses_read(self):
        proto = FakeProtocol(files={"/a": b"x"})
        proto.connect()  # note: no unlock()
        ctx = AttackContext(protocol=proto, device=proto.hello())
        session = Session(ctx)
        with pytest.raises(DeviceLockedError):
            session.read_file("/a")


class TestExtractAll:
    def test_extracts_every_discoverable_file(self):
        files = {"/a": b"1", "/b": b"2", "/c": b"3"}
        session, _ = make_session(files=files)
        result = session.extract_all()
        assert result.files == files
        assert result.errors == {}

    def test_partial_failure_does_not_lose_successful_files(self):
        """
        One unreadable path shouldn't discard everything else - extraction
        is per-file best-effort, not all-or-nothing (see README).
        """
        session, proto = make_session(files={"/a": b"1", "/b": b"2"})
        result = session.extract(["/a", "/b", "/does-not-exist"])
        assert result.files == {"/a": b"1", "/b": b"2"}
        assert "/does-not-exist" in result.errors
        assert result.succeeded == ["/a", "/b"]
        assert result.failed == ["/does-not-exist"]


class TestExtractionAbort:
    """
    A connection drop or crash mid-extraction means every remaining path
    is unreachable too. Reported once via `.aborted` (see session.py).
    """

    def test_connection_drop_stops_extraction_and_keeps_prior_successes(self):
        session, _ = make_session(
            files={"/a": b"1", "/b": b"2", "/c": b"3"}, drop_on_read="/b"
        )
        result = session.extract(["/a", "/b", "/c"])
        assert result.files == {"/a": b"1"}
        assert result.errors == {}  # "/b" is not a per-file error
        assert "/b" not in result.errors
        assert "/c" not in result.files and "/c" not in result.errors  # never attempted
        assert result.aborted is not None

    def test_device_crash_stops_extraction_the_same_way(self):
        session, _ = make_session(
            files={"/a": b"1", "/b": b"2"}, crash_on_read="/a"
        )
        result = session.extract(["/a", "/b"])
        assert result.files == {}
        assert result.errors == {}
        assert result.aborted is not None
        assert "/b" not in result.files and "/b" not in result.errors

    def test_no_abort_on_clean_run(self):
        session, _ = make_session(files={"/a": b"1"})
        result = session.extract(["/a"])
        assert result.aborted is None

    def test_extract_all_aborts_cleanly_if_listing_itself_drops(self):
        # the drop happens before any file is read - extract_all() must
        # still return an ExtractionResult (with .aborted set), not raise
        session, _ = make_session(files={"/a": b"1"}, drop_on_list=True)
        result = session.extract_all()
        assert result.files == {}
        assert result.aborted is not None
