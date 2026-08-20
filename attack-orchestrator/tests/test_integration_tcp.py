"""
Integration tests against the real C simulator binary over a real TCP
socket - no mocks, no in-memory fakes.
"""

import pytest

from orchestrator import AttackSelector, Orchestrator, TCPProtocol, NoViableAttackError
from orchestrator.attacks import all_attacks


def orchestrator_for(handle) -> Orchestrator:
    proto = TCPProtocol("127.0.0.1", handle.port)
    selector = AttackSelector(all_attacks())
    return Orchestrator(proto, selector)


class TestRealSimulatorHappyPath:
    def test_full_run_extracts_files(self, spawn_simulator):
        handle = spawn_simulator(model="iPhone8,1", ios="14.4", battery=60)
        orch = orchestrator_for(handle)
        session = orch.run()
        try:
            result = session.extract_all()
            assert result.succeeded  
            assert result.errors == {}
            assert orch.attempts[0].attack_id == "checkm8_style"
        finally:
            session.close()

    def test_agent_attack_selected_on_newer_device(self, spawn_simulator):
        handle = spawn_simulator(model="iPhone15,1", ios="17.0", battery=70)
        orch = orchestrator_for(handle)
        session = orch.run()
        assert orch.attempts[0].attack_id == "agent_style"
        session.close()

    def test_agent_attack_excluded_on_bfu_device_over_real_socket(self, spawn_simulator):
        """
        Same device as the newer-device test above, but BFU (--bfu).
        agent_style requires AFU, so no attack is compatible- this proves
        --bfu actually round-trips through HELLO, not just that the
        orchstrator's check works.
        """
        handle = spawn_simulator(model="iPhone15,1", ios="17.0", battery=70, bfu=True)
        orch = orchestrator_for(handle)
        with pytest.raises(NoViableAttackError):
            orch.run()
        assert orch.attempts == []

    def test_jailbreak_attack_selected_over_real_socket(self, spawn_simulator):
        """
        A newer, already-jailbroken device. jailbreak_ssh_style should
        outrank agent_style here proving --jailbroken actually
        round-trips through HELLO, not just working against FakeProtocol.
        """
        handle = spawn_simulator(model="iPhone15,1", ios="17.0", battery=70, jailbroken=True)
        orch = orchestrator_for(handle)
        session = orch.run()
        assert orch.attempts[0].attack_id == "jailbreak_ssh_style"
        session.close()


class TestRealSimulatorStageFailure:
    def test_falls_back_when_first_attack_fails_a_stage(self, spawn_simulator):
        # iOS in the overlap window, so both attacks are compatible,
        # and checkm8's first stage is forced to fail
        handle = spawn_simulator(model="iPhone8,1", ios="15.5", battery=60, fail_stages=[1])
        orch = orchestrator_for(handle)
        session = orch.run()
        assert [a.attack_id for a in orch.attempts] == ["checkm8_style", "agent_style"]
        assert orch.attempts[0].success is False
        assert orch.attempts[1].success is True
        session.close()

    def test_no_viable_attack_when_all_fail(self, spawn_simulator):
        handle = spawn_simulator(
            model="iPhone8,1", ios="15.5", battery=60, fail_stages=[1, 10]
        )
        orch = orchestrator_for(handle)
        with pytest.raises(NoViableAttackError):
            orch.run()
        assert len(orch.attempts) == 2


class TestRealSimulatorConnectionDrop:
    def test_persistent_drop_exhausts_retries_and_reports_dropped(self, spawn_simulator):
        """
        The connection drops every time stage 2 is requested (a persistent
        fault, not a one-shot glitch), so this proves the retry policy
        actually terminates instead of looping forever. Recovery from a
        single transient drop is covered against FakeProtocol in
        test_orchestrator_fake.py.
        """
        handle = spawn_simulator(model="iPhone8,1", ios="14.4", battery=60, drop_stage=2)
        orch = orchestrator_for(handle)
        orch.max_connection_retries = 2
        with pytest.raises(NoViableAttackError):
            orch.run()
        # checkm8_style is the only compatible attack on this device
        assert len(orch.attempts) == 1
        assert orch.attempts[0].connection_dropped is True
        assert orch.attempts[0].success is False

    def test_persistent_crash_falls_through_with_zero_reconnects(self, spawn_simulator, caplog):
        """
        Crashes on checkm8_style's second stage. Unlike a drop, the device
        replies (ERR CRASH) before closing - this must not trigger a
        retry, so the orchestrator gets exactly one attempt before falling
        through to agent_style.
        """
        import logging

        handle = spawn_simulator(model="iPhone8,1", ios="15.5", battery=60, crash_stage=2)
        orch = orchestrator_for(handle)
        with caplog.at_level(logging.WARNING):
            session = orch.run()
        assert [a.attack_id for a in orch.attempts] == ["checkm8_style", "agent_style"]
        assert orch.attempts[0].success is False
        assert orch.attempts[0].device_crashed is True
        assert orch.attempts[0].connection_dropped is False
        assert orch.attempts[1].success is True
        # checkm8_style itself must never reconnect after the crash. (The
        # dead socket means agent_style's own first stage may trigger it's
        # own reconnect - that's unrelated to "never retry a crash".)
        assert not [
            r for r in caplog.records if "reconnecting" in r.message and "checkm8_style" in r.message
        ]
        session.close()

    def test_next_attack_gets_a_fresh_connection_after_retries_exhausted(self, spawn_simulator):
        """
        checkm8_style's drop-retries exhaust with the socket dead; falling
        through must hand agent_style a live connection, not that dead
        socket - otherwise agent_style's first stage-send would fail on
        the stale socket and get misreported as agent_style's own
        connection drop. Set with a zero-retry budget so any such phantom
        drop has no room to recover: agent_style must succeed outright.
        """
        handle = spawn_simulator(model="iPhone8,1", ios="15.5", battery=60, drop_stage=2)
        orch = orchestrator_for(handle)
        orch.max_connection_retries = 0
        session = orch.run()
        assert [a.attack_id for a in orch.attempts] == ["checkm8_style", "agent_style"]
        assert orch.attempts[0].connection_dropped is True
        assert orch.attempts[1].connection_dropped is False
        assert orch.attempts[1].success is True
        session.close()

    def test_read_refused_before_any_attack_unlocks_device(self, spawn_simulator):
        """
        Connects raw and sends READ immediately, skipping HELLO/STAGE/
        UNLOCK. Proves the simulator enforces lock state itself, not just
        the Python client.
        """
        import socket

        handle = spawn_simulator(model="iPhone8,1", ios="14.4", battery=60)
        with socket.create_connection(("127.0.0.1", handle.port), timeout=2) as sock:
            payload = b"READ /var/mobile/Library/db/contacts.db"
            sock.sendall(len(payload).to_bytes(4, "big") + payload)
            reply_len = int.from_bytes(sock.recv(4), "big")
            reply = sock.recv(reply_len).decode("utf-8")
        assert reply.startswith("ERR LOCKED")
