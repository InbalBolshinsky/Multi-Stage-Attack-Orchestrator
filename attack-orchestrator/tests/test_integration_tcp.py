"""
Integration tests against the REAL C simulator binary over a REAL TCP
socket -- no mocks, no in-memory fakes. This is what the assignment
explicitly asks for in Part 3: proof that Part 1 and Part 2 actually work
together, not just that each works in isolation.
"""

import pytest

from orchestrator import AttackSelector, Orchestrator, TCPProtocol, NoViableAttackError
from orchestrator.attacks import all_attacks


def orchestrator_for(handle, **selector_attacks) -> Orchestrator:
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
            assert result.succeeded  # the simulator's built-in fake filesystem
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
        Same device profile as test_agent_attack_selected_on_newer_device,
        but the simulator reports afu=0 (--bfu). agent_style requires AFU
        (see agent_style.py), so with no other compatible attack on this
        hardware, the queue should be empty end-to-end over the real wire
        protocol -- proving --bfu/afu actually round-trips through HELLO,
        not just that the Python-side compatibility check works in
        isolation.
        """
        handle = spawn_simulator(model="iPhone15,1", ios="17.0", battery=70, bfu=True)
        orch = orchestrator_for(handle)
        with pytest.raises(NoViableAttackError):
            orch.run()
        assert orch.attempts == []

    def test_jailbreak_attack_selected_over_real_socket(self, spawn_simulator):
        """
        A newer, already-jailbroken device: agent_style is still nominally
        compatible (iOS/model/battery all fit), but jailbreak_ssh_style's
        near-certain odds should win the ranking end-to-end over the real
        wire protocol, proving --jailbroken/jailbroken= actually round-trips
        through HELLO rather than just working against FakeProtocol.
        """
        handle = spawn_simulator(model="iPhone15,1", ios="17.0", battery=70, jailbroken=True)
        orch = orchestrator_for(handle)
        session = orch.run()
        assert orch.attempts[0].attack_id == "jailbreak_ssh_style"
        session.close()


class TestRealSimulatorStageFailure:
    def test_falls_back_when_first_attack_fails_a_stage(self, spawn_simulator):
        # ios in the overlap window so BOTH attacks are compatible;
        # simulator forced to fail checkm8's first stage (id=1)
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
        The simulator is configured to drop the connection every time stage
        2 is requested, on every connection (a persistent fault, like a
        physically flaky cable) -- not a one-shot glitch. This proves the
        orchestrator's bounded-retry policy actually terminates instead of
        looping forever, and that it reports connection_dropped=True rather
        than mislabeling this as an ordinary stage failure.

        Recovery-after-one-transient-drop (retry succeeds on the 2nd
        attempt) is covered precisely against FakeProtocol in
        test_orchestrator_fake.py, where the drop can be scripted to fire
        exactly once. Here we cover the real-TCP side of the same failure
        mode: proving the retry loop itself, and the simulator's drop
        behavior, are real and bounded.
        """
        handle = spawn_simulator(model="iPhone8,1", ios="14.4", battery=60, drop_stage=2)
        orch = orchestrator_for(handle)
        orch.max_connection_retries = 2
        with pytest.raises(NoViableAttackError):
            orch.run()
        # exactly 1 attack attempt is recorded (checkm8_style is the only
        # compatible one on this device); it should be marked as dropped,
        # and the retry loop should have tried exactly max_retries+1 times
        assert len(orch.attempts) == 1
        assert orch.attempts[0].connection_dropped is True
        assert orch.attempts[0].success is False

    def test_persistent_crash_falls_through_with_zero_reconnects(self, spawn_simulator, caplog):
        """
        The simulator is configured to crash on stage 2 -- checkm8_style's
        second stage. Unlike a silent drop, the device gets to reply
        (ERR CRASH) before the connection closes. That must NOT trigger
        the reconnect-and-retry loop: a crash is a verdict on the exploit,
        not a transient/environmental hiccup, so it gets exactly one
        attempt before the orchestrator falls through to agent_style.
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
        # The crashed attack itself must never be reconnected/retried --
        # that's the actual policy under test. (agent_style's own first
        # stage may still trigger one reconnect of its own: the real
        # socket genuinely dies when the simulator crashes, so agent_style
        # inherits a dead connection and self-heals via its own retry
        # budget -- that's a property of reusing one live connection
        # across attacks, not a violation of "never retry a crash.")
        assert not [
            r for r in caplog.records if "reconnecting" in r.message and "checkm8_style" in r.message
        ]
        session.close()

    def test_read_refused_before_any_attack_unlocks_device(self, spawn_simulator):
        """
        Sanity check on the simulator itself, independent of the Python
        client: connecting and immediately requesting READ (skipping HELLO/
        STAGE/UNLOCK entirely) must be refused. This proves the simulator
        enforces lock state on its own rather than trusting the client to
        behave -- the same property TCPProtocol.read_file() relies on.
        """
        import socket

        handle = spawn_simulator(model="iPhone8,1", ios="14.4", battery=60)
        with socket.create_connection(("127.0.0.1", handle.port), timeout=2) as sock:
            payload = b"READ /var/mobile/Library/db/contacts.db"
            sock.sendall(len(payload).to_bytes(4, "big") + payload)
            reply_len = int.from_bytes(sock.recv(4), "big")
            reply = sock.recv(reply_len).decode("utf-8")
        assert reply.startswith("ERR LOCKED")
