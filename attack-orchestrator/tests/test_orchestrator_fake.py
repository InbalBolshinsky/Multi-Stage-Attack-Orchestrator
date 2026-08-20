"""
These exercise the actual policy decisions from planning:
  - stage-logic failure -> abort attack, fall back to next compatible attack
  - connection drop -> bounded reconnect-and-retry of the SAME attack
  - retries exhausted / no attacks left -> NoViableAttackError

All against FakeProtocol - no sockets, no C process.
"""

import pytest

from orchestrator import Orchestrator, FakeProtocol, NoViableAttackError

FILES = {"/var/mobile/a.db": b"AAAA", "/var/mobile/b.jpg": b"BBBB"}


def make_orchestrator(selector, **fake_kwargs) -> tuple[Orchestrator, FakeProtocol]:
    proto = FakeProtocol(files=dict(FILES), **fake_kwargs)
    return Orchestrator(proto, selector), proto


class TestCleanSuccess:
    def test_returns_working_session(self, selector):
        orch, _ = make_orchestrator(selector, model="iPhone8,1", ios_version="14.4", battery=60)
        session = orch.run()
        result = session.extract_all()
        assert set(result.succeeded) == set(FILES.keys())
        assert result.files["/var/mobile/a.db"] == b"AAAA"

    def test_picks_highest_scoring_compatible_attack(self, selector):
        # both compatible on 15.5 - selector should try checkm8 first (higher estimated prob)
        orch, _ = make_orchestrator(selector, model="iPhone8,1", ios_version="15.5", battery=60)
        orch.run()
        assert orch.attempts[0].attack_id == "checkm8_style"
        assert len(orch.attempts) == 1  # succeeded on first try, no fallback needed


class TestStageFailureFallback:
    def test_falls_back_to_next_attack_on_stage_failure(self, selector):
        # both compatible; force checkm8's first stage to fail so it falls
        # through to agent-style
        orch, _ = make_orchestrator(
            selector, model="iPhone8,1", ios_version="15.5", battery=60, fail_stages={1}
        )
        session = orch.run()
        assert [a.attack_id for a in orch.attempts] == ["checkm8_style", "agent_style"]
        assert orch.attempts[0].success is False
        assert orch.attempts[1].success is True
        assert session.extract_all().succeeded  # session is actually usable

    def test_does_not_retry_the_same_stage_on_logic_failure(self, selector):
        # fail_stages is permanent (unlike a drop) - retrying in place
        # would fail forever, so it must fall through instead
        orch, _ = make_orchestrator(
            selector, model="iPhone8,1", ios_version="14.4", battery=60, fail_stages={2}
        )
        with pytest.raises(NoViableAttackError):
            orch.run()
        # only one attempt at checkm8 - no blind retries of a failed stage
        assert len(orch.attempts) == 1
        assert orch.attempts[0].stage_results[-1].success is False


class TestConnectionDropHandling:
    def test_reconnects_and_retries_same_attack(self, selector):
        """
        Drops only the first connection, then changes the reported battery
        on reconnect - proves the Session ends up with the refreshed
        post-reconnect device state, not the original one.
        """
        proto = FakeProtocol(model="iPhone8,1", ios_version="14.4", battery=60, files=dict(FILES))
        original_connect = proto.connect
        state = {"connects": 0}

        def connect_with_one_drop():
            original_connect()
            state["connects"] += 1
            if state["connects"] == 1:
                proto.drop_at_stage = 2
            else:
                proto.drop_at_stage = None
                proto.battery = 42

        proto.connect = connect_with_one_drop
        orch = Orchestrator(proto, selector, max_connection_retries=2)
        session = orch.run()
        assert session.extract_all().succeeded
        assert state["connects"] == 2  # exactly one retry needed
        assert session.device.battery == 42

    def test_gives_up_after_max_retries(self, selector):
        orch, proto = make_orchestrator(
            selector, model="iPhone8,1", ios_version="14.4", battery=60, drop_at_stage=2
        )
        orch.max_connection_retries = 2
        with pytest.raises(NoViableAttackError):
            orch.run()
        assert orch.attempts[0].connection_dropped is True


class TestDeviceCrashHandling:
    def test_crash_falls_back_with_zero_reconnect_attempts(self, selector, caplog):
        """
        A crash on checkm8's stage 2 aborts it outright - no retry, unlike
        a drop - and falls through to agent_style.

        checkm8_style itself must never reconnect after the crash; that's
        the "never retry a crash" policy. The orchestrator opens exactly
        one fresh connection before agent_style's turn, since the crash
        left the old one dead and agent_style needs a live connection to
        run on.
        """
        import logging

        orch, _ = make_orchestrator(
            selector, model="iPhone8,1", ios_version="15.5", battery=60, crash_at_stage=2
        )
        with caplog.at_level(logging.WARNING):
            session = orch.run()
        assert [a.attack_id for a in orch.attempts] == ["checkm8_style", "agent_style"]
        assert orch.attempts[0].success is False
        assert orch.attempts[0].device_crashed is True
        assert orch.attempts[0].connection_dropped is False
        assert orch.attempts[1].success is True
        assert not [
            r for r in caplog.records if "reconnecting" in r.message and "checkm8_style" in r.message
        ]
        session.close()

    def test_crash_exhausts_to_no_viable_attack_without_retrying(self, selector):
        # both attacks compatible; crash checkm8 at stage 2 and fail
        # agent-style's first stage outright - neither should ever retry
        orch, _ = make_orchestrator(
            selector,
            model="iPhone8,1",
            ios_version="15.5",
            battery=60,
            crash_at_stage=2,
            fail_stages={10},
        )
        with pytest.raises(NoViableAttackError):
            orch.run()
        assert len(orch.attempts) == 2
        assert orch.attempts[0].device_crashed is True
        assert orch.attempts[1].success is False


class TestNoViableAttack:
    def test_incompatible_device_raises_immediately(self, selector):
        orch, _ = make_orchestrator(selector, model="Nokia3310", ios_version="1.0", battery=60)
        with pytest.raises(NoViableAttackError):
            orch.run()
        assert orch.attempts == []  # never even tried - filtered before any run

    def test_all_attacks_exhausted(self, selector):
        orch, _ = make_orchestrator(
            selector,
            model="iPhone8,1",
            ios_version="15.5",  # both compatible
            battery=60,
            fail_stages={1, 10},  # first stage of BOTH attacks fails
        )
        with pytest.raises(NoViableAttackError):
            orch.run()
        assert len(orch.attempts) == 2
        assert all(a.success is False for a in orch.attempts)
