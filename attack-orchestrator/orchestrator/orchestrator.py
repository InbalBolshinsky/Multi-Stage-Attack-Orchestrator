"""
Orchestrator: the top-level entry point. Connects, picks an attack, runs
it, and applies this failure-handling policy (see README):

  - Stage logic failure (a stage returns False) -> this exploit doesn't
    work here. Abort and fall through to the next compatible attack.

  - Connection dropped mid-chain -> transient, not a verdict on the
    exploit. Reconnect and retry this attack from the start (bounded by
    max_connection_retries).

  - Device crashed mid-chain -> the stage broke the device. Not transient,
    so treated like a logic failure: abort and move to the next attack.

  - Queue exhausted -> NoViableAttackError.
"""

from __future__ import annotations

import logging

from .attack import Attack, AttackResult
from .context import AttackContext
from .device import DeviceState
from .errors import NoViableAttackError
from .protocol import Protocol
from .selector import AttackSelector
from .session import Session

logger = logging.getLogger(__name__)


class Orchestrator:
    def __init__(
        self,
        protocol: Protocol,
        selector: AttackSelector,
        max_connection_retries: int = 2,
    ) -> None:
        self.protocol = protocol
        self.selector = selector
        self.max_connection_retries = max_connection_retries
        self.attempts: list[AttackResult] = []  # full audit trail

    def run(self) -> Session:
        """
        Not a `with self.protocol:` block on purpose: on success we hand
        back a Session that still needs the connection open for
        read_file()/extract_all(). We only close explicitly on the
        failure paths below -- a successful Session owns the connection
        until the caller is done with it.
        """
        self.protocol.connect()
        device = self.protocol.hello()
        queue = self.selector.build_queue(device)
        if not queue:
            self.protocol.close()
            raise NoViableAttackError(f"no compatible attack for device {device!r}")

        for i, attack in enumerate(queue):
            result, device = self._run_with_retries(attack, device)
            self.attempts.append(result)
            if result.success:
                context = AttackContext(protocol=self.protocol, device=device)
                return Session(context)
            logger.info(
                "attack %s failed at stage %s (dropped=%s, crashed=%s); trying next candidate",
                attack.attack_id,
                result.failed_stage.stage_id if result.failed_stage else None,
                result.connection_dropped,
                result.device_crashed,
            )
            is_last = i == len(queue) - 1
            if not is_last and (result.connection_dropped or result.device_crashed):
                # Retries were exhausted (drop) or never attempted (crash),
                # either way the channel is now dead. Reconnect before the
                # next candidate gets a turn, so its first stage doesn't
                # inherit this dead socket and get misreported as its own
                # connection drop.
                self.protocol.close()
                self.protocol.connect()
                device = self.protocol.hello()

        self.protocol.close()
        raise NoViableAttackError(
            f"all {len(queue)} compatible attack(s) failed for device {device!r}"
        )

    def _run_with_retries(self, attack: Attack, device: DeviceState) -> tuple[AttackResult, DeviceState]:
        """
        Returns the attack's result AND the device state from whichever
        connection actually produced it - a reconnect mid-retry re-runs
        hello(), so the caller needs that refreshed state.
        """
        context = AttackContext(protocol=self.protocol, device=device)
        attempt = 0
        result = attack.run(context)
        # Never retry a crash, only a dropped connection.
        while (
            result.connection_dropped
            and not result.device_crashed
            and attempt < self.max_connection_retries
        ):
            attempt += 1
            logger.warning(
                "connection dropped during %s (attempt %d/%d); reconnecting",
                attack.attack_id,
                attempt,
                self.max_connection_retries,
            )
            self.protocol.close()
            self.protocol.connect()
            device = self.protocol.hello()
            context = AttackContext(protocol=self.protocol, device=device)
            result = attack.run(context)
        return result, device
