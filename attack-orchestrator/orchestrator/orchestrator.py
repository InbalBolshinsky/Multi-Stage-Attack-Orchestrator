"""
Orchestrator: the top-level entry point. Connects, picks an attack, runs
it, and implements the failure-handling policy decided during planning:

  - Stage-logic failure (a stage ran and returned False) -> abort this
    attack, fall through to the next compatible attack in the queue. A
    logical failure means this exploit doesn't apply/work here; retrying
    the identical stage against the identical device state is not expected
    to change the outcome.

  - Connection dropped mid-chain -> transient/environmental, not a verdict
    on the exploit. Reconnect and retry THIS attack from the start, bounded
    by max_connection_retries. Retrying from the start (not mid-chain) is
    deliberate: a partially-applied exploit can leave the device in a state
    we can't safely assume anything about, so we don't resume a chain
    in-place after a drop (see README, grounded in how real low-level
    extraction tooling treats a failed attempt -- prefer a clean retry over
    resuming blind).

  - Queue exhausted -> NoViableAttackError.
"""

from __future__ import annotations

import logging

from .attack import Attack, AttackResult
from .context import AttackContext
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
        self.attempts: list[AttackResult] = []  # full audit trail, useful for tests/debugging

    def run(self) -> Session:
        """
        Note: deliberately NOT a `with self.protocol:` block. A successful
        run hands back a live Session that still needs the connection open
        for read_file()/extract_all() -- closing on every exit (including
        the success path, which a context manager would do as soon as we
        return) would hand back a Session wired to a dead connection. We
        only close explicitly on the failure paths below; a successful
        Session owns the connection until the caller is done with it.
        """
        self.protocol.connect()
        device = self.protocol.hello()
        queue = self.selector.build_queue(device)
        if not queue:
            self.protocol.close()
            raise NoViableAttackError(f"no compatible attack for device {device!r}")

        for attack in queue:
            result = self._run_with_retries(attack, device)
            self.attempts.append(result)
            if result.success:
                context = AttackContext(protocol=self.protocol, device=device)
                return Session(context)
            logger.info(
                "attack %s failed at stage %s (dropped=%s); trying next candidate",
                attack.attack_id,
                result.failed_stage.stage_id if result.failed_stage else None,
                result.connection_dropped,
            )

        self.protocol.close()
        raise NoViableAttackError(
            f"all {len(queue)} compatible attack(s) failed for device {device!r}"
        )

    def _run_with_retries(self, attack: Attack, device) -> AttackResult:
        context = AttackContext(protocol=self.protocol, device=device)
        attempt = 0
        result = attack.run(context)
        while result.connection_dropped and attempt < self.max_connection_retries:
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
        return result
