"""
Attack: an ordered sequence of Stages, and a compatibility check that
decides whether this attack is even a candidate for a given device.

Composite pattern: an Attack is made of Stages (see stage.py) and exposes a
single run() over the whole chain, just like a lone Stage would.

Strategy pattern: every Attack is interchangeable to its callers -- the
AttackSelector only calls is_compatible(), and the Orchestrator only calls
run(), neither needs to know which concrete attack it's holding.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import reduce

from .context import AttackContext
from .device import DeviceState, IOSVersion
from .errors import ConnectionDropped, DeviceCrashed
from .stage import Stage, StageResult


@dataclass(frozen=True)
class AttackResult:
    attack_id: str
    success: bool
    stage_results: list[StageResult]
    failed_stage: Stage | None = None
    connection_dropped: bool = False
    device_crashed: bool = False


class Attack:
    """
    Base class for a concrete attack. Subclasses just set a few class
    attributes (compatibility bounds) and a list of stages -- no custom
    logic needed.

    is_compatible() is a checklist: every check must pass for the attack
    to be considered compatible.
    """

    attack_id: str = "base-attack"
    name: str = "Unnamed attack"

    # Compatibility bounds. None means "no constraint on this dimension."
    min_ios: str | None = None
    max_ios: str | None = None
    compatible_models: frozenset[str] | None = None
    min_battery: int = 0
    # Set one True if the attack needs the device in that exact state
    # (see agent_style.py). Never set both True - that can never match.
    requires_afu: bool = False
    requires_bfu: bool = False
    # True only if the attack needs the device already jailbroken
    # (see jailbreak_ssh_style.py).
    requires_jailbreak: bool = False

    def __init__(self, stages: list[Stage]) -> None:
        if not stages:
            raise ValueError(f"{self.attack_id}: an attack needs at least one stage")
        self.stages = stages

    # -- selection ----------------------------------------------------

    def is_compatible(self, device: DeviceState) -> bool:
        if self.compatible_models is not None and device.model not in self.compatible_models:
            return False
        if self.min_ios is not None and device.ios_version < IOSVersion(self.min_ios):
            return False
        if self.max_ios is not None and device.ios_version > IOSVersion(self.max_ios):
            return False
        if device.battery < self.min_battery:
            return False
        if self.requires_afu and not device.after_first_unlock:
            return False
        if self.requires_bfu and device.after_first_unlock:
            return False
        if self.requires_jailbreak and not device.jailbroken:
            return False
        return True

    @property
    def estimated_success_probability(self) -> float:
        """Product of each stage's probability, since every stage must
        succeed for the whole attack to succeed."""
        return reduce(lambda acc, s: acc * s.success_probability, self.stages, 1.0)

    # -- execution ------------------------------------------------------

    def run(self, context: AttackContext) -> AttackResult:
        """
        Run every stage in order, stopping at the first failure.

        The Orchestrator handles three outcomes differently (see README):
        - stage returns False -> attack failed, try the next attack.
        - connection dropped -> transient, may retry the same attack.
        - device crashed -> treated like a failure, but flagged separately
          so logs and tests can tell it apart from an ordinary failure.

        The closing UNLOCK gets the same drop/crash handling as a stage: a
        connection that dies right at unlock (every stage having passed) is
        a retryable drop, not an exception that escapes run().
        """
        results: list[StageResult] = []
        # Tracks what a drop/crash would be blamed on: the stage in flight,
        # or None once we're past the stages and into the closing UNLOCK.
        in_flight: Stage | None = None
        try:
            for stage in self.stages:
                in_flight = stage
                result = stage.run(context)
                results.append(result)
                if not result.success:
                    return self._failed(results, failed_stage=stage)
            in_flight = None
            context.protocol.unlock()
        except ConnectionDropped:
            return self._failed(results, failed_stage=in_flight, connection_dropped=True)
        except DeviceCrashed:
            return self._failed(results, failed_stage=in_flight, device_crashed=True)
        return AttackResult(attack_id=self.attack_id, success=True, stage_results=results)

    def _failed(
        self,
        results: list[StageResult],
        *,
        failed_stage: Stage | None = None,
        connection_dropped: bool = False,
        device_crashed: bool = False,
    ) -> AttackResult:
        return AttackResult(
            attack_id=self.attack_id,
            success=False,
            stage_results=results,
            failed_stage=failed_stage,
            connection_dropped=connection_dropped,
            device_crashed=device_crashed,
        )

    def __repr__(self) -> str:
        return f"<Attack {self.attack_id} stages={[s.stage_id for s in self.stages]}>"
