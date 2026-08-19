"""
Attack: an ordered sequence of Stages, plus the compatibility check that
decides whether this attack is even a candidate for a given device.

Composite: an Attack is structurally "made of" Stages (see stage.py) and
exposes a single run() over the whole chain, the same shape a lone Stage
would have from the caller's perspective.

Strategy: from the Orchestrator's point of view, every Attack is
interchangeable -- it just calls is_compatible() and run() without knowing
which concrete attack it's holding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
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
    Base class for a concrete attack. Subclasses set class-level metadata
    (compatibility bounds) and provide the stage list.

    Compatibility is a flat conjunction of simple checks -- see the planning
    discussion on why this doesn't need to be a decision tree: nothing here
    branches differently per attack, every attack just answers yes/no to the
    same handful of questions.
    """

    attack_id: str = "base-attack"
    name: str = "Unnamed attack"

    # Compatibility bounds. None means "no constraint on this dimension."
    min_ios: str | None = None
    max_ios: str | None = None
    compatible_models: frozenset[str] | None = None
    min_battery: int = 0

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
        return True

    @property
    def estimated_success_probability(self) -> float:
        """Product of each stage's declared probability -- the chain only
        succeeds end-to-end if every stage does."""
        return reduce(lambda acc, s: acc * s.success_probability, self.stages, 1.0)

    # -- execution ------------------------------------------------------

    def run(self, context: AttackContext) -> AttackResult:
        """
        Run every stage in order. Stops at the first failed stage (see
        README: a failed stage means the exploit doesn't apply/work here,
        retrying the same stage blind isn't productive -- the Orchestrator
        decides whether to fall back to a different attack).

        A dropped connection is reported distinctly rather than as an
        ordinary stage failure, so the Orchestrator can choose different
        handling (e.g. bounded reconnect-and-retry at the transport layer)
        instead of immediately writing off the whole attack.

        A device crash is reported distinctly again, from both of the
        above: like a dropped connection, it's not an ordinary stage
        failure to retry in place -- but unlike a dropped connection, it's
        not transient/environmental either. The stage itself broke the
        device, so it gets the same "don't retry, fall back to the next
        attack" handling as a stage-logic failure, just flagged so the
        Orchestrator's audit trail (and log line) can tell the two apart.
        """
        results: list[StageResult] = []
        for stage in self.stages:
            try:
                result = stage.run(context)
            except ConnectionDropped:
                return AttackResult(
                    attack_id=self.attack_id,
                    success=False,
                    stage_results=results,
                    failed_stage=stage,
                    connection_dropped=True,
                )
            except DeviceCrashed:
                return AttackResult(
                    attack_id=self.attack_id,
                    success=False,
                    stage_results=results,
                    failed_stage=stage,
                    device_crashed=True,
                )
            results.append(result)
            if not result.success:
                return AttackResult(
                    attack_id=self.attack_id,
                    success=False,
                    stage_results=results,
                    failed_stage=stage,
                )
        context.protocol.unlock()
        return AttackResult(attack_id=self.attack_id, success=True, stage_results=results)

    def __repr__(self) -> str:
        return f"<Attack {self.attack_id} stages={[s.stage_id for s in self.stages]}>"
