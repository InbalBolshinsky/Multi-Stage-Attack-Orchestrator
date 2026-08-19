"""
Stage: one step in an attack chain.

Strategy pattern -- every concrete stage implements the same run() method,
so an Attack (or a test) can hold a list of stages without caring what any
individual one actually does.

`success_probability` is a *declared estimate*, used by the selector to
rank attacks (see selector.py). It is not what determines the actual
outcome of a run -- that comes from the device/protocol response, same as
in real exploit tooling: you can estimate how likely a step is to work
against a given target, but the real answer only comes from trying it.
"""

from __future__ import annotations

from dataclasses import dataclass

from .context import AttackContext
from .errors import ConnectionDropped, DeviceCrashed


@dataclass(frozen=True)
class StageResult:
    stage_id: int
    name: str
    success: bool
    detail: str = ""


class Stage:
    """
    Base stage. Concrete stages either use this directly (id/name/probability
    supplied at construction) or subclass it to override run() with custom
    pre/post logic around the device call.
    """

    def __init__(self, stage_id: int, name: str, success_probability: float) -> None:
        if not 0.0 <= success_probability <= 1.0:
            raise ValueError("success_probability must be in [0, 1]")
        self.stage_id = stage_id
        self.name = name
        self.success_probability = success_probability

    def run(self, context: AttackContext) -> StageResult:
        """
        Execute this stage against the device behind context.protocol.

        Lets ConnectionDropped and DeviceCrashed propagate rather than
        catching them -- neither is an ordinary stage failure, each is a
        different failure mode the Attack/Orchestrator layer needs to see
        and handle distinctly (see README, "retry vs. abort vs. fall back").
        """
        try:
            success = context.protocol.run_stage(self.stage_id)
        except (ConnectionDropped, DeviceCrashed):
            raise
        return StageResult(self.stage_id, self.name, success)

    def __repr__(self) -> str:
        return f"Stage(id={self.stage_id}, name={self.name!r}, p={self.success_probability})"
