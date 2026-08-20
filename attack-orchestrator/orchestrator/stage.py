"""
Stage: one step in an attack chain.

Strategy pattern: every concrete stage implements the same run() method,
so an Attack (or a test) can hold a list of stages without caring what any
individual one actually does.

`success_probability` is just a declared estimate used to rank attacks
(see selector.py). The actual outcome of a run always comes from the
device/protocol response, not from this number.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .context import AttackContext
from .errors import ConnectionDropped, DeviceCrashed

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StageResult:
    stage_id: int
    name: str
    success: bool


class Stage:
    """Base stage. Every attack constructs Stage directly, passing an
    id/name/probability - no subclassing needed."""

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
        catching them - the Attack/Orchestrator layer needs to see and
        handle each one distinctly (see README).
        """
        logger.debug("stage %d (%s): starting", self.stage_id, self.name)
        try:
            success = context.protocol.run_stage(self.stage_id)
        except (ConnectionDropped, DeviceCrashed):
            logger.debug("stage %d (%s): connection lost", self.stage_id, self.name)
            raise
        logger.debug(
            "stage %d (%s): %s", self.stage_id, self.name, "succeeded" if success else "failed"
        )
        return StageResult(self.stage_id, self.name, success)

    def __repr__(self) -> str:
        return f"Stage(id={self.stage_id}, name={self.name!r}, p={self.success_probability})"
