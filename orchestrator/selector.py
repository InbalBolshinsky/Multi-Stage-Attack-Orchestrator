"""
AttackSelector: responsible for picking an attack 
out of several attacks that may be valid for this device

Filter to the compatible attacks, then rank them by
estimated_success_probability. The Orchestrator works through that ranking
as a fallback queue: try the best candidate, and if it fails, move to the
next (see orchestrator.py).
"""

from __future__ import annotations

import logging

from .attack import Attack
from .device import DeviceState

logger = logging.getLogger(__name__)


class AttackSelector:
    def __init__(self, attacks: list[Attack] | None = None) -> None:
        self._attacks: list[Attack] = list(attacks) if attacks else []

    def build_queue(self, device: DeviceState) -> list[Attack]:
        """
        Return compatible attacks ordered best-candidate-first.

        Ties in estimated success probability are broken by fewer stages:
        a shorter chain has fewer places to fail and costs less to try.
        """
        compatible = [a for a in self._attacks if a.is_compatible(device)]
        compatible.sort(key=lambda a: (-a.estimated_success_probability, len(a.stages)))
        logger.info(
            "%d/%d attack(s) compatible with device %s (ios=%s): %s",
            len(compatible),
            len(self._attacks),
            device.model,
            device.ios_version,
            ", ".join(f"{a.attack_id} (p={a.estimated_success_probability:.3f})" for a in compatible)
            or "none",
        )
        return compatible
