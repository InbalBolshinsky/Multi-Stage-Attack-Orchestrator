"""
AttackSelector: answers "several attacks may be valid for this device --
how do you pick?"

Filter, then score-and-rank -- deliberately *not* a decision tree (see
planning notes): compatibility is a flat yes/no per attack, there's no
branching structure that differs attack-to-attack to justify one. Ranking
by estimated_success_probability is the ordering the Orchestrator then
works through as a fallback queue: try the best candidate, and if it fails,
move to the next (see attack.py / orchestrator.py for why a failed stage
falls through rather than retrying blindly).
"""

from __future__ import annotations

from .attack import Attack
from .device import DeviceState


class AttackSelector:
    def __init__(self, attacks: list[Attack] | None = None) -> None:
        self._attacks: list[Attack] = list(attacks) if attacks else []

    def register(self, attack: Attack) -> None:
        self._attacks.append(attack)

    def build_queue(self, device: DeviceState) -> list[Attack]:
        """
        Return compatible attacks ordered best-candidate-first.

        Ties in estimated success probability are broken by fewer stages
        first (a shorter chain has fewer places to fail, and costs less
        time/risk to attempt) -- an explicit, arbitrary-but-documented
        tiebreaker rather than leaving order to registration order.
        """
        compatible = [a for a in self._attacks if a.is_compatible(device)]
        compatible.sort(key=lambda a: (-a.estimated_success_probability, len(a.stages)))
        return compatible
