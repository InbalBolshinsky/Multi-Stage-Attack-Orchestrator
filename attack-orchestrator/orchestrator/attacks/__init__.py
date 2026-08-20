"""
Four example attacks, modeled loosely on real-world families discussed in
planning (see README).
These exist to exercise the framework end-to-end.
"""

from ..stage import Stage
from .checkm8_style import Checkm8StyleAttack
from .checkrain_style import CheckrainStyleAttack
from .agent_style import AgentStyleAttack
from .jailbreak_ssh_style import JailbreakSSHStyleAttack

__all__ = [
    "Stage",
    "Checkm8StyleAttack",
    "CheckrainStyleAttack",
    "AgentStyleAttack",
    "JailbreakSSHStyleAttack",
    "all_attacks",
]


def all_attacks() -> list:
    """Convenience factory returning one instance of each known attack,
    ready to hand to AttackSelector."""
    return [Checkm8StyleAttack(), CheckrainStyleAttack(), AgentStyleAttack(), JailbreakSSHStyleAttack()]
