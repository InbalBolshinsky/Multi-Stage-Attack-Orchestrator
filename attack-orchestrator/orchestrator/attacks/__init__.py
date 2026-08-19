"""
Two example attacks, modeled loosely on the two real-world families
discussed in planning (see README): a bootrom-level exploit that targets
older hardware regardless of iOS patch level, and an agent-based approach
for newer devices that requires more battery/user-trust steps.

These exist to exercise the framework end-to-end - they are illustrative,
not meant to represent real exploit internals.
"""

from ..stage import Stage
from .checkm8_style import Checkm8StyleAttack
from .agent_style import AgentStyleAttack

__all__ = ["Stage", "Checkm8StyleAttack", "AgentStyleAttack", "all_attacks"]


def all_attacks() -> list:
    """Convenience factory returning one instance of each known attack,
    ready to register with an AttackSelector."""
    return [Checkm8StyleAttack(), AgentStyleAttack()]
