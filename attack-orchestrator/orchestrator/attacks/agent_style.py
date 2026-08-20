from ..attack import Attack
from ..stage import Stage


class AgentStyleAttack(Attack):
    """
    Sideloaded-agent approach: pushes a small on-device agent that
    escalates privileges through OS-level exploits. Needs enough battery
    and a new enough iOS to sideload and trust an app.

    Requires AFU, since sideloading needs pairing/keychain state that
    only exists once the device has been unlocked.
    """

    attack_id = "agent_style"
    name = "Sideloaded-agent privilege escalation"

    compatible_models = None  # broadly applicable across current models
    min_ios = "15.0"
    max_ios = None
    min_battery = 40  # needs to stay powered through sideload + trust + reboot
    requires_afu = True

    def __init__(self) -> None:
        super().__init__(
            stages=[
                Stage(10, "sideload_agent", success_probability=0.75),
                Stage(11, "establish_trust", success_probability=0.9),
                Stage(12, "elevate_privileges", success_probability=0.8),
            ]
        )
