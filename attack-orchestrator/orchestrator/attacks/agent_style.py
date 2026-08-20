from ..attack import Attack
from ..stage import Stage


class AgentStyleAttack(Attack):
    """
    Sideloaded-agent approach, modeled on the real-world pattern of pushing
    a small on-device agent that chains OS-level exploits to escalate
    privileges. Needs the device usable enough to sideload and trust an
    app, so it carries a higher battery floor than a bootrom-level attack,
    and only targets newer iOS where the bootrom route is patched.

    `requires_afu = True`: sideloading and trusting an app leans on
    pairing/keychain state that only exists once the passcode has been
    entered at least once since boot -- it can't bootstrap against a
    freshly-booted, never-unlocked (BFU) device the way a bootrom exploit
    can. That's the actual reason `checkm8_style` remains valuable even on
    hardware new enough to also run this attack: it's the one path that
    doesn't care whether the device is AFU or BFU.
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
