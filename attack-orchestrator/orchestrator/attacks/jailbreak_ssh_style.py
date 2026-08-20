from ..attack import Attack
from ..stage import Stage


class JailbreakSSHStyleAttack(Attack):
    """
    Uses a jailbreak the device already has (e.g. from a prior
    checkra1n run) to connect over SSH, instead of running a new
    exploit chain. Only compatible when the device is already jailbroken -
    no model/iOS bounds needed, since that hard work is already done.

    Doesn't replace checkm8_style/agent_style - it only applies to a
    narrower slice of devices (already jailbroken ones), so it just
    competes for ranking.
    """

    attack_id = "jailbreak_ssh_style"
    name = "Existing-jailbreak SSH access"

    compatible_models = None  # the jailbreak already handled hardware-specific work
    min_ios = None
    max_ios = None
    min_battery = 5  # just needs enough charge to stay powered for an SSH session
    requires_jailbreak = True

    def __init__(self) -> None:
        super().__init__(
            stages=[
                Stage(30, "connect_via_ssh", success_probability=0.98),
                Stage(31, "mount_root_filesystem", success_probability=0.97),
            ]
        )
