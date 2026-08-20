from ..attack import Attack
from ..stage import Stage


class JailbreakSSHStyleAttack(Attack):
    """
    Piggybacks on a jailbreak the device already has (e.g. from a prior
    checkra1n/unc0ver run), modeled on the real-world pattern where a
    forensic tool doesn't run its own exploit chain against an
    already-jailbroken device -- it just uses the SSH/filesystem access
    the jailbreak already exposes. That's why this attack is compatible
    only when `device.jailbroken` is set, has no model/iOS bounds (a
    jailbreak already did the hard, hardware/version-specific part), and
    has by far the highest estimated_success_probability of any example
    attack here: the exploit work is already done, this is just "connect
    and read."

    Not a substitute for checkm8_style/agent_style -- it's compatible on a
    strictly narrower slice of devices (only ones already jailbroken), so
    it competes for ranking rather than replacing the others in the queue.
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
