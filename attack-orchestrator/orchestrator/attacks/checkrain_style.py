from ..attack import Attack
from ..stage import Stage
from .checkm8_style import BOOTROM_VULNERABLE_MODELS


class CheckrainStyleAttack(Attack):
    """
    A jailbreak similar to checkra1n: uses the same bootrom exploit as
    checkm8, then installs Cydia to fully jailbreak the device.

    This all happens before the device's own operating system starts, so
    it works whether or not the device has been unlocked since boot.
    """

    attack_id = "checkrain_style"
    name = "Checkra1n-style semi-tethered jailbreak"

    compatible_models = BOOTROM_VULNERABLE_MODELS & frozenset({"iPhone10,1", "iPhone10,4"})
    min_ios = None       # the exploit can't be patched
    max_ios = "14.8"     # checkra1n doesn't have solid support past this
    min_battery = 15     # needs enough charge to fully start up the device

    def __init__(self) -> None:
        super().__init__(
            stages=[
                Stage(20, "enter_dfu_mode", success_probability=0.95),
                Stage(21, "exploit_bootrom", success_probability=0.9),
                Stage(22, "boot_patched_kernel", success_probability=0.9),
                Stage(23, "install_cydia_substrate", success_probability=0.85),
            ]
        )
