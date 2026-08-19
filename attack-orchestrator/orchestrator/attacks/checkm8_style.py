from ..attack import Attack
from ..stage import Stage

# Hardware generations vulnerable to the unpatchable checkm8 bootrom exploit.
# Shared with CheckrainStyleAttack (checkrain_style.py) since it's literally
# the same underlying bootrom exploit, just packaged into a full jailbreak
# rather than a bare DFU ramdisk mount -- checkrain's own supported-device
# list is a *subset* of this, not identical to it (see checkrain_style.py),
# which is true to the real-world tool.
BOOTROM_VULNERABLE_MODELS = frozenset({"iPhone8,1", "iPhone8,2", "iPhone10,1", "iPhone10,4", "iPhone12,1"})


class Checkm8StyleAttack(Attack):
    """
    Bootrom-level exploit, modeled on the real-world pattern where an
    unpatchable bootrom vulnerability makes an exploit apply "regardless of
    patch level" but only to specific hardware generations. Because it
    doesn't rely on booting the installed OS, it can afford a much lower
    battery threshold than an approach that needs the device fully running.
    """

    attack_id = "checkm8_style"
    name = "Bootrom-level exploit"

    compatible_models = BOOTROM_VULNERABLE_MODELS
    min_ios = None      # unpatchable at the bootrom -- applies across iOS versions
    max_ios = "15.7"    # ...within the range this exploit was actually written for
    min_battery = 10    # DFU-mode-style entry needs very little charge

    def __init__(self) -> None:
        super().__init__(
            stages=[
                Stage(1, "enter_dfu_mode", success_probability=0.95),
                Stage(2, "exploit_bootrom", success_probability=0.9),
                Stage(3, "mount_ramdisk", success_probability=0.95),
            ]
        )
