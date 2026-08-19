from ..attack import Attack
from ..stage import Stage


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

    compatible_models = frozenset({"iPhone8,1", "iPhone8,2", "iPhone10,1", "iPhone10,4", "iPhone12,1"})
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
