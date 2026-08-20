from ..attack import Attack
from ..stage import Stage

# Hardware vulnerable to the checkm8 bootrom exploit. Shared with
# CheckrainStyleAttack, whose supported-device list is a subset of this.
BOOTROM_VULNERABLE_MODELS = frozenset({"iPhone8,1", "iPhone8,2", "iPhone10,1", "iPhone10,4", "iPhone12,1"})


class Checkm8StyleAttack(Attack):
    """
    Bootrom-level exploit: an unpatchable vulnerability that works
    regardless of iOS patch level, but only on specific hardware. Runs
    below the OS entirely (DFU mode), so it needs very little battery and
    doesn't care whether the device is AFU or BFU.
    """

    attack_id = "checkm8_style"
    name = "Bootrom-level exploit"

    compatible_models = BOOTROM_VULNERABLE_MODELS
    min_ios = None      # unpatchable, so no iOS floor
    max_ios = "15.7"    # exploit doesn't apply past this version
    min_battery = 10    # DFU entry needs very little charge

    def __init__(self) -> None:
        super().__init__(
            stages=[
                Stage(1, "enter_dfu_mode", success_probability=0.95),
                Stage(2, "exploit_bootrom", success_probability=0.9),
                Stage(3, "mount_ramdisk", success_probability=0.95),
            ]
        )
