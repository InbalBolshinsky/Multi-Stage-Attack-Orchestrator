from ..attack import Attack
from ..stage import Stage
from .checkm8_style import BOOTROM_VULNERABLE_MODELS


class CheckrainStyleAttack(Attack):
    """
    Semi-tethered jailbreak built on top of the checkm8 bootrom exploit,
    modeled on the real-world checkra1n: same unpatchable bootrom entry
    point as Checkm8StyleAttack, but it doesn't stop at mounting a ramdisk
    -- it boots a patched kernel and installs a package manager (Cydia) to
    get a full userland jailbreak.

    That's reflected in three ways relative to Checkm8StyleAttack:
    - `compatible_models` is a *subset* of the checkm8-vulnerable hardware,
      not the full set -- checkra1n's real officially-supported device list
      was narrower than every bootrom-exploitable chip.
    - `min_battery` is higher -- it needs to boot the device far enough to
      install userland software, not just mount a read-only ramdisk.
    - two extra stages lower its `estimated_success_probability` below
      Checkm8StyleAttack's, even sharing the same first-stage odds --
      more steps, more places to fail, which is why the selector still
      prefers the plain bootrom exploit when both are compatible and the
      caller only needs file read access, not a full jailbreak.
    """

    attack_id = "checkrain_style"
    name = "Checkra1n-style semi-tethered jailbreak"

    compatible_models = frozenset({"iPhone10,1", "iPhone10,4"})
    min_ios = None       # bootrom entry point is unpatchable, same as checkm8
    max_ios = "14.8"     # checkra1n never gained solid support past this
    min_battery = 15     # boots further into userland than a bare ramdisk mount

    def __init__(self) -> None:
        super().__init__(
            stages=[
                Stage(20, "enter_dfu_mode", success_probability=0.95),
                Stage(21, "exploit_bootrom", success_probability=0.9),
                Stage(22, "boot_patched_kernel", success_probability=0.9),
                Stage(23, "install_cydia_substrate", success_probability=0.85),
            ]
        )
