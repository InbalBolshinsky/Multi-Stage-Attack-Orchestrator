import pytest

from orchestrator.attacks import (
    Checkm8StyleAttack,
    CheckrainStyleAttack,
    AgentStyleAttack,
    JailbreakSSHStyleAttack,
)
from orchestrator.device import DeviceState, IOSVersion


def device(
    model="iPhone8,1",
    ios="14.4",
    battery=60,
    locked=True,
    after_first_unlock=True,
    jailbroken=False,
):
    return DeviceState.from_wire(model, ios, battery, locked, after_first_unlock, jailbroken)


class TestCheckm8StyleCompatibility:
    @pytest.mark.parametrize(
        "kwargs, expected",
        [
            ({"model": "iPhone8,1", "ios": "14.4", "battery": 15}, True),
            ({"model": "iPhone15,1", "ios": "14.4"}, False),  # unsupported model
            ({"model": "iPhone8,1", "ios": "16.0"}, False),  # ios too new
            ({"model": "iPhone8,1", "ios": "14.4", "battery": 5}, False),  # battery too low
        ],
        ids=["old_device", "unsupported_model", "ios_too_new", "low_battery"],
    )
    def test_compatibility(self, kwargs, expected):
        assert Checkm8StyleAttack().is_compatible(device(**kwargs)) == expected

    def test_battery_exactly_at_floor_is_compatible(self):
        attack = Checkm8StyleAttack()
        assert attack.is_compatible(device(battery=attack.min_battery))


class TestCheckrainStyleCompatibility:
    @pytest.mark.parametrize(
        "kwargs, expected",
        [
            ({"model": "iPhone10,1", "ios": "14.4", "battery": 20}, True),
            # iPhone8,1 is checkm8-vulnerable hardware, but checkra1n's own
            # supported list is a strict subset of that -- it doesn't cover it
            ({"model": "iPhone8,1", "ios": "14.4"}, False),
            # unlike checkm8_style, checkra1n never gained solid iOS 15+ support
            ({"model": "iPhone10,1", "ios": "15.0"}, False),
            # higher floor than checkm8_style: it boots further into userland
            ({"model": "iPhone10,1", "ios": "14.4", "battery": 10}, False),
        ],
        ids=["within_supported_window", "model_outside_subset", "past_ios_ceiling", "low_battery"],
    )
    def test_compatibility(self, kwargs, expected):
        assert CheckrainStyleAttack().is_compatible(device(**kwargs)) == expected

    def test_lower_estimated_probability_than_checkm8_style_despite_shared_first_stages(self):
        # same DFU/bootrom entry point and odds, but two extra stages
        # (patched kernel boot, Cydia install) pull the overall chain odds
        # below the bare-ramdisk checkm8_style attack
        assert CheckrainStyleAttack().estimated_success_probability < Checkm8StyleAttack().estimated_success_probability


class TestAgentStyleCompatibility:
    @pytest.mark.parametrize(
        "kwargs, expected",
        [
            ({"ios": "14.4"}, False),
            ({"model": "iPhone15,1", "ios": "17.0", "battery": 50}, True),
            ({"ios": "17.0", "battery": 10}, False),
        ],
        ids=["ios_too_old", "new_ios_any_model", "low_battery"],
    )
    def test_compatibility(self, kwargs, expected):
        assert AgentStyleAttack().is_compatible(device(**kwargs)) == expected


class TestAfuBfuCompatibility:
    @pytest.mark.parametrize(
        "after_first_unlock, expected",
        [(False, False), (True, True)],
        ids=["bfu_incompatible", "afu_compatible"],
    )
    def test_agent_style_requires_afu(self, after_first_unlock, expected):
        # sideloading/trust leans on state that only exists once the device
        # has been unlocked at least once since boot
        d = device(model="iPhone15,1", ios="17.0", battery=50, after_first_unlock=after_first_unlock)
        assert AgentStyleAttack().is_compatible(d) == expected

    def test_checkm8_style_compatible_regardless_of_afu_bfu(self):
        # bootrom-level exploit happens below the OS, so first-unlock state
        # is irrelevant -- this is its actual practical edge over agent_style
        afu = device(model="iPhone8,1", ios="14.4", battery=15, after_first_unlock=True)
        bfu = device(model="iPhone8,1", ios="14.4", battery=15, after_first_unlock=False)
        assert Checkm8StyleAttack().is_compatible(afu)
        assert Checkm8StyleAttack().is_compatible(bfu)


class TestJailbreakSSHStyleCompatibility:
    @pytest.mark.parametrize(
        "kwargs, expected",
        [
            ({"jailbroken": False}, False),
            # no model/iOS bounds -- the jailbreak already did the
            # hardware/version-specific work
            ({"model": "iPhone15,1", "ios": "17.0", "battery": 10, "jailbroken": True}, True),
        ],
        ids=["not_jailbroken", "jailbroken_regardless_of_model_or_ios"],
    )
    def test_compatibility(self, kwargs, expected):
        assert JailbreakSSHStyleAttack().is_compatible(device(**kwargs)) == expected

    def test_other_attacks_unaffected_by_jailbroken_flag(self):
        # requires_jailbreak defaults to False -- jailbroken=True must not
        # change compatibility for attacks that don't care about it
        d = device(model="iPhone8,1", ios="14.4", battery=60, jailbroken=True)
        assert Checkm8StyleAttack().is_compatible(d)
        assert not AgentStyleAttack().is_compatible(d)  # excluded on iOS, unrelated to jailbreak

    def test_outranks_checkm8_style_when_both_compatible(self):
        # on shared bootrom-vulnerable, jailbroken hardware, the
        # already-jailbroken path's near-certain odds should rank first
        d = device(model="iPhone8,1", ios="14.4", battery=60, jailbroken=True)
        assert Checkm8StyleAttack().is_compatible(d)
        assert JailbreakSSHStyleAttack().is_compatible(d)
        assert (
            JailbreakSSHStyleAttack().estimated_success_probability
            > Checkm8StyleAttack().estimated_success_probability
        )


class TestEstimatedSuccessProbability:
    def test_is_product_of_stage_probabilities(self):
        attack = Checkm8StyleAttack()
        expected = 1.0
        for stage in attack.stages:
            expected *= stage.success_probability
        assert attack.estimated_success_probability == expected

    def test_lower_than_any_individual_stage(self):
        attack = AgentStyleAttack()
        assert attack.estimated_success_probability < min(s.success_probability for s in attack.stages)


class TestIOSVersionComparison:
    @pytest.mark.parametrize(
        "lower, higher",
        [
            ("9.0", "15.0"),  # numeric, not lexicographic -- "9" would otherwise sort after "1"
            ("15.7", "16.0"),  # minor release
            ("14.8", "14.8.1"),  # patch release
        ],
        ids=["numeric_not_lexicographic", "minor_release", "patch_release"],
    )
    def test_orders_numerically(self, lower, higher):
        assert IOSVersion(lower) < IOSVersion(higher)
