from orchestrator import AttackSelector
from orchestrator.attack import Attack
from orchestrator.attacks import Checkm8StyleAttack, AgentStyleAttack
from orchestrator.device import DeviceState
from orchestrator.stage import Stage


def device(model="iPhone8,1", ios="14.4", battery=60, after_first_unlock=True, jailbroken=False):
    return DeviceState.from_wire(
        model, ios, battery, locked=True, after_first_unlock=after_first_unlock, jailbroken=jailbroken
    )


def test_filters_out_incompatible_attacks(selector):
    # old iOS -> only checkm8-style is compatible, agent-style must be excluded
    queue = selector.build_queue(device(ios="14.4"))
    assert [a.attack_id for a in queue] == ["checkm8_style"]


def test_both_compatible_and_ranked_by_probability_when_ios_in_overlap_window(selector):
    # iOS 15.5 sits in the overlap: >= agent's min_ios(15.0) and <= checkm8's max_ios(15.7).
    # checkm8_style's higher estimated probability must rank it first.
    d = device(model="iPhone8,1", ios="15.5", battery=60)
    queue = selector.build_queue(d)
    assert [a.attack_id for a in queue] == ["checkm8_style", "agent_style"]


def test_agent_style_drops_out_of_overlap_window_when_bfu(selector):
    # same overlap window as above, but the device hasn't been unlocked
    # since boot -- agent_style requires AFU, checkm8_style doesn't care
    d = device(model="iPhone8,1", ios="15.5", battery=60, after_first_unlock=False)
    queue = selector.build_queue(d)
    assert [a.attack_id for a in queue] == ["checkm8_style"]


def test_empty_queue_when_nothing_compatible(selector):
    # battery below both attacks' floors
    queue = selector.build_queue(device(battery=1))
    assert queue == []


def test_checkrain_and_checkm8_both_compatible_on_shared_bootrom_hardware(selector):
    # checkrain_style's device subset (iPhone10,1/10,4) is disjoint from the
    # iPhone8,1 used above, but it's still checkm8-vulnerable hardware -- on
    # it, both bootrom-based attacks are candidates, and the plain
    # ramdisk-mount (checkm8_style) outranks the full-jailbreak chain
    # (checkrain_style) because it has fewer stages to fail
    d = device(model="iPhone10,1", ios="14.4", battery=60)
    queue = selector.build_queue(d)
    assert [a.attack_id for a in queue] == ["checkm8_style", "checkrain_style"]


def test_checkrain_excluded_past_its_ios_ceiling(selector):
    # same hardware subset, but iOS 15.0 is past checkrain_style's practical
    # ceiling (14.8) -- checkm8_style (unpatchable bootrom) and agent_style
    # (min_ios 15.0) remain candidates, mirroring the iPhone8,1 overlap case
    d = device(model="iPhone10,1", ios="15.0", battery=60)
    queue = selector.build_queue(d)
    assert {a.attack_id for a in queue} == {"checkm8_style", "agent_style"}


def test_jailbreak_ssh_style_added_to_queue_and_ranked_first_when_jailbroken(selector):
    # same shared bootrom hardware as the checkm8/checkrain case, but also
    # jailbroken -- jailbreak_ssh_style becomes compatible too, and its
    # near-certain odds should outrank both bootrom-based attacks
    d = device(model="iPhone10,1", ios="14.4", battery=60, jailbroken=True)
    queue = selector.build_queue(d)
    assert [a.attack_id for a in queue] == ["jailbreak_ssh_style", "checkm8_style", "checkrain_style"]


def test_ties_broken_by_fewer_stages():
    """
    Isolated check of the tiebreak rule documented in AttackSelector.build_queue
    (fewer stages wins on an estimated-probability tie). Deliberately built
    from two minimal synthetic attacks with an exact tie (0.5 * 0.5 == 0.25,
    both exactly representable in binary floating point -- no approx needed)
    rather than contorting the real example attacks' realistic numbers to
    coincide, which would tie their odds to each other's stage counts for no
    real-world reason.
    """

    class ShortChain(Attack):
        attack_id = "short_chain"

        def __init__(self):
            super().__init__(stages=[Stage(901, "only_stage", success_probability=0.25)])

    class LongChain(Attack):
        attack_id = "long_chain"

        def __init__(self):
            super().__init__(
                stages=[
                    Stage(902, "first_stage", success_probability=0.5),
                    Stage(903, "second_stage", success_probability=0.5),
                ]
            )

    short_chain, long_chain = ShortChain(), LongChain()
    assert short_chain.estimated_success_probability == long_chain.estimated_success_probability

    selector = AttackSelector([long_chain, short_chain])  # registered long-first, on purpose
    queue = selector.build_queue(device())
    assert [a.attack_id for a in queue] == ["short_chain", "long_chain"]
