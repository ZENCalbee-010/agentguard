"""The banking policies are frozen research artifacts (decision D-007).

If a test here fails because you edited ``benchmarks/banking_policies.py``, that edit changes a frozen
experimental protocol and needs human approval; do not just update the constants.
"""

from __future__ import annotations

from agentguard.benchmarks.banking_analysis import (
    STRATA,
    UTILITY_EXCLUDED,
    UTILITY_INACTION_EXPECTED,
    UTILITY_STRICT_EXCLUDED,
)
from agentguard.benchmarks.banking_policies import (
    POLICY_V1,
    POLICY_V2,
    POLICY_VERSION,
    policies_hash,
    policy_for,
    task_ids,
)

FROZEN_V1 = "3efdfa4e65b51ddde41704e69029c1c8503d335c515b0b497ed430d7ab66d0e9"
FROZEN_V2 = "086eaa0107dd639737c801ea42b7200121e6cc36a8822fab1eea736fefa86f4e"
READ_ONLY_ADDED_IN_V2 = {
    "get_iban",
    "get_balance",
    "get_most_recent_transactions",
    "get_scheduled_transactions",
    "get_user_info",
}
SIDE_EFFECTS = {
    "send_money",
    "schedule_transaction",
    "update_scheduled_transaction",
    "update_password",
    "update_user_info",
}


def test_both_policy_sets_are_unchanged_since_they_were_frozen() -> None:
    assert (POLICY_V1, POLICY_V2, POLICY_VERSION) == ("banking-v1", "banking-v2", "banking-v2")
    assert policies_hash(POLICY_V1) == FROZEN_V1  # the M7 pilot used this set
    assert policies_hash(POLICY_V2) == FROZEN_V2


def test_there_is_one_policy_per_banking_user_task() -> None:
    assert task_ids() == tuple(f"user_task_{i}" for i in range(16))
    for version in (POLICY_V1, POLICY_V2):
        assert all(policy_for(t, version).capabilities for t in task_ids())


def test_v2_is_v1_plus_read_only_capabilities_and_nothing_else() -> None:
    for t in task_ids():
        v1 = {c.cap_id: c for c in policy_for(t, POLICY_V1).capabilities}
        v2 = {c.cap_id: c for c in policy_for(t, POLICY_V2).capabilities}
        assert set(v1) <= set(v2), t  # nothing removed or modified
        added = [v2[i] for i in v2 if i not in v1]
        assert {c.tool for c in added} <= READ_ONLY_ADDED_IN_V2, t
        assert all(not c.constraints and c.effect == "allow" for c in added)
        side = lambda caps: sorted(c.cap_id for c in caps.values() if c.tool in SIDE_EFFECTS)  # noqa: E731
        assert side(v1) == side(v2), t  # every side-effecting capability is identical
        assert not any(c.tool == "read_file" for c in added)  # file reads stay pinned per task


def test_no_policy_contains_an_attacker_value() -> None:
    for version in (POLICY_V1, POLICY_V2):
        blob = "".join(policy_for(t, version).model_dump_json() for t in task_ids()).lower()
        for marker in ("us133000000121212121212", "new_password", "attacker", "evil"):
            assert marker not in blob


def test_side_effecting_capabilities_cap_the_number_of_calls() -> None:
    for t in task_ids():
        for cap in policy_for(t).capabilities:
            if cap.tool in SIDE_EFFECTS:
                assert cap.max_calls == 1, (t, cap.tool)


def test_utility_strata_are_pinned() -> None:
    """Option B (F-6): which tasks enter the utility statistics. Changing this needs approval."""
    assert {"user_task_5", "user_task_6", "user_task_8"} == UTILITY_EXCLUDED
    assert {"user_task_9", "user_task_10"} == UTILITY_INACTION_EXPECTED
    assert UTILITY_STRICT_EXCLUDED == UTILITY_EXCLUDED | UTILITY_INACTION_EXPECTED
    assert {k: len(task_ids()) - len(v) for k, v in STRATA.items()} == {
        "all_16": 16,
        "valid_13": 13,
        "strict_11": 11,
    }
