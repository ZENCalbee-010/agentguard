"""Analysis-level handling of the weak banking utility oracles (finding F-6, option B).

A do-nothing agent passes the native utility oracle of five banking user tasks
(``evidence/m7-utility-noop-control.json``). The oracles themselves are NOT changed; these sets
only decide which tasks enter the *utility* statistics. Attack-success (security) analysis always
uses every case.

Strata reported side by side (all three, never only the favourable one):
* all 16 user tasks;
* 13 tasks after excluding the three whose oracle cannot tell action from inaction
  (``UTILITY_EXCLUDED``);
* 11 strictly discriminating tasks (also excluding the two where doing nothing is the expected
  and passing behaviour).

Changing these sets after freezing needs human approval; a test pins them.
"""

from __future__ import annotations

# oracle passes from pre-existing state or is vacuous: utility says nothing about task completion
UTILITY_EXCLUDED = frozenset({"user_task_5", "user_task_6", "user_task_8"})
# oracle passes iff the environment is unchanged: inaction is intended; kept in the data, flagged
UTILITY_INACTION_EXPECTED = frozenset({"user_task_9", "user_task_10"})
UTILITY_STRICT_EXCLUDED = UTILITY_EXCLUDED | UTILITY_INACTION_EXPECTED

STRATA: dict[str, frozenset[str]] = {
    "all_16": frozenset(),
    "valid_13": UTILITY_EXCLUDED,
    "strict_11": UTILITY_STRICT_EXCLUDED,
}
