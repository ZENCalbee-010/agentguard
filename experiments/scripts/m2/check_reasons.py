import json, warnings, collections
warnings.filterwarnings("ignore")
from agentdojo.task_suite.load_suites import get_suites
res = {}
for ci in (True, False):
    for name, s in get_suites("v1.2.2").items():
        ok, (u, inj) = s.check(check_injectable=ci)
        reasons = collections.Counter(msg or "PASS" for _, msg in u.values())
        res[f"{name}|check_injectable={ci}"] = {
            "user": dict(reasons),
            "user_failing_ids": [k for k, (p, m) in u.items() if not p][:50],
            "injection_pass": sum(1 for v in inj.values() if v), "injection_total": len(inj),
            "injection_failing": [k for k, v in inj.items() if not v],
        }
print(json.dumps(res, indent=1))
