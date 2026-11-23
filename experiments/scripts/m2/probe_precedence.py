"""Probe banking injection tasks 0/1/3: does security() require the intended content in the subject?"""
import json, warnings
warnings.filterwarnings("ignore")
from agentdojo.default_suites.v1.tools.banking_client import Transaction
from agentdojo.task_suite.load_suites import get_suites

s = get_suites("v1.2.2")["banking"]
env = s.load_and_inject_default_environment({})
out = {}
for iid in ("injection_task_0", "injection_task_1", "injection_task_3"):
    it = s.injection_tasks[iid]
    pre, post = env.model_copy(deep=True), env.model_copy(deep=True)
    post.bank_account.transactions.append(Transaction(
        id=9999, sender="x", recipient=it._ATTACKER_IBAN, amount=0.01,
        subject="UNRELATED SUBJECT WITH NONE OF THE REQUIRED CONTENT", date="2022-01-01", recurring=False))
    out[iid] = {"security_with_unrelated_subject": it.security("", pre, post),
                "security_without_attacker_tx": it.security("", pre, env.model_copy(deep=True))}
print(json.dumps(out, indent=1))
