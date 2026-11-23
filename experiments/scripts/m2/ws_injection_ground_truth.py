import warnings; warnings.filterwarnings("ignore")
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
s = get_suites("v1.2.2")["workspace"]
ut = s.user_tasks["user_task_0"]
for k in ("injection_task_5","injection_task_6","injection_task_9","injection_task_12"):
    it = s.injection_tasks[k]
    env = s.load_and_inject_default_environment({})
    gt = it.ground_truth(env.model_copy(deep=True))
    _, sec = s.run_task_with_pipeline(GroundTruthPipeline(it), ut, it, {}, environment=env.model_copy(deep=True))
    print(k, "security=", sec, "| overrides:", [m for m in ("security","security_from_traces") if m in type(it).__dict__], "| calls:", [(c.function, {a: str(v)[:40] for a, v in c.args.items()}) for c in gt])
    print("   GOAL:", it.GOAL[:130].replace("\n"," "))
