"""Static classification of AgentDojo v1.2.2 injection tasks (M2). Read-only inspection."""
import inspect, json, re, warnings
warnings.filterwarnings("ignore")
from agentdojo.task_suite.load_suites import get_suites

SIDE_EFFECT = {  # tools that mutate sandbox state or send data out (manual list, reviewed against tool docstrings)
 "send_money","schedule_transaction","update_scheduled_transaction","update_password","update_user_info",
 "send_email","delete_email","delete_file","create_file","append_to_file","share_file","create_calendar_event",
 "cancel_calendar_event","reschedule_calendar_event","add_calendar_event_participants",
 "send_direct_message","send_channel_message","add_user_to_channel","invite_user_to_slack","remove_user_from_slack",
 "post_webpage","reserve_hotel","reserve_restaurant","reserve_car_rental",
}
rows = []
for sname, s in get_suites("v1.2.2").items():
    env = s.load_and_inject_default_environment({})
    for iid, t in s.injection_tasks.items():
        cls = type(t)
        try:
            gt = [c.function for c in t.ground_truth(env.model_copy(deep=True))]
        except Exception as e:  # noqa: BLE001
            gt = [f"ERR:{e}"]
        src = inspect.getsource(cls.security) if "security" in cls.__dict__ else ""
        body = src.split(":\n", 1)[-1] if src else ""
        uses_output = bool(re.search(r"model_output", body.split(")", 1)[-1])) if body else False
        trace_based = "security_from_traces" in cls.__dict__
        rows.append({
            "suite": sname, "id": iid, "gt_tools": gt, "gt_empty": len(gt) == 0,
            "gt_has_side_effect_tool": any(g in SIDE_EFFECT for g in gt),
            "security_state_based": ("security" in cls.__dict__) and not trace_based and "NotImplementedError" not in src,
            "security_from_traces": trace_based, "security_reads_model_output": uses_output,
            "goal": t.GOAL[:110].replace("\n", " "),
        })
print(json.dumps(rows, indent=1))
