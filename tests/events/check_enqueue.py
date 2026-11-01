# Checks a task Rust enqueued (ak-events, tests/enqueue.rs) against what
# Django writes for the same actor and arguments. Run inside a stack:
#   MESSAGE_ID=… python -m manage shell < check_enqueue.py
# The message is rebuilt by dramatiq with Rust's
# message_id and timestamp and must be byte-identical. The row and its
# TaskLog must match a Django-enqueued row field by field.
import pickle
import os

from authentik.events.tasks import event_trigger_dispatch
from authentik.tasks.models import Task, TaskLog
from authentik.tenants.utils import get_current_tenant

mid = os.environ["MESSAGE_ID"]
rust = Task.objects.get(message_id=mid)
m = pickle.loads(bytes(rust.message))
msg = event_trigger_dispatch.message(*m["args"])
d = msg.asdict()
d["message_id"] = m["message_id"]
d["message_timestamp"] = m["message_timestamp"]
d["options"] = {"model_create_defaults": {"tenant": get_current_tenant()}}
same_bytes = pickle.dumps(d) == bytes(rust.message)

django_msg = event_trigger_dispatch.send(*m["args"])
django = Task.objects.get(message_id=django_msg.message_id)
skip = {"message_id", "message", "mtime"}
fields = [f.attname for f in Task._meta.concrete_fields if f.attname not in skip]
row_diffs = [f for f in fields if getattr(rust, f) != getattr(django, f)]
log_fields = ["event", "log_level", "logger", "attributes", "previous"]
logs = lambda t: [[getattr(l, f) for f in log_fields] for l in TaskLog.objects.filter(task=t)]
same_logs = logs(rust) == logs(django)
print(f"[enqueue] bytes={same_bytes} row_diffs={row_diffs} logs={same_logs}")
print("[enqueue] " + ("ok" if same_bytes and not row_diffs and same_logs else "MISMATCH"))
django.delete()
