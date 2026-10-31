"""API tokens for the M7 read-API differential.

Run inside an authentik 2026.2.7 server container after tests/models/populate.py
and tests/rbac/populate.py:
  python -m manage shell < tests/api/populate.py

Every M6 subject (and akadmin) gets a non-expiring API token whose key is
"m7-<username>". Extra tokens cover the edges the read API must decline or
answer like Django: an expired token (Django deletes it while looking it up),
a recovery-intent token, and the inactive user's token.
"""

from datetime import timedelta

from django.db import transaction
from django.utils.timezone import now

from authentik.core.models import Token, TokenIntents, User

transaction.set_autocommit(False)
subjects = [u for u in User.objects.filter(username__startswith="m6-")] + [
    User.objects.get(username="akadmin")
]
for user in subjects:
    Token.objects.create(
        identifier=f"m7-{user.username}", key=f"m7-{user.username}", user=user,
        intent=TokenIntents.INTENT_API, expiring=False,
    )
admin = User.objects.get(username="akadmin")
Token.objects.create(
    identifier="m7-expired", key="m7-expired", user=admin, intent=TokenIntents.INTENT_API,
    expiring=True, expires=now() - timedelta(days=1),
)
Token.objects.create(
    identifier="m7-recovery", key="m7-recovery", user=admin,
    intent=TokenIntents.INTENT_RECOVERY, expiring=False,
)
# JSON escaping: quotes, backslashes, control characters, non-ASCII.
from authentik.rbac.models import Role  # noqa: E402

Role.objects.create(name='m7-weird "q" \\ \x01\x1f\x7f \u00e9 \u2028 \U0001f600')
transaction.commit()
print(f"[populate] tokens for {len(subjects)} subjects")
print("[populate] ok")
