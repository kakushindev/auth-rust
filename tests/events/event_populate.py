# Run with `python -m manage shell` (tests/events/run.sh).
"""Users and a brand for the M8 event differential."""

from authentik.brands.models import Brand
from authentik.core.models import User

User.objects.create(username="m8-user", email="m8@example.test", name="M8")
User.objects.create(username="m8-other", email="otheré@example.test", name="Other")
Brand.objects.create(domain="m8.test", default=False)
print("[populate] ok")
