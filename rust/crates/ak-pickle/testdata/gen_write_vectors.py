"""Regenerate write_vectors.json inside the 2026.2.7 reference image:
`python -m manage shell < gen_write_vectors.py > write_vectors.json`.
Each value is `pickle.dumps(obj, 5).hex()`; src/write.rs's tests rebuild the
same objects and must produce the same bytes. `tenant` is the default
tenant row as a dramatiq message's `model_create_defaults` carries it, with
the reference's field values (see tests)."""

import json
import pickle
import uuid

import django

from authentik.tenants.models import Tenant

cases = {
    "none": None,
    "true": True,
    "ints": [0, 1, 255, 256, 65535, 65536, -1, -5, 2**31 - 1, -(2**31), 2**31, -(2**31) - 1, 2**63, -(2**63), 2**100, -(2**100)],
    "floats": [0.0, -0.0, 1.5, 1e300],
    "strs": ["", "a", "é\U0001f600", "x" * 300],
    "bytes": [b"", b"ab", b"y" * 300],
    "tuples": [(), (1,), (1, 2), (1, 2, 3), (1, 2, 3, 4)],
    "nested": {"a": [1], "b": {}, "c": {"x": 1}, "d": []},
    "uuid_small": uuid.UUID(int=12345),
    "uuid_big": uuid.UUID("ffffffff-ffff-ffff-ffff-ffffffffffff"),
    "biglist": list(range(1001)),
}
out = {k: pickle.dumps(v, 5).hex() for k, v in cases.items()}
tenant = Tenant.objects.get(schema_name="public")
out["tenant"] = pickle.dumps({"tenant": tenant}, 5).hex()
out["tenant_fields"] = [[f.attname, repr(getattr(tenant, f.attname))] for f in Tenant._meta.concrete_fields]
out["django_version"] = django.__version__
print(json.dumps(out, indent=1))
