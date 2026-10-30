"""Print, as JSON, the class Django resolves for every row of the five
multi-table-inheritance hierarchies (`select_subclasses()`), keyed by root
table and primary key. Run with `python -m manage shell < django_classes.py`."""

import json

from authentik.core.models import GroupSourceConnection, PropertyMapping, Provider, Source, UserSourceConnection

out = {}
for model in (Provider, Source, PropertyMapping, UserSourceConnection, GroupSourceConnection):
    out[model._meta.db_table] = {
        str(obj.pk): type(obj).__name__ for obj in model.objects.select_subclasses()
    }
print("DJANGO_CLASSES " + json.dumps(out, sort_keys=True))
