"""Roles, groups, users and permissions for the M6 permission differential.

Run inside an authentik 2026.2.7 server container after
tests/models/populate.py (which gives every model rows):
  python -m manage shell < tests/rbac/populate.py

- m6-model holds model-wide permissions; m6-object holds per-object
  permissions on the first two rows of every model with rows (view on the
  first; change and delete on the second).
- m6-parent / m6-child sit on a group hierarchy (g-parent > g-child >
  g-grandchild), so a grandchild member inherits both.
- m6-dup-a and m6-dup-b both grant view on one application: guardian's
  per-object count then satisfies [view, change].
- m6-anon is assigned to the AnonymousUser row; m6-broken holds an object
  permission whose object_pk does not cast to the model's key.
- Superusers come from a superuser group, directly or through a child group.
"""

from django.apps import apps
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, transaction
from guardian.models import RoleObjectPermission

from authentik.core.models import Application, Group, User, UserTypes
from authentik.rbac.models import Role

transaction.set_autocommit(False)
roles = {
    name: Role.objects.create(name=f"m6-{name}")
    for name in ["model", "object", "parent", "child", "dup-a", "dup-b", "anon", "broken"]
}
roles["model"].assign_perms([
    "authentik_core.view_application", "authentik_core.change_application", "authentik_core.view_user",
    "authentik_flows.view_flow", "authentik_rbac.view_role", "authentik_core.impersonate",
    "authentik_rbac.access_admin_interface",
])
roles["parent"].assign_perms(["authentik_core.view_group", "authentik_brands.view_brand"])
roles["anon"].assign_perms("authentik_brands.view_brand")

tables = set(connection.introspection.table_names())
sampled = 0
for i, ctype in enumerate(ContentType.objects.order_by("app_label", "model")):
    model = ctype.model_class()
    if model is None or model._meta.db_table not in tables or model._meta.proxy:
        continue
    # A parent model's manager may yield subclass instances, whose
    # permissions belong to the subclass.
    objs = [o for o in model._base_manager.order_by("pk")[:2] if ContentType.objects.get_for_model(o) == ctype]
    perms = {p.codename: p for p in Permission.objects.filter(content_type=ctype)}
    if not objs or not perms:
        continue
    name = model._meta.model_name
    if f"view_{name}" in perms:
        roles["object"].assign_perms(perms[f"view_{name}"], objs[0])
    if len(objs) > 1:
        for action in ("change", "delete"):
            if f"{action}_{name}" in perms:
                roles["object"].assign_perms(perms[f"{action}_{name}"], objs[1])
    if i % 3 == 0:
        roles["child"].assign_perms(list(perms.values()), objs[0])
    sampled += 1

app = Application.objects.order_by("pk").first()
for role in ("dup-a", "dup-b", "anon"):
    roles[role].assign_perms("authentik_core.view_application", app)
RoleObjectPermission.objects.bulk_create([
    RoleObjectPermission(
        role=roles["broken"], permission=Permission.objects.get(codename="view_application"),
        content_type=ContentType.objects.get_for_model(Application), object_pk="not-a-uuid",
    )
])

parent = Group.objects.create(name="m6-g-parent")
parent.roles.add(roles["parent"])
child = Group.objects.create(name="m6-g-child")
child.roles.add(roles["child"])
child.parents.add(parent)
grandchild = Group.objects.create(name="m6-g-grandchild")
grandchild.parents.add(child)
superusers = Group.objects.create(name="m6-g-super", is_superuser=True)
super_child = Group.objects.create(name="m6-g-super-child")
super_child.parents.add(superusers)

USERS = {
    "m6-none": ({}, [], []),
    "m6-direct": ({}, ["model", "object"], []),
    "m6-grandchild": ({}, [], [grandchild]),
    "m6-child-direct": ({}, ["object"], [child]),
    "m6-dup": ({}, ["dup-a", "dup-b"], []),
    "m6-super": ({}, [], [superusers]),
    "m6-super-sub": ({}, [], [super_child]),
    "m6-inactive": ({"is_active": False}, ["model", "object"], []),
    "m6-inactive-super": ({"is_active": False}, [], [superusers]),
    "m6-service": ({"type": UserTypes.INTERNAL_SERVICE_ACCOUNT}, ["object"], []),
    "m6-service-none": ({"type": UserTypes.INTERNAL_SERVICE_ACCOUNT}, [], []),
    "m6-broken": ({}, ["broken"], []),
}
for username, (fields, user_roles, groups) in USERS.items():
    user = User.objects.create(username=username, **fields)
    user.roles.add(*[roles[r] for r in user_roles])
    user.groups.add(*groups)
User.objects.get(username="AnonymousUser").roles.add(roles["anon"])
assert apps.get_model("authentik_core", "User")
transaction.commit()
print(f"[populate] sampled {sampled} models")
print("[populate] ok")
