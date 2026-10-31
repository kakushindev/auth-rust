# Run with `python -m manage shell` after populate.py (run.sh).
"""Django's permission decisions for every subject, as JSON.

Subjects are the m6-* users, an inactive one as impersonation leaves it
(is_active forced True), and Django's AnonymousUser. For each:
- global: which of all permissions (plus malformed names) has_perm grants;
- objects: has_perm on two sampled rows of every model, for each of the
  model's permissions (and a codename-only and a foreign-app name);
- get_objects_for_user for [view], [view, change], [change, delete] and
  error cases, on every model;
- ObjectFilter on every model (and with an owner field);
- ObjectPermissions.has_permission / has_object_permission for methods,
  lookups and the create-without-permission flag;
- permission_required.
Everything runs in a transaction rolled back at the end.
"""

import json
import types

from django.contrib.auth.models import AnonymousUser, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, transaction
from django.db.models import ForeignKey, UUIDField
from django.http import Http404
from guardian.shortcuts import get_objects_for_user
from rest_framework.exceptions import MethodNotAllowed, PermissionDenied

from authentik.core.models import User
from authentik.rbac.decorators import permission_required
from authentik.rbac.filters import ObjectFilter
from authentik.rbac.permissions import ObjectPermissions


def cast_type(field):
    if isinstance(field, ForeignKey):
        return cast_type(field.target_field)
    return "uuid" if isinstance(field, UUIDField) else "bigint"


def err(exc):
    return f"error:{type(exc).__name__}"


def subjects():
    names = ["m6-none", "m6-direct", "m6-grandchild", "m6-child-direct", "m6-dup", "m6-super", "m6-super-sub",
             "m6-inactive", "m6-inactive-super", "m6-service", "m6-service-none", "m6-broken"]
    out = {name: User.objects.get(username=name) for name in names}
    impersonated = User.objects.get(username="m6-inactive")
    impersonated.is_active = True
    out["m6-inactive-impersonated"] = impersonated
    out["anonymous"] = AnonymousUser()
    return out


def subject_info(name, user):
    if isinstance(user, AnonymousUser):
        return {"name": name, "anonymous": True}
    return {"name": name, "anonymous": False, "user_id": user.pk, "is_active": user.is_active}


tables = set(connection.introspection.table_names())
models = []
for ctype in ContentType.objects.order_by("app_label", "model"):
    model = ctype.model_class()
    if model is None or model._meta.db_table not in tables or model._meta.proxy:
        continue
    concrete = ContentType.objects.get_for_model(model)
    models.append({
        "app_label": model._meta.app_label, "model_name": model._meta.model_name,
        "ctype_app_label": concrete.app_label, "ctype_model": concrete.model,
        "pk_cast": cast_type(model._meta.pk), "class": model,
        "db_table": model._meta.db_table, "pk_column": model._meta.pk.column,
        "pks": sorted(str(pk) for pk in model._base_manager.values_list("pk", flat=True)),
        "perms": sorted(f"{ctype.app_label}.{p.codename}" for p in Permission.objects.filter(content_type=ctype)),
    })
all_perms = sorted(f"{ct}.{code}" for ct, code in Permission.objects.values_list("content_type__app_label", "codename"))
extra_perms = ["view_application", "impersonate", "nope.view_x", "", ".", "authentik_core.",
               "authentik_core.view_application.x", "AUTHENTIK_CORE.view_application"]

out = {"models": [{k: v for k, v in m.items() if k != "class"} for m in models], "subjects": [],
       "all_perms": all_perms, "extra_perms": extra_perms}
DRF_MODELS = [("authentik_core", "application"), ("authentik_flows", "flow"), ("authentik_core", "user"),
              ("authentik_core", "token"), ("authentik_rbac", "role")]
METHODS = ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE"]

with transaction.atomic():
    for name, user in subjects().items():
        record = subject_info(name, user)
        record["global"] = [p for p in all_perms + extra_perms if user.has_perm(p)]
        objects = []
        for index, m in enumerate(models):
            for obj in m["class"]._base_manager.order_by("pk")[:2]:
                perms = list(m["perms"])
                if perms:
                    perms.append(perms[0].split(".", 1)[1])
                perms.append("authentik_flows.view_flow" if m["app_label"] != "authentik_flows" else "authentik_core.view_user")
                granted, errors = [], {}
                for perm in perms:
                    try:
                        if user.has_perm(perm, obj):
                            granted.append(perm)
                    except Exception as exc:  # noqa: BLE001
                        errors[perm] = err(exc)
                own = ContentType.objects.get_for_model(obj)
                objects.append({"model": index, "pk": str(obj.pk), "checked": perms, "granted": granted,
                                "errors": errors, "obj_app_label": obj._meta.app_label,
                                "obj_model_name": obj._meta.model_name, "obj_ctype_app_label": own.app_label,
                                "obj_ctype_model": own.model})
        record["objects"] = objects
        visible = []
        for index, m in enumerate(models):
            prefix = f"{m['app_label']}.%s_{m['model_name']}"
            sets = [[prefix % "view"], [prefix % "view", prefix % "change"], [prefix % "change", prefix % "delete"]]
            sets = [s for s in sets if all(p in m["perms"] for p in s)]
            if index % 20 == 0:
                sets += [[], [f"view_{m['model_name']}"], [prefix % "view", "authentik_flows.view_flow"]]
            for perms in sets:
                qs = m["class"]._base_manager.all()
                sid = transaction.savepoint()
                try:
                    result = get_objects_for_user(user, perms, qs)
                    got = "all" if result is qs else sorted(str(pk) for pk in result.values_list("pk", flat=True))
                except Exception as exc:  # noqa: BLE001
                    got = err(exc)
                transaction.savepoint_rollback(sid)
                visible.append({"model": index, "perms": perms, "result": got})
        record["get_objects"] = visible
        filtered = []
        for index, m in enumerate(models):
            owners = [None] + (["user"] if (m["app_label"], m["model_name"]) == ("authentik_core", "token") else [])
            for owner in owners:
                if owner and isinstance(user, AnonymousUser):
                    continue
                qs = m["class"]._base_manager.all()
                view = types.SimpleNamespace(owner_field=owner) if owner else types.SimpleNamespace()
                request = types.SimpleNamespace(user=user)
                sid = transaction.savepoint()
                try:
                    result = ObjectFilter().filter_queryset(request, qs, view)
                    if owner and result is not qs:
                        got = "owner"
                    else:
                        got = "all" if result is qs else sorted(str(pk) for pk in result.values_list("pk", flat=True))
                except PermissionDenied:
                    got = "denied"
                except Exception as exc:  # noqa: BLE001
                    got = err(exc)
                transaction.savepoint_rollback(sid)
                filtered.append({"model": index, "owner": owner is not None, "result": got})
        record["object_filter"] = filtered
        drf = []
        for app_label, model_name in DRF_MODELS:
            index = next(i for i, m in enumerate(models) if (m["app_label"], m["model_name"]) == (app_label, model_name))
            model = models[index]["class"]
            for method in METHODS:
                for lookup in (False, True):
                    for allow_create in (False, True):
                        view = types.SimpleNamespace(
                            lookup_field="pk", lookup_url_kwarg=None, kwargs={"pk": "x"} if lookup else {},
                            queryset=model._base_manager.all(), rbac_allow_create_without_perm=allow_create)
                        try:
                            got = ObjectPermissions().has_permission(
                                types.SimpleNamespace(method=method, user=user), view)
                        except MethodNotAllowed:
                            got = "MethodNotAllowed"
                        drf.append({"model": index, "kind": "has_permission", "method": method, "lookup": lookup,
                                    "allow_create": allow_create, "result": got})
                for obj in model._base_manager.order_by("pk")[:2]:
                    owner = model_name == "token"
                    owner_matches = owner and getattr(obj, "user", None) == user
                    view = types.SimpleNamespace(queryset=model._base_manager.all(),
                                                 **({"owner_field": "user"} if owner else {}))
                    try:
                        got = ObjectPermissions().has_object_permission(
                            types.SimpleNamespace(method=method, user=user), view, obj)
                    except Http404:
                        got = "Http404"
                    except MethodNotAllowed:
                        got = "MethodNotAllowed"
                    drf.append({"model": index, "kind": "has_object_permission", "method": method,
                                "pk": str(obj.pk), "owner_matches": owner_matches, "result": got})
        record["drf"] = drf
        required = []
        user_index = next(i for i, m in enumerate(models) if (m["app_label"], m["model_name"]) == ("authentik_core", "user"))
        targets = [str(u.pk) for u in User.objects.filter(username__in=["m6-none", "akadmin"]).order_by("pk")] + [None]
        for target in targets:
            for obj_perm in [None, "authentik_core.impersonate", "authentik_core.reset_user_password"]:
                for global_perms in [[], ["authentik_core.view_user"], ["authentik_rbac.access_admin_interface", "authentik_core.add_user"]]:
                    class FakeView:
                        def get_object(self):
                            if target is None:
                                raise Http404
                            return User.objects.get(pk=target)

                        def permission_denied(self, request):
                            raise PermissionDenied

                    wrapped = permission_required(obj_perm, global_perms)(lambda self, request: "allow")
                    try:
                        got = wrapped(FakeView(), types.SimpleNamespace(user=user))
                    except PermissionDenied:
                        got = "deny"
                    except Http404:
                        got = "not_found"
                    required.append({"model": user_index, "pk": target, "obj_perm": obj_perm,
                                     "global_perms": global_perms, "result": got})
        record["permission_required"] = required
        out["subjects"].append(record)
    transaction.set_rollback(True)

print("RBAC_DECISIONS " + json.dumps(out))
