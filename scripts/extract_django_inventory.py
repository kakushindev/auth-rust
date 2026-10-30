# Runs inside the reference authentik container via `ak shell` and prints a JSON
# inventory taken from the live Django app registry, URL resolver, dramatiq broker
# and settings. Output is the runtime evidence the feature matrix is built from.
import json
import sys

from django.apps import apps
from django.conf import settings
from django.urls import URLPattern, URLResolver, get_resolver


def model_entry(model):
    fields = []
    for f in model._meta.get_fields(include_hidden=True):
        if f.auto_created and not f.concrete:
            continue
        entry = {
            "name": f.name,
            "type": type(f).__name__,
        }
        if getattr(f, "concrete", False) and hasattr(f, "column"):
            entry["column"] = f.column
        if f.is_relation and f.related_model is not None and f.related_model != "self":
            rel = f.related_model
            entry["related"] = f"{rel._meta.app_label}.{rel.__name__}" if hasattr(rel, "_meta") else str(rel)
        if f.many_to_many and getattr(f, "remote_field", None) is not None:
            through = f.remote_field.through
            if through is not None and hasattr(through, "_meta"):
                entry["through"] = through._meta.db_table
        if getattr(f, "concrete", False):
            entry["null"] = bool(getattr(f, "null", False))
            default = getattr(f, "default", None)
            from django.db.models.fields import NOT_PROVIDED

            if default is not NOT_PROVIDED:
                entry["default"] = getattr(default, "__qualname__", None) or repr(default)
        fields.append(entry)
    parents = [f"{p._meta.app_label}.{p.__name__}" for p in model._meta.parents]
    return {
        "app_label": model._meta.app_label,
        "model": model.__name__,
        "module": model.__module__,
        "db_table": model._meta.db_table,
        "abstract": model._meta.abstract,
        "proxy": model._meta.proxy,
        "managed": model._meta.managed,
        "parents": parents,
        "fields": fields,
    }


def walk(patterns, prefix=""):
    for p in patterns:
        if isinstance(p, URLResolver):
            yield from walk(p.url_patterns, prefix + str(p.pattern))
        elif isinstance(p, URLPattern):
            cb = p.callback
            view = getattr(cb, "cls", None) or getattr(cb, "view_class", None)
            name = (
                f"{view.__module__}.{view.__name__}"
                if view is not None
                else f"{getattr(cb, '__module__', '?')}.{getattr(cb, '__name__', repr(cb))}"
            )
            actions = getattr(cb, "actions", None)
            yield {
                "pattern": prefix + str(p.pattern),
                "name": p.name,
                "view": name,
                "actions": dict(actions) if actions else None,
            }


def actors():
    import dramatiq

    broker = dramatiq.get_broker()
    out = []
    for name in sorted(broker.actors):
        actor = broker.actors[name]
        fn = actor.fn
        out.append(
            {
                "actor": name,
                "queue": actor.queue_name,
                "module": getattr(fn, "__module__", None),
                "options": {k: repr(v) for k, v in actor.options.items()},
            }
        )
    return out


def app_entry(cfg):
    return {
        "label": cfg.label,
        "name": cfg.name,
        "verbose_name": str(cfg.verbose_name),
        "class": f"{type(cfg).__module__}.{type(cfg).__name__}",
    }


data = {
    "installed_apps": list(settings.INSTALLED_APPS),
    "shared_apps": list(settings.SHARED_APPS),
    "tenant_apps": list(settings.TENANT_APPS),
    "app_configs": [app_entry(c) for c in apps.get_app_configs()],
    "models": [model_entry(m) for m in apps.get_models(include_auto_created=True)],
    "urls": list(walk(get_resolver().url_patterns)),
    "actors": actors(),
    "middleware": list(settings.MIDDLEWARE),
    "authentication_backends": list(settings.AUTHENTICATION_BACKENDS),
    "password_hashers": list(settings.PASSWORD_HASHERS),
    "session_engine": settings.SESSION_ENGINE,
    "rest_framework": {k: repr(v) for k, v in settings.REST_FRAMEWORK.items()},
}
sys.stdout.write("@@INVENTORY@@" + json.dumps(data, sort_keys=True, default=str) + "\n")
