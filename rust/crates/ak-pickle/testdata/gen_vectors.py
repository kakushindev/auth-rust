"""Regenerate vectors.json with CPython 3.14: pickles (protocol 5) of the
kinds of objects authentik keeps in sessions, each with Python's own
description of the value (type name, and value or length)."""

import collections
import dataclasses
import datetime
import decimal
import enum
import json
import pickle
import sys
import uuid
import zoneinfo


class Color(enum.Enum):
    RED = "red"


class Flag(enum.StrEnum):
    ON = "on"


@dataclasses.dataclass
class Plan:
    flow_pk: str
    bindings: list
    context: dict


class FakeModel:
    """Pickles like a Django model instance."""

    def __init__(self, pk):
        self.id = pk

    def __reduce__(self):
        return (model_unpickle, (("authentik_core", "User"),), {"id": self.id, "_state": None})


def model_unpickle(model_id):
    return FakeModel.__new__(FakeModel)


model_unpickle.__module__ = "django.db.models.base"
model_unpickle.__qualname__ = "model_unpickle"
# Make the stand-in importable where Django's lives, so pickle can name it.
import types  # noqa: E402

for _name in ("django", "django.db", "django.db.models", "django.db.models.base"):
    sys.modules.setdefault(_name, types.ModuleType(_name))
sys.modules["django.db.models.base"].model_unpickle = model_unpickle


class Lazy:
    """Pickles like Django's SimpleLazyObject (request.user)."""

    def __init__(self, wrapped):
        self.wrapped = wrapped

    def __reduce__(self):
        return (unpickle_lazyobject, (self.wrapped,))


def unpickle_lazyobject(wrapped):
    return wrapped


unpickle_lazyobject.__module__ = "django.utils.functional"
sys.modules["django.utils"] = types.ModuleType("django.utils")
sys.modules["django.utils.functional"] = types.ModuleType("django.utils.functional")
sys.modules["django.utils.functional"].unpickle_lazyobject = unpickle_lazyobject


def describe(v):
    if isinstance(v, FakeModel):
        return {"type": "model:authentik_core.User"}
    t = type(v)
    name = t.__qualname__ if t.__module__ == "builtins" else f"{t.__module__}.{t.__qualname__}"
    out = {"type": name}
    # Exact builtin types: a str or int subclass (StrEnum, IntEnum) is an
    # object, as the pickle describes it.
    if v is None or t in (bool, int, str):
        out["value"] = str(v)
    elif t in (list, tuple, dict, set, frozenset, bytes, bytearray):
        out["len"] = len(v)
    return out


class ImmutableUntilBuilt(dict):
    """Like Django's QueryDict: a dict subclass whose __setitem__ the
    unpickler calls (dictitems) before BUILD restores its state."""

    def __setitem__(self, key, value):
        super().__setitem__(key, [value])


class Items(list):
    pass


query = ImmutableUntilBuilt()
dict.__setitem__(query, "next", "/")
query.mutable = False
listsub = Items([1, 2])
listsub.tag = "t"
shared = ["shared"]
recursive = [1]
recursive.append(recursive)
values = {
    "none": None, "true": True, "small": 7, "neg": -300, "i32": 2**31 - 1, "big": 2**200, "negbig": -(2**70),
    "float": 1.5, "str": "Gapura ✓ 🚪", "bytes": b"\x00\xff", "bytearray": bytearray(b"ab"),
    "tuple": (1, "a"), "tuple3": (1, 2, 3), "tuple5": (1, 2, 3, 4, 5), "list": [1, [2, [3]]], "dict": {"a": {"b": 1}},
    "set": {1, 2}, "frozenset": frozenset({"x"}), "shared": [shared, shared], "recursive": recursive,
    "datetime": datetime.datetime(2026, 10, 31, 12, 0, tzinfo=datetime.UTC),
    "zoned": datetime.datetime(2026, 10, 31, tzinfo=zoneinfo.ZoneInfo("Asia/Jakarta")),
    "date": datetime.date(2026, 1, 2), "timedelta": datetime.timedelta(days=1, seconds=3),
    "decimal": decimal.Decimal("1.10"), "uuid": uuid.UUID(int=1), "enum": Color.RED, "strenum": Flag.ON,
    "dataclass": Plan("f", [FakeModel(1)], {"pending_user": FakeModel(2)}), "model": FakeModel(42),
    "lazy_user": Lazy(FakeModel(4)), "lazy_str": Lazy("x"),
    "querydict_like": query, "ordereddict": collections.OrderedDict(a=1, b=2), "list_subclass": listsub,
    "defaultdict": collections.defaultdict(list, {"a": [1]}), "counter": collections.Counter("aab"),
    "long_str": "x" * 300, "long_bytes": b"y" * 300,
}
out = []
for name, v in values.items():
    data = pickle.dumps({"k": v}, protocol=5)
    # Described as unpickled, which is what a session holds.
    out.append({"name": name, "pickle": data.hex(), "describe": describe(pickle.loads(data)["k"])})
json.dump({"python": sys.version.split()[0], "vectors": out}, open(sys.argv[1], "w"), ensure_ascii=False, indent=0)
print(len(out), "pickles")
