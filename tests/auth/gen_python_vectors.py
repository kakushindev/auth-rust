"""Reference outputs for lenient base64, json.loads, int(), truthiness, len()
and JSON nesting depth, printed as JSON. Run with the Python of the pinned
authentik image, since the depth limit depends on its stack:
  docker exec -i <server> python -I - < tests/auth/gen_python_vectors.py \
    > rust/crates/ak-auth/testdata/python_vectors.json"""

import base64
import binascii
import json
import math
import random
import sys


def tag(v):
    if v is None:
        return {"t": "none"}
    if isinstance(v, bool):
        return {"t": "bool", "v": v}
    if isinstance(v, int):
        return {"t": "int", "v": str(v)}
    if isinstance(v, float):
        return {"t": "float", "v": "nan" if math.isnan(v) else ("inf" if v == math.inf else ("-inf" if v == -math.inf else v.hex()))}
    if isinstance(v, str):
        return {"t": "str", "v": [ord(c) for c in v]}
    if isinstance(v, list):
        return {"t": "list", "v": [tag(x) for x in v]}
    if isinstance(v, dict):
        return {"t": "dict", "v": [[[ord(c) for c in k], tag(x)] for k, x in v.items()]}
    raise TypeError(type(v))


def b64(data: bytes):
    rem = len(data) % 4
    if rem:
        data += b"=" * (4 - rem)
    try:
        return base64.urlsafe_b64decode(data).hex()
    except (TypeError, binascii.Error):
        return None


rng = random.Random(42)
alphabet = b"ABCxyz019-_+/=!. \n\xff"
b64_cases = [b"", b"YQ", b"YQ==YQ", b"YQ=x", b"Y=Q", b"!!YW!Jj!", b"YWJjZA==ZZ", b"=YQ", b"YQ\n=="]
b64_cases += [bytes(rng.choice(alphabet) for _ in range(rng.randrange(0, 12))) for _ in range(400)]

json_cases = [
    b'{"a": 1}', b'{"a": 1, "a": 2}', b'[1, 2.5, -0, -0.0, 1e400, 1E-2, 12345678901234567890]',
    b'NaN', b'-Infinity', b'"\\ud800"', b'"\\ud83d\\ude00"', b'"\\ud83d x"', b'"a\\u0000b"',
    b'"\\x"', b'"\x01"', b' \t{"k" : [true, false, null]} \r\n', b'01', b'1.', b'.5', b'-', b'1e', b'1e+',
    b'{"a":1,}', b'[1,]', b'{"sid": "abc"} x', "\"é\"".encode(), "\"é\"".encode("utf-16"),
    "{\"a\": 1}".encode("utf-32"), "[1]".encode("utf-16-be"), "[1]".encode("utf-16-le"), b'\xef\xbb\xbf[2]',
    b'"\xed\xa0\x80"', b'"\xff"', b'{"a": {"b": [{}]}}', b'"' + b'1' * 5 + b'"', b'1' * 4301, b'1' * 4300,
]
json_out = []
for case in json_cases:
    try:
        json_out.append([case.hex(), tag(json.loads(case))])
    except RecursionError:
        json_out.append([case.hex(), "RecursionError"])
    except ValueError:
        json_out.append([case.hex(), "ValueError"])

value_cases = ["0", "1", "-7", "1.9", "-1.9", "true", "false", "null", "[]", "[1]", "{}", '{"a":1}', '""',
               '"12"', '" 12 "', '"+3"', '"-0"', '"1_000"', '"1__0"', '"_1"', '"1_"', '"1.5"', '"abc"',
               '"١٢"', "NaN", "Infinity", "1e30", "123456789012345678901234567890", "0.0", '"x"']
value_out = []
for case in value_cases:
    v = json.loads(case)
    try:
        as_int = str(int(v))
    except Exception as exc:  # noqa: BLE001
        as_int = type(exc).__name__
    try:
        length = len(v)
    except TypeError:
        length = "TypeError"
    value_out.append([case, as_int, bool(v), length])

depth_out = []
for depth in (1, 3000, 20000, 100000):
    try:
        json.loads("[" * depth + "]" * depth)
        depth_out.append([depth, "ok"])
    except RecursionError:
        depth_out.append([depth, "RecursionError"])

json.dump(
    {"python": sys.version.split()[0], "base64": [[c.hex(), b64(c)] for c in b64_cases], "json": json_out, "values": value_out, "depth": depth_out},
    sys.stdout,
    ensure_ascii=False,
)
