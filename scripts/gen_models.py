#!/usr/bin/env python3
"""Generate rust/crates/ak-models/src/generated.rs from the pinned schema
snapshot (baseline/schema/reference-schema.json) and the Django inventory
(baseline/inventory/django.json).

One row type per table, with every column in table order and its exact
Postgres type; the primary key; whether the relation is writable; and the
multi-table-inheritance graph (child table, parent table, parent-link
column, Django class name) for the hierarchies Django resolves with
`select_subclasses()`. Unknown Postgres types fail generation instead of
being approximated. Re-run after re-pinning; the crate's tests check the
generated columns against the live database.
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "rust/crates/ak-models/src/generated.rs"

# M4 scope: core identity models, brands, tenants, providers and sources
# (non-Enterprise), plus the policy-binding parent of applications/sources.
PREFIXES = ("authentik_core_", "authentik_brands_", "authentik_tenants_", "authentik_providers_", "authentik_sources_")
EXTRA_TABLES = {"authentik_policies_policybindingmodel"}
# Hierarchies whose most-derived class Django resolves (InheritanceManager).
MTI_ROOTS = {
    "authentik_core_provider",
    "authentik_core_source",
    "authentik_core_propertymapping",
    "authentik_core_usersourceconnection",
    "authentik_core_groupsourceconnection",
}

TYPES = {
    "integer": "i32",
    "bigint": "i64",
    "smallint": "i16",
    "boolean": "bool",
    "text": "String",
    "uuid": "uuid::Uuid",
    "timestamp with time zone": "chrono::DateTime<chrono::Utc>",
    "date": "chrono::NaiveDate",
    "double precision": "f64",
    # jsonb keeps numerals and text exactly; RawValue round-trips them.
    "jsonb": "sqlx::types::Json<Box<serde_json::value::RawValue>>",
    "inet": "ipnet::IpNet",
    "bytea": "Vec<u8>",
    "text[]": "Vec<Option<String>>",
}
COPY = {
    "i32",
    "i64",
    "i16",
    "bool",
    "uuid::Uuid",
    "chrono::DateTime<chrono::Utc>",
    "chrono::NaiveDate",
    "f64",
    "ipnet::IpNet",
}
KEYWORDS = {"type", "default", "match", "ref", "self", "use", "mod", "fn", "impl", "move", "loop", "where", "async", "await", "dyn", "final", "macro", "priv", "static", "struct", "trait", "true", "false", "enum", "crate", "super", "as", "box", "break", "const", "continue", "else", "extern", "for", "if", "in", "let", "mut", "pub", "return", "unsafe", "while", "abstract", "become", "do", "override", "typeof", "unsized", "virtual", "yield", "try", "gen"}


def field_name(column, all_columns):
    """A Rust field for the column: keywords get a `_` suffix, and a leading
    underscore (`_scope`) is dropped unless another column has that name,
    then it becomes a `raw_` prefix."""
    if column in KEYWORDS:
        return f"{column}_"
    if column.startswith("_"):
        bare = column.lstrip("_")
        return f"raw_{bare}" if bare in all_columns or bare in KEYWORDS else bare
    return column


def rust_type(pg):
    if re.fullmatch(r"character varying\(\d+\)", pg):
        return "String"
    if pg not in TYPES:
        sys.exit(f"unmapped Postgres type {pg!r}")
    return TYPES[pg]


def camel(name):
    return "".join(part[:1].upper() + part[1:] for part in re.split(r"_+", name) if part)


def main():
    schema = json.loads((ROOT / "baseline/schema/reference-schema.json").read_text())["sections"]
    models = json.loads((ROOT / "baseline/inventory/django.json").read_text())["models"]
    by_label = {f"{m['app_label']}.{m['model']}": m for m in models}
    by_table = {m["db_table"]: m for m in models if not m.get("proxy")}

    def relation(table):
        return schema["relations"].get(f"public.{table}")

    tables = sorted(
        t
        for t, m in by_table.items()
        if (t.startswith(PREFIXES) and "enterprise" not in m.get("module", "") or t in EXTRA_TABLES)
        and relation(t)
    )

    def columns(table):
        cols = [
            (k.split(".", 2)[2], v)
            for k, v in schema["columns"].items()
            if k.split(".")[1] == table and k.startswith("public.")
        ]
        return sorted(cols, key=lambda c: int(c[1]["position"]))

    def primary_key(table):
        for key, c in schema["constraints"].items():
            if key.split(".")[1] == table and c["type"] == "p":
                return [col.strip() for col in re.search(r"PRIMARY KEY \((.*)\)", c["definition"]).group(1).split(",")]
        return []

    def parent_link(table):
        """(parent table, link column) of an MTI child, from its primary key's
        foreign key."""
        pk = primary_key(table)
        if len(pk) != 1:
            return None
        for key, c in schema["constraints"].items():
            if key.split(".")[1] == table and c["type"] == "f":
                m = re.match(r"FOREIGN KEY \((\w+)\) REFERENCES (\w+)\(", c["definition"])
                if m and m.group(1) == pk[0]:
                    return m.group(2), pk[0]
        return None

    names = {}
    for t in tables:
        name = camel(by_table[t]["model"])
        if name in names.values():
            name = camel(t.removeprefix("authentik_"))
        names[t] = name
    if len(set(names.values())) != len(names):
        sys.exit("row type names are not unique")

    out = [
        "// @generated by scripts/gen_models.py from baseline/schema/reference-schema.json",
        "// and baseline/inventory/django.json. Do not edit by hand.",
        "",
        "use sqlx::{Postgres, postgres::PgArguments, query::Query};",
        "",
        "use crate::Row;",
        "",
    ]
    for t in tables:
        cols = columns(t)
        pk = primary_key(t)
        kind = relation(t)["kind"]
        writable = kind == "r"
        generated = {name for name, c in cols if c["generated"]}
        always = any(c["identity"] == "a" for _, c in cols)
        if generated:
            sys.exit(f"{t}: generated columns {generated} need write support")
        name = names[t]
        out.append(f"/// `{t}` (Django `{by_table[t]['app_label']}.{by_table[t]['model']}`).")
        if sum(1 for _, c in cols if c["type"] == "boolean") > 3:
            out.append('#[expect(clippy::struct_excessive_bools, reason = "mirrors the table")]')
        out.append("#[derive(Debug, Clone, sqlx::FromRow)]")
        out.append(f"pub struct {name} {{")
        for col, c in cols:
            ty = rust_type(c["type"])
            if c["not_null"] != "true":
                ty = f"Option<{ty}>"
            field = field_name(col, [c for c, _ in cols])
            if field != col:
                out.append(f'    #[sqlx(rename = "{col}")]')
            out.append(f"    /// `{c['type']}`{' not null' if c['not_null'] == 'true' else ''}")
            out.append(f"    pub {field}: {ty},")
        out.append("}")
        out.append("")
        fields = [field_name(c, [n for n, _ in cols]) for c, _ in cols]
        # Copy types bind by value, the others by reference.
        binds = [
            f"self.{f}" if rust_type(c["type"]) in COPY else f"&self.{f}"
            for f, (_, c) in zip(fields, cols)
        ]
        out.append(f"impl Row for {name} {{")
        out.append(f'    const TABLE: &\'static str = "{t}";')
        out.append("    const COLUMNS: &'static [&'static str] = &[" + ", ".join(f'"{c}"' for c, _ in cols) + "];")
        out.append("    const PRIMARY_KEY: &'static [&'static str] = &[" + ", ".join(f'"{c}"' for c in pk) + "];")
        out.append(f"    const WRITABLE: bool = {'true' if writable else 'false'};")
        out.append(f"    const OVERRIDING_SYSTEM_VALUE: bool = {'true' if always else 'false'};")
        out.append("")
        out.append("    fn bind_columns<'q>(")
        out.append("        &'q self,")
        out.append("        query: Query<'q, Postgres, PgArguments>,")
        out.append("    ) -> Query<'q, Postgres, PgArguments> {")
        out.append("        query" + "".join(f"\n            .bind({b})" for b in binds))
        out.append("    }")
        out.append("}")
        out.append("")

    out.append("/// Calls `$m!(RowType)` for every generated row type.")
    out.append("#[macro_export]")
    out.append("macro_rules! for_each_row {")
    out.append("    ($m:ident) => {")
    for t in tables:
        out.append(f"        $m!($crate::generated::{names[t]});")
    out.append("    };")
    out.append("}")
    out.append("")

    # MTI graph over every model (Enterprise included), restricted to the roots.
    edges = []
    for t, m in by_table.items():
        if not m["parents"] or not relation(t):
            continue
        link = parent_link(t)
        if not link:
            continue
        parent_table, column = link
        edges.append((t, parent_table, column, m["model"]))

    def root_of(table):
        seen = set()
        while table not in MTI_ROOTS:
            parent = next((p for c, p, _, _ in edges if c == table), None)
            if parent is None or table in seen:
                return None
            seen.add(table)
            table = parent
        return table

    edges = sorted(e for e in edges if root_of(e[0]))
    out.append("/// Multi-table inheritance below the hierarchies Django resolves with")
    out.append("/// `select_subclasses()`.")
    out.append("///")
    out.append("/// Entries are (child table, parent table, parent-link column, Django class")
    out.append("/// name). Enterprise subclasses are included: their rows are not ported but")
    out.append("/// still belong to these hierarchies.")
    out.append("pub const INHERITANCE: &[(&str, &str, &str, &str)] = &[")
    for child, parent, column, cls in edges:
        out.append(f'    ("{child}", "{parent}", "{column}", "{cls}"),')
    out.append("];")
    out.append("")
    out.append("/// Root tables of the hierarchies in [`INHERITANCE`], with their Django class.")
    out.append("pub const INHERITANCE_ROOTS: &[(&str, &str)] = &[")
    for root in sorted(MTI_ROOTS):
        out.append(f'    ("{root}", "{by_table[root]["model"]}"),')
    out.append("];")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(out) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(tables)} row types, {len(edges)} inheritance edges")


if __name__ == "__main__":
    main()
