"""Constants derived from the kernel's YNL netlink specs (#167).

The kernel describes its netlink families in YAML (Documentation/netlink/specs).
Its C header generator, tools/net/ynl, names every constant from a spec by
fixed rules. This module applies the same rules to the specs vendored in
third_party/ynl-specs, and returns `{C_NAME: value}`: the same shape the header
parser in audit_uapi_constants.py returns, so the two can be compared and
merged.

The naming rules, from tools/net/ynl (`c_upper` is upper case with `-` as `_`):

  - A `const` definition is `c_upper(name-prefix or "<family>-" + name)`.
  - An `enum` or `flags` definition's entries are
    `c_upper(name-prefix or "<family>-<enum>-" + entry)`. Values start at
    `value-start` (0) and count up, unless an entry gives its own. For `flags`
    the value is a bit index, and the constant is `1 << index`.
  - An attribute set's attributes are
    `c_upper(name-prefix or "<family>-a-" [+ "<set>-"] + attribute)`. The set
    name is left out for the set named after the family. Values start at 1
    and count up, unless an attribute gives its own. A `subset-of` set reuses
    another set's ids and defines nothing.
  - A `unified` operation list's commands are
    `c_upper(name-prefix or "<family>-cmd-" + name)`, from 1. A `directional`
    list names requests and replies apart and is not derived.
  - A definition with `header:` belongs to another header and is skipped.

These rules agree with the 6.12 headers on every constant both define, for
every vendored spec, except the quirks listed in
scripts/audit-uapi-constants.ynl-quirks.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

SPEC_DIR = Path(__file__).resolve().parent.parent / "third_party" / "ynl-specs"


def c_upper(name: str) -> str:
    return name.upper().replace("-", "_")


def derive(spec: dict) -> dict[str, int]:
    """Every constant one spec defines, by the generator's naming rules."""
    out: dict[str, int] = {}
    for consts in derive_groups(spec).values():
        out.update(consts)
    return out


def derive_groups(spec: dict) -> dict[str, dict[str, int]]:
    """The same constants, keyed by the definition that declares them:
    `"enum <name>"`, `"attrs <set>"`, `"const"` or `"ops"`."""
    family = spec["name"]
    groups: dict[str, dict[str, int]] = {}

    for d in spec.get("definitions") or []:
        if d.get("header"):
            continue
        kind = d.get("type")
        if kind == "const":
            if isinstance(d.get("value"), int):
                name = c_upper(d.get("name-prefix", f"{family}-") + d["name"])
                groups.setdefault("const", {})[name] = d["value"]
        elif kind in ("enum", "flags"):
            prefix = d.get("name-prefix", f"{family}-{d['name']}-")
            value = d.get("value-start", 0)
            out = groups.setdefault(f"enum {d['name']}", {})
            for i, entry in enumerate(d.get("entries") or []):
                if isinstance(entry, dict):
                    name = entry["name"]
                    if "value" in entry:
                        value = entry["value"]
                    elif i:
                        value += 1
                else:
                    name = entry
                    if i:
                        value += 1
                out[c_upper(prefix + name)] = (1 << value) if kind == "flags" else value

    for attr_set in spec.get("attribute-sets") or []:
        if "subset-of" in attr_set:
            continue
        if "name-prefix" in attr_set:
            prefix = attr_set["name-prefix"]
        elif attr_set["name"] == family:
            prefix = f"{family}-a-"
        else:
            prefix = f"{family}-a-{attr_set['name']}-"
        value = 1
        out = groups.setdefault(f"attrs {attr_set['name']}", {})
        for attr in attr_set.get("attributes") or []:
            if "value" in attr:
                value = attr["value"]
            out[c_upper(prefix + attr["name"])] = value
            value += 1

    operations = spec.get("operations") or {}
    if operations.get("enum-model", "unified") == "unified":
        prefix = operations.get("name-prefix", f"{family}-cmd-")
        value = 1
        out = groups.setdefault("ops", {})
        for op in operations.get("list") or []:
            if "value" in op:
                value = op["value"]
            out[c_upper(prefix + op["name"])] = value
            value += 1

    return {group: consts for group, consts in groups.items() if consts}


def verify_hashes(spec_dir: Path = SPEC_DIR) -> list[str]:
    """Problems with the vendored specs against SOURCE: a file whose sha256
    differs, one SOURCE lists that is missing, or one SOURCE doesn't list."""
    source = spec_dir / "SOURCE"
    if not source.exists():
        return [f"{source} is missing; run scripts/vendor-ynl-specs.sh"]
    want: dict[str, str] = {}
    for line in source.read_text().splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].endswith(".yaml"):
            want[parts[1]] = parts[0]
    problems = []
    present = {p.name for p in spec_dir.glob("*.yaml")}
    for name, digest in sorted(want.items()):
        path = spec_dir / name
        if not path.exists():
            problems.append(f"{name}: listed in SOURCE, not present")
            continue
        got = hashlib.sha256(path.read_bytes()).hexdigest()
        if got != digest:
            problems.append(
                f"{name}: sha256 {got} differs from SOURCE ({digest}); a vendored "
                "spec is never edited by hand, re-run scripts/vendor-ynl-specs.sh"
            )
    for name in sorted(present - set(want)):
        problems.append(f"{name}: present but not listed in SOURCE")
    return problems


def load(spec_dir: Path = SPEC_DIR) -> dict[str, dict[str, int]]:
    """`{spec name: {C_NAME: value}}` for every vendored spec. Needs PyYAML."""
    return {
        name: {k: v for consts in groups.values() for k, v in consts.items()}
        for name, groups in load_groups(spec_dir).items()
    }


def load_groups(spec_dir: Path = SPEC_DIR) -> dict[str, dict[str, dict[str, int]]]:
    """`{spec name: {group: {C_NAME: value}}}`, as `derive_groups` keys them."""
    import yaml  # noqa: PLC0415  (optional dependency, imported on use)

    return {
        path.stem: derive_groups(yaml.safe_load(path.read_text()))
        for path in sorted(spec_dir.glob("*.yaml"))
    }
