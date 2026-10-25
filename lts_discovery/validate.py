"""Validate a report against discovery.schema.json without third-party packages.

Supports the JSON Schema keywords the schema uses: type, const, enum, required,
properties, additionalProperties (false), items, minimum, minLength, oneOf,
format date-time and local $ref to #/$defs.
"""

import json
from datetime import datetime
from importlib import resources

SCHEMA_VERSION = 1

_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


def load_schema():
    return json.loads(resources.files("lts_discovery").joinpath("discovery.schema.json").read_text())


def _is_datetime(s):
    try:
        datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return False
    return "T" in s


def _check(value, schema, root, path, errors):
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            raise ValueError(f"unsupported $ref {ref}")
        return _check(value, root["$defs"][ref[len("#/$defs/"):]], root, path, errors)

    if "oneOf" in schema:
        matches = sum(1 for s in schema["oneOf"] if not _errors(value, s, root, path))
        if matches != 1:
            errors.append(f"{path}: matches {matches} of oneOf, expected 1")
        return

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected {schema['const']!r}, got {value!r}")
        return
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} not one of {schema['enum']}")
        return

    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_TYPES[t](value) for t in types):
            errors.append(f"{path}: expected {'/'.join(types)}, got {type(value).__name__}")
            return

    if isinstance(value, (int, float)) and not isinstance(value, bool) and "minimum" in schema and value < schema["minimum"]:
        errors.append(f"{path}: {value} below minimum {schema['minimum']}")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{path}: shorter than {schema['minLength']}")
        if schema.get("format") == "date-time" and not _is_datetime(value):
            errors.append(f"{path}: {value!r} is not an ISO 8601 date-time")

    if isinstance(value, dict):
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing {key}")
        for key, v in value.items():
            if key in props:
                _check(v, props[key], root, f"{path}.{key}", errors)
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}: unexpected property {key}")

    if isinstance(value, list) and "items" in schema:
        for i, v in enumerate(value):
            _check(v, schema["items"], root, f"{path}[{i}]", errors)


def _errors(value, schema, root, path):
    errors = []
    _check(value, schema, root, path, errors)
    return errors


def check_refs(report):
    """Cross-references the schema can't express: every *_id points at a real object."""
    errors = []
    clusters = {c["id"] for c in report.get("clusters", [])}
    hosts = {h["id"] for h in report.get("hosts", [])}
    datastores = {d["id"] for d in report.get("datastores", [])}
    vms = {v["id"] for v in report.get("vms", [])}

    def want(kind, known, ref, where):
        if ref is not None and ref not in known:
            errors.append(f"{where}: unknown {kind} {ref!r}")

    for i, c in enumerate(report.get("clusters", [])):
        for ref in c.get("host_ids", []):
            want("host", hosts, ref, f"$.clusters[{i}].host_ids")
    for i, h in enumerate(report.get("hosts", [])):
        want("cluster", clusters, h.get("cluster_id"), f"$.hosts[{i}].cluster_id")
    for i, d in enumerate(report.get("datastores", [])):
        for ref in d.get("host_ids", []):
            want("host", hosts, ref, f"$.datastores[{i}].host_ids")
    for i, v in enumerate(report.get("vms", [])):
        want("host", hosts, v.get("host_id"), f"$.vms[{i}].host_id")
        want("cluster", clusters, v.get("cluster_id"), f"$.vms[{i}].cluster_id")
        for j, d in enumerate(v.get("disks", [])):
            want("datastore", datastores, d.get("datastore_id"), f"$.vms[{i}].disks[{j}].datastore_id")
    for i, p in enumerate(report.get("performance", [])):
        want(p["entity"], hosts if p["entity"] == "host" else vms, p["entity_id"], f"$.performance[{i}].entity_id")
    for kind, items in (("cluster", report.get("clusters", [])), ("host", report.get("hosts", [])),
                        ("datastore", report.get("datastores", [])), ("vm", report.get("vms", []))):
        ids = [x["id"] for x in items]
        for dup in sorted({x for x in ids if ids.count(x) > 1}):
            errors.append(f"$: duplicate {kind} id {dup!r}")
    return errors


def validate(report, schema=None):
    """Return a list of error strings; empty means the report is valid."""
    schema = schema or load_schema()
    errors = _errors(report, schema, schema, "$")
    if not errors:
        errors = check_refs(report)
    return errors
