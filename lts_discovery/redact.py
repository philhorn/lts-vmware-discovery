"""Build the redacted summary that --submit may upload.

Names and ids become salted HMACs so references still join up; addresses,
serials and other identifiers are dropped. The salt stays in the full local
report, so LTS can map the summary back once the customer sends that report.
"""

import copy
import hashlib
import hmac
import secrets

# Replaced by a salted hash wherever they appear.
HASH_KEYS = {"id", "name", "cluster_id", "host_id", "datastore_id", "entity_id", "network", "portgroup"}
HASH_LIST_KEYS = {"host_ids"}

# Removed wherever they appear.
DROP_KEYS = {
    "source_detail", "redaction_salt", "warnings",  # warnings are free text and may name things
    "serial", "uuid", "mac", "ip", "netmask", "ip_addresses", "hostname",
    "identifier", "devices", "nfs_server", "nfs_path",
}

# Removed only inside these parents, where they identify hardware (elsewhere "device" is e.g. vmnic0).
DROP_KEYS_UNDER = {"device": {"local_disks", "cache", "capacity"}}

# Kept as-is inside these parents (the product name is "VMware vCenter Server", not a customer fact).
KEEP_KEYS_UNDER = {"name": {"product"}}


def new_salt():
    return secrets.token_hex(16)


def hash_value(value, salt):
    digest = hmac.new(bytes.fromhex(salt), str(value).encode(), hashlib.sha256).hexdigest()
    return "h:" + digest[:16]


def _walk(node, salt, parent):
    if isinstance(node, list):
        return [_walk(v, salt, parent) for v in node]
    if not isinstance(node, dict):
        return node
    out = {}
    for key, value in node.items():
        if key in DROP_KEYS or parent in DROP_KEYS_UNDER.get(key, ()):
            continue
        if parent in KEEP_KEYS_UNDER.get(key, ()):
            out[key] = value
        elif key in HASH_KEYS and isinstance(value, str):
            out[key] = hash_value(value, salt)
        elif key in HASH_LIST_KEYS:
            out[key] = [hash_value(v, salt) for v in value]
        else:
            out[key] = _walk(value, salt, key)
    return out


def redact(report, salt=None):
    """Return a redacted copy of report. Uses the report's own salt unless one is given."""
    salt = salt or report.get("collection", {}).get("redaction_salt")
    if not salt:
        raise ValueError("report has no collection.redaction_salt; pass salt= explicitly")
    summary = _walk(copy.deepcopy(report), salt, None)
    summary["collection"]["redacted"] = True
    return summary
