"""Redacted summary: nothing identifying survives, references still join."""

import json
import unittest
from pathlib import Path

from lts_discovery.redact import DROP_KEYS, HASH_KEYS, HASH_LIST_KEYS, hash_value, new_salt, redact
from lts_discovery.validate import validate

FIXTURES = Path(__file__).resolve().parent / "fixtures"
REPORTS = sorted(FIXTURES.glob("*.json"))


def identifying_strings(node, parent=None, found=None):
    """Every string a summary must not contain, read from the full report."""
    found = set() if found is None else found
    if isinstance(node, list):
        for v in node:
            identifying_strings(v, parent, found)
    elif isinstance(node, dict):
        for k, v in node.items():
            sensitive = k in DROP_KEYS | HASH_KEYS | HASH_LIST_KEYS or (k == "device" and parent in {"local_disks", "cache", "capacity"})
            if sensitive and parent != "product":
                for s in (v if isinstance(v, list) else [v]):
                    if isinstance(s, str) and len(s) > 3:
                        found.add(s)
            else:
                identifying_strings(v, k, found)
    return found


class Redaction(unittest.TestCase):
    def test_summary_is_valid_and_marked(self):
        for path in REPORTS:
            with self.subTest(path.name):
                summary = redact(json.loads(path.read_text()))
                self.assertEqual(validate(summary), [])
                self.assertTrue(summary["collection"]["redacted"])
                self.assertNotIn("redaction_salt", summary["collection"])

    def test_no_identifying_string_survives(self):
        for path in REPORTS:
            report = json.loads(path.read_text())
            text = json.dumps(redact(report))
            secrets = identifying_strings(report)
            self.assertTrue(secrets)
            for s in secrets:
                with self.subTest(path.name, value=s):
                    self.assertNotIn(s, text)

    def test_no_addresses_survive(self):
        for path in REPORTS:
            text = json.dumps(redact(json.loads(path.read_text())))
            for marker in ("192.0.2.", "198.51.100.", "example.test", "iqn.", "naa.", "eui.", "00:50:56", "20:00:00"):
                with self.subTest(path.name, marker=marker):
                    self.assertNotIn(marker, text)

    def test_sizing_facts_survive(self):
        report = json.loads((FIXTURES / "vcenter-vsan-site.json").read_text())
        summary = redact(report)
        self.assertEqual(summary["hosts"][0]["cpu"], report["hosts"][0]["cpu"])
        self.assertEqual(summary["hosts"][0]["hardware"]["model"], "Rack Server 2U")
        self.assertEqual(len(summary["hosts"][0]["vsan"]["disk_groups"][0]["capacity"]), 4)
        self.assertEqual(summary["collection"]["product"]["name"], "VMware vCenter Server")
        self.assertEqual(summary["datastores"][1]["backing"]["array_model"], "ARRAY-1")
        self.assertEqual(summary["vms"][2]["snapshots"][0]["size_gb"], 41.5)

    def test_hashes_are_salted_and_stable(self):
        a, b = new_salt(), new_salt()
        self.assertNotEqual(a, b)
        self.assertEqual(hash_value("SQL01", a), hash_value("SQL01", a))
        self.assertNotEqual(hash_value("SQL01", a), hash_value("SQL01", b))
        self.assertRegex(hash_value("SQL01", a), r"^h:[0-9a-f]{16}$")

    def test_salt_is_required(self):
        report = json.loads((FIXTURES / "vcenter-vsan-site.json").read_text())
        del report["collection"]["redaction_salt"]
        with self.assertRaises(ValueError):
            redact(report)

    def test_input_not_modified(self):
        path = FIXTURES / "vcenter-vsan-site.json"
        report = json.loads(path.read_text())
        redact(report)
        self.assertEqual(report, json.loads(path.read_text()))


if __name__ == "__main__":
    unittest.main()
