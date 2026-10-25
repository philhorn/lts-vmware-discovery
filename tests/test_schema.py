"""Schema and cross-reference checks.

    python3 -m unittest discover -s tests -v
"""

import copy
import json
import unittest
from pathlib import Path

from lts_discovery.validate import load_schema, validate

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


class FixturesValid(unittest.TestCase):
    def test_every_fixture_is_valid(self):
        paths = sorted(FIXTURES.glob("*.json"))
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(path.name):
                self.assertEqual(validate(json.loads(path.read_text())), [])

    def test_schema_is_draft_2020_12(self):
        self.assertEqual(load_schema()["$schema"], "https://json-schema.org/draft/2020-12/schema")


class SchemaRejects(unittest.TestCase):
    def setUp(self):
        self.report = fixture("vcenter-vsan-site.json")

    def assertInvalid(self, report, fragment):
        errors = validate(report)
        self.assertTrue(any(fragment in e for e in errors), errors)

    def test_wrong_schema_version(self):
        self.report["schema_version"] = 2
        self.assertInvalid(self.report, "$.schema_version")

    def test_missing_required(self):
        del self.report["hosts"][0]["cpu"]
        self.assertInvalid(self.report, "$.hosts[0]: missing cpu")

    def test_unknown_property(self):
        self.report["vms"][0]["root_password"] = "x"
        self.assertInvalid(self.report, "unexpected property root_password")

    def test_bad_enum(self):
        self.report["datastores"][0]["type"] = "ntfs"
        self.assertInvalid(self.report, "$.datastores[0].type")

    def test_bool_is_not_integer(self):
        self.report["vms"][0]["cpu"]["vcpus"] = True
        self.assertInvalid(self.report, "$.vms[0].cpu.vcpus")

    def test_negative_size(self):
        self.report["vms"][0]["disks"][0]["size_gb"] = -1
        self.assertInvalid(self.report, "below minimum")

    def test_bad_timestamp(self):
        self.report["collection"]["collected_at"] = "yesterday"
        self.assertInvalid(self.report, "date-time")

    def test_null_cluster_allowed_but_not_empty_string(self):
        self.report["hosts"][2]["cluster_id"] = ""
        self.assertInvalid(self.report, "$.hosts[2].cluster_id")


class CrossReferences(unittest.TestCase):
    def setUp(self):
        self.report = fixture("vcenter-vsan-site.json")

    def test_dangling_host(self):
        self.report["vms"][0]["host_id"] = "host-99"
        self.assertIn("$.vms[0].host_id: unknown host 'host-99'", validate(self.report))

    def test_dangling_datastore(self):
        self.report["vms"][0]["disks"][0]["datastore_id"] = "datastore-gone"
        self.assertIn("$.vms[0].disks[0].datastore_id: unknown datastore 'datastore-gone'", validate(self.report))

    def test_perf_entity_kind_checked(self):
        self.report["performance"][0]["entity_id"] = "vm-101"
        self.assertIn("$.performance[0].entity_id: unknown host 'vm-101'", validate(self.report))

    def test_duplicate_ids(self):
        self.report["vms"].append(copy.deepcopy(self.report["vms"][0]))
        self.assertIn("$: duplicate vm id 'vm-101'", validate(self.report))


if __name__ == "__main__":
    unittest.main()
