import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from lts_discovery.cli import _pins, _split_port, main

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class Cli(unittest.TestCase):
    def test_validate_fixtures(self):
        code, out, _ = run("validate", *map(str, sorted(FIXTURES.glob("*.json"))))
        self.assertEqual(code, 0)
        self.assertIn("ok", out)

    def test_validate_reports_errors(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.json"
            bad.write_text(json.dumps({"schema_version": 1}))
            code, out, err = run("validate", str(bad))
        self.assertEqual(code, 1)
        self.assertIn("missing collection", err)

    def test_redact_writes_summary(self):
        with tempfile.TemporaryDirectory() as d:
            out_path = Path(d) / "summary.json"
            code, _, _ = run("redact", str(FIXTURES / "esxi-standalone.json"), "-o", str(out_path))
            summary = json.loads(out_path.read_text())
        self.assertEqual(code, 0)
        self.assertTrue(summary["collection"]["redacted"])

    def test_split_port(self):
        self.assertEqual(_split_port("esx01.example.test", 443), ("esx01.example.test", 443))
        self.assertEqual(_split_port("192.0.2.10:8443", 443), ("192.0.2.10", 8443))
        self.assertEqual(_split_port("[2001:db8::1]:8443", 443), ("2001:db8::1", 8443))
        self.assertEqual(_split_port("[2001:db8::1]", 443), ("2001:db8::1", 443))

    def test_thumbprint_pins(self):
        self.assertEqual(_pins(["AA:BB"], ["esx01"]), {"esx01": "AA:BB"})
        self.assertEqual(_pins(["esx01=AA", "esx02=BB"], ["esx01", "esx02"]), {"esx01": "AA", "esx02": "BB"})
        with self.assertRaises(ValueError):
            _pins(["AA:BB"], ["esx01", "esx02"])
        with self.assertRaises(ValueError):
            _pins(["esx09=AA"], ["esx01"])

    def test_collect_needs_a_target(self):
        with self.assertRaises(SystemExit):
            run("collect", "--user", "u")


if __name__ == "__main__":
    unittest.main()
