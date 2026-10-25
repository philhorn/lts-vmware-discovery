import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from lts_discovery.cli import main

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


if __name__ == "__main__":
    unittest.main()
