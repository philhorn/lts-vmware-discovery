"""End-to-end collection against govmomi's vcsim simulator.

Runs only when LTS_VCSIM points at a vcsim binary (CI downloads one):

    LTS_VCSIM=/path/to/vcsim python3 -m unittest tests.test_vcsim -v
"""

import contextlib
import io
import json
import os
import re
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

VCSIM = os.environ.get("LTS_VCSIM")

try:
    import pyVmomi  # noqa: F401
except ImportError:
    pyVmomi = None

from lts_discovery.cli import main
from lts_discovery.validate import validate


def start_vcsim(*flags):
    proc = subprocess.Popen([VCSIM, "-l", "127.0.0.1:0", "-username", "user", "-password", "pass", *flags], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    deadline = time.time() + 30
    while time.time() < deadline:
        line = proc.stdout.readline()
        m = re.search(r"GOVC_URL=https://[^@]+@127\.0\.0\.1:(\d+)/sdk", line)
        if m:
            return proc, int(m.group(1))
    proc.kill()
    raise RuntimeError("vcsim did not start")


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue() + err.getvalue()


@unittest.skipUnless(VCSIM and pyVmomi, "set LTS_VCSIM to a vcsim binary and install pyVmomi")
class Vcsim(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["LTS_DISCOVER_PASSWORD"] = "pass"
        cls.sims = [start_vcsim("-esx"), start_vcsim("-esx"), start_vcsim()]
        cls.esx1, cls.esx2, cls.vc = (f"127.0.0.1:{port}" for _, port in cls.sims)

    @classmethod
    def tearDownClass(cls):
        for proc, _ in cls.sims:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def collect(self, *args):
        d = tempfile.mkdtemp()
        code, out = run("collect", "--user", "user", "-o", d, *args)
        report = json.loads((Path(d) / "report.json").read_text()) if (Path(d) / "report.json").exists() else None
        summary = (Path(d) / "summary.json").read_text() if (Path(d) / "summary.json").exists() else None
        return code, out, report, summary

    def test_esxi_host(self):
        code, out, report, summary = self.collect("--esxi", self.esx1, "--allow-extra-privileges")
        self.assertEqual(code, 0, out)
        self.assertEqual(validate(report), [])
        self.assertEqual(report["collection"]["source"], "esxi")
        self.assertEqual(report["collection"]["product"]["name"], "VMware ESXi")
        self.assertEqual(len(report["hosts"]), 1)
        self.assertGreater(len(report["vms"]), 0)
        self.assertNotIn("127.0.0.1", summary)

    def test_several_esxi_hosts_merge(self):
        code, out, report, _ = self.collect("--esxi", self.esx1, self.esx2, "--allow-extra-privileges")
        self.assertEqual(code, 0, out)
        self.assertEqual(validate(report), [])
        self.assertEqual(len(report["hosts"]), 2)
        self.assertEqual(len({h["id"] for h in report["hosts"]}), 2)

    def test_vcenter(self):
        code, out, report, _ = self.collect("--vcenter", self.vc, "--allow-extra-privileges")
        self.assertEqual(code, 0, out)
        self.assertEqual(validate(report), [])
        self.assertEqual(report["collection"]["source"], "vcenter")
        self.assertGreaterEqual(len(report["clusters"]), 1)
        self.assertTrue(any(h["cluster_id"] for h in report["hosts"]))

    def test_refuses_admin_account(self):
        # vcsim's user holds every privilege, like an administrator would
        code, out, report, _ = self.collect("--esxi", self.esx1)
        self.assertEqual(code, 1)
        self.assertIn("beyond read-only", out)
        self.assertIsNone(report)

    def test_bad_login(self):
        os.environ["LTS_DISCOVER_PASSWORD"] = "wrong"
        try:
            code, out, _, _ = self.collect("--esxi", self.esx1, "--allow-extra-privileges")
        finally:
            os.environ["LTS_DISCOVER_PASSWORD"] = "pass"
        self.assertEqual(code, 1)
        self.assertIn("login failed", out)

    def test_several_hosts_pinned_separately(self):
        from lts_discovery.vsphere import server_fingerprint
        pins = [f"{t}={server_fingerprint(*t.split(':')[:1], int(t.split(':')[1]))}" for t in (self.esx1, self.esx2)]
        code, out, report, _ = self.collect("--esxi", self.esx1, self.esx2, "--allow-extra-privileges",
                                            "--thumbprint", pins[0], "--thumbprint", pins[1])
        self.assertEqual(code, 0, out)
        self.assertEqual(len(report["hosts"]), 2)

    def test_wrong_target_kind(self):
        code, out, _, _ = self.collect("--vcenter", self.esx1, "--allow-extra-privileges")
        self.assertEqual(code, 1)
        self.assertIn("use --esxi", out)

    def test_thumbprint_pinning(self):
        from lts_discovery.vsphere import server_fingerprint
        host, port = self.esx1.split(":")
        good = server_fingerprint(host, int(port))
        code, out, _, _ = self.collect("--esxi", self.esx1, "--allow-extra-privileges", "--thumbprint", good)
        self.assertEqual(code, 0, out)
        bad = "00:" * 31 + "00"
        code, out, _, _ = self.collect("--esxi", self.esx1, "--allow-extra-privileges", "--thumbprint", bad)
        self.assertEqual(code, 1)
        self.assertIn("does not match", out)

    def test_pinned_session_rejects_another_certificate(self):
        import shutil
        import ssl
        from pyVim.connect import SmartConnect
        from lts_discovery.vsphere import pinned_context
        if not shutil.which("openssl"):
            self.skipTest("openssl not available")
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{d}/k.pem",
                            "-out", f"{d}/c.pem", "-days", "1", "-subj", "/CN=other"], check=True, capture_output=True)
            other = ssl.PEM_cert_to_DER_cert(Path(f"{d}/c.pem").read_text())
        host, port = self.esx1.split(":")
        with self.assertRaises(ssl.SSLCertVerificationError):
            SmartConnect(host=host, port=int(port), user="user", pwd="pass", sslContext=pinned_context(other))


if __name__ == "__main__":
    unittest.main()
