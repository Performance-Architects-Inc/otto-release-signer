"""sign.py signs only Otto's exact statement and checks its own signature. Run: python -m unittest discover tests"""
import contextlib
import io
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import release_sig  # noqa: E402
import sign  # noqa: E402

COMMIT = "8353160d59a46fd8571ce59ad41c5e947c1b2472"


@unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen is needed")
class Sign(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.key = self.d / "k"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", str(self.key)], check=True)
        pub = (self.d / "k.pub").read_text().split()
        self.signers = self.d / "allowed_signers"
        self.signers.write_text(f"{pub[0]} {pub[1]} test\n")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def run_sign(self, version="0.149.1", commit=COMMIT, date="2026-11-21", signers=None):
        out = self.d / "release.sig"
        with contextlib.redirect_stdout(io.StringIO()):
            sign.main(["--version", version, "--commit", commit, "--date", date, "--key", str(self.key),
                       "--signers", str(signers or self.signers), "--out", str(out)])
        return out.read_text()

    def test_runs_the_way_sign_yml_runs_it(self):
        """sign.yml runs `python -I sign.py`: isolated mode, script folder not on sys.path (run 44968889349 failed so)."""
        out = self.d / "release.sig"
        p = subprocess.run([sys.executable, "-I", str(ROOT / "sign.py"), "--version", "0.149.1", "--commit", COMMIT,
                            "--date", "2026-11-21", "--key", str(self.key), "--signers", str(self.signers),
                            "--out", str(out)], cwd=self.d, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("BEGIN SSH SIGNATURE", out.read_text())

    def test_signs_exactly_the_statement_otto_verifies(self):
        sig = self.run_sign()
        text = release_sig.statement("0.149.1", COMMIT, "2026-11-21")
        res = release_sig.check(text, sig, self.signers.read_text().splitlines(), tag="v0.149.1", commit=COMMIT)
        self.assertTrue(res["ok"], res)
        self.assertFalse(release_sig.check(text, sig, self.signers.read_text().splitlines(), tag="v0.149.0")["ok"])

    def test_refuses_anything_but_the_three_checked_fields(self):
        for bad in ({"version": "v0.149.1"}, {"version": "0.149"}, {"commit": COMMIT[:12]}, {"commit": COMMIT + "\nx: y"},
                    {"date": "21/11/2026"}, {"version": "0.149.1\nchannel: internal"}):
            with self.subTest(bad=bad), self.assertRaises(SystemExit):
                self.run_sign(**bad)

    def test_a_key_not_in_allowed_signers_writes_nothing(self):
        other = self.d / "other"
        other.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl other\n")
        with self.assertRaises(SystemExit):
            self.run_sign(signers=other)
        self.assertFalse((self.d / "release.sig").exists())


if __name__ == "__main__":
    unittest.main()
