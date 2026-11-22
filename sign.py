"""Sign one Otto release statement (Otto roadmap item 45), run by .github/workflows/sign.yml after the release approver
approves the job in the GitHub app.

It builds the statement itself from the version, commit and date (release_sig.statement, the exact text Otto and every
client account verify), so nothing but those three checked fields can be signed. It signs with ssh-keygen, checks the
signature against this repo's allowed_signers, and writes the armored signature (public data) to --out.

release_sig.py is a copy of Otto's scripts/release_sig.py (the same check client accounts run); tests/test_sign.py
fails when the two differ in what they sign or accept.
"""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import release_sig

HERE = Path(__file__).resolve().parent


def trusted_lines(path):
    lines = [ln.strip() for ln in Path(path).read_text(encoding="utf-8").splitlines()]
    keys = [ln for ln in lines if ln and not ln.startswith("#")]
    if not keys:
        raise SystemExit(f"{path} holds no key")
    return keys


def sign(text, key, ssh_keygen=None):
    exe = ssh_keygen or shutil.which("ssh-keygen")
    if not exe:
        raise SystemExit("ssh-keygen not found")
    d = tempfile.mkdtemp(prefix="otto-sign-")
    try:
        f = Path(d) / "statement"
        f.write_bytes(text.encode("utf-8"))
        p = subprocess.run([exe, "-Y", "sign", "-f", str(key), "-n", release_sig.NAMESPACE, str(f)],
                           capture_output=True, text=True)
        sig = Path(str(f) + ".sig")
        if p.returncode != 0 or not sig.exists():
            raise SystemExit("ssh-keygen did not sign: " + (p.stderr or "")[:300])
        return sig.read_text(encoding="ascii")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--version", required=True, help="the release, major.minor.patch (no v)")
    p.add_argument("--commit", required=True, help="the full 40-character commit the release tag points to")
    p.add_argument("--date", required=True, help="the statement's date, YYYY-MM-DD")
    p.add_argument("--key", required=True, help="the private key file")
    p.add_argument("--signers", default=str(HERE / "allowed_signers"))
    p.add_argument("--out", default="release.sig")
    p.add_argument("--ssh-keygen")
    a = p.parse_args(argv)
    try:
        text = release_sig.statement(a.version.strip(), a.commit.strip().lower(), a.date.strip())
    except release_sig.Refused as exc:
        raise SystemExit(f"not signed: {exc}")
    sig = sign(text, a.key, a.ssh_keygen)
    res = release_sig.check(text, sig, trusted_lines(a.signers), tag="v" + a.version.strip(),
                            commit=a.commit.strip().lower())
    if not res["ok"]:
        raise SystemExit("the signature does not verify against allowed_signers, nothing written: " + res["reason"])
    Path(a.out).write_text(sig, encoding="ascii", newline="\n")
    print(json.dumps({"ok": True, "version": res["version"], "tag": res["tag"], "commit": res["commit"],
                      "date": res["date"], "key": res["key"], "statement": text, "signature": sig}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
