"""Signed client releases (roadmap item 45): the statement the user signs and the check that runs before Otto deploys.

For each release offered to clients the user signs a short statement with a key held in a security device that asks
for his biometric on every signature:

    otto-release-statement: 1
    version: 0.99.0
    tag: v0.99.0
    commit: <the 40-hex commit the tag points to>
    channel: clients
    date: 2026-11-20

The signature is an SSH signature (`ssh-keygen -Y sign -n otto-release`, the SSHSIG format), so the key can live in a
FIDO2 security key (`sk-ssh-ed25519@openssh.com`, a USB fingerprint key) or in Windows Hello through Windows'
OpenSSH (`sk-ecdsa-sha2-nistp256@openssh.com`). A plain `ssh-ed25519` key is accepted too: it is the software test
key the lab proves the flow with.

The check is pure Python on `cryptography` and nothing else, because this file is also, word for word, the body of
OTTO_GOVERNANCE.CORE.VERIFY_RELEASE in snowsight/backend/sync_task.sql (a test keeps the two identical): the same
code checks a release on a laptop (`/otto:upgrade`, scripts/release_sign.py) and inside a client's Snowflake account
(`SYNC`). It never names, reads or writes anything: it takes the statement, the signature, the trusted public keys
(the account's RELEASE_SIGNERS, the repo's .otto/release_signers) and the tag and commit about to be deployed, and
answers ok or why not.

A security-key signature carries the device's flags. Otto requires user presence and user verification (the
fingerprint, the face or the PIN) on every security-key signature, so a signature made without the biometric is
refused even with the right key. Make the key with `-O verify-required` (docs: skills/otto-version/SKILL.md).
"""

import base64
import hashlib
import re
import struct

NAMESPACE = "otto-release"
HEADER = "otto-release-statement: 1"
FIELDS = ("version", "tag", "commit", "channel", "date")
CHANNELS = ("clients",)
MAGIC = b"SSHSIG"
ED25519 = "ssh-ed25519"
SK_ED25519 = "sk-ssh-ed25519@openssh.com"
SK_ECDSA = "sk-ecdsa-sha2-nistp256@openssh.com"
KEY_TYPES = (ED25519, SK_ED25519, SK_ECDSA)
FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


class Refused(Exception):
    """Why a release is not deployed."""


# ---------- the statement ----------

def statement(version, commit, date, channel="clients"):
    """The exact text the user signs: LF line ends, one trailing newline."""
    fields = {"version": version, "tag": "v" + version, "commit": commit, "channel": channel, "date": date}
    check_fields(fields)
    return HEADER + "\n" + "".join(k + ": " + fields[k] + "\n" for k in FIELDS)


def parse_statement(text):
    """{field: value} of a statement; Refused unless it is exactly the form statement() writes."""
    if not isinstance(text, str) or "\r" in text or not text.endswith("\n"):
        raise Refused("the statement is not LF text ending in a newline")
    lines = text[:-1].split("\n")
    if not lines or lines[0] != HEADER:
        raise Refused("the statement does not start with '" + HEADER + "'")
    fields = {}
    for line in lines[1:]:
        k, sep, v = line.partition(": ")
        if not sep or k not in FIELDS or k in fields:
            raise Refused("unexpected statement line: " + line[:80])
        fields[k] = v
    if tuple(k for k in fields) != FIELDS:
        raise Refused("the statement must have " + ", ".join(FIELDS) + " in that order")
    check_fields(fields)
    return fields


def check_fields(f):
    if not VERSION_RE.match(f.get("version") or ""):
        raise Refused("version is not major.minor.patch")
    if f.get("tag") != "v" + f["version"]:
        raise Refused("tag is not v<version>")
    if not COMMIT_RE.match(f.get("commit") or ""):
        raise Refused("commit is not a full 40-character lower-case hash")
    if f.get("channel") not in CHANNELS:
        raise Refused("channel is not one of " + ", ".join(CHANNELS))
    if not DATE_RE.match(f.get("date") or ""):
        raise Refused("date is not YYYY-MM-DD")


# ---------- SSH wire format ----------

class _Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise Refused("the signature is truncated")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def uint32(self):
        return struct.unpack(">I", self.take(4))[0]

    def byte(self):
        return self.take(1)[0]

    def string(self):
        return self.take(self.uint32())

    def text(self):
        try:
            return self.string().decode("ascii")
        except UnicodeDecodeError:
            raise Refused("a name in the signature is not ASCII")

    def done(self):
        if self.pos != len(self.data):
            raise Refused("the signature has trailing bytes")


def _string(b):
    return struct.pack(">I", len(b)) + b


def unarmor(sig):
    """The SSHSIG blob from the armored text ssh-keygen -Y sign writes."""
    if not isinstance(sig, str):
        raise Refused("no signature")
    lines = [ln.strip() for ln in sig.strip().replace("\r", "").split("\n")]
    if len(lines) < 3 or lines[0] != "-----BEGIN SSH SIGNATURE-----" or lines[-1] != "-----END SSH SIGNATURE-----":
        raise Refused("the signature is not an armored SSH signature")
    try:
        return base64.b64decode("".join(lines[1:-1]), validate=True)
    except ValueError:
        raise Refused("the signature is not valid base64")


def key_blob(line):
    """(key type, public key blob) of an allowed-signer or .pub line: '[principal] <type> <base64> [comment]'."""
    parts = (line or "").split()
    for i, p in enumerate(parts[:2]):
        if p in KEY_TYPES and i + 1 < len(parts):
            try:
                blob = base64.b64decode(parts[i + 1], validate=True)
            except ValueError:
                raise Refused("a trusted key is not valid base64")
            if _Reader(blob).text() != p:
                raise Refused("a trusted key's type does not match its data")
            return p, blob
    raise Refused("not a supported public key line (" + ", ".join(KEY_TYPES) + ")")


def fingerprint(blob):
    """SHA256:... as ssh-keygen -l prints it."""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def parse_sshsig(blob):
    r = _Reader(blob)
    if r.take(6) != MAGIC:
        raise Refused("not an SSHSIG signature")
    if r.uint32() != 1:
        raise Refused("unsupported SSHSIG version")
    out = {"publickey": r.string(), "namespace": r.text(), "reserved": r.string(), "hash": r.text(),
           "signature": r.string()}
    r.done()
    return out


def _verify_raw(pub, sig, signed, require_uv):
    """Check one SSH signature over signed with the public key blob pub; Refused when it does not hold."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    k = _Reader(pub)
    ktype = k.text()
    s = _Reader(sig)
    stype = s.text()
    if stype != ktype:
        raise Refused("the signature type does not match the key")
    raw = s.string()
    if ktype == ED25519:
        point = k.string()
        k.done()
        s.done()
        data = signed
    elif ktype in (SK_ED25519, SK_ECDSA):
        if ktype == SK_ECDSA:
            if k.text() != "nistp256":
                raise Refused("the security key is not on curve P-256")
        point = k.string()
        app = k.string()
        k.done()
        flags = s.byte()
        counter = s.uint32()
        s.done()
        if not flags & FLAG_USER_PRESENT:
            raise Refused("the security key did not see the user's touch (user-presence flag off)")
        if require_uv and not flags & FLAG_USER_VERIFIED:
            raise Refused("the security key did not verify the user (no fingerprint, face or PIN): "
                          "the key must be made with -O verify-required")
        data = (hashlib.sha256(app).digest() + bytes([flags]) + struct.pack(">I", counter)
                + hashlib.sha256(signed).digest())
    else:
        raise Refused("unsupported key type " + ktype)
    try:
        if ktype in (ED25519, SK_ED25519):
            if len(point) != 32 or len(raw) != 64:
                raise Refused("malformed Ed25519 key or signature")
            Ed25519PublicKey.from_public_bytes(point).verify(raw, data)
        else:
            rs = _Reader(raw)
            r_int = int.from_bytes(rs.string(), "big")
            s_int = int.from_bytes(rs.string(), "big")
            rs.done()
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
            key.verify(encode_dss_signature(r_int, s_int), data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise Refused("the signature does not match the statement")
    except ValueError as exc:
        raise Refused("malformed key or signature: " + str(exc)[:120])


def verify_signature(message, armored, trusted, namespace=NAMESPACE, require_uv=True):
    """The fingerprint of the trusted key that signed message (bytes); Refused otherwise."""
    sig = parse_sshsig(unarmor(armored))
    if sig["namespace"] != namespace:
        raise Refused("the signature is for '" + sig["namespace"] + "', not " + namespace)
    if sig["hash"] not in ("sha512", "sha256"):
        raise Refused("unsupported hash " + sig["hash"])
    blobs = []
    for line in trusted or []:
        line = (line or "").strip()
        if line and not line.startswith("#"):
            blobs.append(key_blob(line)[1])
    if not blobs:
        raise Refused("no trusted release key is installed here")
    if sig["publickey"] not in blobs:
        raise Refused("signed by a key that is not trusted here (" + fingerprint(sig["publickey"]) + ")")
    h = hashlib.sha512(message).digest() if sig["hash"] == "sha512" else hashlib.sha256(message).digest()
    signed = MAGIC + _string(namespace.encode()) + _string(sig["reserved"]) + _string(sig["hash"].encode()) + _string(h)
    _verify_raw(sig["publickey"], sig["signature"], signed, require_uv)
    return fingerprint(sig["publickey"])


def check(statement_text, armored, trusted, tag=None, commit=None, require_uv=True):
    """The whole check before a deploy: a dict with ok True and the statement's fields, or ok False and the reason.

    tag and commit are what is about to be deployed (the release tag and the commit it points to); both must be the
    ones the user signed."""
    try:
        if isinstance(trusted, str):
            trusted = trusted.splitlines()
        fields = parse_statement(statement_text)
        key = verify_signature(statement_text.encode("utf-8"), armored, trusted, require_uv=require_uv)
        if tag is not None and tag != fields["tag"]:
            raise Refused("the signed statement is for " + fields["tag"] + ", not " + str(tag))
        if commit is not None and (commit or "").lower() != fields["commit"]:
            raise Refused("the tag points to " + str(commit)[:12] + ", not the signed commit " + fields["commit"][:12])
        out = {"ok": True, "key": key}
        out.update(fields)
        return out
    except Refused as exc:
        return {"ok": False, "reason": str(exc)}


def channel_entry(doc, version=None):
    """The signed entry for version in a client release channel record (roadmap item 44: channel.json, the offer and
    its history, each with its own statement and signature), or None. Without a version: the offer, once signed. A
    single signed entry ({statement, signature}) stands for itself. A withdrawn version has no entry."""
    if not isinstance(doc, dict):
        return None
    if "statement" in doc:
        entries = [doc]
    else:
        offered = doc.get("offered") if isinstance(doc.get("offered"), dict) else None
        if version is None:
            version = (offered or {}).get("version")
        entries = ([offered] if offered else []) + [e for e in doc.get("history") or [] if isinstance(e, dict)]
        withdrawn = {w.get("version") for w in doc.get("withdrawn") or [] if isinstance(w, dict)}
        if version in withdrawn:
            return None
    for e in entries:
        if e.get("signature") and (version is None or e.get("version") == version):
            return e
    return None


def main(statement_text, signature, signers, tag, commit):
    """The handler of OTTO_GOVERNANCE.CORE.VERIFY_RELEASE (Python UDF): SIGNERS is the account's trusted key lines."""
    return check(statement_text, signature, [str(s) for s in (signers or [])], tag=tag, commit=commit)
