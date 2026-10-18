#!/usr/bin/env python3
"""Independent FOSS-478 reference-vector oracle.

Uses Python hashlib/struct and Python cryptography Ed25519 implementation,
NOT Rust ed25519-dalek or Rust canonical-encoding routines.
This verifies a PUBLIC TEST FIXTURE, not production trust-anchor provenance.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from cryptography import __version__ as cryptography_version
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REQ_DOMAIN = b"openscion.promotion.request.v1\x00"
AUTH_DOMAIN = b"openscion.promotion.authorization.v1\x00"


def u32(n):
    return struct.pack(">I", n)


def u64(n):
    return struct.pack(">Q", n)


def field(s):
    raw = s.encode("ascii")
    return u32(len(raw)) + raw


def optional_revision(value):
    return b"\x00" if value is None else b"\x01" + field(value)


def digest(value):
    return hashlib.sha256(value).digest()


def frame(domain, body):
    return domain + u64(len(body)) + body


class Reader:
    def __init__(self, payload):
        self.raw = payload
        self.offset = 0

    def take(self, n):
        end = self.offset + n
        if n < 0 or end > len(self.raw):
            raise AssertionError("truncated canonical authorization")
        part = self.raw[self.offset:end]
        self.offset = end
        return part

    def integer(self, n):
        return int.from_bytes(self.take(n), "big")

    def string(self):
        length = self.integer(4)
        assert 1 <= length <= 128, "unbounded field"
        return self.take(length).decode("ascii")

    def opt_revision(self):
        tag = self.integer(1)
        if tag == 0:
            return None
        assert tag == 1, "invalid optional field discriminator"
        return self.string()

    def complete(self):
        assert self.offset == len(self.raw), "unknown trailing canonical fields"


def run(vector):
    assert vector["format"] == "openscion.foss478.public-test-vector.v1"
    cases = []

    def passed(label):
        cases.append(label)
        print(json.dumps({"case": label, "result": "PASS"}, sort_keys=True))

    evidence = bytes.fromhex(vector["evidence_bundle_hex"])
    policy_digest = bytes.fromhex(vector["policy_digest_hex"])
    evidence_digest = bytes.fromhex(vector["evidence_digest_hex"])
    assert digest(evidence) == evidence_digest
    passed("independent_evidence_sha256")

    payload = (
        field(vector["subject"])
        + field(vector["channel"])
        + optional_revision(vector["expected_head"])
        + field(vector["candidate"])
        + field(vector["policy_id"])
        + policy_digest
        + u64(vector["policy_epoch"])
        + evidence_digest
        + field(vector["idempotency_key"])
    )
    fingerprint = digest(frame(REQ_DOMAIN, payload))
    assert fingerprint.hex() == vector["request_fingerprint_hex"]
    passed("independent_request_fingerprint")

    wire = bytes.fromhex(vector["signed_statement_hex"])
    assert wire.startswith(AUTH_DOMAIN)
    size_offset = len(AUTH_DOMAIN)
    body_size = int.from_bytes(wire[size_offset:size_offset+8], "big")
    assert body_size == len(wire) - size_offset - 8
    reader = Reader(wire[size_offset+8:])
    assert reader.string() == vector["audience"]
    assert reader.string() == vector["issuer_key_id"]
    assert reader.integer(8) == 2
    assert reader.integer(1) == 1
    assert reader.take(32) == fingerprint
    assert reader.string() == vector["channel"]
    assert reader.opt_revision() == vector["expected_head"]
    assert reader.string() == vector["candidate"]
    assert reader.string() == vector["policy_id"]
    assert reader.take(32) == policy_digest
    assert reader.integer(8) == vector["policy_epoch"]
    assert reader.take(32) == evidence_digest
    assert reader.integer(8) == 7
    assert reader.integer(8) == 11
    assert reader.integer(1) == 2
    assert reader.integer(1) == 1
    assert reader.take(32) == bytes([9]) * 32
    assert reader.integer(8) == 1799999970
    assert reader.integer(8) == 1800000300
    reader.complete()
    passed("independent_canonical_wire_decoder")

    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(vector["public_key_hex"]))
    signature = bytes.fromhex(vector["signature_hex"])
    public_key.verify(signature, wire)
    passed("independent_ed25519_signature")

    try:
        public_key.verify(signature, wire + b"\x00")
    except InvalidSignature:
        passed("mutated_wire_signature_rejected")
    else:
        raise AssertionError("modified signed bytes verified unexpectedly")

    changed = bytearray(signature)
    changed[0] ^= 1
    try:
        public_key.verify(bytes(changed), wire)
    except InvalidSignature:
        passed("forged_signature_rejected")
    else:
        raise AssertionError("modified Ed25519 signature verified unexpectedly")

    assert digest(frame(REQ_DOMAIN, payload + b"wrong")) != fingerprint
    passed("request_scope_extension_changes_fingerprint")

    assert len(cases) == 7
    print(json.dumps({
        "protocol": "openscion.foss478.independent-oracle.v1",
        "result": "PASS",
        "tests": len(cases),
        "crypto_library": f"Python cryptography {cryptography_version}",
        "vector_sha256": hashlib.sha256(
            (json.dumps(vector, sort_keys=True, separators=(",", ":")) + "\n").encode()
        ).hexdigest()
    }, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--vector",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "vectors" / "authorization-v1.json",
    )
    args = parser.parse_args()
    with args.vector.open(encoding="utf-8") as fh:
        run(json.load(fh))


if __name__ == "__main__":
    main()
