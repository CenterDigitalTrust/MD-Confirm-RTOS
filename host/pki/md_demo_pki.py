#!/usr/bin/env python3
"""
md_demo_pki.py - Demo Offline CA, Device Certificates, Key Rotation & Revocation

WARNING: DEMO ONLY - NOT FOR PRODUCTION USE.
This script stores Ed25519 CA and device private keys on the host filesystem.
There is NO HSM, TPM 2.0, or secure-element hardware protection here.
For the system boundary and limitations, see docs/TRUST_BOUNDARY.md.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
import stat
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

DEMO_WARNING = (
    "DEMO ONLY - NOT FOR PRODUCTION USE: Software keys stored on filesystem "
    "without HSM/TPM hardware protection."
)
CERT_DOMAIN_SEP = b"MDFP1-DEMO-CERT\n"
ROTATION_DOMAIN_SEP = b"MDFP1-KEY-ROTATION\n"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_json_bytes(obj: dict[str, Any]) -> bytes:
    """Serialize dict as sorted compact UTF-8 JSON (RFC 8785 JCS subset)."""
    ordered = {k: obj[k] for k in sorted(obj.keys())}
    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_key_id(pub_hex: str) -> str:
    """Return 16-char lowercase key_id matching mdfp::compute_key_id() and md_verify_cli."""
    clean = pub_hex.strip().lower()
    if len(clean) != 64:
        raise ValueError(f"Expected 64-char Ed25519 public key hex, got len={len(clean)}")
    bytes.fromhex(clean)
    return clean[:16]


def load_ed25519_public_key_hex(path_or_hex: str) -> str:
    """Load 32-byte Ed25519 public key hex from hex string, .hex file, or cert/info JSON."""
    candidate = path_or_hex.strip()
    if len(candidate) == 64:
        try:
            raw = bytes.fromhex(candidate)
            Ed25519PublicKey.from_public_bytes(raw)
            return candidate.lower()
        except ValueError:
            pass

    if not os.path.exists(path_or_hex):
        raise ValueError(f"Public key hex or file not found: '{path_or_hex}'")

    with open(path_or_hex, "rb") as fh:
        raw_bytes = fh.read()

    if len(raw_bytes) == 32:
        Ed25519PublicKey.from_public_bytes(raw_bytes)
        return raw_bytes.hex()
    if len(raw_bytes) == 64:
        # Either 64-char hex without newline OR raw TweetNaCl seed||pub binary
        try:
            text = raw_bytes.decode("ascii").strip()
            if len(text) == 64:
                raw_pk = bytes.fromhex(text)
                Ed25519PublicKey.from_public_bytes(raw_pk)
                return text.lower()
        except (UnicodeDecodeError, ValueError):
            pk_raw = raw_bytes[32:]
            Ed25519PublicKey.from_public_bytes(pk_raw)
            return pk_raw.hex()

    text = raw_bytes.decode("utf-8").strip()
    if text.startswith("{"):
        parsed = json.loads(text)
        for field in ("public_key", "public_key_hex", "device_pub_hex"):
            if field in parsed and isinstance(parsed[field], str):
                return compute_key_id_validated_hex(parsed[field])
        raise ValueError(f"JSON file '{path_or_hex}' lacks 'public_key' field")

    clean = text.lower()
    if len(clean) == 128:
        # FileSigner 128-hex seed||pub file -> derive / extract pub half
        raw_sk = bytes.fromhex(clean)
        seed = raw_sk[:32]
        embedded_pub = raw_sk[32:]
        priv = Ed25519PrivateKey.from_private_bytes(seed)
        derived_pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        if derived_pub != embedded_pub:
            raise ValueError(f"Corrupt 128-hex key file '{path_or_hex}': seed/pub mismatch")
        return derived_pub.hex()

    if len(clean) != 64:
        raise ValueError(
            f"Unsupported public key format in '{path_or_hex}' (expected 64-hex or 128-hex, got {len(clean)} chars)"
        )
    raw_pk = bytes.fromhex(clean)
    Ed25519PublicKey.from_public_bytes(raw_pk)
    return clean


def compute_key_id_validated_hex(pub_hex: str) -> str:
    clean = pub_hex.strip().lower()
    raw = bytes.fromhex(clean)
    Ed25519PublicKey.from_public_bytes(raw)
    return clean


def load_ed25519_private_key(path_or_hex: str) -> tuple[Ed25519PrivateKey, bytes, bytes]:
    """Load private key (FileSigner 128-hex seed||pub, 64-raw, 64-hex seed, or JSON).

    Returns (Ed25519PrivateKey, seed_32, pub_32).
    """
    raw_bytes: bytes | None = None
    candidate = path_or_hex.strip()
    if len(candidate) in (64, 128):
        try:
            raw_bytes = bytes.fromhex(candidate)
            if len(raw_bytes) == 32:
                priv = Ed25519PrivateKey.from_private_bytes(raw_bytes)
                pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                return priv, raw_bytes, pub
            if len(raw_bytes) == 64:
                seed, embedded_pub = raw_bytes[:32], raw_bytes[32:]
                priv = Ed25519PrivateKey.from_private_bytes(seed)
                pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                if pub != embedded_pub:
                    raise ValueError("Ed25519 seed/public mismatch in 128-hex key")
                return priv, seed, pub
        except ValueError:
            raw_bytes = None

    if not os.path.exists(path_or_hex):
        raise ValueError(f"Private key file or hex not found: '{path_or_hex}'")

    with open(path_or_hex, "rb") as fh:
        data = fh.read()

    if len(data) == 64:
        # Distinguish binary 64-byte raw TweetNaCl sk vs 64-char ASCII hex seed
        try:
            ascii_txt = data.decode("ascii").strip()
            if len(ascii_txt) == 64:
                seed = bytes.fromhex(ascii_txt)
                priv = Ed25519PrivateKey.from_private_bytes(seed)
                pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                return priv, seed, pub
        except (UnicodeDecodeError, ValueError):
            pass
        seed, embedded_pub = data[:32], data[32:]
        priv = Ed25519PrivateKey.from_private_bytes(seed)
        pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        if pub != embedded_pub:
            raise ValueError(f"Corrupt raw 64-byte key file '{path_or_hex}': seed/pub mismatch")
        return priv, seed, pub

    if len(data) == 32:
        priv = Ed25519PrivateKey.from_private_bytes(data)
        pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return priv, data, pub

    text = data.decode("utf-8").strip()
    if text.startswith("{"):
        parsed = json.loads(text)
        for field in ("sk_hex", "seed_hex", "private_key_hex"):
            if field in parsed and isinstance(parsed[field], str):
                return load_ed25519_private_key(parsed[field])
        raise ValueError(f"JSON key file '{path_or_hex}' lacks sk_hex/seed_hex field")

    clean = text.lower()
    raw_hex = bytes.fromhex(clean)
    if len(raw_hex) == 32:
        priv = Ed25519PrivateKey.from_private_bytes(raw_hex)
        pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return priv, raw_hex, pub
    if len(raw_hex) == 64:
        seed, embedded_pub = raw_hex[:32], raw_hex[32:]
        priv = Ed25519PrivateKey.from_private_bytes(seed)
        pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        if pub != embedded_pub:
            raise ValueError(f"Corrupt hex key file '{path_or_hex}': seed/pub mismatch")
        return priv, seed, pub

    raise ValueError(f"Unsupported private key length in '{path_or_hex}': {len(raw_hex)} bytes")


def write_secret_key_strict(path: str, seed_bytes: bytes, pub_bytes: bytes) -> None:
    """Write 128-hex seed||pub file compatible with FileSigner (0600 permissions)."""
    if len(seed_bytes) != 32 or len(pub_bytes) != 32:
        raise ValueError("Expected 32-byte seed and 32-byte public key")
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    content = ((seed_bytes + pub_bytes).hex() + "\n").encode("ascii")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, content)
    finally:
        os.close(fd)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def generate_keypair_files(
    sk_out: str,
    pub_out: str | None = None,
    *,
    seed: bytes | None = None,
) -> dict[str, str]:
    """Generate an Ed25519 keypair and write FileSigner-compatible 128-hex key."""
    if seed is not None:
        if len(seed) != 32:
            raise ValueError("Seed must be exactly 32 bytes")
        priv = Ed25519PrivateKey.from_private_bytes(seed)
    else:
        priv = Ed25519PrivateKey.generate()

    seed_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    write_secret_key_strict(sk_out, seed_bytes, pub_bytes)

    pub_hex = pub_bytes.hex()
    key_id = pub_hex[:16]
    if pub_out:
        parent = os.path.dirname(os.path.abspath(pub_out))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(pub_out, "w", encoding="utf-8") as fh:
            fh.write(pub_hex + "\n")

    return {
        "sk_path": sk_out,
        "pub_path": pub_out or "",
        "public_key": pub_hex,
        "key_id": key_id,
    }


def init_ca(out_dir: str, *, prefix: str = "ca", seed: bytes | None = None) -> dict[str, str]:
    """Create a demo offline CA Ed25519 keypair under out_dir."""
    os.makedirs(out_dir, exist_ok=True)
    sk_path = os.path.join(out_dir, f"{prefix}_key.hex")
    pub_path = os.path.join(out_dir, f"{prefix}_pub.hex")
    info_path = os.path.join(out_dir, f"{prefix}_info.json")

    res = generate_keypair_files(sk_path, pub_path, seed=seed)
    info = {
        "demo_only": True,
        "warning": DEMO_WARNING,
        "key_id": res["key_id"],
        "public_key": res["public_key"],
        "created_at": utc_now_iso(),
    }
    with open(info_path, "w", encoding="utf-8") as fh:
        json.dump(info, fh, indent=2, sort_keys=True)
        fh.write("\n")

    res["info_path"] = info_path
    return res


def issue_device_certificate(
    ca_key_source: str,
    *,
    device_id: str,
    device_pub_source: str,
    not_before: str | None = None,
    not_after: str | None = None,
    valid_days: int = 365,
    version: int = 1,
) -> dict[str, Any]:
    """Issue a signed demo Ed25519 device certificate (JSON signed with CA key)."""
    if not device_id or not device_id.strip():
        raise ValueError("device_id must be non-empty")

    ca_priv, _, ca_pub = load_ed25519_private_key(ca_key_source)
    ca_key_id = ca_pub.hex()[:16]
    device_pub_hex = load_ed25519_public_key_hex(device_pub_source)
    device_key_id = device_pub_hex[:16]

    now = datetime.now(timezone.utc).replace(microsecond=0)
    nb_str = not_before or now.strftime("%Y-%m-%dT%H:%M:%SZ")
    if not_after:
        na_str = not_after
    else:
        nb_dt = datetime.fromisoformat(nb_str.replace("Z", "+00:00"))
        na_str = (nb_dt + timedelta(days=valid_days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    payload: dict[str, Any] = {
        "ca_key_id": ca_key_id,
        "demo_only": True,
        "device_id": device_id.strip(),
        "key_id": device_key_id,
        "not_after": na_str,
        "not_before": nb_str,
        "public_key": device_pub_hex,
        "version": int(version),
    }
    sig_hex = ca_priv.sign(CERT_DOMAIN_SEP + canonical_json_bytes(payload)).hex()
    cert = {**payload, "sig": sig_hex}
    return {k: cert[k] for k in sorted(cert.keys())}


def issue_key_rotation(
    *,
    device_id: str,
    old_pub_source: str,
    new_pub_source: str,
    issuer_type: str,
    signer_key_source: str,
    effective_tree_size: int = 0,
    issued_at: str | None = None,
    version: int = 1,
) -> dict[str, Any]:
    """Issue a signed key-rotation record certifying new_key by old_key or CA."""
    if issuer_type not in ("old_key", "ca"):
        raise ValueError(f"issuer_type must be 'old_key' or 'ca', got '{issuer_type}'")
    if effective_tree_size < 0:
        raise ValueError("effective_tree_size must be >= 0")

    old_pub_hex = load_ed25519_public_key_hex(old_pub_source)
    new_pub_hex = load_ed25519_public_key_hex(new_pub_source)
    if old_pub_hex == new_pub_hex:
        raise ValueError("old_public_key and new_public_key must differ")

    signer_priv, _, signer_pub = load_ed25519_private_key(signer_key_source)
    signer_pub_hex = signer_pub.hex()
    signer_key_id = signer_pub_hex[:16]

    if issuer_type == "old_key" and signer_pub_hex != old_pub_hex:
        raise ValueError(
            "issuer_type='old_key' requires signer_key to match old_public_key"
        )

    payload: dict[str, Any] = {
        "demo_only": True,
        "device_id": device_id.strip(),
        "effective_tree_size": int(effective_tree_size),
        "issued_at": issued_at or utc_now_iso(),
        "issuer_key_id": signer_key_id,
        "issuer_type": issuer_type,
        "new_key_id": new_pub_hex[:16],
        "new_public_key": new_pub_hex,
        "old_key_id": old_pub_hex[:16],
        "old_public_key": old_pub_hex,
        "version": int(version),
    }
    sig_hex = signer_priv.sign(ROTATION_DOMAIN_SEP + canonical_json_bytes(payload)).hex()
    rot = {**payload, "sig": sig_hex}
    return {k: rot[k] for k in sorted(rot.keys())}


def revoke_key(
    revoked_file: str,
    *,
    key_source: str | None = None,
    cert_path: str | None = None,
    reason: str = "compromised-or-retired-demo",
    as_json: bool = False,
) -> dict[str, Any]:
    """Add a key_id/public_key entry to a revocation file (text or JSON)."""
    pub_hex = ""
    key_id = ""

    if cert_path:
        with open(cert_path, "r", encoding="utf-8") as fh:
            cert_obj = json.load(fh)
        payload = cert_obj.get("cert", cert_obj) if isinstance(cert_obj, dict) else {}
        pub_hex = str(payload.get("public_key", "")).strip().lower()
        key_id = str(payload.get("key_id", pub_hex[:16])).strip().lower()
    elif key_source:
        cand = key_source.strip().lower()
        if len(cand) == 16:
            bytes.fromhex(cand)
            key_id = cand
        else:
            pub_hex = load_ed25519_public_key_hex(key_source)
            key_id = pub_hex[:16]
    else:
        raise ValueError("Provide either key_source or cert_path")

    if not key_id and not pub_hex:
        raise ValueError("Could not extract key_id or public_key to revoke")

    entry = {
        "key_id": key_id,
        "public_key": pub_hex,
        "reason": reason,
        "revoked_at": utc_now_iso(),
        "demo_only": True,
    }

    parent = os.path.dirname(os.path.abspath(revoked_file))
    if parent:
        os.makedirs(parent, exist_ok=True)

    use_json = as_json or revoked_file.lower().endswith(".json")
    if use_json:
        existing: list[Any] = []
        if os.path.exists(revoked_file):
            with open(revoked_file, "r", encoding="utf-8") as fh:
                raw = fh.read().strip()
                if raw:
                    loaded = json.loads(raw)
                    if isinstance(loaded, dict) and isinstance(loaded.get("revoked"), list):
                        existing = loaded["revoked"]
                    elif isinstance(loaded, list):
                        existing = loaded
        existing.append(entry)
        with open(revoked_file, "w", encoding="utf-8") as fh:
            json.dump({"demo_only": True, "revoked": existing}, fh, indent=2, sort_keys=True)
            fh.write("\n")
    else:
        with open(revoked_file, "a", encoding="utf-8") as fh:
            fh.write(f"# revoked_at={entry['revoked_at']} reason={reason} (DEMO ONLY)\n")
            if pub_hex:
                fh.write(f"{pub_hex}\n")
            else:
                fh.write(f"{key_id}\n")

    return entry


def _write_json(path: str, data: dict[str, Any]) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="MD-Confirm Demo PKI Tooling (DEMO ONLY - NOT FOR PRODUCTION USE)"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ca = sub.add_parser("init-ca", help="Create demo offline CA keypair")
    p_ca.add_argument("--out-dir", required=True, help="Directory for CA files")
    p_ca.add_argument("--prefix", default="ca", help="Filename prefix (default: ca)")

    p_gk = sub.add_parser(
        "gen-device-key",
        help="Generate FileSigner-compatible 128-hex seed||pub key (mode 0600)",
    )
    p_gk.add_argument("--sk-out", required=True, help="Output secret key file path")
    p_gk.add_argument("--pub-out", help="Optional output public key hex file")

    p_cert = sub.add_parser("issue-cert", help="Sign a demo device certificate with CA key")
    p_cert.add_argument("--ca-key", required=True, help="CA secret key path or hex")
    p_cert.add_argument("--device-id", required=True, help="Device identifier")
    p_cert.add_argument("--device-pub", required=True, help="Device pub hex, .hex, or sk file")
    p_cert.add_argument("--not-before", help="ISO-8601 UTC validity start (default: now)")
    p_cert.add_argument("--not-after", help="ISO-8601 UTC validity end")
    p_cert.add_argument("--valid-days", type=int, default=365, help="Validity days (default: 365)")
    p_cert.add_argument("--out", required=True, help="Output certificate JSON path")

    p_rot = sub.add_parser(
        "rotate-key",
        help="Issue a signed key-rotation record (certified by old_key or ca)",
    )
    p_rot.add_argument("--device-id", required=True, help="Device identifier")
    p_rot.add_argument("--old-pub", required=True, help="Old device pub hex or file")
    p_rot.add_argument("--new-pub", required=True, help="New device pub hex or file")
    p_rot.add_argument(
        "--issuer-type",
        required=True,
        choices=["old_key", "ca"],
        help="Certifying authority: old_key or ca",
    )
    p_rot.add_argument("--signer-key", required=True, help="Secret key for old_key or ca")
    p_rot.add_argument(
        "--effective-tree-size",
        type=int,
        default=0,
        help="Journal leaf count after which new_key becomes active (0 = from start/inline)",
    )
    p_rot.add_argument("--issued-at", help="ISO-8601 UTC timestamp")
    p_rot.add_argument("--out", required=True, help="Output rotation JSON path")

    p_rev = sub.add_parser("revoke", help="Revoke a device key/cert in revocation list")
    p_rev.add_argument("--revoked-file", required=True, help="Revocation file path (.txt or .json)")
    p_rev.add_argument("--key", help="key_id (16-hex), pub hex, or key file")
    p_rev.add_argument("--cert", help="Device certificate JSON to revoke")
    p_rev.add_argument("--reason", default="revoked-in-demo", help="Revocation reason string")
    p_rev.add_argument("--json", action="store_true", help="Write JSON revocation list")

    args = parser.parse_args(argv)

    print(f"[DEMO PKI] {DEMO_WARNING}")

    if args.cmd == "init-ca":
        res = init_ca(args.out_dir, prefix=args.prefix)
        print(json.dumps(res, indent=2, sort_keys=True))
        return 0

    if args.cmd == "gen-device-key":
        res = generate_keypair_files(args.sk_out, args.pub_out)
        print(json.dumps(res, indent=2, sort_keys=True))
        return 0

    if args.cmd == "issue-cert":
        cert = issue_device_certificate(
            args.ca_key,
            device_id=args.device_id,
            device_pub_source=args.device_pub,
            not_before=args.not_before,
            not_after=args.not_after,
            valid_days=args.valid_days,
        )
        _write_json(args.out, cert)
        print(f"[DEMO PKI] Issued device cert for {cert['device_id']} key_id={cert['key_id']} -> {args.out}")
        return 0

    if args.cmd == "rotate-key":
        rot = issue_key_rotation(
            device_id=args.device_id,
            old_pub_source=args.old_pub,
            new_pub_source=args.new_pub,
            issuer_type=args.issuer_type,
            signer_key_source=args.signer_key,
            effective_tree_size=args.effective_tree_size,
            issued_at=args.issued_at,
        )
        _write_json(args.out, rot)
        print(
            f"[DEMO PKI] Issued key rotation ({rot['issuer_type']}): "
            f"{rot['old_key_id']} -> {rot['new_key_id']} at tree_size>{rot['effective_tree_size']} -> {args.out}"
        )
        return 0

    if args.cmd == "revoke":
        entry = revoke_key(
            args.revoked_file,
            key_source=args.key,
            cert_path=args.cert,
            reason=args.reason,
            as_json=args.json,
        )
        print(json.dumps(entry, indent=2, sort_keys=True))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
