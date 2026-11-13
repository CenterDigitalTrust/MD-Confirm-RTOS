"""Tests for Task 5 Demo PKI, CA cert verification, revocation, and key rotation."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_VERIFY_DIR = os.path.join(_REPO_ROOT, "host", "verify-cli")
_PKI_DIR = os.path.join(_REPO_ROOT, "host", "pki")
for _d in (_VERIFY_DIR, _PKI_DIR):
    if _d not in sys.path:
        sys.path.insert(0, _d)

import md_demo_pki  # noqa: E402
import md_verify_cli  # noqa: E402
from merkle_rfc6962 import leaf_hash, merkle_tree_hash  # noqa: E402


def _canon_bytes(obj: dict) -> bytes:
    ordered = {k: obj[k] for k in sorted(obj.keys())}
    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sign_sth(
    priv: Ed25519PrivateKey,
    *,
    device_id: str,
    tree_size: int,
    root_hash: str,
    prev_sth_sha256: str,
    timestamp: int,
    key_id: str,
) -> tuple[dict, bytes]:
    sth = {
        "device_id": device_id,
        "key_id": key_id,
        "prev_sth_sha256": prev_sth_sha256,
        "root_hash": root_hash,
        "timestamp": timestamp,
        "tree_size": tree_size,
        "version": 1,
    }
    canon = _canon_bytes(sth)
    sig_hex = priv.sign(b"MDFP1-STH\n" + canon).hex()
    return {**sth, "sig": sig_hex}, hashlib.sha256(canon).digest()


def _build_epoch_journal_and_sths(
    out_dir: str,
    *,
    device_id: str,
    signers: list[tuple[int, int, Ed25519PrivateKey, str]],
    inline_rotations: dict[int, tuple[dict, int]] | None = None,
    sth_boundaries: list[int] | None = None,
) -> tuple[str, str]:
    """Create a multi-epoch signed journal + sth.log.

    signers: [(start_pos, end_pos, priv_key, pub_hex), ...] (1-based inclusive)
    inline_rotations: {pos_1based: (rotation_dict, ...)} optional inline KEY_ROTATION records
    """
    inline_rotations = inline_rotations or {}
    sth_boundaries = sth_boundaries or []

    def signer_for(pos: int) -> tuple[Ed25519PrivateKey, str]:
        for s, e, priv, pub_hex in signers:
            if s <= pos <= e:
                return priv, pub_hex
        raise ValueError(f"No signer configured for record position {pos}")

    total = max(e for _, e, _, _ in signers)
    leaves_raw: list[bytes] = []
    journal_lines: list[str] = []
    sth_lines: list[str] = []
    prev_sth_sha256 = "0" * 64

    for pos in range(1, total + 1):
        priv, _ = signer_for(pos)
        raw_digest = hashlib.sha256(f"frame-bytes-{pos}".encode()).hexdigest()

        if pos in inline_rotations:
            rot_obj = inline_rotations[pos]
            canon_obj = {
                "client_time_ns": 1700000000000000000 + pos * 33333333,
                "clock_cycles": 1000000 + pos * 50000,
                "device_id": device_id,
                "event_type": "KEY_ROTATION",
                "frame_seq": pos,
                "frame_sha256": raw_digest,
                "k_ref_id": "kref-sim-0x20261111",
                "k_ref_version": "sim-1d-v1",
                "ncc": 0.99,
                "ncc_threshold": 0.75,
                "pce_db": 36.12,
                "pce_linear": 4092.6,
                "pce_threshold_linear": 60.0,
                "raw_sha256": raw_digest,
                "rotation": rot_obj,
                "scenario": 1,
                "sensor_id": "sim-bayer-64x64-01",
                "seq": pos,
                "verdict": "KEY_ROTATION",
            }
            rec_type = "KEY_ROTATION"
            verdict = "KEY_ROTATION"
        else:
            canon_obj = {
                "client_time_ns": 1700000000000000000 + pos * 33333333,
                "clock_cycles": 1000000 + pos * 50000,
                "device_id": device_id,
                "event_type": "AUTHENTIC",
                "frame_seq": pos,
                "frame_sha256": raw_digest,
                "k_ref_id": "kref-sim-0x20261111",
                "k_ref_version": "sim-1d-v1",
                "ncc": 0.99,
                "ncc_threshold": 0.75,
                "pce_db": 36.12,
                "pce_linear": 4092.6,
                "pce_threshold_linear": 60.0,
                "raw_sha256": raw_digest,
                "scenario": 1,
                "sensor_id": "sim-bayer-64x64-01",
                "seq": pos,
                "verdict": "VERIFIED_AUTHENTIC_SILICON",
            }
            rec_type = "AUTHENTIC"
            verdict = "VERIFIED_AUTHENTIC_SILICON"

        canon_bytes = _canon_bytes(canon_obj)
        leaf_b = leaf_hash(canon_bytes)
        leaf_hex = leaf_b.hex()
        leaves_raw.append(leaf_b)
        root_hex = merkle_tree_hash(leaves_raw, prehashed=True).hex()
        sig_hex = priv.sign(f"MDFP1\n{root_hex}".encode("utf-8")).hex()

        line = (
            f"RECORD #{pos} | SEQ: {pos} | TYPE: {rec_type} | VERDICT: {verdict} | "
            f"RAW_SHA256: {raw_digest} | LEAF: {leaf_hex} | MERKLE_ROOT: {root_hex} | "
            f"SIG: {sig_hex} | CANON: {canon_bytes.decode('utf-8')}"
        )
        journal_lines.append(line)

        if pos in sth_boundaries:
            _, sth_pub_hex = signer_for(pos)
            sth_obj, sth_sha = _sign_sth(
                priv,
                device_id=device_id,
                tree_size=pos,
                root_hash=root_hex,
                prev_sth_sha256=prev_sth_sha256,
                timestamp=1700000000000000000 + pos * 33333333,
                key_id=sth_pub_hex[:16],
            )
            prev_sth_sha256 = sth_sha.hex()
            sth_lines.append(json.dumps(sth_obj, separators=(",", ":")))

    journal_path = os.path.join(out_dir, "journal.log")
    sth_path = os.path.join(out_dir, "sth.log")
    with open(journal_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(journal_lines) + "\n")
    if sth_lines:
        with open(sth_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(sth_lines) + "\n")
    return journal_path, sth_path


def test_demo_pki_cli_workflow_and_filesigner_format():
    with tempfile.TemporaryDirectory() as tmp:
        ca_dir = os.path.join(tmp, "ca")
        assert md_demo_pki.main(["init-ca", "--out-dir", ca_dir]) == 0
        ca_sk = os.path.join(ca_dir, "ca_key.hex")
        ca_pub = os.path.join(ca_dir, "ca_pub.hex")
        assert os.path.exists(ca_sk)
        assert os.path.exists(ca_pub)
        with open(os.path.join(ca_dir, "ca_info.json"), "r", encoding="utf-8") as fh:
            ca_info = json.load(fh)
        assert ca_info["demo_only"] is True
        assert "DEMO ONLY" in ca_info["warning"]

        dev1_sk = os.path.join(tmp, "dev1_key.hex")
        dev1_pub = os.path.join(tmp, "dev1_pub.hex")
        assert md_demo_pki.main(["gen-device-key", "--sk-out", dev1_sk, "--pub-out", dev1_pub]) == 0
        with open(dev1_sk, "r", encoding="utf-8") as fh:
            sk_hex = fh.read().strip()
        assert len(sk_hex) == 128  # FileSigner-compatible 128-hex seed||pub

        cert_path = os.path.join(tmp, "dev1_cert.json")
        assert (
            md_demo_pki.main(
                [
                    "issue-cert",
                    "--ca-key",
                    ca_sk,
                    "--device-id",
                    "ADAS_CAM_FRONT_01",
                    "--device-pub",
                    dev1_pub,
                    "--not-before",
                    "2026-01-01T00:00:00Z",
                    "--not-after",
                    "2028-01-01T00:00:00Z",
                    "--out",
                    cert_path,
                ]
            )
            == 0
        )
        with open(cert_path, "r", encoding="utf-8") as fh:
            cert = json.load(fh)
        for key in ("device_id", "public_key", "not_before", "not_after", "key_id", "sig"):
            assert key in cert
        assert cert["demo_only"] is True


def test_verify_journal_with_ca_pub_and_cert_validity():
    with tempfile.TemporaryDirectory() as tmp:
        ca_info = md_demo_pki.init_ca(os.path.join(tmp, "ca"))
        dev1 = md_demo_pki.generate_keypair_files(os.path.join(tmp, "dev1_key.hex"))
        dev1_priv, _, _ = md_demo_pki.load_ed25519_private_key(dev1["sk_path"])
        cert = md_demo_pki.issue_device_certificate(
            ca_info["sk_path"],
            device_id="ADAS_CAM_FRONT_01",
            device_pub_source=dev1["public_key"],
            not_before="2026-01-01T00:00:00Z",
            not_after="2026-12-31T23:59:59Z",
        )
        cert_path = os.path.join(tmp, "dev1_cert.json")
        with open(cert_path, "w", encoding="utf-8") as fh:
            json.dump(cert, fh)

        j_path, sth_path = _build_epoch_journal_and_sths(
            tmp,
            device_id="ADAS_CAM_FRONT_01",
            signers=[(1, 5, dev1_priv, dev1["public_key"])],
            sth_boundaries=[3, 5],
        )

        # Valid using CA pub file path + within cert validity window
        res = md_verify_cli.verify_journal(
            j_path,
            ca_pub=ca_info["pub_path"],
            device_cert_path=cert_path,
            sth_log_path=sth_path,
            at_time="2026-06-15T12:00:00Z",
        )
        assert res.ok, res.failures
        assert res.sth_verified_count == 2

        # CLI exit 0 using raw CA pub hex directly
        rc = md_verify_cli.main(
            [
                j_path,
                "--sth-log",
                sth_path,
                "--ca-pub",
                ca_info["public_key"],
                "--device-cert",
                cert_path,
                "--at-time",
                "2026-06-15T12:00:00Z",
            ]
        )
        assert rc == 0

        # Missing --device-cert must fail
        res_nocert = md_verify_cli.verify_journal(j_path, ca_pub=ca_info["pub_path"])
        assert not res_nocert.ok
        assert any("MISSING_DEVICE_CERT" in f for f in res_nocert.failures)

        # Expired cert must fail
        res_exp = md_verify_cli.verify_journal(
            j_path,
            ca_pub=ca_info["pub_path"],
            device_cert_path=cert_path,
            at_time="2027-01-02T00:00:00Z",
        )
        assert not res_exp.ok
        assert any("CERT_EXPIRED" in f for f in res_exp.failures)

        # Not-yet-valid cert must fail
        res_early = md_verify_cli.verify_journal(
            j_path,
            ca_pub=ca_info["pub_path"],
            device_cert_path=cert_path,
            at_time="2025-12-31T23:59:59Z",
        )
        assert not res_early.ok
        assert any("CERT_NOT_YET_VALID" in f for f in res_early.failures)

        # Tampered cert signature must fail
        bad_cert = dict(cert)
        bad_cert["device_id"] = "SPOOFED_CAMERA"
        bad_cert_path = os.path.join(tmp, "bad_cert.json")
        with open(bad_cert_path, "w", encoding="utf-8") as fh:
            json.dump(bad_cert, fh)
        res_bad_cert = md_verify_cli.verify_journal(
            j_path,
            ca_pub=ca_info["pub_path"],
            device_cert_path=bad_cert_path,
            at_time="2026-06-15T12:00:00Z",
        )
        assert not res_bad_cert.ok
        assert any("CERT_INVALID_SIGNATURE" in f for f in res_bad_cert.failures)

        # Cross-device substitution (valid CA cert for OTHER device) must fail
        other_cert = md_demo_pki.issue_device_certificate(
            ca_info["sk_path"],
            device_id="ADAS_CAM_REAR_99",
            device_pub_source=dev1["public_key"],
            not_before="2026-01-01T00:00:00Z",
            not_after="2027-01-01T00:00:00Z",
        )
        other_cert_path = os.path.join(tmp, "other_cert.json")
        with open(other_cert_path, "w", encoding="utf-8") as fh:
            json.dump(other_cert, fh)
        res_wrong_dev = md_verify_cli.verify_journal(
            j_path,
            ca_pub=ca_info["pub_path"],
            device_cert_path=other_cert_path,
            at_time="2026-06-15T12:00:00Z",
        )
        assert not res_wrong_dev.ok
        assert any("device_id" in f for f in res_wrong_dev.failures)


def test_revoked_key_rejection_text_and_json():
    with tempfile.TemporaryDirectory() as tmp:
        ca_info = md_demo_pki.init_ca(os.path.join(tmp, "ca"))
        dev1 = md_demo_pki.generate_keypair_files(os.path.join(tmp, "dev1_key.hex"))
        dev1_priv, _, _ = md_demo_pki.load_ed25519_private_key(dev1["sk_path"])
        cert = md_demo_pki.issue_device_certificate(
            ca_info["sk_path"],
            device_id="ADAS_CAM_FRONT_01",
            device_pub_source=dev1["public_key"],
            not_before="2026-01-01T00:00:00Z",
            not_after="2027-01-01T00:00:00Z",
        )
        cert_path = os.path.join(tmp, "dev1_cert.json")
        with open(cert_path, "w", encoding="utf-8") as fh:
            json.dump(cert, fh)

        j_path, sth_path = _build_epoch_journal_and_sths(
            tmp,
            device_id="ADAS_CAM_FRONT_01",
            signers=[(1, 4, dev1_priv, dev1["public_key"])],
            sth_boundaries=[4],
        )

        # Revoke via text file (key_id comment)
        rev_txt = os.path.join(tmp, "revoked.txt")
        assert (
            md_demo_pki.main(
                ["revoke", "--revoked-file", rev_txt, "--cert", cert_path, "--reason", "key-leak"]
            )
            == 0
        )
        rc_txt = md_verify_cli.main(
            [
                j_path,
                "--sth-log",
                sth_path,
                "--ca-pub",
                ca_info["pub_path"],
                "--device-cert",
                cert_path,
                "--revoked",
                rev_txt,
                "--at-time",
                "2026-06-15T12:00:00Z",
            ]
        )
        assert rc_txt == 2

        # Revoke via JSON list (also verify legacy --device-pubkey path respects --revoked)
        rev_json = os.path.join(tmp, "revoked.json")
        md_demo_pki.revoke_key(rev_json, key_source=dev1["key_id"], as_json=True)
        res_json = md_verify_cli.verify_journal(
            j_path,
            device_pubkey_hex=dev1["public_key"],
            revoked_path=rev_json,
        )
        assert not res_json.ok
        assert any("KEY_REVOKED" in f for f in res_json.failures)


def test_key_rotation_certified_by_old_key_external():
    with tempfile.TemporaryDirectory() as tmp:
        ca_info = md_demo_pki.init_ca(os.path.join(tmp, "ca"))
        k1 = md_demo_pki.generate_keypair_files(os.path.join(tmp, "k1_key.hex"))
        k2 = md_demo_pki.generate_keypair_files(os.path.join(tmp, "k2_key.hex"))
        k1_priv, _, _ = md_demo_pki.load_ed25519_private_key(k1["sk_path"])
        k2_priv, _, _ = md_demo_pki.load_ed25519_private_key(k2["sk_path"])

        cert1 = md_demo_pki.issue_device_certificate(
            ca_info["sk_path"],
            device_id="ADAS_CAM_FRONT_01",
            device_pub_source=k1["public_key"],
            not_before="2026-01-01T00:00:00Z",
            not_after="2027-01-01T00:00:00Z",
        )
        cert1_path = os.path.join(tmp, "cert1.json")
        with open(cert1_path, "w", encoding="utf-8") as fh:
            json.dump(cert1, fh)

        rot_old = md_demo_pki.issue_key_rotation(
            device_id="ADAS_CAM_FRONT_01",
            old_pub_source=k1["public_key"],
            new_pub_source=k2["public_key"],
            issuer_type="old_key",
            signer_key_source=k1["sk_path"],
            effective_tree_size=4,
        )
        rot_path = os.path.join(tmp, "rot_old.json")
        with open(rot_path, "w", encoding="utf-8") as fh:
            json.dump(rot_old, fh)

        j_path, sth_path = _build_epoch_journal_and_sths(
            tmp,
            device_id="ADAS_CAM_FRONT_01",
            signers=[
                (1, 4, k1_priv, k1["public_key"]),
                (5, 8, k2_priv, k2["public_key"]),
            ],
            sth_boundaries=[4, 8],
        )

        # Save STH #1 (signed by k1) as trusted external checkpoint
        with open(sth_path, "r", encoding="utf-8") as fh:
            first_sth_line = fh.readline().strip()
        cp_path = os.path.join(tmp, "cp1.sth")
        with open(cp_path, "w", encoding="utf-8") as fh:
            fh.write(first_sth_line + "\n")

        res_ok = md_verify_cli.verify_journal(
            j_path,
            ca_pub=ca_info["pub_path"],
            device_cert_path=cert1_path,
            rotation_paths=[rot_path],
            sth_log_path=sth_path,
            checkpoint_path=cp_path,
            at_time="2026-06-15T12:00:00Z",
        )
        assert res_ok.ok, res_ok.failures
        assert res_ok.sth_verified_count == 2
        assert res_ok.has_external_checkpoint is True

        # Without rotation record, post-rotation records MUST fail signature check
        res_missing_rot = md_verify_cli.verify_journal(
            j_path,
            ca_pub=ca_info["pub_path"],
            device_cert_path=cert1_path,
            sth_log_path=sth_path,
            at_time="2026-06-15T12:00:00Z",
        )
        assert not res_missing_rot.ok
        assert res_missing_rot.sig_failures >= 4

        # Forged rotation signature MUST fail
        bad_rot = dict(rot_old)
        bad_rot["sig"] = "00" * 64
        bad_rot_path = os.path.join(tmp, "bad_rot.json")
        with open(bad_rot_path, "w", encoding="utf-8") as fh:
            json.dump(bad_rot, fh)
        res_bad_rot = md_verify_cli.verify_journal(
            j_path,
            ca_pub=ca_info["pub_path"],
            device_cert_path=cert1_path,
            rotation_paths=[bad_rot_path],
            at_time="2026-06-15T12:00:00Z",
        )
        assert not res_bad_rot.ok
        assert any("ROTATION_INVALID_SIGNATURE" in f for f in res_bad_rot.failures)

        # Revoked new key MUST be rejected
        rev_k2 = os.path.join(tmp, "rev_k2.txt")
        md_demo_pki.revoke_key(rev_k2, key_source=k2["key_id"])
        res_rev_k2 = md_verify_cli.verify_journal(
            j_path,
            ca_pub=ca_info["pub_path"],
            device_cert_path=cert1_path,
            rotation_paths=[rot_path],
            revoked_path=rev_k2,
            at_time="2026-06-15T12:00:00Z",
        )
        assert not res_rev_k2.ok
        assert any("KEY_REVOKED" in f for f in res_rev_k2.failures)


def test_key_rotation_certified_by_ca_and_inline_record():
    with tempfile.TemporaryDirectory() as tmp:
        ca_info = md_demo_pki.init_ca(os.path.join(tmp, "ca"))
        k1 = md_demo_pki.generate_keypair_files(os.path.join(tmp, "k1_key.hex"))
        k2 = md_demo_pki.generate_keypair_files(os.path.join(tmp, "k2_key.hex"))
        k1_priv, _, _ = md_demo_pki.load_ed25519_private_key(k1["sk_path"])
        k2_priv, _, _ = md_demo_pki.load_ed25519_private_key(k2["sk_path"])

        cert1 = md_demo_pki.issue_device_certificate(
            ca_info["sk_path"],
            device_id="ADAS_CAM_FRONT_01",
            device_pub_source=k1["public_key"],
            not_before="2026-01-01T00:00:00Z",
            not_after="2027-01-01T00:00:00Z",
        )
        cert1_path = os.path.join(tmp, "cert1.json")
        with open(cert1_path, "w", encoding="utf-8") as fh:
            json.dump(cert1, fh)

        # Case A: External rotation certified by CA at tree_size=3
        rot_ca = md_demo_pki.issue_key_rotation(
            device_id="ADAS_CAM_FRONT_01",
            old_pub_source=k1["public_key"],
            new_pub_source=k2["public_key"],
            issuer_type="ca",
            signer_key_source=ca_info["sk_path"],
            effective_tree_size=3,
        )
        rot_ca_path = os.path.join(tmp, "rot_ca.json")
        with open(rot_ca_path, "w", encoding="utf-8") as fh:
            json.dump(rot_ca, fh)

        j_ext, sth_ext = _build_epoch_journal_and_sths(
            tmp,
            device_id="ADAS_CAM_FRONT_01",
            signers=[
                (1, 3, k1_priv, k1["public_key"]),
                (4, 6, k2_priv, k2["public_key"]),
            ],
            sth_boundaries=[3, 6],
        )
        res_ca = md_verify_cli.verify_journal(
            j_ext,
            ca_pub=ca_info["pub_path"],
            device_cert_path=cert1_path,
            rotation_paths=[rot_ca_path],
            sth_log_path=sth_ext,
            at_time="2026-06-15T12:00:00Z",
        )
        assert res_ca.ok, res_ca.failures
        assert res_ca.sth_verified_count == 2

        # CA-signed rotation MUST NOT be trusted when --ca-pub is omitted
        res_no_ca = md_verify_cli.verify_journal(
            j_ext,
            device_pubkey_hex=k1["public_key"],
            rotation_paths=[rot_ca_path],
        )
        assert not res_no_ca.ok
        assert any("ROTATION_UNTRUSTED" in f for f in res_no_ca.failures)

        # Case B: Inline KEY_ROTATION leaf record at position #4 (no external --rotation)
        inline_dir = os.path.join(tmp, "inline")
        os.makedirs(inline_dir, exist_ok=True)
        rot_inline = md_demo_pki.issue_key_rotation(
            device_id="ADAS_CAM_FRONT_01",
            old_pub_source=k1["public_key"],
            new_pub_source=k2["public_key"],
            issuer_type="ca",
            signer_key_source=ca_info["sk_path"],
            effective_tree_size=4,
        )
        j_in, sth_in = _build_epoch_journal_and_sths(
            inline_dir,
            device_id="ADAS_CAM_FRONT_01",
            signers=[
                (1, 4, k1_priv, k1["public_key"]),
                (5, 7, k2_priv, k2["public_key"]),
            ],
            inline_rotations={4: rot_inline},
            sth_boundaries=[4, 7],
        )
        res_inline = md_verify_cli.verify_journal(
            j_in,
            ca_pub=ca_info["pub_path"],
            device_cert_path=cert1_path,
            sth_log_path=sth_in,
            at_time="2026-06-15T12:00:00Z",
        )
        assert res_inline.ok, res_inline.failures
        assert res_inline.sth_verified_count == 2


def test_extended_canon_task5_fields_and_tamper_detection():
    with tempfile.TemporaryDirectory() as tmp:
        k1 = md_demo_pki.generate_keypair_files(os.path.join(tmp, "k1_key.hex"))
        k1_priv, _, _ = md_demo_pki.load_ed25519_private_key(k1["sk_path"])
        j_path, sth_path = _build_epoch_journal_and_sths(
            tmp,
            device_id="ADAS_CAM_FRONT_01",
            signers=[(1, 3, k1_priv, k1["public_key"])],
            sth_boundaries=[3],
        )

        res = md_verify_cli.verify_journal(
            j_path, device_pubkey_hex=k1["public_key"], sth_log_path=sth_path
        )
        assert res.ok, res.failures

        # Corrupt frame_sha256 vs raw_sha256 inside CANON while keeping LEAF valid and re-signed?
        # Wait: even just rewriting CANON without touching LEAF triggers LEAF mismatch AND field check
        with open(j_path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        rec2_prefix, rec2_canon = lines[1].split(" | CANON: ", 1)
        obj2 = json.loads(rec2_canon)
        obj2["frame_sha256"] = "f" * 64
        new_canon = _canon_bytes(obj2)
        new_leaf = leaf_hash(new_canon).hex()
        # Recompute journal prefix root and signature cleanly so ONLY field consistency is tested!
        rec1_leaf = bytes.fromhex(lines[0].split(" | LEAF: ", 1)[1].split(" | ", 1)[0])
        new_root = merkle_tree_hash([rec1_leaf, bytes.fromhex(new_leaf)], prehashed=True).hex()
        new_sig = k1_priv.sign(f"MDFP1\n{new_root}".encode("utf-8")).hex()
        parts2 = rec2_prefix.split(" | ")
        # Preserve SEQ/TYPE/VERDICT/RAW_SHA256, update LEAF/MERKLE_ROOT/SIG
        rebuilt = " | ".join(
            [
                parts2[0],
                parts2[1],
                parts2[2],
                parts2[3],
                parts2[4],
                f"LEAF: {new_leaf}",
                f"MERKLE_ROOT: {new_root}",
                f"SIG: {new_sig}",
            ]
        ) + f" | CANON: {new_canon.decode('utf-8')}"
        tampered_j = os.path.join(tmp, "tampered_field.log")
        with open(tampered_j, "w", encoding="utf-8") as fh:
            fh.write("\n".join([lines[0], rebuilt]) + "\n")

        res_bad = md_verify_cli.verify_journal(tampered_j, device_pubkey_hex=k1["public_key"])
        assert not res_bad.ok
        assert any("frame_sha256" in f for f in res_bad.failures)
