#!/usr/bin/env python3
"""
md_verify_cli.py - Standalone Independent Forensic Verifier CLI
Project: MD-Confirm RTOS | Track: Automotive & Mobility
Standards: RFC 6962 Merkle Trees + RFC 8032 Ed25519 + RFC 8785 JCS + RFC 3161 TSA / Solana

Independent Verification Architecture:
1. Does NOT trust the QNX node or HTTP server by itself.
2. Independently validates RFC 8032 Ed25519 signatures of journal records and
   Signed Tree Heads (STHs) against a pinned Device Ed25519 Public Key.
3. Independently recomputes strict RFC 6962 prefix roots and consistency proofs.
4. Verifies append-only growth relative to external checkpoints (--checkpoint STH_FILE,
   --solana-tx, and/or --tsa-tsr + --tsa-ca), explicitly reporting its trust basis.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from merkle_rfc6962 import (  # noqa: E402
    IncrementalMerkleFrontier,
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    merkle_tree_hash,
    node_hash as _rfc_node_hash,
    verify_consistency,
    verify_inclusion,
)


def node_hash(left: bytes | str, right: bytes | str) -> bytes | str:
    """RFC 6962 interior node hash; preserves hex string mode when both args are str."""
    if isinstance(left, str) and isinstance(right, str):
        return _rfc_node_hash(bytes.fromhex(left), bytes.fromhex(right)).hex()
    return _rfc_node_hash(bytes(left), bytes(right))

# Pinned Device Public Key for QNX ADAS Node #01 (DO NOT MODIFY)
PINNED_DEVICE_PUBLIC_KEY_HEX = (
    "7ea81ac6c1fc3a9a567a7693e3d930a5c140a3a05fa270d763f291160696a468"
)

STH_REQUIRED_KEYS = (
    "version",
    "device_id",
    "tree_size",
    "root_hash",
    "timestamp",
    "prev_sth_sha256",
    "key_id",
)

__all__ = [
    "PINNED_DEVICE_PUBLIC_KEY_HEX",
    "VerificationResult",
    "merkle_tree_hash",
    "inclusion_proof",
    "verify_inclusion",
    "consistency_proof",
    "verify_consistency",
    "leaf_hash",
    "node_hash",
    "compute_merkle_root",
    "verify_journal",
]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonicalize_sth(sth_obj: dict[str, Any]) -> bytes:
    """Serialize STH object to UTF-8 RFC 8785 canonical JSON."""
    for key in STH_REQUIRED_KEYS:
        if key not in sth_obj:
            raise ValueError(f"STH missing required key '{key}'")
    ordered = {k: sth_obj[k] for k in sorted(sth_obj.keys())}
    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_merkle_root(leaves_hex: list[str]) -> str:
    """Compute strict RFC 6962 Merkle root hex from 64-char hex leaf digests."""
    return merkle_tree_hash(leaves_hex, prehashed=True).hex()


def fetch_lines(source: str) -> list[str]:
    if source.startswith(("http://", "https://")):
        req = urllib.request.Request(
            source, headers={"User-Agent": "MD-Confirm-Verifier/3.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            text = resp.read().decode("utf-8")
            return [line.strip() for line in text.splitlines() if line.strip()]
    if os.path.exists(source):
        with open(source, "r", encoding="utf-8") as fh:
            return [line.strip() for line in fh if line.strip()]
    return []


def fetch_solana_tx_memo(tx_signature: str, rpc_url: str) -> str | None:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            tx_signature,
            {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0},
        ],
    }
    req = urllib.request.Request(
        rpc_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "MD-Confirm-Verifier/3.0"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        res = json.loads(resp.read().decode("utf-8"))

    if not res.get("result"):
        return None

    tx = res["result"]["transaction"]
    message = tx["message"]
    for ix in message.get("instructions", []):
        if ix.get("program") == "spl-memo":
            return ix.get("parsed")
        if ix.get("programId") == "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr":
            return ix.get("parsed") or ix.get("data")
    return None


def parse_journal_record(line: str) -> tuple[int | None, dict[str, str]]:
    segments = line.split(" | ")
    rec_num: int | None = None
    if segments and segments[0].startswith("RECORD #"):
        try:
            rec_num = int(segments[0][len("RECORD #"):].strip())
        except ValueError:
            rec_num = None

    fields: dict[str, str] = {}
    for seg in segments:
        if ": " in seg:
            key, val = seg.split(": ", 1)
            fields[key] = val
    return rec_num, fields


def _extract_sth_entry(obj: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    if "sth" in obj and isinstance(obj["sth"], dict):
        return obj["sth"], obj.get("sig")
    if "sig" in obj and isinstance(obj["sig"], str) and "tree_size" in obj:
        sth_copy = {k: v for k, v in obj.items() if k != "sig"}
        return sth_copy, obj["sig"]
    return obj, None


def load_sth_entries(path: str) -> list[tuple[dict[str, Any], str | None]]:
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read().strip()
    if not raw:
        raise ValueError(f"Empty STH file: {path}")

    # Single JSON object (possibly multi-line)
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return [_extract_sth_entry(parsed)]
        if isinstance(parsed, list):
            return [_extract_sth_entry(item) for item in parsed]
    except json.JSONDecodeError:
        pass

    entries: list[tuple[dict[str, Any], str | None]] = []
    for lineno, line in enumerate(raw.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        parsed_line = json.loads(stripped)
        if not isinstance(parsed_line, dict):
            raise ValueError(f"Invalid STH object at line {lineno} of {path}")
        entries.append(_extract_sth_entry(parsed_line))
    if not entries:
        raise ValueError(f"No STH entries found in {path}")
    return entries


def verify_sth_object(
    sth_obj: dict[str, Any],
    sig_hex: str | None,
    pub_key: Ed25519PublicKey,
    expected_key_id: str,
    *,
    require_signature: bool = True,
) -> tuple[bool, str, bytes]:
    """Validate STH fields, canonical JSON, key_id, and Ed25519 signature."""
    try:
        canon_bytes = canonicalize_sth(sth_obj)
    except Exception as exc:  # noqa: BLE001
        return False, f"FAIL:STH_INVALID_FORMAT ({exc})", b""

    if str(sth_obj.get("key_id", "")) != expected_key_id:
        return (
            False,
            f"FAIL:STH_KEY_ID_MISMATCH (got {sth_obj.get('key_id')}, expected {expected_key_id})",
            canon_bytes,
        )

    root_hex = str(sth_obj.get("root_hash", ""))
    if len(root_hex) != 64:
        return False, "FAIL:STH_INVALID_FORMAT (invalid root_hash length)", canon_bytes

    if require_signature or sig_hex is not None:
        if not sig_hex or len(sig_hex) != 128:
            return False, "FAIL:STH_INVALID_SIGNATURE (missing or invalid length)", canon_bytes
        try:
            sig_bytes = bytes.fromhex(sig_hex)
            pub_key.verify(sig_bytes, b"MDFP1-STH\n" + canon_bytes)
        except Exception:  # noqa: BLE001
            return False, "FAIL:STH_INVALID_SIGNATURE (Ed25519 verification failed)", canon_bytes

    return True, "OK", canon_bytes


def verify_tsa_token(
    sth_sha256_hex: str,
    tsr_path: str,
    ca_file: str | None,
    *,
    untrusted_file: str | None = None,
    openssl_bin: str = "openssl",
) -> tuple[bool, str]:
    """Verify an RFC 3161 .tsr file binds sth_sha256_hex via `openssl ts -verify`."""
    if not ca_file or not os.path.exists(ca_file):
        return False, "FAIL:TSA_VERIFICATION_FAILED (--tsa-ca CAfile is required and must exist)"
    if not os.path.exists(tsr_path):
        return False, f"FAIL:TSA_VERIFICATION_FAILED (TSR file not found: {tsr_path})"

    resolved = shutil.which(openssl_bin) or openssl_bin
    cmd = [
        resolved,
        "ts",
        "-verify",
        "-digest",
        sth_sha256_hex,
        "-in",
        tsr_path,
        "-CAfile",
        ca_file,
    ]
    if untrusted_file:
        cmd.extend(["-untrusted", untrusted_file])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return False, "FAIL:TSA_VERIFICATION_FAILED (openssl executable not found)"

    if proc.returncode != 0 or "Verification: OK" not in proc.stdout:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"rc={proc.returncode}"
        return False, f"FAIL:TSA_VERIFICATION_FAILED ({detail})"
    return True, "OK"


@dataclass
class VerificationResult:
    ok: bool
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    total_records: int = 0
    recalculated_root: str = ""
    last_recorded_root: str = ""
    sig_failures: int = 0
    tamper_failures: int = 0
    sth_verified_count: int = 0
    trust_basis_lines: list[str] = field(default_factory=list)
    has_external_checkpoint: bool = False
    audit_lines: list[str] = field(default_factory=list)
    solana_memo: str | None = None


def verify_journal(
    source: str,
    *,
    device_pubkey_hex: str = PINNED_DEVICE_PUBLIC_KEY_HEX,
    sth_log_path: str | None = None,
    checkpoint_path: str | None = None,
    solana_tx: str | None = None,
    solana_rpc: str = "https://api.mainnet-beta.solana.com",
    tsa_tsr_path: str | None = None,
    tsa_ca_path: str | None = None,
    tsa_untrusted_path: str | None = None,
    tsa_sth_path: str | None = None,
    openssl_bin: str = "openssl",
    solana_memo_fetcher=None,
) -> VerificationResult:
    """Run full independent verification across journal, STH chain, and external checkpoints."""
    res = VerificationResult(ok=False)

    records = fetch_lines(source)
    if not records:
        res.failures.append(f"FAIL:EMPTY_JOURNAL (Unable to load records from '{source}')")
        return res

    res.total_records = len(records)
    device_pub_bytes = bytes.fromhex(device_pubkey_hex)
    pub_key = Ed25519PublicKey.from_public_bytes(device_pub_bytes)
    expected_key_id = device_pubkey_hex[:16].lower()

    frontier = IncrementalMerkleFrontier()
    seen_leaves: dict[str, int] = {}
    leaf_hashes_bytes: list[bytes] = []
    prefix_roots_bytes: list[bytes] = []

    for idx, rec in enumerate(records):
        rec_num, parts = parse_journal_record(rec)
        seq_str = parts.get("SEQ", str(idx + 1))
        leaf_hex = parts.get("LEAF", "")
        recorded_root = parts.get("MERKLE_ROOT", "")
        sig_hex = parts.get("SIG", "")

        # 0. Sequential record numbering check
        if rec_num is not None and rec_num != idx + 1:
            res.tamper_failures += 1
            res.failures.append(
                f"FAIL:RECORD_NUMBER_GAP_OR_REORDER (line {idx + 1}: found RECORD #{rec_num}, expected #{idx + 1})"
            )

        # 1. Leaf hash format & uniqueness check (detect duplicated leaves)
        valid_leaf = False
        if len(leaf_hex) != 64 or "TAMPERED" in rec:
            res.tamper_failures += 1
            res.failures.append(
                f"FAIL:METADATA_TAMPER (Record #{idx + 1} Seq {seq_str}: invalid LEAF or tamper marker)"
            )
            leaf_digest = hashlib.sha256(f"INVALID_LEAF_{idx}".encode()).digest()
        else:
            try:
                leaf_digest = bytes.fromhex(leaf_hex)
                valid_leaf = len(leaf_digest) == 32
            except ValueError:
                valid_leaf = False
                leaf_digest = hashlib.sha256(f"BAD_HEX_{idx}".encode()).digest()
                res.tamper_failures += 1
                res.failures.append(
                    f"FAIL:METADATA_TAMPER (Record #{idx + 1} Seq {seq_str}: non-hex LEAF)"
                )

        if valid_leaf:
            if leaf_hex in seen_leaves:
                first_idx = seen_leaves[leaf_hex]
                res.tamper_failures += 1
                res.failures.append(
                    f"FAIL:DUPLICATED_LEAF (Record #{idx + 1} duplicates Record #{first_idx} leaf {leaf_hex[:16]}...)"
                )
            else:
                seen_leaves[leaf_hex] = idx + 1

        # 2. Canonical JSON metadata recomputation and field consistency check
        if "CANON" in parts:
            canon_str = parts["CANON"]
            expected_leaf = sha256_hex(b"\x00" + canon_str.encode("utf-8"))
            if not hmac.compare_digest(expected_leaf, leaf_hex.lower()):
                res.tamper_failures += 1
                res.failures.append(
                    f"FAIL:METADATA_TAMPER (Record #{idx + 1}: SHA-256(0x00||CANON) != LEAF)"
                )
            try:
                canon_obj = json.loads(canon_str)
                if not isinstance(canon_obj, dict):
                    raise ValueError("CANON is not a JSON object")
                if list(canon_obj.keys()) != sorted(canon_obj.keys()):
                    raise ValueError("CANON keys not in RFC 8785 sorted order")
                if str(canon_obj.get("frame_seq")) != parts.get("SEQ"):
                    raise ValueError("SEQ disagrees with CANON.frame_seq")
                if str(canon_obj.get("raw_sha256")) != parts.get("RAW_SHA256"):
                    raise ValueError("RAW_SHA256 disagrees with CANON.raw_sha256")
                if str(canon_obj.get("verdict")) != parts.get("VERDICT"):
                    raise ValueError("VERDICT disagrees with CANON.verdict")
                ev = str(canon_obj.get("event_type", ""))
                expected_type = "GHOST_EVENT" if ev.startswith("GHOST") else "AUTHENTIC"
                if parts.get("TYPE") != expected_type:
                    raise ValueError("TYPE disagrees with CANON.event_type")
            except Exception as exc:  # noqa: BLE001
                res.tamper_failures += 1
                res.failures.append(
                    f"FAIL:METADATA_TAMPER (Record #{idx + 1}: {exc})"
                )

        # 3. Cumulative RFC 6962 prefix Merkle root verification (catches swaps/reorders)
        expected_prefix_root_bytes = frontier.append_leaf_hash(leaf_digest)
        expected_prefix_root_hex = expected_prefix_root_bytes.hex()
        leaf_hashes_bytes.append(leaf_digest)
        prefix_roots_bytes.append(expected_prefix_root_bytes)

        if not hmac.compare_digest(expected_prefix_root_hex, recorded_root.lower()):
            res.tamper_failures += 1
            res.failures.append(
                f"FAIL:MERKLE_ROOT_MISMATCH (Record #{idx + 1} Seq {seq_str}: recorded root "
                f"{recorded_root[:16]}... != RFC6962 prefix root {expected_prefix_root_hex[:16]}...)"
            )

        # 4. Ed25519 signature verification against pinned device public key
        if len(sig_hex) != 128:
            res.sig_failures += 1
            res.failures.append(
                f"FAIL:INVALID_SIGNATURE (Record #{idx + 1} Seq {seq_str}: invalid length {len(sig_hex)})"
            )
        else:
            try:
                sig_bytes = bytes.fromhex(sig_hex)
                pub_key.verify(sig_bytes, f"MDFP1\n{recorded_root}".encode("utf-8"))
            except Exception:  # noqa: BLE001
                res.sig_failures += 1
                res.failures.append(
                    f"FAIL:INVALID_SIGNATURE (Record #{idx + 1} Seq {seq_str}: Ed25519 SIGNATURE MISMATCH)"
                )

    res.recalculated_root = prefix_roots_bytes[-1].hex()
    _, last_parts = parse_journal_record(records[-1])
    res.last_recorded_root = last_parts.get("MERKLE_ROOT", "")

    display_count = min(8, res.total_records)
    for rec in records[-display_count:]:
        _, parts = parse_journal_record(rec)
        seq = parts.get("SEQ", "?")
        rec_type = parts.get("TYPE", "?")
        verdict = parts.get("VERDICT", "?")
        root_part = parts.get("MERKLE_ROOT", "")[:12] + "..."
        sig_part = parts.get("SIG", "")[:12] + "..."
        res.audit_lines.append(
            f" Seq: {seq:5s} | Type: {rec_type:11s} | Root: {root_part} | Sig: {sig_part} | Status: {verdict}"
        )

    # 5. Optional internal STH log chain verification (--sth-log)
    sth_entries: list[tuple[dict[str, Any], str | None]] = []
    if sth_log_path:
        try:
            sth_entries = load_sth_entries(sth_log_path)
        except Exception as exc:  # noqa: BLE001
            res.failures.append(f"FAIL:STH_INVALID_FORMAT (Could not load sth.log: {exc})")
            sth_entries = []

        prev_sth_sha256 = "0" * 64
        prev_tree_size = 0
        for s_idx, (sth_obj, sth_sig) in enumerate(sth_entries, 1):
            ok_sth, reason, canon_bytes = verify_sth_object(
                sth_obj, sth_sig, pub_key, expected_key_id, require_signature=True
            )
            if not ok_sth:
                res.failures.append(f"{reason} (sth.log entry #{s_idx})")
                continue

            tree_size = int(sth_obj["tree_size"])
            if tree_size <= prev_tree_size:
                res.failures.append(
                    f"FAIL:STH_DECREASING_TREE_SIZE (sth.log entry #{s_idx}: tree_size={tree_size} <= prev={prev_tree_size})"
                )

            actual_prev = str(sth_obj["prev_sth_sha256"]).lower()
            if not hmac.compare_digest(actual_prev, prev_sth_sha256):
                res.failures.append(
                    f"FAIL:BROKEN_PREV_STH_CHAIN (sth.log entry #{s_idx}: prev_sth_sha256={actual_prev[:16]}... != expected {prev_sth_sha256[:16]}...)"
                )

            if tree_size <= 0:
                res.failures.append(
                    f"FAIL:STH_INVALID_FORMAT (sth.log entry #{s_idx} has non-positive tree_size={tree_size})"
                )
            elif tree_size > res.total_records:
                res.failures.append(
                    f"FAIL:TAIL_TRUNCATION (sth.log entry #{s_idx} claims tree_size={tree_size} > journal records={res.total_records})"
                )
            else:
                expected_r = prefix_roots_bytes[tree_size - 1]
                sth_r = bytes.fromhex(str(sth_obj["root_hash"]))
                proof = consistency_proof(tree_size, leaf_hashes_bytes, prehashed=True)
                if not verify_consistency(
                    tree_size,
                    res.total_records,
                    proof,
                    sth_r,
                    prefix_roots_bytes[-1],
                ) or not hmac.compare_digest(sth_r, expected_r):
                    res.failures.append(
                        f"FAIL:STH_JOURNAL_MISMATCH (sth.log entry #{s_idx} root_hash inconsistent with journal)"
                    )

            prev_sth_sha256 = sha256_hex(canon_bytes)
            prev_tree_size = tree_size
            res.sth_verified_count += 1

    # 6. External Checkpoint #1: Signed Tree Head file (--checkpoint STH_FILE)
    cp_entries: list[tuple[dict[str, Any], str | None]] = []
    if checkpoint_path:
        res.has_external_checkpoint = True
        try:
            cp_entries = load_sth_entries(checkpoint_path)
            cp_sth, cp_sig = cp_entries[-1]
        except Exception as exc:  # noqa: BLE001
            res.failures.append(f"FAIL:STH_INVALID_FORMAT (checkpoint load error: {exc})")
            cp_sth, cp_sig = None, None

        if cp_sth is not None:
            ok_cp, reason, _ = verify_sth_object(
                cp_sth,
                cp_sig,
                pub_key,
                expected_key_id,
                require_signature=(cp_sig is not None),
            )
            if not ok_cp:
                res.failures.append(f"{reason} (checkpoint {checkpoint_path})")
            else:
                cp_size = int(cp_sth["tree_size"])
                cp_root_hex = str(cp_sth["root_hash"]).lower()
                cp_root_bytes = bytes.fromhex(cp_root_hex)
                cp_label = f"tree_size={cp_size} root={cp_root_hex[:16]}... [{checkpoint_path}]"
                res.trust_basis_lines.append(
                    f"truncation/rollback detection is relative to checkpoint {cp_label} (source: file)"
                )

                if cp_size <= 0:
                    res.failures.append("FAIL:STH_INVALID_FORMAT (checkpoint tree_size <= 0)")
                elif res.total_records < cp_size:
                    res.failures.append(
                        f"FAIL:TAIL_TRUNCATION (journal tree_size={res.total_records} < checkpoint tree_size={cp_size}; rollback/truncation detected)"
                    )
                else:
                    proof = consistency_proof(cp_size, leaf_hashes_bytes, prehashed=True)
                    if not verify_consistency(
                        cp_size,
                        res.total_records,
                        proof,
                        cp_root_bytes,
                        prefix_roots_bytes[-1],
                    ):
                        res.failures.append(
                            f"FAIL:ROLLBACK_OR_FORK (journal does not consistently extend checkpoint tree_size={cp_size})"
                        )
                    if sth_entries and int(sth_entries[-1][0]["tree_size"]) < cp_size:
                        res.failures.append(
                            f"FAIL:ROLLBACK_OR_FORK (sth.log rolled back below checkpoint tree_size={cp_size})"
                        )

    # 7. External Checkpoint #2: Solana Memo (--solana-tx)
    if solana_tx:
        res.has_external_checkpoint = True
        fetcher = solana_memo_fetcher or fetch_solana_tx_memo
        try:
            memo = fetcher(solana_tx, solana_rpc)
        except Exception as exc:  # noqa: BLE001
            memo = None
            res.failures.append(f"FAIL:SOLANA_RPC_ERROR ({exc})")

        res.solana_memo = memo
        if not memo:
            res.failures.append("FAIL:SOLANA_ANCHOR_MISMATCH (SPL Memo not found in transaction)")
            res.trust_basis_lines.append(
                f"truncation/rollback detection is relative to checkpoint tx={solana_tx} (source: solana)"
            )
        else:
            memo_parts = memo.split("|")
            if len(memo_parts) < 3 or memo_parts[0] != "MDFP1":
                res.failures.append(f"FAIL:SOLANA_ANCHOR_MISMATCH (Unrecognized memo format: {memo})")
                res.trust_basis_lines.append(
                    f"truncation/rollback detection is relative to checkpoint tx={solana_tx} (source: solana)"
                )
            else:
                onchain_root = memo_parts[2].lower()
                memo_num = int(memo_parts[3]) if len(memo_parts) >= 4 and memo_parts[3].isdigit() else None
                cp_label = (
                    f"tx={solana_tx[:16]}... size_or_seq={memo_num if memo_num is not None else '?'} "
                    f"root={onchain_root[:16]}..."
                )
                res.trust_basis_lines.append(
                    f"truncation/rollback detection is relative to checkpoint {cp_label} (source: solana)"
                )

                match_pos: int | None = None
                for pos, root_b in enumerate(prefix_roots_bytes, 1):
                    if hmac.compare_digest(root_b.hex(), onchain_root):
                        match_pos = pos
                        break

                if match_pos is None:
                    if memo_num is not None and memo_num > res.total_records:
                        res.failures.append(
                            f"FAIL:TAIL_TRUNCATION (Solana anchor at {memo_num} exceeds journal records {res.total_records})"
                        )
                    else:
                        res.failures.append(
                            "FAIL:ROLLBACK_OR_FORK (On-chain Solana root not consistent with any prefix of journal)"
                        )
                else:
                    proof = consistency_proof(match_pos, leaf_hashes_bytes, prehashed=True)
                    if not verify_consistency(
                        match_pos,
                        res.total_records,
                        proof,
                        bytes.fromhex(onchain_root),
                        prefix_roots_bytes[-1],
                    ):
                        res.failures.append(
                            "FAIL:ROLLBACK_OR_FORK (RFC 6962 consistency proof failed from Solana anchor)"
                        )

    # 8. External Checkpoint #3: RFC 3161 TSA Token (--tsa-tsr)
    if tsa_tsr_path:
        res.has_external_checkpoint = True
        tsa_sth: dict[str, Any] | None = None
        tsa_sig: str | None = None

        sth_source_path = tsa_sth_path or checkpoint_path or sth_log_path
        if not sth_source_path:
            res.failures.append(
                "FAIL:TSA_VERIFICATION_FAILED (--tsa-sth, --checkpoint, or --sth-log is required alongside --tsa-tsr)"
            )
            res.trust_basis_lines.append(
                f"truncation/rollback detection is relative to checkpoint tsr={tsa_tsr_path} (source: tsa)"
            )
        else:
            try:
                loaded_tsa = load_sth_entries(sth_source_path)
                tsa_sth, tsa_sig = loaded_tsa[-1]
            except Exception as exc:  # noqa: BLE001
                res.failures.append(f"FAIL:TSA_VERIFICATION_FAILED (STH load error: {exc})")

        if tsa_sth is not None:
            ok_tsth, reason, tsa_canon = verify_sth_object(
                tsa_sth,
                tsa_sig,
                pub_key,
                expected_key_id,
                require_signature=(tsa_sig is not None),
            )
            tsa_digest_hex = sha256_hex(tsa_canon) if tsa_canon else ""
            tsa_size = int(tsa_sth.get("tree_size", 0))
            tsa_root_hex = str(tsa_sth.get("root_hash", "")).lower()
            res.trust_basis_lines.append(
                "truncation/rollback detection is relative to checkpoint "
                f"tsr={tsa_tsr_path} tree_size={tsa_size} sth_sha256={tsa_digest_hex[:16]}... (source: tsa)"
            )
            if not ok_tsth:
                res.failures.append(f"{reason} (TSA STH)")
            else:
                ok_tsr, tsr_reason = verify_tsa_token(
                    tsa_digest_hex,
                    tsa_tsr_path,
                    tsa_ca_path,
                    untrusted_file=tsa_untrusted_path,
                    openssl_bin=openssl_bin,
                )
                if not ok_tsr:
                    res.failures.append(tsr_reason)
                elif tsa_size <= 0:
                    res.failures.append("FAIL:STH_INVALID_FORMAT (TSA STH tree_size <= 0)")
                elif res.total_records < tsa_size:
                    res.failures.append(
                        f"FAIL:TAIL_TRUNCATION (journal tree_size={res.total_records} < TSA STH tree_size={tsa_size})"
                    )
                else:
                    proof = consistency_proof(tsa_size, leaf_hashes_bytes, prehashed=True)
                    if not verify_consistency(
                        tsa_size,
                        res.total_records,
                        proof,
                        bytes.fromhex(tsa_root_hex),
                        prefix_roots_bytes[-1],
                    ):
                        res.failures.append(
                            f"FAIL:ROLLBACK_OR_FORK (journal does not extend TSA-anchored STH tree_size={tsa_size})"
                        )

    if not res.has_external_checkpoint:
        res.trust_basis_lines.append(
            "truncation/rollback detection is relative to checkpoint none (source: none)"
        )
        res.warnings.append("WARNING: tail truncation NOT detectable.")

    res.ok = (
        len(res.failures) == 0
        and res.tamper_failures == 0
        and res.sig_failures == 0
        and hmac.compare_digest(res.recalculated_root, res.last_recorded_root.lower())
    )
    return res


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="MD-Confirm RTOS Independent Forensic Verifier CLI"
    )
    parser.add_argument(
        "source",
        nargs="?",
        default="http://127.0.0.1:9090/journal",
        help="URL or local path to tamper-evident journal",
    )
    parser.add_argument("--source", dest="opt_source", help="Alternative flag for journal source")
    parser.add_argument("--sth-log", dest="sth_log", help="Path to sth.log NDJSON Signed Tree Heads")
    parser.add_argument(
        "--checkpoint",
        dest="checkpoint",
        help="Trusted external STH file (verify append-only consistency old -> new)",
    )
    parser.add_argument(
        "--solana-tx",
        dest="solana_tx",
        help="Solana transaction signature for external root checkpoint verification",
    )
    parser.add_argument(
        "--rpc",
        default=os.environ.get("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com"),
        help="Solana RPC endpoint",
    )
    parser.add_argument("--tsa-tsr", dest="tsa_tsr", help="Path to RFC 3161 .tsr timestamp token")
    parser.add_argument("--tsa-ca", dest="tsa_ca", help="CA certificate PEM for openssl ts -verify")
    parser.add_argument(
        "--tsa-untrusted",
        dest="tsa_untrusted",
        help="Optional untrusted/intermediate TSA cert PEM",
    )
    parser.add_argument(
        "--tsa-sth",
        dest="tsa_sth",
        help="STH JSON covered by --tsa-tsr (defaults to --checkpoint or --sth-log)",
    )
    parser.add_argument(
        "--openssl-bin",
        dest="openssl_bin",
        default="openssl",
        help="OpenSSL binary path for --tsa-tsr verification (default: openssl)",
    )
    parser.add_argument(
        "--device-pubkey",
        default=PINNED_DEVICE_PUBLIC_KEY_HEX,
        help="Pinned Device Ed25519 Public Key (hex)",
    )
    args = parser.parse_args(argv)
    source = args.opt_source if args.opt_source else args.source

    print("========================================================================")
    print(" MD-CONFIRM RTOS: INDEPENDENT FORENSIC VERIFIER CLI                     ")
    print(" Standards: RFC 6962 + RFC 8032 + RFC 8785 + External Checkpoints       ")
    print("========================================================================")
    print(f"[*] Journal Source        : {source}")
    print(f"[*] Pinned Device PubKey  : {args.device_pubkey[:16]}...{args.device_pubkey[-16:]}")

    res = verify_journal(
        source,
        device_pubkey_hex=args.device_pubkey,
        sth_log_path=args.sth_log,
        checkpoint_path=args.checkpoint,
        solana_tx=args.solana_tx,
        solana_rpc=args.rpc,
        tsa_tsr_path=args.tsa_tsr,
        tsa_ca_path=args.tsa_ca,
        tsa_untrusted_path=args.tsa_untrusted,
        tsa_sth_path=args.tsa_sth,
        openssl_bin=args.openssl_bin,
    )

    print(f"[+] Loaded {res.total_records} sealed forensic records.")
    if res.audit_lines:
        print(
            f"\n--- AUDIT TRAIL (Showing most recent {len(res.audit_lines)} of {res.total_records} sealed entries) ---"
        )
        for line in res.audit_lines:
            print(line)

    print("\n------------------------------------------------------------------------")
    print(f" Total Sealed Records Audited : {res.total_records}")
    print(f" Recalculated Merkle Root     : {res.recalculated_root}")
    print(f" Last Recorded Merkle Root    : {res.last_recorded_root}")
    if args.sth_log:
        print(f" STH Chain Entries Verified   : {res.sth_verified_count}")

    for basis in res.trust_basis_lines:
        print(f" Trust Basis                  : {basis}")
    for warn in res.warnings:
        print(f" {warn}")

    if res.failures:
        print("\n--- DETECTED INTEGRITY FAILURES ---")
        for fail in res.failures:
            print(f" [FAIL] {fail}")

    print("========================================================================")
    if res.ok:
        if res.has_external_checkpoint:
            print(
                " AUDIT VERDICT                : root, signature, and checkpoint/anchor verified [PASS]"
            )
        else:
            print(" AUDIT VERDICT                : root and signature verified [PASS]")
        print("========================================================================")
        return 0

    print(" AUDIT VERDICT                : VERIFICATION FAILED")
    print("========================================================================")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
