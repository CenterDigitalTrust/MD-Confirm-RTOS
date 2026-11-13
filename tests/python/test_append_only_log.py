"""Comprehensive tests for Task 3: verifiable append-only log (T2).

Covers:
  - All 8 required named attack / failure scenarios
  - Verifier trust-basis reporting (file | solana | tsa | none + truncation warning)
  - End-to-end C++ SealEngine -> Python verifier interoperability (pinned key)
  - Event-triggered anchor_outbox.jsonl + host/anchor/md_anchor.py consumer
  - RFC 3161 second witness host/tsa/md_tsa.py + openssl ts verification
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
from unittest import mock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "host" / "verify-cli"))
sys.path.insert(0, str(REPO_ROOT / "host" / "tsa"))
sys.path.insert(0, str(REPO_ROOT / "host" / "anchor"))

import md_anchor  # noqa: E402
import md_tsa  # noqa: E402
import md_verify_cli  # noqa: E402
import merkle_rfc6962 as m6962  # noqa: E402

# Matches SHA-256("QNX_NEUTRINO_8.0_ADAS_DEVICE_KEY_SEED_2026") in qnx/seal/md-seal.cpp
DEVICE_SEED = bytes.fromhex(
    "f380221e5e91e1bbfde4eebdc1ae5dc5c9451711bbc4d74f31ce69280c1811e8"
)
ALT_SEED = bytes(range(10, 42))


def _canonical_json(obj: dict) -> str:
    ordered = {k: obj[k] for k in sorted(obj.keys())}
    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False)


def _build_synthetic_bundle(
    seed: bytes = DEVICE_SEED,
    count: int = 12,
    sth_every: int = 4,
    ghost_indices: set[int] | None = None,
    device_id: str = "qnx-8.0-adas-node-01",
    start_seq: int = 1,
    salt: str = "",
) -> dict:
    """Build valid journal lines, STH entries, leaves, and roots for attack tests."""
    ghosts = ghost_indices or set()
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub_hex = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    key_id = pub_hex[:16]

    leaves_hex: list[str] = []
    journal_lines: list[str] = []
    sth_entries: list[dict] = []
    roots_hex: list[str] = []
    prev_sth_sha256 = "0" * 64

    for idx in range(1, count + 1):
        seq = start_seq + idx - 1
        is_ghost = idx in ghosts
        verdict = "SPOOF_REJECTED" if is_ghost else "AUTHENTIC"
        rec_type = "GHOST_EVENT" if is_ghost else "AUTHENTIC"
        ev_type = "GHOST_EVENT_WATCHDOG" if is_ghost else "AUTHENTIC_FRAME"
        raw_sha = hashlib.sha256(f"{salt}frame-{seq}".encode("utf-8")).hexdigest()
        canon_obj = {
            "client_time_ns": 1700000000000000000 + idx * 1_000_000,
            "device_id": device_id,
            "event_type": ev_type,
            "frame_seq": seq,
            "ncc": 0.1 if is_ghost else 0.92,
            "pce_db": 1.2 if is_ghost else 31.5,
            "pce_linear": 1.3 if is_ghost else 1412.5,
            "raw_sha256": raw_sha,
            "scenario": 2 if is_ghost else 1,
            "verdict": verdict,
        }
        canon_str = _canonical_json(canon_obj)
        leaf_hex = m6962.leaf_hash(canon_str.encode("utf-8")).hex()
        leaves_hex.append(leaf_hex)
        root_hex = md_verify_cli.compute_merkle_root(leaves_hex)
        roots_hex.append(root_hex)
        sig_hex = priv.sign(f"MDFP1\n{root_hex}".encode("utf-8")).hex()

        line = (
            f"RECORD #{idx} | SEQ: {seq} | TYPE: {rec_type} | LEAF: {leaf_hex} | "
            f"MERKLE_ROOT: {root_hex} | SIG: {sig_hex} | RAW_SHA256: {raw_sha} | "
            f"VERDICT: {verdict} | CANON: {canon_str}"
        )
        journal_lines.append(line)

        if is_ghost or (idx % sth_every == 0):
            sth_obj = {
                "version": 1,
                "device_id": device_id,
                "tree_size": idx,
                "root_hash": root_hex,
                "timestamp": canon_obj["client_time_ns"],
                "prev_sth_sha256": prev_sth_sha256,
                "key_id": key_id,
            }
            sth_canon = md_verify_cli.canonicalize_sth(sth_obj)
            sth_sig = priv.sign(b"MDFP1-STH\n" + sth_canon).hex()
            sth_entries.append({"sth": sth_obj, "sig": sth_sig})
            prev_sth_sha256 = hashlib.sha256(sth_canon).hexdigest()

    return {
        "pub_hex": pub_hex,
        "leaves_hex": leaves_hex,
        "roots_hex": roots_hex,
        "journal_lines": journal_lines,
        "sth_entries": sth_entries,
    }


def _write_lines(path: pathlib.Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_sth_log(path: pathlib.Path, entries: list[dict]) -> None:
    path.write_text(
        "\n".join(json.dumps(item, separators=(",", ":")) for item in entries) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Trust Basis Output Tests (Item 5)
# ---------------------------------------------------------------------------

def test_trust_basis_none_emits_warning():
    bundle = _build_synthetic_bundle(count=8, sth_every=4)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=(os.name == "nt")) as tmpdir:
        d = pathlib.Path(tmpdir)
        jpath = d / "journal.log"
        _write_lines(jpath, bundle["journal_lines"])

        proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "host" / "verify-cli" / "md_verify_cli.py"),
                str(jpath),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    assert proc.returncode == 0
    assert (
        "truncation/rollback detection is relative to checkpoint none (source: none)"
        in proc.stdout
    )
    assert "WARNING: tail truncation NOT detectable." in proc.stdout


def test_trust_basis_file_and_solana_sources():
    bundle = _build_synthetic_bundle(count=8, sth_every=4)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=(os.name == "nt")) as tmpdir:
        d = pathlib.Path(tmpdir)
        jpath = d / "journal.log"
        cpath = d / "cp.sth"
        _write_lines(jpath, bundle["journal_lines"])
        cpath.write_text(json.dumps(bundle["sth_entries"][0]), encoding="utf-8")

        res_file = md_verify_cli.verify_journal(
            str(jpath), checkpoint_path=str(cpath)
        )
        assert res_file.ok is True
        assert not res_file.warnings
        assert any("(source: file)" in ln for ln in res_file.trust_basis_lines)

        cp_root = bundle["roots_hex"][3]
        memo = f"MDFP1|qnx-8.0-adas-node-01|{cp_root}|4"
        res_sol = md_verify_cli.verify_journal(
            str(jpath),
            solana_tx="4N4vyHbzTestTxSignature1234567890",
            solana_memo_fetcher=lambda _tx, _rpc: memo,
        )
        assert res_sol.ok is True
        assert any("(source: solana)" in ln for ln in res_sol.trust_basis_lines)


# ---------------------------------------------------------------------------
# 8 Required Specific Named Failure Cases (Item 4)
# ---------------------------------------------------------------------------

def test_attack_tail_truncation():
    """Tail truncation: remove trailing entries after a trusted checkpoint."""
    bundle = _build_synthetic_bundle(count=12, sth_every=4)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=(os.name == "nt")) as tmpdir:
        d = pathlib.Path(tmpdir)
        jpath = d / "truncated.log"
        cpath = d / "checkpoint_12.sth"
        _write_lines(jpath, bundle["journal_lines"][:7])
        cpath.write_text(json.dumps(bundle["sth_entries"][-1]), encoding="utf-8")

        res_cp = md_verify_cli.verify_journal(str(jpath), checkpoint_path=str(cpath))
        assert res_cp.ok is False
        assert any("FAIL:TAIL_TRUNCATION" in f for f in res_cp.failures)

        memo_12 = f"MDFP1|qnx-8.0-adas-node-01|{bundle['roots_hex'][-1]}|12"
        res_sol = md_verify_cli.verify_journal(
            str(jpath),
            solana_tx="FakeSolanaTx12",
            solana_memo_fetcher=lambda _t, _r: memo_12,
        )
        assert res_sol.ok is False
        assert any("FAIL:TAIL_TRUNCATION" in f for f in res_sol.failures)


def test_attack_rollback_to_earlier_valid_state():
    """Rollback: node reverts to earlier prefix and appends divergent validly signed branch."""
    bundle_orig = _build_synthetic_bundle(count=10, sth_every=4, salt="orig-")
    # Attacker rolls back after leaf 3 and appends 9 validly-signed records (total=12 > cp=8)
    priv = Ed25519PrivateKey.from_private_bytes(DEVICE_SEED)
    fork_lines = list(bundle_orig["journal_lines"][:3])
    fork_leaves = list(bundle_orig["leaves_hex"][:3])
    for idx in range(4, 13):
        canon_obj = {
            "client_time_ns": 1700000900000000000 + idx * 1_000_000,
            "device_id": "qnx-8.0-adas-node-01",
            "event_type": "AUTHENTIC_FRAME",
            "frame_seq": idx,
            "ncc": 0.90,
            "pce_db": 29.0,
            "pce_linear": 794.0,
            "raw_sha256": hashlib.sha256(f"fork-{idx}".encode()).hexdigest(),
            "scenario": 1,
            "verdict": "AUTHENTIC",
        }
        cstr = _canonical_json(canon_obj)
        lhex = m6962.leaf_hash(cstr.encode("utf-8")).hex()
        fork_leaves.append(lhex)
        rhex = md_verify_cli.compute_merkle_root(fork_leaves)
        shex = priv.sign(f"MDFP1\n{rhex}".encode("utf-8")).hex()
        fork_lines.append(
            f"RECORD #{idx} | SEQ: {idx} | TYPE: AUTHENTIC | LEAF: {lhex} | "
            f"MERKLE_ROOT: {rhex} | SIG: {shex} | RAW_SHA256: {canon_obj['raw_sha256']} | "
            f"VERDICT: AUTHENTIC | CANON: {cstr}"
        )

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=(os.name == "nt")) as tmpdir:
        d = pathlib.Path(tmpdir)
        jpath = d / "rolled_back_fork.log"
        jpath_snap = d / "rolled_back_snapshot.log"
        cpath = d / "checkpoint_8.sth"
        _write_lines(jpath, fork_lines)
        _write_lines(jpath_snap, bundle_orig["journal_lines"][:4])
        cpath.write_text(json.dumps(bundle_orig["sth_entries"][1]), encoding="utf-8")

        res_fork = md_verify_cli.verify_journal(str(jpath), checkpoint_path=str(cpath))
        res_snap = md_verify_cli.verify_journal(str(jpath_snap), checkpoint_path=str(cpath))
    assert res_fork.ok is False
    assert any("FAIL:ROLLBACK_OR_FORK" in f for f in res_fork.failures)
    assert res_snap.ok is False
    assert any("FAIL:TAIL_TRUNCATION" in f for f in res_snap.failures)


def test_attack_swap_of_two_records():
    """Swap of two records fails prefix root checks even if RECORD # numbers are renumbered."""
    bundle = _build_synthetic_bundle(count=8, sth_every=4)
    swapped = list(bundle["journal_lines"])
    swapped[2], swapped[3] = swapped[3], swapped[2]

    swapped_renum = list(swapped)
    swapped_renum[2] = swapped_renum[2].replace("RECORD #4 |", "RECORD #3 |", 1)
    swapped_renum[3] = swapped_renum[3].replace("RECORD #3 |", "RECORD #4 |", 1)

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=(os.name == "nt")) as tmpdir:
        d = pathlib.Path(tmpdir)
        jpath = d / "swapped.log"
        jpath_renum = d / "swapped_renum.log"
        _write_lines(jpath, swapped)
        _write_lines(jpath_renum, swapped_renum)
        res = md_verify_cli.verify_journal(str(jpath))
        res_renum = md_verify_cli.verify_journal(str(jpath_renum))

    assert res.ok is False
    assert any("FAIL:RECORD_NUMBER_GAP_OR_REORDER" in f for f in res.failures)
    assert any("FAIL:MERKLE_ROOT_MISMATCH" in f for f in res.failures)
    assert res_renum.ok is False
    assert any("FAIL:MERKLE_ROOT_MISMATCH" in f for f in res_renum.failures)


def test_attack_tail_replaced_and_resigned_with_other_key():
    """Tail replaced by records signed with a different Ed25519 private key."""
    bundle = _build_synthetic_bundle(count=6, sth_every=4)
    alt_priv = Ed25519PrivateKey.from_private_bytes(ALT_SEED)
    leaves = list(bundle["leaves_hex"])
    lines = list(bundle["journal_lines"])

    for pos in (4, 5):  # replace records #5 and #6 using alt_priv
        canon_obj = {
            "client_time_ns": 1700000100000000000 + pos,
            "device_id": "qnx-8.0-adas-node-01",
            "event_type": "AUTHENTIC_FRAME",
            "frame_seq": pos + 1,
            "ncc": 0.99,
            "pce_db": 40.0,
            "pce_linear": 10000.0,
            "raw_sha256": hashlib.sha256(f"evil-{pos}".encode()).hexdigest(),
            "scenario": 1,
            "verdict": "AUTHENTIC",
        }
        cstr = _canonical_json(canon_obj)
        lhex = m6962.leaf_hash(cstr.encode("utf-8")).hex()
        leaves[pos] = lhex
        rhex = md_verify_cli.compute_merkle_root(leaves[: pos + 1])
        evil_sig = alt_priv.sign(f"MDFP1\n{rhex}".encode("utf-8")).hex()
        lines[pos] = (
            f"RECORD #{pos + 1} | SEQ: {pos + 1} | TYPE: AUTHENTIC | LEAF: {lhex} | "
            f"MERKLE_ROOT: {rhex} | SIG: {evil_sig} | RAW_SHA256: {canon_obj['raw_sha256']} | "
            f"VERDICT: AUTHENTIC | CANON: {cstr}"
        )

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=(os.name == "nt")) as tmpdir:
        jpath = pathlib.Path(tmpdir) / "resigned_tail.log"
        _write_lines(jpath, lines)
        res = md_verify_cli.verify_journal(str(jpath))

    assert res.ok is False
    assert res.sig_failures >= 2
    assert any("FAIL:INVALID_SIGNATURE" in f for f in res.failures)


def test_attack_duplicated_leaf():
    """Duplicated leaf even with recomputed root and valid signature is rejected."""
    bundle = _build_synthetic_bundle(count=4, sth_every=4)
    priv = Ed25519PrivateKey.from_private_bytes(DEVICE_SEED)
    leaves = list(bundle["leaves_hex"])
    lines = list(bundle["journal_lines"])

    dup_leaf = leaves[1]
    leaves.append(dup_leaf)
    new_root = md_verify_cli.compute_merkle_root(leaves)
    new_sig = priv.sign(f"MDFP1\n{new_root}".encode("utf-8")).hex()
    dup_canon = lines[1].split(" | CANON: ", 1)[1]
    raw_sha = json.loads(dup_canon)["raw_sha256"]
    lines.append(
        f"RECORD #5 | SEQ: 2 | TYPE: AUTHENTIC | LEAF: {dup_leaf} | "
        f"MERKLE_ROOT: {new_root} | SIG: {new_sig} | RAW_SHA256: {raw_sha} | "
        f"VERDICT: AUTHENTIC | CANON: {dup_canon}"
    )

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=(os.name == "nt")) as tmpdir:
        jpath = pathlib.Path(tmpdir) / "dup_leaf.log"
        _write_lines(jpath, lines)
        res = md_verify_cli.verify_journal(str(jpath))

    assert res.ok is False
    assert any("FAIL:DUPLICATED_LEAF" in f for f in res.failures)


def test_attack_one_flipped_bit_in_metadata():
    """Flipping one bit in CANON or pipe metadata triggers FAIL:METADATA_TAMPER."""
    bundle = _build_synthetic_bundle(count=3, sth_every=4)
    lines_canon = list(bundle["journal_lines"])
    # Flip 1 character ('9' -> '8') inside pce_db in CANON JSON of record #2
    lines_canon[1] = lines_canon[1].replace('"pce_db":31.5', '"pce_db":30.5')

    lines_field = list(bundle["journal_lines"])
    lines_field[1] = lines_field[1].replace("VERDICT: AUTHENTIC", "VERDICT: AUTHENTID")

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=(os.name == "nt")) as tmpdir:
        d = pathlib.Path(tmpdir)
        j1 = d / "flip_canon.log"
        j2 = d / "flip_field.log"
        _write_lines(j1, lines_canon)
        _write_lines(j2, lines_field)
        res1 = md_verify_cli.verify_journal(str(j1))
        res2 = md_verify_cli.verify_journal(str(j2))

    assert res1.ok is False
    assert any("FAIL:METADATA_TAMPER" in f for f in res1.failures)
    assert res2.ok is False
    assert any("FAIL:METADATA_TAMPER" in f for f in res2.failures)


def test_attack_sth_with_decreasing_tree_size():
    """Validly signed STH whose tree_size decreases relative to the previous STH."""
    bundle = _build_synthetic_bundle(count=8, sth_every=4)
    priv = Ed25519PrivateKey.from_private_bytes(DEVICE_SEED)
    sths = list(bundle["sth_entries"])
    first_canon = md_verify_cli.canonicalize_sth(sths[0]["sth"])
    # Craft second STH claiming smaller tree_size=2 with valid prev_sth_sha256 & Ed25519 sig
    bad_sth = {
        "version": 1,
        "device_id": "qnx-8.0-adas-node-01",
        "tree_size": 2,
        "root_hash": bundle["roots_hex"][1],
        "timestamp": 1700000009000000000,
        "prev_sth_sha256": hashlib.sha256(first_canon).hexdigest(),
        "key_id": bundle["pub_hex"][:16],
    }
    bad_canon = md_verify_cli.canonicalize_sth(bad_sth)
    bad_sig = priv.sign(b"MDFP1-STH\n" + bad_canon).hex()
    sths[1] = {"sth": bad_sth, "sig": bad_sig}

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=(os.name == "nt")) as tmpdir:
        d = pathlib.Path(tmpdir)
        jpath = d / "journal.log"
        spath = d / "sth.log"
        _write_lines(jpath, bundle["journal_lines"])
        _write_sth_log(spath, sths)
        res = md_verify_cli.verify_journal(str(jpath), sth_log_path=str(spath))

    assert res.ok is False
    assert any("FAIL:STH_DECREASING_TREE_SIZE" in f for f in res.failures)


def test_attack_broken_prev_sth_chain():
    """Validly signed STH with broken prev_sth_sha256 hash chain."""
    bundle = _build_synthetic_bundle(count=8, sth_every=4)
    priv = Ed25519PrivateKey.from_private_bytes(DEVICE_SEED)
    sths = list(bundle["sth_entries"])
    broken_sth = dict(sths[1]["sth"])
    broken_sth["prev_sth_sha256"] = "f" * 64
    broken_canon = md_verify_cli.canonicalize_sth(broken_sth)
    broken_sig = priv.sign(b"MDFP1-STH\n" + broken_canon).hex()
    sths[1] = {"sth": broken_sth, "sig": broken_sig}

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=(os.name == "nt")) as tmpdir:
        d = pathlib.Path(tmpdir)
        jpath = d / "journal.log"
        spath = d / "sth.log"
        _write_lines(jpath, bundle["journal_lines"])
        _write_sth_log(spath, sths)
        res = md_verify_cli.verify_journal(str(jpath), sth_log_path=str(spath))

    assert res.ok is False
    assert any("FAIL:BROKEN_PREV_STH_CHAIN" in f for f in res.failures)


# ---------------------------------------------------------------------------
# End-to-End C++ SealEngine -> Python Verifier + Anchor Outbox Consumer
# ---------------------------------------------------------------------------

def test_cpp_seal_engine_e2e_with_python_verifier_and_outbox():
    cxx = shutil.which("g++") or shutil.which("clang++")
    cc = shutil.which("gcc") or shutil.which("clang")
    if not cxx or not cc:
        pytest.skip("C++ host compiler unavailable")

    cpp_driver = r"""
#include "mdfp_seal_core.h"
extern "C" {
#include "tweetnacl.h"
void randombytes(unsigned char* x, unsigned long long n) {
    for (unsigned long long i = 0; i < n; ++i) x[i] = static_cast<unsigned char>(i);
}
}
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

static const unsigned char kSeed[32] = {
    0xf3,0x80,0x22,0x1e,0x5e,0x91,0xe1,0xbb,0xfd,0xe4,0xee,0xbd,0xc1,0xae,0x5d,0xc5,
    0xc9,0x45,0x17,0x11,0xbb,0xc4,0xd7,0x4f,0x31,0xce,0x69,0x28,0x0c,0x18,0x11,0xe8
};
static const unsigned char kPub[32] = {
    0x7e,0xa8,0x1a,0xc6,0xc1,0xfc,0x3a,0x9a,0x56,0x7a,0x76,0x93,0xe3,0xd9,0x30,0xa5,
    0xc1,0x40,0xa3,0xa0,0x5f,0xa2,0x70,0xd7,0x63,0xf2,0x91,0x16,0x06,0x96,0xa4,0x68
};

int main(int argc, char** argv) {
    if (argc < 4) return 1;
    uint8_t sk[64];
    std::memcpy(sk, kSeed, 32);
    std::memcpy(sk + 32, kPub, 32);
    auto sign_fn = [&](const std::string& m) {
        std::vector<uint8_t> sm(m.size() + 64U);
        unsigned long long smlen = 0;
        crypto_sign(sm.data(), &smlen, reinterpret_cast<const uint8_t*>(m.data()), m.size(), sk);
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (int i = 0; i < 64; ++i) oss << std::setw(2) << static_cast<unsigned>(sm[i]);
        return oss.str();
    };
    mdfp::SealConfig cfg;
    cfg.journal_path = argv[1];
    cfg.sth_path = argv[2];
    cfg.outbox_path = argv[3];
    cfg.device_id = "qnx-8.0-adas-node-01";
    cfg.key_id = mdfp::key_id_from_pubkey_bytes(kPub);
    cfg.sth_interval = 32;
    mdfp::SealEngine eng(cfg, sign_fn);
    for (uint32_t seq = 1; seq <= 34; ++seq) {
        mdfp::SealInput in;
        in.hw_eof_ns = 1700000000000000000ULL + static_cast<uint64_t>(seq) * 1000000ULL;
        in.is_ghost_event = (seq == 11);
        in.frame_seq = seq;
        in.ncc = in.is_ghost_event ? 0.14 : 0.91;
        in.pce_db = in.is_ghost_event ? 1.8 : 30.25;
        in.pce_linear = in.is_ghost_event ? 1.5 : 1059.25;
        in.raw_sha256 = MdfpSha256::hash_hex(reinterpret_cast<const uint8_t*>(&seq), sizeof(seq));
        in.scenario = in.is_ghost_event ? 2U : 1U;
        in.verdict = in.is_ghost_event ? "SPOOF_REJECTED" : "AUTHENTIC";
        if (!eng.seal_record(in).io_ok) return 2;
    }
    return 0;
}
"""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=(os.name == "nt")) as tmpdir:
        d = pathlib.Path(tmpdir)
        driver_cpp = d / "driver.cpp"
        driver_cpp.write_text(cpp_driver, encoding="utf-8")
        tweet_obj = d / "tweetnacl.o"
        exe_path = d / ("driver.exe" if os.name == "nt" else "driver")

        subprocess.run(
            [cc, "-O2", "-c", str(REPO_ROOT / "qnx" / "common" / "tweetnacl.c"), "-o", str(tweet_obj)],
            check=True,
        )
        subprocess.run(
            [
                cxx,
                "-std=c++17",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-D_POSIX_C_SOURCE=200809L",
                f"-I{REPO_ROOT / 'qnx' / 'common'}",
                str(driver_cpp),
                str(tweet_obj),
                "-o",
                str(exe_path),
            ],
            check=True,
        )

        jpath = d / "journal.log"
        spath = d / "sth.log"
        opath = d / "anchor_outbox.jsonl"
        subprocess.run([str(exe_path), str(jpath), str(spath), str(opath)], check=True)

        # Save STH #1 (at GHOST_EVENT #11) as trusted external checkpoint
        sth_lines = [ln for ln in spath.read_text(encoding="utf-8").splitlines() if ln.strip()]
        assert len(sth_lines) == 2  # leaf #11 GHOST_EVENT + leaf #32 periodic K=32
        cp_path = d / "cp_11.sth"
        cp_path.write_text(sth_lines[0] + "\n", encoding="utf-8")

        # Python verifier verifies all 34 C++-produced records, full sth.log chain, and checkpoint
        proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "host" / "verify-cli" / "md_verify_cli.py"),
                str(jpath),
                "--sth-log",
                str(spath),
                "--checkpoint",
                str(cp_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "source: file" in proc.stdout

        # Outbox consumer processes both events in dry-run, advances cursor cleanly
        receipts_1 = md_anchor.consume_outbox(
            str(opath),
            "https://api.mainnet-beta.solana.com",
            "",
            dry_run=True,
        )
        assert len(receipts_1) == 2
        assert receipts_1[0]["tree_size"] == 11
        assert receipts_1[0]["event"] == "GHOST_EVENT"
        assert receipts_1[1]["tree_size"] == 32
        assert receipts_1[1]["event"] == "PERIODIC_STH"

        # Second invocation with no new outbox lines must emit zero duplicates
        receipts_2 = md_anchor.consume_outbox(
            str(opath),
            "https://api.mainnet-beta.solana.com",
            "",
            dry_run=True,
        )
        assert receipts_2 == []


# ---------------------------------------------------------------------------
# RFC 3161 TSA Client & Verifier Tests (Item 7)
# ---------------------------------------------------------------------------

def test_tsa_client_and_verifier_protocol_mocked():
    bundle = _build_synthetic_bundle(count=6, sth_every=3)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=(os.name == "nt")) as tmpdir:
        d = pathlib.Path(tmpdir)
        jpath = d / "journal.log"
        spath = d / "sth.log"
        tsr_path = d / "sth.tsr"
        ca_path = d / "tsa_ca.pem"
        _write_lines(jpath, bundle["journal_lines"])
        _write_sth_log(spath, bundle["sth_entries"])
        ca_path.write_text("-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n", encoding="utf-8")

        received_bodies: list[bytes] = []

        class MockTsaHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                received_bodies.append(self.rfile.read(length))
                self.send_response(200)
                self.send_header("Content-Type", "application/timestamp-reply")
                self.end_headers()
                self.wfile.write(b"DER-TSR-MOCK-BYTES")

            def log_message(self, format, *args):  # noqa: A002
                return

        server = HTTPServer(("127.0.0.1", 0), MockTsaHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            def fake_openssl_query(cmd, capture_output=True, text=True, check=False):
                out_idx = cmd.index("-out") + 1
                pathlib.Path(cmd[out_idx]).write_bytes(b"DER-TSQ-MOCK")
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            with mock.patch("md_tsa.subprocess.run", side_effect=fake_openssl_query):
                summary = md_tsa.request_rfc3161_timestamp(
                    str(spath),
                    f"http://127.0.0.1:{server.server_port}/tsr",
                    str(tsr_path),
                )
        finally:
            server.shutdown()
            server.server_close()

        assert received_bodies == [b"DER-TSQ-MOCK"]
        assert summary["tree_size"] == 6
        assert tsr_path.read_bytes() == b"DER-TSR-MOCK-BYTES"

        # Verifier passes when openssl ts -verify outputs Verification: OK
        with mock.patch(
            "md_verify_cli.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, stdout="Verification: OK\n", stderr=""),
        ):
            res_ok = md_verify_cli.verify_journal(
                str(jpath),
                sth_log_path=str(spath),
                tsa_tsr_path=str(tsr_path),
                tsa_ca_path=str(ca_path),
            )
        assert res_ok.ok is True
        assert any("(source: tsa)" in ln for ln in res_ok.trust_basis_lines)

        # Verifier fails when openssl ts -verify rejects digest/signature
        with mock.patch(
            "md_verify_cli.subprocess.run",
            return_value=subprocess.CompletedProcess([], 1, stdout="Verification: FAILED\n", stderr="digest mismatch"),
        ):
            res_bad = md_verify_cli.verify_journal(
                str(jpath),
                sth_log_path=str(spath),
                tsa_tsr_path=str(tsr_path),
                tsa_ca_path=str(ca_path),
            )
        assert res_bad.ok is False
        assert any("FAIL:TSA_VERIFICATION_FAILED" in f for f in res_bad.failures)


def test_tsa_real_openssl_end_to_end():
    openssl_bin = shutil.which("openssl")
    if not openssl_bin:
        pytest.skip("openssl CLI not installed on this host")

    bundle = _build_synthetic_bundle(count=6, sth_every=3)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=(os.name == "nt")) as tmpdir:
        d = pathlib.Path(tmpdir)
        jpath = d / "journal.log"
        spath = d / "sth.log"
        _write_lines(jpath, bundle["journal_lines"])
        _write_sth_log(spath, bundle["sth_entries"])

        ca_key = d / "ca.key"
        ca_crt = d / "ca.pem"
        tsa_key = d / "tsa.key"
        tsa_csr = d / "tsa.csr"
        tsa_crt = d / "tsa.pem"
        tsa_ext = d / "tsa.ext"
        tsa_conf = d / "tsa.cnf"
        tsr_out = d / "signed.tsr"
        serial_file = d / "tsa.srl"
        serial_file.write_text("01\n", encoding="utf-8")

        tsa_ext.write_text(
            "basicConstraints=CA:FALSE\n"
            "keyUsage=digitalSignature,nonRepudiation\n"
            "extendedKeyUsage=critical,timeStamping\n"
            "subjectKeyIdentifier=hash\n",
            encoding="utf-8",
        )
        tsa_conf.write_text(
            "[tsa]\n"
            "default_tsa = tsa_config1\n"
            "[tsa_config1]\n"
            f"serial = {serial_file.as_posix()}\n"
            f"signer_cert = {tsa_crt.as_posix()}\n"
            f"signer_key = {tsa_key.as_posix()}\n"
            f"certs = {ca_crt.as_posix()}\n"
            "signer_digest = sha256\n"
            "default_policy = 1.2.3.4.1\n"
            "other_policies = 1.2.3.4.5.6\n"
            "digests = sha256\n"
            "accuracy = secs:1\n",
            encoding="utf-8",
        )

        subprocess.run(
            [
                openssl_bin,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "30",
                "-keyout",
                str(ca_key),
                "-out",
                str(ca_crt),
                "-subj",
                "/CN=MD-Confirm-Test-CA",
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                openssl_bin,
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(tsa_key),
                "-out",
                str(tsa_csr),
                "-subj",
                "/CN=MD-Confirm-Test-TSA",
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                openssl_bin,
                "x509",
                "-req",
                "-in",
                str(tsa_csr),
                "-CA",
                str(ca_crt),
                "-CAkey",
                str(ca_key),
                "-CAcreateserial",
                "-out",
                str(tsa_crt),
                "-days",
                "30",
                "-extfile",
                str(tsa_ext),
            ],
            check=True,
            capture_output=True,
        )

        class RealOpenSslTsaHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                tsq_bytes = self.rfile.read(length)
                req_file = d / "incoming.tsq"
                resp_file = d / "outgoing.tsr"
                req_file.write_bytes(tsq_bytes)
                subprocess.run(
                    [
                        openssl_bin,
                        "ts",
                        "-reply",
                        "-config",
                        str(tsa_conf),
                        "-queryfile",
                        str(req_file),
                        "-out",
                        str(resp_file),
                    ],
                    check=True,
                    capture_output=True,
                )
                body = resp_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/timestamp-reply")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):  # noqa: A002
                return

        server = HTTPServer(("127.0.0.1", 0), RealOpenSslTsaHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            md_tsa.request_rfc3161_timestamp(
                str(spath),
                f"http://127.0.0.1:{server.server_port}",
                str(tsr_out),
                openssl_bin=openssl_bin,
            )
        finally:
            server.shutdown()
            server.server_close()

        proc_ok = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "host" / "verify-cli" / "md_verify_cli.py"),
                str(jpath),
                "--sth-log",
                str(spath),
                "--tsa-tsr",
                str(tsr_out),
                "--tsa-ca",
                str(ca_crt),
                "--tsa-untrusted",
                str(tsa_crt),
                "--openssl-bin",
                openssl_bin,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc_ok.returncode == 0, proc_ok.stdout + proc_ok.stderr
        assert "(source: tsa)" in proc_ok.stdout

        # Now truncate the journal after the TSA-timestamped STH and verify failure
        trunc_path = d / "truncated_after_tsa.log"
        _write_lines(trunc_path, bundle["journal_lines"][:4])
        cp_sth_file = d / "tsa_sth.json"
        cp_sth_file.write_text(json.dumps(bundle["sth_entries"][-1]), encoding="utf-8")

        res_trunc = md_verify_cli.verify_journal(
            str(trunc_path),
            tsa_tsr_path=str(tsr_out),
            tsa_ca_path=str(ca_crt),
            tsa_untrusted_path=str(tsa_crt),
            tsa_sth_path=str(cp_sth_file),
            openssl_bin=openssl_bin,
        )
        assert res_trunc.ok is False
        assert any("FAIL:TAIL_TRUNCATION" in f for f in res_trunc.failures)
