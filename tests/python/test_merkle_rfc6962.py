"""Exhaustive tests for RFC 6962 Merkle Tree Hash, inclusion, and consistency proofs.

Cross-checks host/verify-cli/merkle_rfc6962.py against a second, independent
recursive implementation written directly from RFC 6962 Sections 2.1, 2.1.1,
and 2.1.2 inside this test module across all tree sizes 1..64.
"""

from __future__ import annotations

import hashlib
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
VERIFY_CLI_DIR = os.path.join(REPO_ROOT, "host", "verify-cli")
if VERIFY_CLI_DIR not in sys.path:
    sys.path.insert(0, VERIFY_CLI_DIR)

import merkle_rfc6962 as m6962  # noqa: E402


# ---------------------------------------------------------------------------
# Independent Reference Implementation from RFC 6962 Sections 2.1 / 2.1.1 / 2.1.2
# ---------------------------------------------------------------------------

def _ref_k(n: int) -> int:
    k = 1
    while (k << 1) < n:
        k <<= 1
    return k


def ref_mth(d: list[bytes]) -> bytes:
    n = len(d)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashlib.sha256(b"\x00" + d[0]).digest()
    k = _ref_k(n)
    return hashlib.sha256(b"\x01" + ref_mth(d[:k]) + ref_mth(d[k:])).digest()


def ref_path(m: int, d: list[bytes]) -> list[bytes]:
    n = len(d)
    if n == 1:
        return []
    k = _ref_k(n)
    if m < k:
        return ref_path(m, d[:k]) + [ref_mth(d[k:])]
    return ref_path(m - k, d[k:]) + [ref_mth(d[:k])]


def ref_subproof(m: int, d: list[bytes], b: bool) -> list[bytes]:
    n = len(d)
    if m == n:
        return [] if b else [ref_mth(d)]
    k = _ref_k(n)
    if m <= k:
        return ref_subproof(m, d[:k], b) + [ref_mth(d[k:])]
    return ref_subproof(m - k, d[k:], False) + [ref_mth(d[:k])]


def ref_reconstruct_root_from_inclusion(
    leaf_data: bytes, leaf_idx: int, tree_size: int, proof: list[bytes]
) -> tuple[bytes, int]:
    """Independent recursive evaluator following RFC 6962 split directly."""
    if tree_size == 1:
        return hashlib.sha256(b"\x00" + leaf_data).digest(), 0
    k = _ref_k(tree_size)
    if leaf_idx < k:
        left_h, used = ref_reconstruct_root_from_inclusion(leaf_data, leaf_idx, k, proof)
        right_h = proof[used]
        return hashlib.sha256(b"\x01" + left_h + right_h).digest(), used + 1
    right_h, used = ref_reconstruct_root_from_inclusion(
        leaf_data, leaf_idx - k, tree_size - k, proof
    )
    left_h = proof[used]
    return hashlib.sha256(b"\x01" + left_h + right_h).digest(), used + 1


# ---------------------------------------------------------------------------
# Exhaustive Tests (1..64)
# ---------------------------------------------------------------------------

def _make_entries(n: int, prefix: bytes = b"leaf-") -> list[bytes]:
    return [f"{prefix.decode()}{i}".encode("utf-8") for i in range(n)]


def test_empty_and_known_sha256_empty_root():
    # RFC 6962 Section 2.1: MTH({}) = SHA-256()
    expected_empty = bytes.fromhex(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert m6962.merkle_tree_hash([]) == expected_empty
    assert ref_mth([]) == expected_empty
    assert m6962.IncrementalMerkleFrontier().root() == expected_empty


def test_exhaustive_merkle_tree_hash_and_frontier_1_to_64():
    entries = _make_entries(64)
    frontier = m6962.IncrementalMerkleFrontier()
    for n in range(1, 65):
        sub = entries[:n]
        actual = m6962.merkle_tree_hash(sub)
        expected = ref_mth(sub)
        frontier_root = frontier.append_raw(entries[n - 1])
        assert actual == expected, f"MTH mismatch at n={n}"
        assert frontier_root == expected, f"Frontier mismatch at n={n}"
        # Cross-check prehashed=True equivalence
        hashed = [m6962.leaf_hash(e) for e in sub]
        assert m6962.merkle_tree_hash(hashed, prehashed=True) == expected


def test_exhaustive_inclusion_proofs_1_to_64():
    entries = _make_entries(64)
    for n in range(1, 65):
        sub = entries[:n]
        root = ref_mth(sub)
        for m in range(n):
            proof = m6962.inclusion_proof(m, sub)
            ref_p = ref_path(m, sub)
            assert proof == ref_p, f"inclusion_proof mismatch at n={n}, m={m}"

            # Independent recursive verifier check
            rec_root, consumed = ref_reconstruct_root_from_inclusion(sub[m], m, n, proof)
            assert consumed == len(proof)
            assert rec_root == root

            # Tested verifier check
            assert m6962.verify_inclusion(sub[m], m, n, proof, root) is True
            assert (
                m6962.verify_inclusion(
                    m6962.leaf_hash(sub[m]), m, n, proof, root, prehashed=True
                )
                is True
            )

            # Negative inclusion checks on targeted boundary indices
            tampered_leaf = sub[m] + b"X"
            assert m6962.verify_inclusion(tampered_leaf, m, n, proof, root) is False
            tampered_root = bytes([root[0] ^ 0x01]) + root[1:]
            assert m6962.verify_inclusion(sub[m], m, n, proof, tampered_root) is False
            if n > 1:
                wrong_idx = (m + 1) % n
                assert m6962.verify_inclusion(sub[m], wrong_idx, n, proof, root) is False
                # Truncated or padded proof must fail
                assert m6962.verify_inclusion(sub[m], m, n, proof[:-1], root) is False
                assert (
                    m6962.verify_inclusion(sub[m], m, n, proof + [b"\x00" * 32], root)
                    is False
                )


def test_exhaustive_consistency_proofs_1_to_64():
    entries = _make_entries(64)
    roots = {n: ref_mth(entries[:n]) for n in range(1, 65)}

    for n in range(1, 65):
        sub_n = entries[:n]
        second_root = roots[n]
        for m in range(1, n + 1):
            first_root = roots[m]
            proof = m6962.consistency_proof(m, sub_n)
            ref_p = ref_subproof(m, sub_n, True)
            assert proof == ref_p, f"consistency_proof mismatch at m={m}, n={n}"
            assert (
                m6962.verify_consistency(m, n, proof, first_root, second_root) is True
            )

            # Mutated prefix or wrong root must fail
            bad_first = bytes([first_root[0] ^ 0x80]) + first_root[1:]
            assert (
                m6962.verify_consistency(m, n, proof, bad_first, second_root) is False
            )
            bad_second = bytes([second_root[0] ^ 0x80]) + second_root[1:]
            assert (
                m6962.verify_consistency(m, n, proof, first_root, bad_second) is False
            )

            # Proof corruption (flip one bit in each step, truncate, extend)
            if proof:
                bad_proof = list(proof)
                bad_proof[0] = bytes([bad_proof[0][0] ^ 0x01]) + bad_proof[0][1:]
                assert (
                    m6962.verify_consistency(m, n, bad_proof, first_root, second_root)
                    is False
                )
                assert (
                    m6962.verify_consistency(m, n, proof[:-1], first_root, second_root)
                    is False
                )
            assert (
                m6962.verify_consistency(
                    m, n, proof + [b"\x11" * 32], first_root, second_root
                )
                is False
            )


def test_consistency_rejects_shrink_fork_and_reorder():
    entries_a = _make_entries(17, b"logA-")
    entries_b = entries_a[:8] + _make_entries(9, b"forkB-")
    root_8 = m6962.merkle_tree_hash(entries_a[:8])
    root_17_a = m6962.merkle_tree_hash(entries_a)
    root_17_b = m6962.merkle_tree_hash(entries_b)

    # Shrink / rollback: n < m must always fail
    assert m6962.verify_consistency(17, 8, [], root_17_a, root_8) is False

    # Valid proof from A fails against forked tree B
    proof_a = m6962.consistency_proof(8, entries_a)
    assert m6962.verify_consistency(8, 17, proof_a, root_8, root_17_b) is False

    # Reordered prefix fails
    swapped = list(entries_a)
    swapped[2], swapped[3] = swapped[3], swapped[2]
    root_17_swapped = m6962.merkle_tree_hash(swapped)
    proof_swapped = m6962.consistency_proof(8, swapped)
    assert m6962.verify_consistency(8, 17, proof_swapped, root_8, root_17_swapped) is False
