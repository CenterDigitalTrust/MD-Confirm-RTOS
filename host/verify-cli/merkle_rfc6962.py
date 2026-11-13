"""RFC 6962 Merkle Tree Hash, Inclusion Proofs, and Consistency Proofs.

Implements strict Certificate Transparency (RFC 6962 Sections 2.1, 2.1.1, 2.1.2)
semantics with SHA-256 domain separation:
  - Empty tree root: SHA-256(b"")
  - Leaf hash:       SHA-256(b"\\x00" + data)
  - Interior node:   SHA-256(b"\\x01" + left + right)
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Sequence

EMPTY_HASH: bytes = hashlib.sha256(b"").digest()


def largest_power_of_two_less_than(n: int) -> int:
    """Return k = largest power of 2 strictly less than n (n >= 2)."""
    if n < 2:
        raise ValueError(f"n must be >= 2 to split subtree, got {n}")
    return 1 << ((n - 1).bit_length() - 1)


def leaf_hash(data: bytes | str) -> bytes:
    """Compute RFC 6962 Section 2.1 leaf hash: SHA-256(0x00 || data)."""
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    return hashlib.sha256(b"\x00" + raw).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Compute RFC 6962 Section 2.1 interior node hash: SHA-256(0x01 || left || right)."""
    if len(left) != 32 or len(right) != 32:
        raise ValueError("left and right child hashes must each be 32 bytes")
    return hashlib.sha256(b"\x01" + left + right).digest()


def _prepare_leaves(entries: Sequence[bytes | str], *, prehashed: bool) -> list[bytes]:
    if not prehashed:
        return [leaf_hash(entry) for entry in entries]
    leaves: list[bytes] = []
    for idx, entry in enumerate(entries):
        b = bytes.fromhex(entry) if isinstance(entry, str) else bytes(entry)
        if len(b) != 32:
            raise ValueError(f"prehashed leaf at index {idx} must be 32 bytes, got {len(b)}")
        leaves.append(b)
    return leaves


def _subtree_hash(leaves: Sequence[bytes], start: int, end: int) -> bytes:
    count = end - start
    if count <= 0:
        return EMPTY_HASH
    if count == 1:
        return leaves[start]
    k = largest_power_of_two_less_than(count)
    return node_hash(
        _subtree_hash(leaves, start, start + k),
        _subtree_hash(leaves, start + k, end),
    )


def merkle_tree_hash(entries: Sequence[bytes | str], *, prehashed: bool = False) -> bytes:
    """Compute RFC 6962 Section 2.1 Merkle Tree Hash MTH(D[n]).

    Args:
        entries: Raw entry bytes/strings, or 32-byte/64-hex leaf digests if prehashed=True.
        prehashed: Treat entries as already hashed with leaf_hash() (0x00 prefix).

    Returns:
        32-byte SHA-256 Merkle root digest.
    """
    if len(entries) == 0:
        return EMPTY_HASH
    leaves = _prepare_leaves(entries, prehashed=prehashed)
    return _subtree_hash(leaves, 0, len(leaves))


def _path_sub(leaves: Sequence[bytes], m: int, start: int, end: int) -> list[bytes]:
    n = end - start
    if n == 1:
        return []
    k = largest_power_of_two_less_than(n)
    if m < k:
        return _path_sub(leaves, m, start, start + k) + [_subtree_hash(leaves, start + k, end)]
    return _path_sub(leaves, m - k, start + k, end) + [_subtree_hash(leaves, start, start + k)]


def inclusion_proof(
    leaf_index: int,
    entries: Sequence[bytes | str],
    *,
    prehashed: bool = False,
) -> list[bytes]:
    """Generate an RFC 6962 Section 2.1.1 Merkle audit path PATH(m, D[n]).

    Args:
        leaf_index: 0-based index m in [0, len(entries) - 1].
        entries: Full list of tree entries D[n].
        prehashed: Treat entries as precomputed 32-byte leaf hashes.

    Returns:
        List of 32-byte sibling hashes ordered from leaf level toward the root.
    """
    n = len(entries)
    if n == 0 or leaf_index < 0 or leaf_index >= n:
        raise ValueError(f"leaf_index {leaf_index} out of range for tree_size {n}")
    leaves = _prepare_leaves(entries, prehashed=prehashed)
    return _path_sub(leaves, leaf_index, 0, n)


def verify_inclusion(
    leaf: bytes | str,
    leaf_index: int,
    tree_size: int,
    proof: Sequence[bytes],
    root_hash: bytes,
    *,
    prehashed: bool = False,
) -> bool:
    """Verify an RFC 6962 Section 2.1.1 inclusion proof against root_hash.

    Args:
        leaf: Raw leaf bytes/string (or 32-byte/64-hex leaf digest if prehashed=True).
        leaf_index: 0-based leaf index m.
        tree_size: Total number of leaves n in the tree.
        proof: Sequence of 32-byte audit path hashes.
        root_hash: Expected 32-byte root hash.
        prehashed: Set True if ``leaf`` is already a 32-byte (or hex) leaf hash.

    Returns:
        True iff the inclusion proof cryptographically binds ``leaf`` at
        ``leaf_index`` into the tree of size ``tree_size`` with ``root_hash``.
    """
    if tree_size <= 0 or leaf_index < 0 or leaf_index >= tree_size:
        return False
    if len(root_hash) != 32:
        return False

    try:
        if prehashed:
            current = bytes.fromhex(leaf) if isinstance(leaf, str) else bytes(leaf)
            if len(current) != 32:
                return False
        else:
            current = leaf_hash(leaf)
    except ValueError:
        return False

    if tree_size == 1:
        return len(proof) == 0 and hmac.compare_digest(current, root_hash)

    fn = leaf_index
    sn = tree_size - 1
    for p in proof:
        if len(p) != 32 or sn == 0:
            return False
        if (fn & 1) or (fn == sn):
            current = node_hash(p, current)
            while fn != 0 and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            current = node_hash(current, p)
        fn >>= 1
        sn >>= 1

    return sn == 0 and hmac.compare_digest(current, root_hash)


def _subproof(
    leaves: Sequence[bytes],
    m: int,
    start: int,
    end: int,
    complete_subtree: bool,
) -> list[bytes]:
    n = end - start
    if m == n:
        if complete_subtree:
            return []
        return [_subtree_hash(leaves, start, end)]

    k = largest_power_of_two_less_than(n)
    if m <= k:
        return _subproof(leaves, m, start, start + k, complete_subtree) + [
            _subtree_hash(leaves, start + k, end)
        ]
    return _subproof(leaves, m - k, start + k, end, False) + [
        _subtree_hash(leaves, start, start + k)
    ]


def consistency_proof(
    first_size: int,
    entries: Sequence[bytes | str],
    *,
    prehashed: bool = False,
) -> list[bytes]:
    """Generate an RFC 6962 Section 2.1.2 consistency proof PROOF(m, D[n]).

    Args:
        first_size: Prior tree size m (1 <= m <= len(entries)).
        entries: Full list of entries D[n] for the newer tree of size n.
        prehashed: Treat entries as precomputed 32-byte leaf hashes.

    Returns:
        List of 32-byte node hashes proving D[0:m] is a prefix of D[0:n].
    """
    n = len(entries)
    if first_size < 1 or first_size > n:
        raise ValueError(f"first_size {first_size} must satisfy 1 <= m <= {n}")
    leaves = _prepare_leaves(entries, prehashed=prehashed)
    return _subproof(leaves, first_size, 0, n, True)


def verify_consistency(
    first_size: int,
    second_size: int,
    proof: Sequence[bytes],
    first_root: bytes,
    second_root: bytes,
) -> bool:
    """Verify an RFC 6962 Section 2.1.2 consistency proof between two roots.

    Rejects shrinking trees (second_size < first_size), mismatched sizes/roots,
    malformed proof lengths, and forked/reordered histories.
    """
    if first_size <= 0 or second_size < first_size:
        return False
    if len(first_root) != 32 or len(second_root) != 32:
        return False

    if first_size == second_size:
        return len(proof) == 0 and hmac.compare_digest(first_root, second_root)

    if len(proof) == 0:
        return False
    for p in proof:
        if len(p) != 32:
            return False

    fn = first_size - 1
    sn = second_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1

    if fn == 0:
        fr = first_root
        sr = first_root
        idx = 0
    else:
        fr = proof[0]
        sr = proof[0]
        idx = 1

    for c in proof[idx:]:
        if sn == 0:
            return False
        if (fn & 1) or (fn == sn):
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while fn != 0 and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1

    return (
        sn == 0
        and hmac.compare_digest(fr, first_root)
        and hmac.compare_digest(sr, second_root)
    )


class IncrementalMerkleFrontier:
    """Append-only RFC 6962 frontier maintaining O(log N) complete subtree roots.

    Allows O(log N) amortized append and O(log N) root computation across an
    entire journal prefix verification pass.
    """

    def __init__(self) -> None:
        # Stack of (subtree_leaf_count, subtree_hash) strictly decreasing in height.
        self._stack: list[tuple[int, bytes]] = []
        self._count: int = 0

    @property
    def size(self) -> int:
        return self._count

    def append_leaf_hash(self, leaf_digest: bytes) -> bytes:
        if len(leaf_digest) != 32:
            raise ValueError("leaf_digest must be 32 bytes")
        h = leaf_digest
        sz = 1
        while self._stack and self._stack[-1][0] == sz:
            _, left_h = self._stack.pop()
            h = node_hash(left_h, h)
            sz <<= 1
        self._stack.append((sz, h))
        self._count += 1
        return self.root()

    def append_raw(self, data: bytes | str) -> bytes:
        return self.append_leaf_hash(leaf_hash(data))

    def root(self) -> bytes:
        if not self._stack:
            return EMPTY_HASH
        acc = self._stack[-1][1]
        for _, left_h in reversed(self._stack[:-1]):
            acc = node_hash(left_h, acc)
        return acc
