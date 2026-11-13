import pathlib
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "host" / "verify-cli"))

import md_verify_cli  # noqa: E402


def _make_journal(records_data):
    priv = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    pub_hex = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    leaves = []
    lines = []
    for idx, (seq, rec_type, verdict) in enumerate(records_data, start=1):
        leaf = md_verify_cli.sha256_hex(f"\x00leaf-{idx}-{seq}".encode("utf-8"))
        leaves.append(leaf)
        root = md_verify_cli.compute_merkle_root(leaves)
        sig = priv.sign(f"MDFP1\n{root}".encode("utf-8")).hex()
        raw_sha = md_verify_cli.sha256_hex(f"raw-{seq}".encode("utf-8"))
        lines.append(
            f"RECORD #{idx} | SEQ: {seq} | TYPE: {rec_type} | LEAF: {leaf} | "
            f"MERKLE_ROOT: {root} | SIG: {sig} | RAW_SHA256: {raw_sha} | VERDICT: {verdict}"
        )
    return pub_hex, "\n".join(lines) + "\n"


def test_pinned_pubkey_unchanged():
    assert md_verify_cli.PINNED_DEVICE_PUBLIC_KEY_HEX == (
        "7ea81ac6c1fc3a9a567a7693e3d930a5c140a3a05fa270d763f291160696a468"
    )


def test_sha256_and_node_hash():
    assert md_verify_cli.sha256_hex(b"") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    a = md_verify_cli.sha256_hex(b"\x00a")
    b = md_verify_cli.sha256_hex(b"\x00b")
    expected_node = md_verify_cli.sha256_hex(b"\x01" + bytes.fromhex(a) + bytes.fromhex(b))
    assert md_verify_cli.node_hash(a, b) == expected_node
    assert md_verify_cli.compute_merkle_root([a, b]) == expected_node


def test_verify_cli_passes_valid_journal():
    pub_hex, journal_text = _make_journal([
        (1, "AUTHENTIC", "VERIFIED_AUTHENTIC_SILICON"),
        (2, "AUTHENTIC", "VERIFIED_AUTHENTIC_SILICON"),
        (3, "GHOST_EVENT", "GHOST_EVENT_WATCHDOG_TRIPPED"),
    ])
    with tempfile.TemporaryDirectory() as tmpdir:
        jpath = pathlib.Path(tmpdir) / "journal.log"
        jpath.write_text(journal_text, encoding="utf-8")

        proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "host" / "verify-cli" / "md_verify_cli.py"),
                str(jpath),
                "--device-pubkey",
                pub_hex,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    assert proc.returncode == 0
    assert "root and signature verified [PASS]" in proc.stdout


def test_verify_cli_rejects_bad_signature():
    pub_hex, journal_text = _make_journal([
        (1, "AUTHENTIC", "VERIFIED_AUTHENTIC_SILICON"),
    ])
    lines = journal_text.splitlines()
    # Keep exact 128-hex length while corrupting signature
    parts = lines[0].split(" | ")
    for i, part in enumerate(parts):
        if part.startswith("SIG: "):
            sig = part[5:]
            flipped = ("f" if sig[0] != "f" else "0") + sig[1:]
            parts[i] = "SIG: " + flipped
    tampered = " | ".join(parts)

    with tempfile.TemporaryDirectory() as tmpdir:
        jpath = pathlib.Path(tmpdir) / "tampered.log"
        jpath.write_text(tampered + "\n", encoding="utf-8")

        proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "host" / "verify-cli" / "md_verify_cli.py"),
                str(jpath),
                "--device-pubkey",
                pub_hex,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    assert proc.returncode == 2
    assert "SIGNATURE MISMATCH" in proc.stdout
