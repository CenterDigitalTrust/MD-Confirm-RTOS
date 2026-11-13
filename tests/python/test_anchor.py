import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "host" / "anchor"))

import md_anchor  # noqa: E402


def test_b58_roundtrip_and_leading_zeros():
    samples = [
        b"",
        b"\x00",
        b"\x00\x00\x01\x02\x03",
        b"QNX-MD-CONFIRM-SOLANA-MEMO",
        bytes(range(32)),
    ]
    for raw in samples:
        encoded = md_anchor.b58encode(raw)
        decoded = md_anchor.b58decode(encoded)
        assert decoded == raw


def test_encode_compact_u16():
    assert md_anchor.encode_compact_u16(0) == b"\x00"
    assert md_anchor.encode_compact_u16(1) == b"\x01"
    assert md_anchor.encode_compact_u16(127) == b"\x7f"
    assert md_anchor.encode_compact_u16(128) == b"\x80\x01"
    assert md_anchor.encode_compact_u16(16384) == b"\x80\x80\x01"


def test_memo_program_id_decodes_to_32_bytes():
    prog = md_anchor.b58decode(md_anchor.MEMO_PROGRAM_B58)
    assert len(prog) == 32
    assert md_anchor.b58encode(prog) == md_anchor.MEMO_PROGRAM_B58
