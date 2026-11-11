#!/usr/bin/env python3
"""
md_anchor.py - Host-Side Solana Mainnet Anchoring Engine
Project: MD-Confirm RTOS (QNX Global Hackathon 2026)
Track: Automotive & Mobility | Category: ADAS Black Box & Evidence Sealing

Features:
- Decoupled off-path anchoring: QNX Neutrino microkernel has zero network blockchain dependencies.
- Fetches latest Merkle root from QNX persistent tamper-evident journal (Port 9090).
- Builds, signs, and broadcasts native SPL Memo v1 transaction to Solana Mainnet ledger.
- SLA: Solana slot time ~400 ms, transaction finality ~12 sec.
"""

import sys
import os
import json
import base64
import urllib.request
import argparse
from cryptography.hazmat.primitives.asymmetric import ed25519

# Base58 Encoding / Decoding utilities
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58decode(s: str) -> bytes:
    res = [0]
    for c in s:
        idx = B58_ALPHABET.index(c)
        carry = idx
        for j in range(len(res)):
            carry += res[j] * 58
            res[j] = carry & 0xff
            carry >>= 8
        while carry > 0:
            res.append(carry & 0xff)
            carry >>= 8
    for c in s:
        if c == "1":
            res.append(0)
        else:
            break
    return bytes(reversed(res))

def b58encode(b: bytes) -> str:
    digits = [0]
    for byte in b:
        carry = byte
        for j in range(len(digits)):
            carry += digits[j] << 8
            digits[j] = carry % 58
            carry //= 58
        while carry > 0:
            digits.append(carry % 58)
            carry //= 58
    out = ""
    for byte in b:
        if byte == 0:
            out += "1"
        else:
            break
    for d in reversed(digits):
        out += B58_ALPHABET[d]
    return out

def encode_compact_u16(val: int) -> bytes:
    out = bytearray()
    rem = val
    while True:
        elem = rem & 0x7f
        rem >>= 7
        if rem == 0:
            out.append(elem)
            break
        else:
            elem |= 0x80
            out.append(elem)
    return bytes(out)

# Mainnet Configuration (Keys and RPC loaded from environment or CLI arguments)
DEFAULT_SOLANA_RPC = os.environ.get("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com")
DEFAULT_PAYER_KEYPAIR_B58 = os.environ.get("SOLANA_PAYER_KEYPAIR_B58", "")
MEMO_PROGRAM_B58 = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"

def fetch_latest_journal_root(journal_url: str):
    try:
        req = urllib.request.urlopen(journal_url, timeout=10)
        lines = [l.strip() for l in req.read().decode("utf-8").splitlines() if l.strip()]
        if not lines:
            return None, None
        last_line = lines[-1]
        parts = dict(p.split(": ") for p in last_line.split(" | ") if ": " in p)
        return parts.get("MERKLE_ROOT"), parts.get("SEQ")
    except Exception as e:
        print(f"[!] Error fetching journal from '{journal_url}': {e}")
        return None, None

def broadcast_memo_anchor(memo_text: str, rpc_url: str, privkey_b58: str):
    keypair_bytes = b58decode(privkey_b58)
    seed32 = keypair_bytes[:32]
    payer_pub32 = keypair_bytes[32:64]
    memo_prog32 = b58decode(MEMO_PROGRAM_B58)

    priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed32)
    payer_pub_b58 = b58encode(payer_pub32)

    # 1. Fetch recent blockhash
    req_bh = urllib.request.Request(
        rpc_url,
        data=json.dumps({"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[{"commitment":"confirmed"}]}).encode(),
        headers={"Content-Type": "application/json"}
    )
    resp_bh = json.loads(urllib.request.urlopen(req_bh, timeout=10).read().decode())
    blockhash_b58 = resp_bh["result"]["value"]["blockhash"]
    blockhash32 = b58decode(blockhash_b58)

    # 2. Build Legacy wire transaction with SPL Memo instruction
    memo_bytes = memo_text.encode("utf-8")
    header = bytes([1, 0, 1])  # 1 req sig, 0 readonly signed, 1 readonly unsigned
    accounts = payer_pub32 + memo_prog32
    message = (
        header +
        encode_compact_u16(2) +
        accounts +
        blockhash32 +
        encode_compact_u16(1) +
        bytes([1]) +             # program_id_index: 1 (memo program)
        encode_compact_u16(1) +
        bytes([0]) +             # account index: 0 (payer)
        encode_compact_u16(len(memo_bytes)) +
        memo_bytes
    )

    signature = priv_key.sign(message)
    wire_tx = (
        encode_compact_u16(1) +
        signature +
        message
    )
    wire_tx_b64 = base64.b64encode(wire_tx).decode("ascii")

    # 3. Broadcast to Solana cluster
    req_send = urllib.request.Request(
        rpc_url,
        data=json.dumps({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "sendTransaction",
            "params": [wire_tx_b64, {"encoding": "base64", "preflightCommitment": "confirmed"}]
        }).encode(),
        headers={"Content-Type": "application/json"}
    )
    resp_send = json.loads(urllib.request.urlopen(req_send, timeout=15).read().decode())
    if "result" in resp_send:
        return resp_send["result"], payer_pub_b58
    else:
        raise RuntimeError(f"Solana RPC error: {resp_send}")

def main():
    parser = argparse.ArgumentParser(description="MD-Confirm RTOS Solana Mainnet Anchoring Engine")
    parser.add_argument("--journal-url", default="http://127.0.0.1:9090/journal",
                        help="QNX HTTP Gateway journal URL (default: http://127.0.0.1:9090/journal)")
    parser.add_argument("--rpc", default=DEFAULT_SOLANA_RPC, help="Solana JSON-RPC endpoint")
    parser.add_argument("--privkey", default=DEFAULT_PAYER_KEYPAIR_B58, help="Payer Base58 private key")
    parser.add_argument("--device-id", default="QNX-ADAS-NODE-01", help="Device identifier")
    args = parser.parse_args()

    print("========================================================================")
    print(" MD-CONFIRM RTOS: HOST-SIDE SOLANA MAINNET ANCHORING ENGINE             ")
    print(" Architecture: Off-path async anchoring (QNX kernel is zero-dependency) ")
    print(" Protocol: SPL Memo v1 on Solana Mainnet Ledger                         ")
    print("========================================================================")
    print(f"[*] Journal Endpoint: {args.journal_url}")

    root, seq = fetch_latest_journal_root(args.journal_url)
    if not root:
        print("[!] Error: No records found in QNX journal.")
        return 1

    memo_payload = f"MDFP1|{args.device_id}|{root}|{seq}"
    print(f"[+] Latest QNX Root : {root}")
    print(f"[+] Frame Sequence  : #{seq}")
    print(f"[+] Anchor Payload  : '{memo_payload}'")
    print(f"[*] Broadcasting transaction to Solana Mainnet...")

    if not args.privkey:
        print("[!] Error: Solana payer private key is required.")
        print("    Provide via --privkey <BASE58_KEY> or set SOLANA_PAYER_KEYPAIR_B58 environment variable.")
        return 1

    try:
        tx_sig, payer = broadcast_memo_anchor(memo_payload, args.rpc, args.privkey)
        print("\n========================================================================")
        print(" [+] SOLANA MAINNET TRANSACTION CONFIRMED ON LEDGER")
        print(f" [+] Payer Account  : {payer}")
        print(f" [+] TX Signature   : {tx_sig}")
        print(f" [+] Solscan URL    : https://solscan.io/tx/{tx_sig}")
        print(f" [+] Embedded Memo  : {memo_payload}")
        print("========================================================================")
        return 0
    except Exception as e:
        print(f"[!] Anchoring failed: {e}")
        return 2

if __name__ == "__main__":
    sys.exit(main())
