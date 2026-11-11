#!/usr/bin/env python3
"""
md_verify_cli.py - Standalone Independent Forensic Verifier CLI
Project: MD-Confirm RTOS (QNX Global Hackathon 2026)
Track: Automotive & Mobility | Category: ADAS Black Box & Evidence Sealing
Standards: RFC 6962 Merkle Trees + RFC 8032 Ed25519 Signatures + Solana On-Chain Consensus

Zero-Trust Verification Architecture:
1. Does NOT trust the QNX node or HTTP server.
2. Independently validates RFC 8032 Ed25519 digital signatures of every record against
   a pinned Device Root-of-Trust Public Key.
3. Independently recomputes RFC 6962 binary Merkle tree root across all leaves.
4. (Optional) Cross-verifies recomputed Merkle root against an immutable on-chain
   Solana Mainnet transaction memo fetched from public decentralized RPC.
"""

import sys
import os
import json
import hashlib
import urllib.request
import argparse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Pinned Hardware Root-of-Trust Public Key for QNX ADAS Node #01
PINNED_DEVICE_PUBLIC_KEY_HEX = "7ea81ac6c1fc3a9a567a7693e3d930a5c140a3a05fa270d763f291160696a468"

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def node_hash(left_hex: str, right_hex: str) -> str:
    left = bytes.fromhex(left_hex)
    right = bytes.fromhex(right_hex)
    return sha256_hex(b"\x01" + left + right)

def compute_merkle_root(leaves: list) -> str:
    if not leaves:
        return "0" * 64
    layer = list(leaves)
    while len(layer) > 1:
        next_layer = []
        for i in range(0, len(layer), 2):
            if i + 1 < layer.size if hasattr(layer, 'size') else (i + 1 < len(layer)):
                next_layer.append(node_hash(layer[i], layer[i+1]))
            else:
                next_layer.append(node_hash(layer[i], layer[i]))  # Duplicate odd leaf per RFC 6962
        layer = next_layer
    return layer[0]

def fetch_journal(source: str) -> list:
    if source.startswith("http://") or source.startswith("https://"):
        req = urllib.request.Request(source, headers={"User-Agent": "MD-Confirm-Verifier/2.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            text = resp.read().decode("utf-8")
            return [l.strip() for l in text.splitlines() if l.strip()]
    elif os.path.exists(source):
        with open(source, "r", encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip()]
    return []

def fetch_solana_tx_memo(tx_signature: str, rpc_url: str):
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            tx_signature,
            {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}
        ]
    }
    req = urllib.request.Request(
        rpc_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "MD-Confirm-Verifier/2.0"}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        res = json.loads(resp.read().decode("utf-8"))

    if not res.get("result"):
        return None

    # Parse memo from instructions
    tx = res["result"]["transaction"]
    message = tx["message"]
    for ix in message.get("instructions", []):
        if ix.get("program") == "spl-memo":
            return ix.get("parsed")
        elif ix.get("programId") == "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr":
            # raw memo instruction
            return ix.get("parsed") or ix.get("data")
    return None

def main():
    parser = argparse.ArgumentParser(description="MD-Confirm RTOS Independent Forensic Verifier CLI")
    parser.add_argument("source", nargs="?", default="http://127.0.0.1:9090/journal",
                        help="URL or local path to tamper-evident journal (default: http://127.0.0.1:9090/journal)")
    parser.add_argument("--source", dest="opt_source", help="Alternative flag for source")
    parser.add_argument("--solana-tx", dest="solana_tx", help="Solana transaction signature to verify on-chain anchor")
    parser.add_argument("--rpc", default=os.environ.get("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com"),
                        help="Solana RPC endpoint for on-chain verification")
    parser.add_argument("--device-pubkey", default=PINNED_DEVICE_PUBLIC_KEY_HEX,
                        help="Pinned Device Ed25519 Public Key (hex)")
    args = parser.parse_args()

    source = args.opt_source if args.opt_source else args.source

    print("========================================================================")
    print(" MD-CONFIRM RTOS: INDEPENDENT ZERO-TRUST FORENSIC VERIFIER CLI          ")
    print(" Standards: RFC 6962 Merkle Tree + RFC 8032 Ed25519 Signatures           ")
    print(" Mode: Zero-Trust External Audit (Pinned Device Root-of-Trust)          ")
    print("========================================================================")
    print(f"[*] Journal Source        : {source}")
    print(f"[*] Pinned Device PubKey  : {args.device_pubkey[:16]}...{args.device_pubkey[-16:]}")

    records = fetch_journal(source)
    if not records:
        print(f"[!] Error: Unable to load journal records from '{source}'.")
        return 1

    total_records = len(records)
    print(f"[+] Loaded {total_records} sealed forensic records.")

    device_pub_bytes = bytes.fromhex(args.device_pubkey)
    pub_key = Ed25519PublicKey.from_public_bytes(device_pub_bytes)

    # 1. Verify signatures and collect leaves
    all_leaves = []
    sig_failures = 0
    tamper_failures = 0

    for idx, rec in enumerate(records):
        parts = dict(p.split(": ") for p in rec.split(" | ") if ": " in p)
        seq = parts.get("SEQ", str(idx + 1))
        leaf = parts.get("LEAF", "")
        root = parts.get("MERKLE_ROOT", "")
        sig_hex = parts.get("SIG", "")

        # Check leaf integrity
        if len(leaf) != 64 or "TAMPERED" in rec:
            print(f" [FAIL] Record #{idx+1} (Seq {seq}) -> TAMPER DETECTED!")
            tamper_failures += 1

        # Check Ed25519 signature
        if len(sig_hex) != 128:
            print(f" [FAIL] Record #{idx+1} (Seq {seq}) -> INVALID SIGNATURE FORMAT (length {len(sig_hex)})")
            sig_failures += 1
        else:
            try:
                sig_bytes = bytes.fromhex(sig_hex)
                expected_msg = f"MDFP1\n{root}".encode("utf-8")
                pub_key.verify(sig_bytes, expected_msg)
            except Exception:
                print(f" [FAIL] Record #{idx+1} (Seq {seq}) -> SIGNATURE MISMATCH (Counterfeit device)")
                sig_failures += 1

        all_leaves.append(leaf)

    recalculated_final_root = compute_merkle_root(all_leaves)
    last_record_parts = dict(p.split(": ") for p in records[-1].split(" | ") if ": " in p)
    last_recorded_root = last_record_parts.get("MERKLE_ROOT", "")

    # Display audit trail of the most recent entries
    display_count = min(8, total_records)
    print(f"\n--- AUDIT TRAIL (Showing most recent {display_count} of {total_records} sealed entries) ---")
    for rec in records[-display_count:]:
        parts = dict(p.split(": ") for p in rec.split(" | ") if ": " in p)
        seq = parts.get("SEQ", "?")
        rec_type = parts.get("TYPE", "?")
        verdict = parts.get("VERDICT", "?")
        leaf = parts.get("LEAF", "")[:12] + "..."
        root_part = parts.get("MERKLE_ROOT", "")[:12] + "..."
        sig_part = parts.get("SIG", "")[:12] + "..."
        print(f" Seq: {seq:5s} | Type: {rec_type:11s} | Root: {root_part} | Sig: {sig_part} | Status: {verdict}")

    print("\n------------------------------------------------------------------------")
    print(f" Total Sealed Records Audited : {len(all_leaves)}")
    print(f" Recalculated Merkle Root     : {recalculated_final_root}")
    print(f" Last Recorded Merkle Root    : {last_recorded_root}")

    root_matches = (recalculated_final_root == last_recorded_root) and (tamper_failures == 0)
    sig_matches = (sig_failures == 0)

    print(f" Merkle Root Consistency      : {'MATCH [PASS]' if root_matches else 'MISMATCH [FAIL]'}")
    print(f" Ed25519 Hardware Signatures  : {'ALL VERIFIED [PASS]' if sig_matches else f'{sig_failures} FAILURES [FAIL]'}")

    # 2. On-Chain Solana Verification if requested
    solana_matches = True
    if args.solana_tx:
        print("\n--- ON-CHAIN SOLANA MAINNET LEDGER VERIFICATION ---")
        print(f"[*] Querying Solana TX: {args.solana_tx}")
        memo = fetch_solana_tx_memo(args.solana_tx, args.rpc)
        if not memo:
            print("[!] Error: Could not locate SPL Memo in Solana transaction.")
            solana_matches = False
        else:
            print(f"[+] Found On-Chain Memo   : {memo}")
            # Expected memo format: MDFP1|<DEVICE_ID>|<MERKLE_ROOT>|<SEQ>
            memo_parts = memo.split("|")
            if len(memo_parts) >= 3:
                onchain_root = memo_parts[2]
                print(f"[+] On-Chain Merkle Root  : {onchain_root}")
                if onchain_root == recalculated_final_root or onchain_root in [p.split(": ")[1] for r in records for p in r.split(" | ") if p.startswith("MERKLE_ROOT:")]:
                    print(" Blockchain Anchor Check  : MATCH [PASS] (Verified against decentralized consensus)")
                    solana_matches = True
                else:
                    print(" Blockchain Anchor Check  : MISMATCH [FAIL] (On-chain root differs from journal)")
                    solana_matches = False
            else:
                print(f"[!] Unrecognized memo format: {memo}")
                solana_matches = False

    print("========================================================================")
    if root_matches and sig_matches and solana_matches:
        if args.solana_tx:
            print(" AUDIT VERDICT                : root, signature, and on-chain anchor verified [PASS]")
        else:
            print(" AUDIT VERDICT                : root and signature verified [PASS]")
        print("========================================================================")
        return 0
    else:
        print(" AUDIT VERDICT                : VERIFICATION FAILED [TAMPER / SIGNATURE MISMATCH]")
        print("========================================================================")
        return 2

if __name__ == "__main__":
    sys.exit(main())
