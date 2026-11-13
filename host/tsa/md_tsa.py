#!/usr/bin/env python3
"""MD-Confirm RTOS — Optional RFC 3161 Second Witness (Time-Stamping Authority Client).

Requests an RFC 3161 TimeStampResp (.tsr) for sha256(canonical_json(STH)) from a
user-configured TSA endpoint (--tsa-url; no endpoint is hardcoded). Runs on the
host only; QNX real-time processes perform zero network I/O.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from typing import Any

STH_REQUIRED_KEYS = (
    "version",
    "device_id",
    "tree_size",
    "root_hash",
    "timestamp",
    "prev_sth_sha256",
    "key_id",
)


def canonicalize_sth(sth_obj: dict[str, Any]) -> bytes:
    """Serialize an STH object to UTF-8 RFC 8785 canonical JSON bytes."""
    for key in STH_REQUIRED_KEYS:
        if key not in sth_obj:
            raise ValueError(f"STH object missing required field: {key}")
    ordered = {k: sth_obj[k] for k in sorted(sth_obj.keys())}
    return json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_sth_sha256_hex(sth_obj: dict[str, Any]) -> str:
    """Compute SHA-256 hex digest of the canonical STH JSON."""
    return hashlib.sha256(canonicalize_sth(sth_obj)).hexdigest()


def extract_sth_record(raw_obj: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    """Accept either wrapper {'sth': {...}, 'sig': '...'} or bare STH dict."""
    if "sth" in raw_obj and isinstance(raw_obj["sth"], dict):
        return raw_obj["sth"], raw_obj.get("sig")
    return raw_obj, None


def load_sth_from_path(path: str, index: int = -1) -> tuple[dict[str, Any], str | None]:
    """Load an STH entry from a JSON file or NDJSON sth.log (default: latest line)."""
    with open(path, "r", encoding="utf-8") as fh:
        raw_text = fh.read().strip()
    if not raw_text:
        raise ValueError(f"STH file is empty: {path}")

    # Single multiline JSON object vs NDJSON lines
    if raw_text.startswith("{") and "\n" not in raw_text:
        return extract_sth_record(json.loads(raw_text))
    try:
        parsed = json.loads(raw_text)
        if isinstance(parsed, dict):
            return extract_sth_record(parsed)
    except json.JSONDecodeError:
        pass

    entries: list[dict[str, Any]] = []
    for lineno, line in enumerate(raw_text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on line {lineno} of {path}: {exc}") from exc
        if not isinstance(obj, dict):
            raise ValueError(f"Expected JSON object on line {lineno} of {path}")
        entries.append(obj)

    if not entries:
        raise ValueError(f"No STH entries found in {path}")
    return extract_sth_record(entries[index])


def build_tsq_with_openssl(
    digest_hex: str,
    *,
    openssl_bin: str = "openssl",
    no_nonce: bool = False,
    policy_oid: str | None = None,
) -> bytes:
    """Invoke `openssl ts -query` to construct a DER TimeStampReq for digest_hex."""
    if len(digest_hex) != 64:
        raise ValueError("digest_hex must be a 64-char SHA-256 hex digest")
    resolved = shutil.which(openssl_bin) or openssl_bin
    with tempfile.TemporaryDirectory() as tmpdir:
        tsq_path = os.path.join(tmpdir, "request.tsq")
        cmd = [
            resolved,
            "ts",
            "-query",
            "-digest",
            digest_hex,
            "-sha256",
            "-cert",
            "-out",
            tsq_path,
        ]
        if no_nonce:
            cmd.append("-no_nonce")
        if policy_oid:
            cmd.extend(["-tspolicy", policy_oid])

        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError(
                f"openssl ts -query failed (rc={proc.returncode}): {proc.stderr.strip()}"
            )
        with open(tsq_path, "rb") as fh:
            return fh.read()


def submit_tsq(tsa_url: str, tsq_bytes: bytes, timeout_s: float = 15.0) -> bytes:
    """POST DER TimeStampReq to an RFC 3161 TSA URL and return DER TimeStampResp."""
    if not tsa_url.startswith(("http://", "https://")):
        raise ValueError(f"Unsupported TSA URL scheme (expected http:// or https://): {tsa_url}")
    req = urllib.request.Request(
        tsa_url,
        data=tsq_bytes,
        headers={"Content-Type": "application/timestamp-query"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            status = getattr(resp, "status", 200)
            body = resp.read()
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Failed to contact TSA {tsa_url}: {exc}") from exc

    if status != 200 or not body:
        raise RuntimeError(f"TSA returned HTTP {status} with {len(body)} bytes")
    return body


def request_rfc3161_timestamp(
    sth_path: str,
    tsa_url: str,
    out_tsr: str,
    *,
    index: int = -1,
    openssl_bin: str = "openssl",
    no_nonce: bool = False,
    policy_oid: str | None = None,
    timeout_s: float = 15.0,
) -> dict[str, Any]:
    """Compute sha256(STH), build TSQ, fetch TSR from TSA, and save .tsr to disk."""
    sth_obj, _ = load_sth_from_path(sth_path, index=index)
    sth_sha256 = compute_sth_sha256_hex(sth_obj)
    tsq_bytes = build_tsq_with_openssl(
        sth_sha256,
        openssl_bin=openssl_bin,
        no_nonce=no_nonce,
        policy_oid=policy_oid,
    )
    tsr_bytes = submit_tsq(tsa_url, tsq_bytes, timeout_s=timeout_s)
    out_dir = os.path.dirname(os.path.abspath(out_tsr))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_tsr, "wb") as fh:
        fh.write(tsr_bytes)

    return {
        "tree_size": sth_obj["tree_size"],
        "root_hash": sth_obj["root_hash"],
        "sth_sha256": sth_sha256,
        "tsr_path": out_tsr,
        "tsr_bytes": len(tsr_bytes),
        "tsa_url": tsa_url,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Request an RFC 3161 timestamp (.tsr) for sha256(STH)"
    )
    parser.add_argument(
        "--sth",
        required=True,
        help="Path to sth.log (NDJSON) or single STH JSON file",
    )
    parser.add_argument(
        "--tsa-url",
        required=True,
        help="RFC 3161 Time-Stamping Authority HTTP(S) URL (not hardcoded)",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Output .tsr file path",
    )
    parser.add_argument(
        "--index",
        type=int,
        default=-1,
        help="STH entry index when reading multi-line sth.log (default: -1 = latest)",
    )
    parser.add_argument(
        "--policy-oid",
        default=None,
        help="Optional TSA policy OID to include in TimeStampReq",
    )
    parser.add_argument(
        "--no-nonce",
        action="store_true",
        help="Omit random nonce in TimeStampReq",
    )
    parser.add_argument(
        "--openssl-bin",
        default="openssl",
        help="OpenSSL executable name or path (default: openssl)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="HTTP request timeout in seconds (default: 15.0)",
    )
    args = parser.parse_args(argv)

    try:
        summary = request_rfc3161_timestamp(
            args.sth,
            args.tsa_url,
            args.out,
            index=args.index,
            openssl_bin=args.openssl_bin,
            no_nonce=args.no_nonce,
            policy_oid=args.policy_oid,
            timeout_s=args.timeout,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[TSA ERROR] {exc}", file=sys.stderr)
        return 1

    print(
        f"[TSA OK] tree_size={summary['tree_size']} sth_sha256={summary['sth_sha256']} "
        f"saved={summary['tsr_path']} ({summary['tsr_bytes']} bytes)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
