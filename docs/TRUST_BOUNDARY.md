# System Trust Boundary & Attestation Semantics

> [!IMPORTANT]
> This document states the exact software and hardware trust boundaries of **MD-Confirm RTOS** as currently implemented (QEMU x86_64 QNX 8.0 demo + Linux/Windows host verifier). Where capabilities are planned rather than implemented, they are marked **`ROADMAP`**.

---

## 1. Plain-Language Security Summary

1. **Whoever can write `/mdfp_frame_shm` can forge frames.** In this bench, `/mdfp_frame_shm` is opened with permissive demo mode (`0666`) and fed synthetic frames by `md-sensor-sim`. There is no real MIPI CSI-2 receiver, ISP, or hardware DMA IOMMU boundary. Any host/local process with write access to `/mdfp_frame_shm` *before* `md-capture` copies a frame can supply arbitrary pixels.
2. **What the Ed25519 signature proves:** **"This node (`md-seal`) accepted these canonical metadata bytes and frame digest (`frame_sha256`) at this `ClockCycles()` / wall timestamp."** It is an integrity and provenance commitment by the sealing node, **not** an unforgeable proof of physical photon capture.
3. **Sensor binding is statistical (PRNU) only.** Pixel authenticity rests on Photo-Response Non-Uniformity (`NCC` / `PCE` against `K_REF`), which is vulnerable to fingerprint-copy attacks if an adversary collects enough frames from the victim camera (see [`docs/PRNU_RESULTS.md`](PRNU_RESULTS.md) and [`host/prnu-eval/`](../host/prnu-eval/)).
4. **No hardware key protection exists today.** `md-seal` signs via [`FileSigner`](../qnx/common/mdfp_signer.h) (software TweetNaCl Ed25519 key stored on disk). While `md-seal` refuses to start on POSIX if the key file is group- or world-readable (`mode & 0077 != 0`), anyone with read access to that user account or root on the QNX target can copy the private key. [`HardwareTokenSignerStub`](../qnx/common/mdfp_signer.h) (PKCS#11 / TPM 2.0 / Secure Element) is an unimplemented stub (`ROADMAP`).
5. **`swtpm` is emulation only.** Anywhere a software TPM (`swtpm`) appears in virtualized experiments or CI discussions, it provides protocol simulation **only** and zero hardware key protection or physical tamper resistance.

---

## 2. Inside vs. Outside the Node Trust Boundary

```text
  OUTSIDE TRUST BOUNDARY                   │  INGESTION BOUNDARY        INSIDE NODE BOUNDARY (PROCESS-ISOLATED IPC)
  ─────────────────────────────────────────┼───────────────────────────────────────────────────────────────────────────────────────
  md-sensor-sim / synthetic producer       │  md-capture                md-verify                     md-seal
  writes `/mdfp_frame_shm` (0666 demo) ────┼─► 1. Single copy out ────► 3. Works ONLY on ───────────► 5. Builds RFC 8785 CANON leaf
  (Untrusted: can mutate shm at any time)  │     into PrivateFrameSnapshot  private IPC copy              + RFC 6962 Merkle root
                                           │  2. SHA-256(private copy)  4. Re-checks SHA-256           + Ed25519 signature (FileSigner)
                                           │     + ClockCycles()            (zero shm reads!)             + STH chain (sth.log)
                                           └───────────────────────────────────────────────────────────────────────────────────────
                                                                                                         │
                                                                                                         ▼
                                                                                              OUTSIDE / TELEMETRY & VERIFIER
                                                                                              md-telemetry (read-only 127.0.0.1:9090)
                                                                                              md_verify_cli.py + External Checkpoints
```

### What Is Inside vs. Outside

| Component | Boundary Status | Role & Limitations |
|---|---|---|
| **Kernel DMA / MIPI CSI-2 ISP** | **NOT PRESENT (`ROADMAP`)** | Synthetic `/mdfp_frame_shm` replaces camera DMA hardware in QEMU. |
| **`md-sensor-sim` & `/mdfp_frame_shm`** | **OUTSIDE (Untrusted Input)** | Any process able to open `/mdfp_frame_shm` can craft pixels, `scenario`, `frame_seq`, or `hw_eof_ns`. |
| **`md-capture` (`capture_copy_from_shm_and_hash`)** | **INGESTION BOUNDARY (`SCHED_FIFO 20`)** | Performs a **single** pass copy out of `/mdfp_frame_shm` into `PrivateFrameSnapshot`, captures `ClockCycles()`, and computes `frame_sha256` strictly over the private copy (`qnx/common/mdfp_ingest.h`). Protects downstream stages from post-copy SHM TOCTOU mutation. Note: telemetry lock-free snapshot is exported via `MdfpSeqlock` (`atomic_thread_fence`). |
| **`md-verify` (`verify_private_frame`)** | **INSIDE (Untrusted-Input Screener)** | Receives the private buffer over QNX `MsgSend()`, makes **zero reads from `/mdfp_frame_shm`**, re-computes `SHA-256(private_bayer_raw)` and fails closed (`BLOCK_INGEST_HASH_MISMATCH`) if bytes disagree with `frame_sha256`. Runs statistical 1D demo PRNU check (host real-image 2D wavelet pipeline is in `host/prnu-eval/`). |
| **`md-seal` (`SealEngine` + `FileSigner`)** | **INSIDE (Signing Boundary)** | Commits `frame_sha256`, `seq`, `clock_cycles`, `sensor_id`, `k_ref_id`, `k_ref_version`, `ncc`, `ncc_threshold`, `pce_linear`, `pce_db`, `pce_threshold_linear`, and `verdict` into RFC 8785 JCS + RFC 6962 leaves (`journal.log`) and chains STHs (`sth.log`). Uses software `FileSigner` (`0600` strict check); **no hardware key isolation**. |
| **`md-telemetry` (`127.0.0.1:9090`)** | **OUTSIDE / READ-ONLY OBSERVER** | Serves metrics and appends read-only logs. Independent verifier [`md_verify_cli.py`](../host/verify-cli/md_verify_cli.py) never trusts HTTP status alone — it recomputes leaves, prefix roots, Ed25519 signatures, and STH consistency proofs. |
| **Offline Demo PKI (`host/pki/md_demo_pki.py`)** | **DEMO TOOLING ONLY** | Issues software Ed25519 device certificates, key rotations (`old_key` or `ca`), and revocation lists to exercise verifier trust chains. **Not production PKI.** |
| **External Checkpoints (`--checkpoint`, `--tsa-tsr`, `--solana-tx`)** | **EXTERNAL WITNESS** | Detect silent log rollback/truncation even if an attacker later compromises the `FileSigner` key on the node (for leaves prior to the anchored root). |

---

## 3. Mitigations Needed Before Production ADAS Deployment (`ROADMAP`)

1. **Hardware Root of Trust & Key Protection:** Replace `FileSigner` with a concrete PKCS#11 HSM, hardware TPM 2.0 (NOT `swtpm` emulation), or SoC Secure Element implementing [`mdfp::Signer`](../qnx/common/mdfp_signer.h) so the signing key is non-exportable.
2. **Kernel/IOMMU Frame Ingestion Isolation:** Eliminate world-writable `/mdfp_frame_shm`; enforce strict QNX resource-manager credentials or hardware ISP/DMA descriptors mapped read-only to `md-capture`.
3. **2D Real-Image PRNU + Multi-Signal Anti-Spoofing:** Replace the 64x64 1D QNX demo residual filter with full 2D wavelet denoising validated on raw Bayer frames + optical/temporal liveliness signals.
4. **Authenticated Time & Watchdog Hardening:** Bind `ClockCycles()` / wall timestamps to external authenticated time (`--tsa-tsr` / secure RTC) and hardware watchdog resets.

See also: [`docs/LIMITATIONS.md`](LIMITATIONS.md) · [`docs/PRNU_RESULTS.md`](PRNU_RESULTS.md) · [`host/pki/README.md`](../host/pki/README.md).
