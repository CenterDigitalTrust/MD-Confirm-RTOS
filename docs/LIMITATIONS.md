# Known Limitations & Verification Boundaries (MD-Confirm RTOS)

This document consolidates the verified engineering, cryptographic, and hardware limitations of **MD-Confirm RTOS** identified in the code audit ([`docs/UPGRADE_AUDIT.md`](UPGRADE_AUDIT.md)).

**Evidence Labels Used Throughout This Repository:**
- **`MEASURED`**: Measured on physical camera hardware or bare-metal target silicon.
- **`SIMULATED`**: Generated on synthetic inputs and/or inside QEMU x86_64 virtualization.
- **`ROADMAP`**: Design target not yet implemented or enforced in code.
- **`NOT YET MEASURED`**: No dataset/hardware evaluation exists yet (`NEVER` extrapolated from synthetic data).

---

## 1. Sensor Hardware & PRNU Signal Limitations

1. **Synthetic Frames Only (`SIMULATED`):** Camera frames are generated artificially in [`qnx/sensor-sim/md-sensor-sim.cpp`](../qnx/sensor-sim/md-sensor-sim.cpp) (`64x64` 16-bit Bayer buffers in POSIX `/mdfp_frame_shm`) with linear congruential PRNG noise. No physical camera sensor, MIPI CSI-2 receiver, or DMA ring buffer is connected.
2. **Simplified PRNU Estimator (`SIMULATED`):** [`qnx/verify/md-verify.cpp`](../qnx/verify/md-verify.cpp) currently uses a 1D 3-sample moving-average residual (`W = I - smooth(I)`), a scalar dot product (`NCC`), and `PCE = ncc^2 * N` (with a fixed fallback when `ncc <= 0.05`) rather than 2D wavelet denoising (Mihcak/Fridrich filter) and 2D FFT peak-to-sidelobe correlation energy.
3. **Real-World Camera Calibration (`NOT YET MEASURED`):** Offline 2D wavelet (`db4`) + FFT PCE evaluation code is implemented in [`host/prnu-eval/`](../host/prnu-eval/) ([`docs/PRNU_RESULTS.md`](PRNU_RESULTS.md)), but real Dresden/VISION camera ROC curves, FAR/FRR across JPEG/downscale/brightness degradations, fingerprint-copy attack $N_{\text{attack}}$ curves, and thermal drift ($-40^\circ\text{C}$ to $+85^\circ\text{C}$) on physical automotive CMOS sensors remain **`NOT YET MEASURED`**.
4. **Scenario 4 Cadence Injection (`ROADMAP`):** [`qnx/verify/md-verify.cpp`](../qnx/verify/md-verify.cpp) does not yet measure inter-frame arrival rhythm or jitter bounds (`MDFP_HARD_JITTER_LIMIT_US`); it matches `msg.scenario == 4` and sets `allow = true`, sealing synthetic Scenario 4 frames into the journal rather than blocking timing anomalies.
5. **Physical Scene Replay (`BOUNDARY`):** PRNU sensor matching verifies pixel noise statistics relative to a reference pattern $K_{\text{REF}}$; optical playback in front of an authentic physical lens (screen-recording attack) or a cycle-accurate FPGA CSI-2 hardware bus emulator lies outside software sensor-layer guarantees.

---

## 2. QNX Real-Time Scheduling & IPC Limitations

1. **QEMU Virtualization Jitter (`SIMULATED`):** All committed runtime evidence in [`docs/evidence/`](evidence/) comes from QEMU x86_64 running QNX SDP 8.0 (`mean_us` $\approx 5230\text{--}5515\,\mu\text{s}$ and `max_us` $\approx 501{,}181\,\mu\text{s}$ in `jitter_*.json`). Bare-metal microsecond/sub-microsecond interrupt latency is **`NOT YET MEASURED`**.
2. **Synchronous Pipeline Blocking (`ROADMAP`):** In [`qnx/capture/md-capture.cpp`](../qnx/capture/md-capture.cpp), `md-capture` does **not** wait on `md-telemetry` HTTP readers (lock-free `/mdfp_stats_shm` seqlock), **but** it still blocks synchronously on `MsgSend(verify_coid, ...)` in its single pulse-receive thread, and `md-verify` blocks synchronously on `MsgSend(seal_coid, ...)`. There is no internal decoupling queue yet.
3. **Single-Slot `/mdfp_frame_shm` TOCTOU (`ROADMAP`):** `md-sensor-sim` writes frames in place to `/mdfp_frame_shm` (`0666`) with no double-buffering or snapshot locking. `md-verify` hashes `shm->bayer_raw` *after* calling `MsgReply()`, and `md-capture` hashes `shm->bayer_raw` a third time for telemetry stats, permitting frame mutation between PRNU verification and SHA-256 sealing.
4. **Partial Process Priority Configuration (`ROADMAP`):** Only `md-capture` (`SCHED_FIFO 21`) and `md-telemetry` (`SCHED_RR 8`) currently call `sched_setscheduler()`. `md-watchdog`, `md-verify`, `md-seal`, and `md-ctl` run at default inherited priority until priority setup is added.
5. **Resource Manager Control Plane (`ROADMAP`):** `md-ctl` (`resmgr_attach` on `/dev/mdconfirm`) currently communicates scenario switches by writing `/tmp/mdfp_active_scenario` rather than direct `MsgSend` IPC to `md-seal` or `md-sensor-sim`.
6. **Persistent `/data` Partition & Journal Reload:** Evidence files (`tamper_evident_journal.log`, `sth.log`, `anchor_outbox.jsonl`) require mounting persistent storage at `/data/mdfp_evidence` (`/tmp` is volatile SHM RAM in QNX). Portable [`qnx/common/mdfp_seal_core.h`](../qnx/common/mdfp_seal_core.h) reloads prior `LEAF` and `sth.log` state on startup (tested in host C++ tests), while the QNX IPC daemon wrapper [`qnx/seal/md-seal.cpp`](../qnx/seal/md-seal.cpp) remains `UNTESTED ON QNX`.

---

## 3. Cryptography, Key Storage & Audit Protocol Limitations

1. **Software Signing Key in Source (`DEMO ONLY`):** On this hackathon bench, the Ed25519 signing seed (`g_device_seed`) in [`qnx/seal/md-seal.cpp`](../qnx/seal/md-seal.cpp) is embedded in source code for deterministic demo reproducibility (and `K_REF` is generated deterministically in code). Production deployment requires an HSM, TPM 2.0, or secure enclave (`ROADMAP`).
2. **STH Exposure via Telemetry (`ROADMAP`):** `SealEngine` persists chained RFC 8785 Signed Tree Heads to `sth.log` and anchor requests to `anchor_outbox.jsonl` every `K = 32` leaves and on every `GHOST_EVENT`, and [`host/verify-cli/md_verify_cli.py`](../host/verify-cli/md_verify_cli.py) verifies canonical JSON preimages (`| CANON:`), leaf uniqueness, strict RFC 6962 inclusion/consistency proofs, `--checkpoint` files, `--solana-tx`, and `--tsa-tsr` tokens. Exposing `sth.log` / `anchor_outbox.jsonl` directly over new `md-telemetry` HTTP endpoints remains on `ROADMAP` (host reads the exported files directly).
3. **External Checkpoint Requirement for Truncation/Rollback:** Modification, full-log rollback, and tail-truncation detection hold **strictly relative to an external checkpoint** (`--checkpoint STH_FILE`, `--solana-tx`, or `--tsa-tsr` + `--tsa-ca`). Without an external checkpoint (`source: none`), an attacker who controls the node before verification can truncate trailing entries cleanly, and the verifier prints `WARNING: tail truncation NOT detectable.`
4. **Verifier CLI Source Flag:** `md_verify_cli.py` accepts a positional `source` or `--source` flag rather than `--journal`.
5. **External Witness Availability:** Host-side Solana anchoring ([`host/anchor/md_anchor.py`](../host/anchor/md_anchor.py) `--outbox`) and RFC 3161 TSA timestamping ([`host/tsa/md_tsa.py`](../host/tsa/md_tsa.py) `--tsa-url`) run asynchronously on the host (zero network code on QNX) and require an external RPC / configured TSA endpoint for live witnessing.

---

## 4. Telemetry Gateway & Host CI Boundaries

1. **Telemetry Network Exposure (`md-telemetry`):** Binds `127.0.0.1:9090` by default (use `--bind <ipv4:port>` explicitly; authentication, TLS, rate limiting, and journal pagination are not implemented). Single-threaded `accept()` loop can still be stalled per connection up to `SO_RCVTIMEO`/`SO_SNDTIMEO` (2 s). `drop_privileges()` QNX `procmgr_ability` stub is currently inactive (`#ifdef __QNX__`).
2. **Host-Only Continuous Integration (No QNX Build in CI):**
   - Proprietary BlackBerry QNX SDP 8.0 headers and cross-compilers (`qcc` / `q++`, `<sys/neutrino.h>`, `<sys/dispatch.h>`, `<sys/resmgr.h>`) cannot be distributed in public GitHub Actions runners.
   - Therefore, **CI does NOT compile or boot `qnx/*.cpp` targets**. Changes to QNX daemons (`md-capture.cpp`, `md-seal.cpp`, `md-telemetry.cpp`, etc.) are **`UNTESTED ON QNX`** unless built and run locally with QNX SDP 8.0.
   - CI validates Python host scripts (`pytest` + `ruff`) and host-compilable C++ core units (`mdfp_seqlock.h`, `mdfp_canon.h`, `mdfp_http.h`, `mdfp_crypto.h`, `tweetnacl.c`) with `-Wall -Wextra`, ASan/UBSan, TSan (threaded seqlock stress test), RFC 8032/8785 known-answer vectors, and `libFuzzer` on the HTTP request parser.
