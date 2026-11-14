# Build & Run Guide — MD-Confirm RTOS

**Target OS:** BlackBerry QNX Neutrino RTOS 8.0.0 (Target: QEMU x86_64 / `x86_64`)  
**Host Toolchain:** Official BlackBerry QNX SDP 8.0 (`q++ -Vgcc_ntox86_64_cxx`, `qcc -Vgcc_ntox86_64`)  
**Build Platform:** Linux x86_64 with QNX SDP environment variables sourced  

---

## 1. Environment Configuration

Source the official QNX SDP 8.0 environment:

```bash
# Set up QNX SDP 8.0 environment
source /path/to/qnxsdp-8.0/qnxsdp-env.sh

# Verify cross-compiler
which q++
q++ -Vgcc_ntox86_64_cxx --version
```

---

## 2. Compiling the QNX Native Modules

```bash
cd qnx

# Clean previous build artifacts
make clean

# Compile all 7 native microkernel binaries with C++17 optimizations
make all
```

The build produces 7 native ELF binaries in `bin/`:
1. `md-sensor-sim` : Synthetic RAW Bayer sensor feeder with wafer PRNU noise simulation (plus optional `--extra-signals` `HMAC` gain modulation)
2. `md-capture`    : High-priority `SCHED_FIFO 21` (explicit `sched_setscheduler`) single-copy frame receiver with `frame_sha256` & `ClockCycles()` (zero network code)
3. `md-verify`     : PCE / NCC correlation & optional `--extra-signals` engine (`Target PRIO 15` constant in `mdfp_protocol.h`)
4. `md-seal`       : RFC 6962 Merkle tree, chained STHs & RFC 8032 Ed25519 software signer (`FileSigner` / TweetNaCl, strict `0600` key check, no hardware key protection; `Target PRIO 12` constant)
5. `md-watchdog`   : Asynchronous pulse timeout watchdog detecting cable cuts (`Target PRIO 22` constant)
6. `md-ctl`        : QNX Native Resource Manager for `/dev/mdconfirm` (`Target PRIO 10` constant)
7. `md-telemetry`  : Low-priority `SCHED_RR 8` (explicit `sched_setscheduler`) read-only HTTP gateway on `127.0.0.1:9090` by default

---

## 3. Persistent Storage Requirement (QNX Partitioning)

> **Important:** In BlackBerry QNX Neutrino RTOS, `/tmp` is backed by RAM (`/dev/shmem`) and is automatically cleared on reboot.
> For a **tamper-evident forensic black box**, evidence must be stored on a non-volatile filesystem.
> In our QNX 8.0 image, a dedicated QNX6 partition (`/dev/hd0t179`) is mounted at `/data`:
> ```bash
> mkdir -p /data/mdfp_evidence
> mount -t qnx6 /dev/hd0t179 /data
> ```
> The default evidence path is `/data/mdfp_evidence/tamper_evident_journal.log`.

---

## 4. QNX Image Assembly (mkqnximage)

To bake a bootable QEMU x86_64 target image using official QNX tools:

```bash
# Generate QEMU x86_64 target virtual disk image (verified on QNX SDP 8.0)
mkqnximage -t qemu-x86_64 \
  --extra-files system_files.custom \
  --post-start post_start.custom \
  -o qnx_md_adas_disk.qcow2

# Launch in QEMU with network port forward for telemetry:
qemu-system-x86_64 -m 2048 -smp 2 \
  -drive file=qnx_md_adas_disk.qcow2,if=virtio \
  -net nic,model=virtio -net user,hostfwd=tcp::9090-:9090 \
  -nographic
```

---

## 5. Running the Pipeline & Attack Scenarios

### Automated Suite:
```bash
# Run Phase 1 (PRNU default: 1, 2, 3, 5) + Phase 2 (--extra-signals: 1, 4, 7, 8) + host CAN demo:
./run_all_scenarios.sh
```

### Manual Service Execution:
Start the isolated daemons in background (bind `127.0.0.1:9090` by default; add `--extra-signals` to `md-verify` & `md-sensor-sim` for Phase 2):
```bash
./bin/md-seal &
./bin/md-verify &
./bin/md-watchdog &
./bin/md-capture &
./bin/md-ctl &
./bin/md-telemetry --bind 127.0.0.1:9090 --journal /data/mdfp_evidence/tamper_evident_journal.log &
```

Trigger individual scenarios using the sensor simulator:
```bash
# Scenario 1: Calibrated Physical CMOS Sensor (Expected: ALLOW & SEAL)
./bin/md-sensor-sim 1 50

# Scenario 2: Foreign Silicon Sensor Swap Attack (Expected: BLOCK_FOREIGN_SENSOR)
./bin/md-sensor-sim 2 20

# Scenario 3: Generative AI Deepfake Injection (Expected: BLOCK_SYNTHETIC_NO_PRNU)
./bin/md-sensor-sim 3 20

# Scenario 5: Physical MIPI Bus Disconnect / Cut (Expected: WATCHDOG GHOST_EVENT)
./bin/md-sensor-sim 5 10

# Phase 2 (--extra-signals enabled on md-verify & md-sensor-sim):
# Scenario 4: K_REF Spoof without HMAC modulation (BLOCK_CHALLENGE_MODULATION)
# Scenario 7: Frame Replay Attack (BLOCK_SEQ_REPLAY)
# Scenario 8: Seq Gap / Timing Out-of-Bounds (BLOCK_SEQ_GAP / BLOCK_TIMING_OUT_OF_BOUNDS)
```

---

## 6. Host-Side Verification & Blockchain Anchoring

Requirements: Python 3.8+ with `cryptography` library installed (`pip install cryptography`).

### 1. Independent Zero-Trust Audit:
```bash
# Offline audit of the captured QNX 8.0 QEMU 65-leaf evidence against Solana Mainnet Slot 469030044 (no QNX SDP required):
python3 host/verify-cli/md_verify_cli.py \
  --source docs/evidence/qnx_8_qemu/tamper_evident_journal.log \
  --sth-log docs/evidence/qnx_8_qemu/sth.log \
  --solana-tx 54DXk4XAxhuQNDrbTqRXZmPFvEDMFVwxa6FLz1vMT6fjzUzepLivCGgGKAJgjgYQKv96TegrCNoCnyowxbEyiXbT

# Verify the Merkle tree and Ed25519 signatures live from a running QNX node:
python3 host/verify-cli/md_verify_cli.py http://127.0.0.1:9090/api/journal

# Optional: Cross-verify live node (or baseline 3568-leaf anchor) against a specific Solana Mainnet TX:
python3 host/verify-cli/md_verify_cli.py http://127.0.0.1:9090/api/journal \
  --solana-tx <SOLANA_MAINNET_TX_SIGNATURE>
```

### 2. Solana Mainnet Anchoring Engine:
```bash
# Export your Solana payer private key and optional custom RPC URL:
export SOLANA_PAYER_KEYPAIR_B58="<YOUR_BASE58_SOLANA_KEYPAIR>"
export SOLANA_RPC_URL="https://api.mainnet-beta.solana.com"

# Broadcast current Merkle root to Solana Mainnet:
python3 host/anchor/md_anchor.py --journal-url http://127.0.0.1:9090/api/journal
```

### 3. Reproducing Host Verification Tests Without QNX SDP 8.0:
```bash
pip install pytest ruff cryptography numpy PyWavelets Pillow scipy matplotlib
ruff check host tests
pytest -v tests/python
```

---

## 7. Continuous Integration (Host Only) & Verification Status

* **GitHub Actions Host CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)):** Runs `ruff` and `pytest` on host Python tools (`host/*`, `tests/python/*`), compiles and tests portable C++ units (`qnx/common/mdfp_seqlock.h`, `qnx/common/mdfp_canon.h`, `qnx/common/mdfp_http.h`, `qnx/common/mdfp_crypto.h`, `qnx/common/mdfp_ingest.h`, `qnx/common/mdfp_signer.h`, `qnx/common/mdfp_seal_core.h`, `qnx/common/tweetnacl.c`) with `-Wall -Wextra -Werror`, ASan/UBSan, ThreadSanitizer (`-fsanitize=thread` on multi-threaded seqlock stress tests), RFC 8032 Ed25519 / RFC 8785 JCS known-answer tests, and `libFuzzer` on the HTTP request parser. **QNX targets (`qnx/*/*.cpp`) are NOT built in CI** because BlackBerry QNX SDP 8.0 headers/toolchains are proprietary.
* **QEMU x86_64 Simulation (`SIMULATED`):** Compilation of all 7 native QNX binaries, QNX IPC (`MsgSend`, `MsgReceive`, `MsgSendPulse`), and scenario evaluation in QNX Neutrino 8.0 QEMU require local QNX SDP 8.0 (`q++` / `qcc`). Any edits to `qnx/*` since the last QEMU build are `UNTESTED ON QNX` until rebuilt with QNX SDP 8.0.
* **Unverified on bare-metal silicon (`NOT YET MEASURED`):** Interfacing with physical automotive CSI-2 camera hardware, real PRNU ROC curves, and hardware key storage via PKCS#11 HSM / TPM 2.0 / Secure Element (`ROADMAP` — [`HardwareTokenSignerStub`](qnx/common/mdfp_signer.h) is unimplemented, and any `swtpm` usage would be software emulation only, not hardware key protection).
