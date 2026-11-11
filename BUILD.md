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
1. `md-sensor-sim` : Synthetic RAW Bayer sensor feeder with PRNU wafer noise simulation
2. `md-capture`    : High-priority `SCHED_FIFO 21` frame receiver with `ClockCycles()` timestamping (zero network code)
3. `md-verify`     : PCE / NCC correlation engine running in `SCHED_FIFO 15`
4. `md-seal`       : RFC 6962 Merkle tree & RFC 8032 Ed25519 hardware signature signer (`SCHED_FIFO 12`)
5. `md-watchdog`   : Asynchronous pulse timeout watchdog detecting cable cuts (`SCHED_FIFO 22`)
6. `md-ctl`        : QNX Native Resource Manager for `/dev/mdconfirm` (`SCHED_RR 10`)
7. `md-telemetry`  : Low-priority read-only telemetry HTTP gateway on port 9090 (`SCHED_RR 8`)

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
# Run all 6 attack scenarios in sequence:
./run_all_scenarios.sh
```

### Manual Service Execution:
Start the isolated daemons in background:
```bash
./bin/md-seal &
./bin/md-verify &
./bin/md-watchdog &
./bin/md-capture &
./bin/md-ctl &
./bin/md-telemetry --bind 0.0.0.0:9090 --journal /data/mdfp_evidence/tamper_evident_journal.log &
```

Trigger individual scenarios using the sensor simulator:
```bash
# Scenario 1: Calibrated Physical CMOS Sensor (Expected: ALLOW & SEAL)
./bin/md-sensor-sim 1 50

# Scenario 2: Foreign Silicon Sensor Swap Attack (Expected: BLOCK)
./bin/md-sensor-sim 2 20

# Scenario 3: Generative AI Deepfake Injection (Expected: BLOCK)
./bin/md-sensor-sim 3 20

# Scenario 5: Physical MIPI Bus Disconnect / Cut (Expected: WATCHDOG ALARM)
./bin/md-sensor-sim 5 10
```

---

## 6. Host-Side Verification & Blockchain Anchoring

Requirements: Python 3.8+ with `cryptography` library installed (`pip install cryptography`).

### 1. Independent Zero-Trust Audit:
```bash
# Verify the Merkle tree and Ed25519 signatures from the running node:
python3 host/verify-cli/md_verify_cli.py http://127.0.0.1:9090/api/journal

# Optional: Cross-verify against on-chain Solana Mainnet anchor:
python3 host/verify-cli/md_verify_cli.py http://127.0.0.1:9090/api/journal \
  --solana-tx 4N4vyHbz3wvMnR6736uePmRPtNdr6Fo6ujk62h1cPhF9tdoUUAicZX7oGwZD4AdRLdkKMC8nD1eEn7Kgb46SPiZW
```

### 2. Solana Mainnet Anchoring Engine:
```bash
# Export your Solana payer private key and optional custom RPC URL:
export SOLANA_PAYER_KEYPAIR_B58="<YOUR_BASE58_SOLANA_KEYPAIR>"
export SOLANA_RPC_URL="https://api.mainnet-beta.solana.com"

# Broadcast current Merkle root to Solana Mainnet:
python3 host/anchor/md_anchor.py --journal-url http://127.0.0.1:9090/api/journal
```

---

## 7. Verification Status & Disclaimers

* **Verified in QEMU x86_64:** Compilation of all 7 native binaries, QNX IPC (`MsgSend`, `MsgReceive`, `MsgSendPulse`), execution in QNX Neutrino 8.0, lock-free `seqlock` on `/mdfp_stats_shm`, attack scenarios 1–6, audit via `md_verify_cli.py`, and ledger anchoring to Solana Mainnet.
* **Unverified on bare-metal silicon:** Interfacing with physical automotive CSI-2 camera hardware (Sony IMX390) and hardware cryptographic co-processor TPM 2.0 / HSM (scheduled on production roadmap).
