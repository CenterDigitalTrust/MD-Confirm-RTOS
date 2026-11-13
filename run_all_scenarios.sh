#!/bin/bash
# run_all_scenarios.sh
# End-to-end execution of QNX 8.0 scenarios (PRNU default + optional SIMULATED Task 7 extra signals)

set -e
source /mnt/qnx-md-rtos/qnx800/qnxsdp-env.sh

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_DIR="$BASE_DIR/bin"

echo "========================================================================"
echo " MD-CONFIRM RTOS: QNX 8.0 NATIVE PIPELINE & ATTACK SCENARIO TESTBENCH   "
echo " Track: Automotive & Mobility | Target: Best Use of QNX Technologies   "
echo "========================================================================"

# Clean up any leftover processes
pkill -f md-capture || true
pkill -f md-verify || true
pkill -f md-seal || true
pkill -f md-watchdog || true
pkill -f md-ctl || true
pkill -f md-telemetry || true
rm -f /dev/shmem/mdfp_frame_shm /dev/shmem/mdfp_stats_shm /data/mdfp_evidence/* /tmp/mdfp_evidence/* 2>/dev/null || true

echo "[+] Starting Background Security Daemons in isolated memory spaces..."
$BIN_DIR/md-seal > /tmp/seal.log 2>&1 &
SEAL_PID=$!
sleep 0.2

$BIN_DIR/md-verify > /tmp/verify.log 2>&1 &
VERIFY_PID=$!
sleep 0.2

$BIN_DIR/md-watchdog > /tmp/watchdog.log 2>&1 &
WATCHDOG_PID=$!
sleep 0.2

$BIN_DIR/md-capture > /tmp/capture.log 2>&1 &
CAPTURE_PID=$!
sleep 0.2

$BIN_DIR/md-telemetry > /tmp/telemetry.log 2>&1 &
TELEMETRY_PID=$!
sleep 0.2

echo "[+] All QNX IPC channels connected and listening (capture, verify, seal, watchdog, telemetry)."

echo ""
echo "------------------------------------------------------------------------"
echo " [SCENARIO 1/4] Native Calibrated Sensor (Authentic Silicon Wafer K_REF)"
echo " Expected: ALLOW, High PCE (> 15 dB), Jitter within limit, Journal Sealed"
echo "------------------------------------------------------------------------"
$BIN_DIR/md-sensor-sim 1 20
sleep 0.5

echo ""
echo "------------------------------------------------------------------------"
echo " [SCENARIO 2/4] Foreign Physical Camera Swap (Rogue Silicon Wafer K_ROGUE)"
echo " Expected: BLOCK_FOREIGN_SENSOR, PCE < 15 dB, Discarded before journal"
echo "------------------------------------------------------------------------"
$BIN_DIR/md-sensor-sim 2 15
sleep 0.5

echo ""
echo "------------------------------------------------------------------------"
echo " [SCENARIO 3/4] Synthetic AI Deepfake (Pure Diffusion, No Silicon PRNU)"
echo " Expected: BLOCK_SYNTHETIC_NO_PRNU, Zero correlation, Discarded"
echo "------------------------------------------------------------------------"
$BIN_DIR/md-sensor-sim 3 15
sleep 0.5

echo ""
echo "------------------------------------------------------------------------"
echo " [SCENARIO 5/4] MIPI Cable Severed / Sensor Power Cut Sabotage"
echo " Expected: Watchdog Pulse Timeout > 50 ms, GHOST_EVENT sealed into Merkle"
echo "------------------------------------------------------------------------"
$BIN_DIR/md-sensor-sim 5 5 || true
sleep 1.0

echo ""
echo "========================================================================"
echo " EXECUTION LOGS FROM HIGH-PRIORITY CAPTURE & VERIFY DAEMONS:            "
echo "========================================================================"
tail -n 25 /tmp/capture.log || true

echo ""
echo "========================================================================"
echo " WATCHDOG SABOTAGE AUDIT TRAIL:                                         "
echo "========================================================================"
tail -n 15 /tmp/watchdog.log || true

echo ""
echo "========================================================================"
echo " INDEPENDENT HOST CLI AUDIT (Zero-Trust Merkle Verification):           "
echo "========================================================================"
python3 $BASE_DIR/host/verify-cli/md_verify_cli.py

echo ""
echo "========================================================================"
echo " SOLANA BLOCKCHAIN ANCHORING:                                           "
echo "========================================================================"
python3 $BASE_DIR/host/anchor/md_anchor.py

echo ""
echo "========================================================================"
echo " [PHASE 2 - SIMULATED] EXTRA SIGNALS BEYOND PRNU (OFF BY DEFAULT)       "
echo " Note: Models per-frame sensor control (real sensor support unverified) "
echo " and shares HMAC secret in software (demonstrates logic, not security). "
echo "========================================================================"
kill $VERIFY_PID 2>/dev/null || true
sleep 0.2
$BIN_DIR/md-verify --extra-signals > /tmp/verify_extra.log 2>&1 &
VERIFY_PID=$!
sleep 0.2

echo "[SIMULATED] (7a) Authentic K_REF + valid HMAC modulation + valid seq/timing (PASS)..."
$BIN_DIR/md-sensor-sim 1 10 --extra-signals --seq-start 100
sleep 0.3

echo "[SIMULATED] (7b) Synthetic K_REF without challenge modulation (Scenario 4 -> BLOCK_CHALLENGE_MODULATION)..."
$BIN_DIR/md-sensor-sim 4 5 --extra-signals --seq-start 110
sleep 0.3

echo "[SIMULATED] (7c) Replayed recorded authentic frames (Scenario 7 -> BLOCK_SEQ_REPLAY / BLOCK_CHALLENGE_MODULATION)..."
$BIN_DIR/md-sensor-sim 7 6 --extra-signals --seq-start 115
sleep 0.3

echo "[SIMULATED] (7d) Sequence gap & timing OOB (Scenario 8 -> BLOCK_SEQ_GAP / BLOCK_TIMING_OUT_OF_BOUNDS)..."
$BIN_DIR/md-sensor-sim 8 4 --extra-signals --seq-start 125
sleep 0.3

echo "[SIMULATED] /api/stats extra_signals + interval p50/p99 snapshot:"
(command -v curl >/dev/null 2>&1 && curl -s http://127.0.0.1:9090/api/stats || true)
echo ""
tail -n 25 /tmp/verify_extra.log || true

echo ""
echo "========================================================================"
echo " [HOST-ONLY SIMULATED] OPTICAL-FLOW VS SYNTHETIC CAN SPEED CONSISTENCY:  "
echo "========================================================================"
python3 $BASE_DIR/host/can-flow/md_can_flow.py --demo

# Clean up background daemons
kill $CAPTURE_PID $VERIFY_PID $SEAL_PID $WATCHDOG_PID $TELEMETRY_PID 2>/dev/null || true
