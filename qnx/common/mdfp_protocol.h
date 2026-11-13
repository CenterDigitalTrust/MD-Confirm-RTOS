// mdfp_protocol.h
// Native QNX Neutrino 8.0 Microkernel IPC Protocol Definitions
// Project: MD-Confirm RTOS (QNX Global Hackathon)
// Author: miracledropletmd | Category: Automotive & Mobility (ADAS Black Box)

#pragma once

#ifndef _QNX_SOURCE
#define _QNX_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/neutrino.h>
#include <sys/syspage.h>
#include <string.h>

#define MDFP_MAGIC 0x4D444650 // 'MDFP'
#define MDFP_VERSION 0x08000100 // v8.0.1

// Channel attachment points registered via QNX name_attach()
#define MDFP_ATTACH_CAPTURE  "mdfp_capture"
#define MDFP_ATTACH_VERIFY   "mdfp_verify"
#define MDFP_ATTACH_SEAL     "mdfp_seal"
#define MDFP_ATTACH_WATCHDOG "mdfp_watchdog"
#define MDFP_RESMGR_PATH     "/dev/mdconfirm"

// Microkernel Process Priorities (Strict ASIL-D Hierarchy)
#define MDFP_PRIO_WATCHDOG   22  // Safety Monitor (SCHED_FIFO): Pulse timeout & bus cut detection
#define MDFP_PRIO_CAPTURE    21  // Hard Real-Time (SCHED_FIFO): IRQ service & ClockCycles timestamping
#define MDFP_PRIO_VERIFY     15  // Real-Time (SCHED_FIFO): PRNU correlation engine
#define MDFP_PRIO_SEAL       12  // Real-Time (SCHED_FIFO): Merkle tree & Ed25519 signing
#define MDFP_PRIO_CTL        10  // Resource Manager (SCHED_RR): /dev/mdconfirm
#define MDFP_PRIO_TELEMETRY   8  // Low Background (SCHED_RR): HTTP telemetry & journal streaming

// Shared memory for zero-copy RAW frame delivery & lockless statistics
#define MDFP_SHM_NAME           "/mdfp_frame_shm"
#define MDFP_STATS_SHM_NAME     "/mdfp_stats_shm"
#define MDFP_TELEMETRY_SHM_NAME "/mdfp_stats_shm" // Alias for compatibility

#include "mdfp_ingest.h"

// Persistent storage path on QNX6 /data partition (NOT wiped on reboot)
#define MDFP_PERSISTENT_JOURNAL_PATH "/data/mdfp_evidence/tamper_evident_journal.log"
#define MDFP_PERSISTENT_STH_PATH     "/data/mdfp_evidence/sth.log"
#define MDFP_PERSISTENT_OUTBOX_PATH  "/data/mdfp_evidence/anchor_outbox.jsonl"
#define MDFP_DEFAULT_KEY_FILE_PATH   "/data/mdfp_evidence/device_ed25519.key"
#define MDFP_STH_INTERVAL_LEAVES     32

// Pulse codes for asynchronous real-time events
#define MDFP_PULSE_EOF_IRQ        (_PULSE_CODE_MINAVAIL + 1)
#define MDFP_PULSE_WATCHDOG_HEART (_PULSE_CODE_MINAVAIL + 2)
#define MDFP_PULSE_WATCHDOG_TICK  (_PULSE_CODE_MINAVAIL + 3)

// Nominal Frame Rate & Timing Budget
#define MDFP_NOMINAL_FPS          30.0
#define MDFP_NOMINAL_INTERVAL_NS  33333333ULL // 33.333 ms
#define MDFP_HARD_JITTER_LIMIT_US 10.0        // QNX ASIL-D threshold

// PRNU Forensic Thresholds:
// PCE is dimensionless energy ratio: (peak^2 / mean sidelobe energy).
// Standard literature threshold (Fridrich, Goljan et al. 2008): PCE >= 60.0 (~17.78 dB power).
#define MDFP_PCE_THRESHOLD_LINEAR 60.0        // Dimensionless literature threshold
#define MDFP_PCE_THRESHOLD_DB     17.78       // 10 * log10(60.0) in power decibels
#define MDFP_NCC_THRESHOLD        0.750       // Normalized Cross-Correlation threshold for synthetic benchmark

// Hackathon Demo Scenarios (+ Task 7 SIMULATED extra-signal attack scenarios)
enum MdfpScenario : uint32_t {
    SCENARIO_1_NATIVE_SENSOR       = 1, // Authentic silicon wafer K_REF -> ALLOW
    SCENARIO_2_FOREIGN_SENSOR      = 2, // Rogue physical camera silicon K_ROGUE -> BLOCK
    SCENARIO_3_SYNTHETIC_NO_PRNU   = 3, // AI deepfake / synthetic frame without PRNU -> BLOCK
    SCENARIO_4_SYNTHETIC_WITH_PRNU = 4, // Synthetic with pre-applied PRNU -> Extra signals block when enabled
    SCENARIO_5_CABLE_SABOTAGE      = 5, // MIPI cut / power loss -> Watchdog GHOST_EVENT
    SCENARIO_6_JOURNAL_TAMPER      = 6, // Tampered ledger record -> CLI detection
    SCENARIO_7_REPLAY_FRAME        = 7, // Replayed recorded authentic frames (SIMULATED)
    SCENARIO_8_SEQ_TIMING_ANOMALY  = 8  // Counter gap / ClockCycles interval out of bounds (SIMULATED)
};

// Shared Memory Buffer Structure (Written by md-sensor-sim, read by md-capture/md-verify)
struct MdfpSharedMemory {
    uint32_t magic;
    uint32_t frame_seq;
    uint32_t scenario;
    uint64_t hw_eof_cycles; // Stamped at simulated EOF IRQ via ClockCycles()
    uint64_t hw_eof_ns;     // Stamped at simulated EOF IRQ via CLOCK_MONOTONIC
    uint32_t width;
    uint32_t height;
    uint32_t payload_bytes;
    uint16_t bayer_raw[MDFP_PRNU_SIZE]; // 16-bit raw sensor data with PRNU noise
};

// Message from md-capture -> md-verify via MsgSend()
// Carries the private Bayer copy + SHA-256 computed over that copy by md-capture
// so md-verify never re-reads /mdfp_frame_shm (eliminates post-hash SHM TOCTOU).
struct MdfpVerifyMsg {
    uint16_t type;    // 0x0100
    uint16_t subtype;
    uint32_t frame_seq;
    uint32_t scenario;
    uint64_t hw_eof_cycles;
    uint64_t hw_eof_ns;
    uint64_t capture_wakeup_cycles;
    uint64_t capture_wakeup_ns;
    uint32_t width;
    uint32_t height;
    uint32_t payload_bytes;
    char sensor_id[32];
    char frame_sha256[65];
    uint16_t bayer_raw[MDFP_PRNU_SIZE];
};

struct MdfpVerifyReply {
    uint32_t status; // 0 = VERIFIED, 1 = REJECTED_SILICON, 2 = REJECTED_TIMING, 3 = INGEST_HASH_MISMATCH
    char verdict[48];
    double ncc;
    double pce_linear; // Dimensionless PCE ratio
    double pce_db;     // Decibel scale: 10 * log10(pce_linear)
    double ncc_threshold;
    double pce_threshold_linear;
    double pce_threshold_db;
    char k_ref_id[32];
    char k_ref_version[16];
    uint64_t verify_start_cycles;
    uint64_t verify_end_cycles;
    uint64_t verify_duration_ns;
    uint8_t extra_signals_enabled;
    uint64_t interval_cycles_p50;
    uint64_t interval_cycles_p99;
    double interval_us_p50;
    double interval_us_p99;
    uint64_t interval_samples;
    uint64_t seq_timing_failures;
    uint64_t challenge_failures;
};

// Message from md-verify / md-watchdog -> md-seal via MsgSend()
struct MdfpSealMsg {
    uint16_t type;    // 0x0200
    uint16_t subtype;
    uint32_t frame_seq;
    uint32_t scenario;
    uint64_t hw_eof_ns;
    uint64_t capture_cycles;
    double ncc;
    double pce_linear;
    double pce_db;
    double ncc_threshold;
    double pce_threshold_linear;
    char raw_sha256[65];
    char sensor_id[32];
    char k_ref_id[32];
    char k_ref_version[16];
    uint64_t inter_frame_ns;
    int64_t inter_frame_jitter_ns;
    uint64_t eof_to_capture_ns;
    uint64_t verify_duration_ns;
    char verdict[48];
    bool is_ghost_event;
};

struct MdfpSealReply {
    uint32_t status;
    uint32_t leaf_index;
    char leaf_sha256[65];
    char merkle_root[65];
    char signature_ed25519[129];
    char journal_path[128];
};

#include "mdfp_seqlock.h"

static inline uint64_t mdfp_cycles() {
    return ClockCycles();
}

static inline uint64_t mdfp_cycles_per_sec() {
    return SYSPAGE_ENTRY(qtime)->cycles_per_sec;
}

static inline uint64_t mdfp_get_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
