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

// Persistent storage path on QNX6 /data partition (NOT wiped on reboot)
#define MDFP_PERSISTENT_JOURNAL_PATH "/data/mdfp_evidence/tamper_evident_journal.log"

// Pulse codes for asynchronous real-time events
#define MDFP_PULSE_EOF_IRQ        (_PULSE_CODE_MINAVAIL + 1)
#define MDFP_PULSE_WATCHDOG_HEART (_PULSE_CODE_MINAVAIL + 2)
#define MDFP_PULSE_WATCHDOG_TICK  (_PULSE_CODE_MINAVAIL + 3)

// Simulated Sensor Resolution (64x64 silicon wafer PRNU crop)
#define MDFP_SENSOR_WIDTH  64
#define MDFP_SENSOR_HEIGHT 64
#define MDFP_PRNU_SIZE     (MDFP_SENSOR_WIDTH * MDFP_SENSOR_HEIGHT) // 4096 pixels
#define MDFP_RAW_BYTES     (MDFP_PRNU_SIZE * 2)                     // 16-bit Bayer: 8192 bytes

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

// 6 Hackathon Demo Scenarios
enum MdfpScenario : uint32_t {
    SCENARIO_1_NATIVE_SENSOR       = 1, // Authentic silicon wafer K_REF -> ALLOW
    SCENARIO_2_FOREIGN_SENSOR      = 2, // Rogue physical camera silicon K_ROGUE -> BLOCK
    SCENARIO_3_SYNTHETIC_NO_PRNU   = 3, // AI deepfake / synthetic frame without PRNU -> BLOCK
    SCENARIO_4_SYNTHETIC_WITH_PRNU = 4, // Synthetic with pre-applied PRNU -> Rhythm/counter boundary
    SCENARIO_5_CABLE_SABOTAGE      = 5, // MIPI cut / power loss -> Watchdog GHOST_EVENT
    SCENARIO_6_JOURNAL_TAMPER      = 6  // Tampered ledger record -> CLI detection
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
struct MdfpVerifyMsg {
    uint16_t type;    // 0x0100
    uint16_t subtype;
    uint32_t frame_seq;
    uint32_t scenario;
    uint64_t hw_eof_cycles;
    uint64_t hw_eof_ns;
    uint64_t capture_wakeup_cycles;
    uint64_t capture_wakeup_ns;
    uint32_t shm_offset;
};

struct MdfpVerifyReply {
    uint32_t status; // 0 = VERIFIED, 1 = REJECTED_SILICON, 2 = REJECTED_TIMING
    char verdict[48];
    double ncc;
    double pce_linear; // Dimensionless PCE ratio
    double pce_db;     // Decibel scale: 10 * log10(pce_linear)
    double pce_threshold_db;
    uint64_t verify_start_cycles;
    uint64_t verify_end_cycles;
    uint64_t verify_duration_ns;
};

// Message from md-verify / md-watchdog -> md-seal via MsgSend()
struct MdfpSealMsg {
    uint16_t type;    // 0x0200
    uint16_t subtype;
    uint32_t frame_seq;
    uint32_t scenario;
    uint64_t hw_eof_ns;
    double ncc;
    double pce_linear;
    double pce_db;
    char raw_sha256[65];
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

// Lock-Free Shared Statistics with Seqlock Versioning
// Writer (md-capture) increments seqlock_version to odd before write, and even after write.
// Reader (md-telemetry) reads atomically with zero locks or blocking.
struct MdfpStatsShared {
    volatile uint32_t seqlock_version; // Odd = write in progress; Even = stable snapshot
    uint32_t magic;                    // MDFP_MAGIC
    uint32_t last_frame_seq;
    uint32_t last_scenario;
    double last_pce_db;
    double last_pce_linear;
    double last_ncc;
    double last_latency_b_us;
    double last_jitter_us;
    uint64_t last_cycles_delta;
    char last_verdict[48];
    char last_frame_sha256[65];
    char last_merkle_root[65];
    uint64_t total_frames;
    uint64_t total_blocked;
    uint64_t total_ghosts;
    uint32_t hist_bins[10];
    uint64_t hist_total_samples;
    double hist_min_us;
    double hist_max_us;
    double hist_mean_us;
};
typedef struct MdfpStatsShared MdfpTelemetryShared; // Backwards compatible alias

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
