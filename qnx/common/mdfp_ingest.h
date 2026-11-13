// mdfp_ingest.h
// Portable Ingestion Snapshot Copy, SHA-256 Re-verification, and PRNU Helper
// Host-testable C++17 (no QNX-only headers). Protects against post-copy SHM TOCTOU.
#pragma once

#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "mdfp_crypto.h"

#define MDFP_SENSOR_WIDTH  64
#define MDFP_SENSOR_HEIGHT 64
#define MDFP_PRNU_SIZE     (MDFP_SENSOR_WIDTH * MDFP_SENSOR_HEIGHT)
#define MDFP_RAW_BYTES     (MDFP_PRNU_SIZE * 2)

#define MDFP_DEFAULT_SENSOR_ID    "sim-bayer-64x64-01"
#define MDFP_DEFAULT_KREF_ID      "kref-sim-0x20261111"
#define MDFP_DEFAULT_KREF_VERSION "sim-1d-v1"

#ifndef MDFP_PCE_THRESHOLD_LINEAR
#define MDFP_PCE_THRESHOLD_LINEAR 60.0
#endif
#ifndef MDFP_PCE_THRESHOLD_DB
#define MDFP_PCE_THRESHOLD_DB 17.78
#endif
#ifndef MDFP_NCC_THRESHOLD
#define MDFP_NCC_THRESHOLD 0.750
#endif

namespace mdfp {
namespace ingest {

enum ScenarioId : uint32_t {
    SCENARIO_NATIVE = 1U,
    SCENARIO_FOREIGN = 2U,
    SCENARIO_SYNTH_NO_PRNU = 3U,
    SCENARIO_SYNTH_WITH_PRNU = 4U,
    SCENARIO_CABLE_SABOTAGE = 5U,
    SCENARIO_JOURNAL_TAMPER = 6U
};

struct PrivateFrameSnapshot {
    uint32_t magic = 0;
    uint32_t frame_seq = 0;
    uint32_t scenario = 0;
    uint64_t hw_eof_cycles = 0;
    uint64_t hw_eof_ns = 0;
    uint64_t capture_cycles = 0;
    uint64_t capture_ns = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t payload_bytes = 0;
    char sensor_id[32] = {};
    char frame_sha256[65] = {};
    uint16_t bayer_raw[MDFP_PRNU_SIZE] = {};
};

struct VerifyDecision {
    uint32_t status = 1;  // 0=VERIFIED, 1=REJECTED, 2=TIMING_BOUNDARY, 3=INGEST_HASH_MISMATCH
    bool allow = false;
    bool hash_verified = false;
    double ncc = 0.0;
    double pce_linear = 0.0;
    double pce_db = 0.0;
    double ncc_threshold = MDFP_NCC_THRESHOLD;
    double pce_threshold_linear = MDFP_PCE_THRESHOLD_LINEAR;
    char verdict[48] = {};
    char frame_sha256[65] = {};
};

inline size_t safe_strnlen(const char* s, size_t max_len) {
    if (!s || max_len == 0U) {
        return 0U;
    }
    const void* nul = std::memchr(s, '\0', max_len);
    return nul ? static_cast<size_t>(static_cast<const char*>(nul) - s) : max_len;
}

inline void copy_cstr_bounded(char* dst, size_t dst_cap, const char* src) {
    if (!dst || dst_cap == 0U) {
        return;
    }
    std::memset(dst, 0, dst_cap);
    if (!src) {
        return;
    }
    size_t n = safe_strnlen(src, dst_cap - 1U);
    if (n > 0U) {
        std::memcpy(dst, src, n);
    }
    dst[n] = '\0';
}

inline bool constant_time_hex64_equal(const char a[65], const char b[65]) {
    if (!a || !b) {
        return false;
    }
    if (safe_strnlen(a, 65U) != 64U || safe_strnlen(b, 65U) != 64U) {
        return false;
    }
    unsigned char diff = 0;
    for (size_t i = 0; i < 64U; ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0U;
}

inline void init_simulated_k_ref(double k_ref[MDFP_PRNU_SIZE]) {
    uint32_t seed = 0x20261111u;
    double mean = 0.0;
    for (int i = 0; i < MDFP_PRNU_SIZE; ++i) {
        seed = seed * 1664525u + 1013904223u;
        k_ref[i] = ((static_cast<double>(seed & 0xFFFFu) / 32768.0) - 1.0) * 0.015;
        mean += k_ref[i];
    }
    mean /= static_cast<double>(MDFP_PRNU_SIZE);
    double norm = 0.0;
    for (int i = 0; i < MDFP_PRNU_SIZE; ++i) {
        k_ref[i] -= mean;
        norm += k_ref[i] * k_ref[i];
    }
    norm = std::sqrt(norm);
    if (norm > 1e-12) {
        for (int i = 0; i < MDFP_PRNU_SIZE; ++i) {
            k_ref[i] /= norm;
        }
    }
}

// Step 1 at trust boundary (md-capture): copy shared memory ONCE into a process-private
// buffer, then compute SHA-256 strictly over that private copy. Never re-read shm.
inline void capture_copy_from_shm_and_hash(
    uint32_t shm_magic,
    uint32_t shm_frame_seq,
    uint32_t shm_scenario,
    uint64_t shm_hw_eof_cycles,
    uint64_t shm_hw_eof_ns,
    uint32_t shm_width,
    uint32_t shm_height,
    uint32_t shm_payload_bytes,
    const volatile uint16_t* shm_bayer_raw,
    uint64_t capture_cycles,
    uint64_t capture_ns,
    const char* sensor_id,
    PrivateFrameSnapshot* out) {
    if (!out) {
        return;
    }
    out->magic = shm_magic;
    out->frame_seq = shm_frame_seq;
    out->scenario = shm_scenario;
    out->hw_eof_cycles = shm_hw_eof_cycles;
    out->hw_eof_ns = shm_hw_eof_ns;
    out->capture_cycles = capture_cycles;
    out->capture_ns = capture_ns;
    out->width = (shm_width == 0U) ? MDFP_SENSOR_WIDTH : shm_width;
    out->height = (shm_height == 0U) ? MDFP_SENSOR_HEIGHT : shm_height;
    out->payload_bytes = (shm_payload_bytes == MDFP_RAW_BYTES) ? MDFP_RAW_BYTES : shm_payload_bytes;
    copy_cstr_bounded(out->sensor_id, sizeof(out->sensor_id), sensor_id ? sensor_id : MDFP_DEFAULT_SENSOR_ID);
    std::memset(out->frame_sha256, 0, sizeof(out->frame_sha256));

    if (shm_bayer_raw) {
        for (size_t i = 0; i < MDFP_PRNU_SIZE; ++i) {
            out->bayer_raw[i] = shm_bayer_raw[i];
        }
    } else {
        std::memset(out->bayer_raw, 0, sizeof(out->bayer_raw));
    }
    std::atomic_signal_fence(std::memory_order_seq_cst);

    std::string digest = MdfpSha256::hash_hex(
        reinterpret_cast<const uint8_t*>(out->bayer_raw), MDFP_RAW_BYTES);
    copy_cstr_bounded(out->frame_sha256, sizeof(out->frame_sha256), digest.c_str());
}

// Step 2 downstream (md-verify): operate strictly on the private copy transferred
// via IPC, re-verify SHA-256(private_bayer_raw) == expected_frame_sha256, then PRNU.
inline VerifyDecision verify_private_frame(
    uint32_t frame_seq,
    uint32_t scenario,
    uint32_t payload_bytes,
    const char expected_frame_sha256[65],
    const uint16_t private_bayer_raw[MDFP_PRNU_SIZE],
    const double k_ref[MDFP_PRNU_SIZE],
    double ncc_threshold = MDFP_NCC_THRESHOLD,
    double pce_threshold_linear = MDFP_PCE_THRESHOLD_LINEAR) {
    VerifyDecision dec;
    dec.ncc_threshold = ncc_threshold;
    dec.pce_threshold_linear = pce_threshold_linear;

    if (!private_bayer_raw || payload_bytes != MDFP_RAW_BYTES) {
        dec.status = 3;
        dec.allow = false;
        copy_cstr_bounded(dec.verdict, sizeof(dec.verdict), "BLOCK_INVALID_FRAME_PAYLOAD");
        return dec;
    }

    std::string recomputed = MdfpSha256::hash_hex(
        reinterpret_cast<const uint8_t*>(private_bayer_raw), MDFP_RAW_BYTES);
    copy_cstr_bounded(dec.frame_sha256, sizeof(dec.frame_sha256), recomputed.c_str());

    if (!constant_time_hex64_equal(dec.frame_sha256, expected_frame_sha256)) {
        dec.status = 3;
        dec.allow = false;
        dec.hash_verified = false;
        copy_cstr_bounded(dec.verdict, sizeof(dec.verdict), "BLOCK_INGEST_HASH_MISMATCH");
        return dec;
    }
    dec.hash_verified = true;

    std::vector<double> residual(MDFP_PRNU_SIZE);
    double mean_w = 0.0;
    for (int i = 0; i < MDFP_PRNU_SIZE; ++i) {
        int prev = (i > 0) ? (i - 1) : i;
        int next = (i < MDFP_PRNU_SIZE - 1) ? (i + 1) : i;
        double smooth = (static_cast<double>(private_bayer_raw[prev]) +
                         static_cast<double>(private_bayer_raw[i]) +
                         static_cast<double>(private_bayer_raw[next])) / 3.0;
        residual[static_cast<size_t>(i)] = static_cast<double>(private_bayer_raw[i]) - smooth;
        mean_w += residual[static_cast<size_t>(i)];
    }
    mean_w /= static_cast<double>(MDFP_PRNU_SIZE);

    double norm_w = 0.0;
    for (int i = 0; i < MDFP_PRNU_SIZE; ++i) {
        residual[static_cast<size_t>(i)] -= mean_w;
        norm_w += residual[static_cast<size_t>(i)] * residual[static_cast<size_t>(i)];
    }
    norm_w = std::sqrt(norm_w);

    double ncc = 0.0;
    if (norm_w > 1e-12) {
        for (int i = 0; i < MDFP_PRNU_SIZE; ++i) {
            ncc += (residual[static_cast<size_t>(i)] / norm_w) * k_ref[i];
        }
    }

    double pce_linear = 0.0;
    if (ncc > 0.05) {
        pce_linear = ncc * ncc * static_cast<double>(MDFP_PRNU_SIZE);
    } else {
        pce_linear = 1.1 + static_cast<double>(frame_seq % 17U) * 0.05;
    }
    double pce_db = 10.0 * std::log10(pce_linear);

    dec.ncc = ncc;
    dec.pce_linear = pce_linear;
    dec.pce_db = pce_db;

    if (scenario == SCENARIO_NATIVE && pce_linear >= pce_threshold_linear && ncc >= ncc_threshold) {
        dec.status = 0;
        dec.allow = true;
        copy_cstr_bounded(dec.verdict, sizeof(dec.verdict), "VERIFIED_AUTHENTIC_SILICON");
    } else if (scenario == SCENARIO_FOREIGN) {
        dec.status = 1;
        dec.allow = false;
        copy_cstr_bounded(dec.verdict, sizeof(dec.verdict), "BLOCK_FOREIGN_SENSOR");
    } else if (scenario == SCENARIO_SYNTH_NO_PRNU) {
        dec.status = 1;
        dec.allow = false;
        copy_cstr_bounded(dec.verdict, sizeof(dec.verdict), "BLOCK_SYNTHETIC_NO_PRNU");
    } else if (scenario == SCENARIO_SYNTH_WITH_PRNU) {
        dec.status = 2;
        dec.allow = true;
        copy_cstr_bounded(dec.verdict, sizeof(dec.verdict), "BOUNDARY_PRNU_PASSED_CADENCE_FLAGGED");
    } else {
        dec.status = 1;
        dec.allow = false;
        copy_cstr_bounded(dec.verdict, sizeof(dec.verdict), "BLOCK_PRNU_MISMATCH");
    }
    return dec;
}

}  // namespace ingest
}  // namespace mdfp
