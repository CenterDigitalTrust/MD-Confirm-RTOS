// mdfp_signals.h
// SIMULATED Independent Signals Beyond PRNU (Sequence/Timing Bounds & HMAC Challenge-Response)
//
// STATUS: SIMULATED / HOST-UNIT-TESTABLE C++17 (no QNX-only headers).
// OFF BY DEFAULT behind ExtraSignalConfig::enabled (or check_* flags).
//
// HONEST LIMITATIONS (SIMULATED MODEL ONLY):
// 1. Sequence/Timing: Checks monotonic per-frame counter (no gaps) and inter-frame
//    ClockCycles() delta bounds, tracking sliding-window p50/p99 statistics.
// 2. Challenge-Response: Derives per-frame exposure/gain modulation from
//    HMAC-SHA256(secret, frame_seq) and checks mean pixel intensity against
//    baseline_intensity * expected_gain within tolerance.
//    - This models a camera sensor with deterministic per-frame exposure/gain control;
//      REAL AUTOMOTIVE SENSOR SUPPORT IS UNVERIFIED (NOT YET MEASURED).
//    - In this simulation, BOTH md-sensor-sim and md-verify share the symmetric HMAC
//      secret in software, so this demonstrates verification logic, NOT hardware security.
#pragma once

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include "mdfp_crypto.h"
#include "mdfp_ingest.h"

namespace mdfp {
namespace signals {

constexpr size_t INTERVAL_WINDOW_CAPACITY = 1024U;
constexpr double DEFAULT_BASELINE_INTENSITY = 2048.0;
constexpr double DEFAULT_MIN_INTERVAL_MS = 10.0;
constexpr double DEFAULT_MAX_INTERVAL_MS = 75.0;
constexpr double DEFAULT_TOLERANCE_RATIO = 0.04;  // +/- 4% around modulated target mean
constexpr double DEFAULT_MIN_TOLERANCE_ADU = 25.0;

inline std::vector<uint8_t> default_demo_shared_secret() {
    static const char kDemoSecret[] = "MDFP-SIMULATED-DEMO-CHALLENGE-SECRET-NOT-PRODUCTION-V1";
    return std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(kDemoSecret),
        reinterpret_cast<const uint8_t*>(kDemoSecret) + sizeof(kDemoSecret) - 1U);
}

// RFC 2104 HMAC-SHA256 built directly atop MdfpSha256::hash_bytes().
inline std::array<uint8_t, 32> hmac_sha256(
    const uint8_t* key,
    size_t key_len,
    const uint8_t* msg,
    size_t msg_len) {
    constexpr size_t kBlockSize = 64U;
    std::array<uint8_t, kBlockSize> key_block{};

    if (key && key_len > 0U) {
        if (key_len > kBlockSize) {
            std::array<uint8_t, 32> hashed_key = MdfpSha256::hash_bytes(key, key_len);
            std::memcpy(key_block.data(), hashed_key.data(), hashed_key.size());
        } else {
            std::memcpy(key_block.data(), key, key_len);
        }
    }

    std::vector<uint8_t> inner(kBlockSize + msg_len, 0U);
    for (size_t i = 0; i < kBlockSize; ++i) {
        inner[i] = static_cast<uint8_t>(key_block[i] ^ 0x36U);
    }
    if (msg && msg_len > 0U) {
        std::memcpy(inner.data() + kBlockSize, msg, msg_len);
    }
    std::array<uint8_t, 32> inner_hash = MdfpSha256::hash_bytes(inner.data(), inner.size());

    std::array<uint8_t, kBlockSize + 32U> outer{};
    for (size_t i = 0; i < kBlockSize; ++i) {
        outer[i] = static_cast<uint8_t>(key_block[i] ^ 0x5CU);
    }
    std::memcpy(outer.data() + kBlockSize, inner_hash.data(), inner_hash.size());
    return MdfpSha256::hash_bytes(outer.data(), outer.size());
}

inline std::string bytes32_to_hex(const std::array<uint8_t, 32>& digest) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : digest) {
        oss << std::setw(2) << static_cast<unsigned int>(b);
    }
    return oss.str();
}

// Compute SIMULATED per-frame exposure/gain multiplier from HMAC-SHA256(secret, be32(frame_seq)).
// Bimodal gain band: [0.65, 0.85] or [1.15, 1.35] (>= 15% excursion away from neutral 1.0)
// so unmodulated frames (gain == 1.0) cannot pass challenge checks by luck.
inline double compute_challenge_gain(
    const uint8_t* secret,
    size_t secret_len,
    uint32_t frame_seq) {
    const uint8_t msg[4] = {
        static_cast<uint8_t>((frame_seq >> 24) & 0xFFU),
        static_cast<uint8_t>((frame_seq >> 16) & 0xFFU),
        static_cast<uint8_t>((frame_seq >> 8) & 0xFFU),
        static_cast<uint8_t>(frame_seq & 0xFFU),
    };
    const std::array<uint8_t, 32> digest = hmac_sha256(secret, secret_len, msg, sizeof(msg));
    const double sign = (digest[0] & 0x01U) ? 1.0 : -1.0;
    const uint32_t r = (static_cast<uint32_t>(digest[1]) << 24) |
                       (static_cast<uint32_t>(digest[2]) << 16) |
                       (static_cast<uint32_t>(digest[3]) << 8) |
                       static_cast<uint32_t>(digest[4]);
    const double frac = static_cast<double>(r) / 4294967295.0;
    const double magnitude = 0.15 + 0.20 * frac;  // [0.15, 0.35]
    return 1.0 + sign * magnitude;
}

inline double compute_mean_intensity(const uint16_t* pixels, size_t count) {
    if (!pixels || count == 0U) {
        return 0.0;
    }
    double sum = 0.0;
    for (size_t i = 0; i < count; ++i) {
        sum += static_cast<double>(pixels[i]);
    }
    return sum / static_cast<double>(count);
}

inline uint64_t ms_to_cycles(double ms, uint64_t cycles_per_sec) {
    if (ms <= 0.0 || cycles_per_sec == 0ULL) {
        return 0ULL;
    }
    double c = (ms / 1000.0) * static_cast<double>(cycles_per_sec);
    return (c > 0.0) ? static_cast<uint64_t>(c) : 0ULL;
}

inline double cycles_to_us(uint64_t cycles, uint64_t cycles_per_sec) {
    if (cycles_per_sec == 0ULL) {
        return 0.0;
    }
    return (static_cast<double>(cycles) * 1000000.0) / static_cast<double>(cycles_per_sec);
}

struct ExtraSignalConfig {
    bool enabled = false;  // OFF by default per Task 7 specification
    bool check_sequence = false;
    bool check_timing = false;
    bool check_challenge = false;
    uint64_t cycles_per_sec = 1000000000ULL;
    uint64_t min_interval_cycles = 0ULL;
    uint64_t max_interval_cycles = 0ULL;
    double min_interval_ms = DEFAULT_MIN_INTERVAL_MS;
    double max_interval_ms = DEFAULT_MAX_INTERVAL_MS;
    double baseline_intensity = DEFAULT_BASELINE_INTENSITY;
    double intensity_tolerance_ratio = DEFAULT_TOLERANCE_RATIO;
    double intensity_tolerance_min = DEFAULT_MIN_TOLERANCE_ADU;
    std::vector<uint8_t> shared_secret = default_demo_shared_secret();

    static ExtraSignalConfig disabled_default(uint64_t cps = 1000000000ULL) {
        ExtraSignalConfig c;
        c.cycles_per_sec = cps ? cps : 1000000000ULL;
        return c;
    }

    static ExtraSignalConfig enabled_sim_default(uint64_t cps = 1000000000ULL) {
        ExtraSignalConfig c;
        c.enabled = true;
        c.check_sequence = true;
        c.check_timing = true;
        c.check_challenge = true;
        c.cycles_per_sec = cps ? cps : 1000000000ULL;
        return c;
    }

    bool any_active() const {
        return enabled && (check_sequence || check_timing || check_challenge);
    }

    uint64_t effective_min_cycles() const {
        return (min_interval_cycles > 0ULL)
                   ? min_interval_cycles
                   : ms_to_cycles(min_interval_ms, cycles_per_sec);
    }

    uint64_t effective_max_cycles() const {
        return (max_interval_cycles > 0ULL)
                   ? max_interval_cycles
                   : ms_to_cycles(max_interval_ms, cycles_per_sec);
    }
};

struct PercentileStats {
    uint64_t sample_count = 0ULL;
    uint64_t p50_cycles = 0ULL;
    uint64_t p99_cycles = 0ULL;
    double p50_us = 0.0;
    double p99_us = 0.0;
};

class IntervalStatsTracker {
public:
    void reset() {
        head_ = 0U;
        count_ = 0U;
        total_samples_ = 0ULL;
    }

    void record(uint64_t interval_cycles) {
        samples_[head_] = interval_cycles;
        head_ = (head_ + 1U) % INTERVAL_WINDOW_CAPACITY;
        if (count_ < INTERVAL_WINDOW_CAPACITY) {
            ++count_;
        }
        ++total_samples_;
    }

    PercentileStats compute(uint64_t cycles_per_sec) const {
        PercentileStats st;
        st.sample_count = total_samples_;
        if (count_ == 0U) {
            return st;
        }
        std::vector<uint64_t> sorted(samples_.begin(), samples_.begin() + count_);
        std::sort(sorted.begin(), sorted.end());
        st.p50_cycles = interpolate(sorted, 0.50);
        st.p99_cycles = interpolate(sorted, 0.99);
        st.p50_us = cycles_to_us(st.p50_cycles, cycles_per_sec);
        st.p99_us = cycles_to_us(st.p99_cycles, cycles_per_sec);
        return st;
    }

private:
    static uint64_t interpolate(const std::vector<uint64_t>& sorted, double q) {
        if (sorted.empty()) {
            return 0ULL;
        }
        if (sorted.size() == 1U) {
            return sorted[0];
        }
        double pos = q * static_cast<double>(sorted.size() - 1U);
        size_t lo = static_cast<size_t>(std::floor(pos));
        size_t hi = std::min(lo + 1U, sorted.size() - 1U);
        double frac = pos - static_cast<double>(lo);
        double val = static_cast<double>(sorted[lo]) * (1.0 - frac) +
                     static_cast<double>(sorted[hi]) * frac;
        return static_cast<uint64_t>(std::llround(val));
    }

    std::array<uint64_t, INTERVAL_WINDOW_CAPACITY> samples_{};
    size_t head_ = 0U;
    size_t count_ = 0U;
    uint64_t total_samples_ = 0ULL;
};

struct ExtraSignalEvaluation {
    bool enabled = false;
    bool seq_ok = true;
    bool timing_ok = true;
    bool challenge_ok = true;
    bool all_ok = true;
    uint64_t interval_cycles = 0ULL;
    double interval_us = 0.0;
    double expected_gain = 1.0;
    double expected_mean_intensity = DEFAULT_BASELINE_INTENSITY;
    double measured_mean_intensity = 0.0;
    char verdict[48] = {};
    PercentileStats interval_stats{};
};

class SignalMonitor {
public:
    explicit SignalMonitor(const ExtraSignalConfig& cfg = ExtraSignalConfig::disabled_default())
        : cfg_(cfg) {}

    void configure(const ExtraSignalConfig& cfg) {
        cfg_ = cfg;
        reset();
    }

    void reset() {
        has_prev_ = false;
        prev_seq_ = 0U;
        prev_cycles_ = 0ULL;
        seq_timing_failures_ = 0ULL;
        challenge_failures_ = 0ULL;
        tracker_.reset();
    }

    const ExtraSignalConfig& config() const { return cfg_; }
    uint64_t seq_timing_failures() const { return seq_timing_failures_; }
    uint64_t challenge_failures() const { return challenge_failures_; }
    PercentileStats current_stats() const { return tracker_.compute(cfg_.cycles_per_sec); }

    ExtraSignalEvaluation evaluate(
        uint32_t frame_seq,
        uint64_t frame_cycles,
        const uint16_t* bayer_raw,
        size_t num_pixels) {
        ExtraSignalEvaluation ev;
        ev.measured_mean_intensity = compute_mean_intensity(bayer_raw, num_pixels);
        std::snprintf(ev.verdict, sizeof(ev.verdict), "%s", "OK");

        if (!cfg_.any_active()) {
            ev.enabled = false;
            ev.all_ok = true;
            ev.interval_stats = tracker_.compute(cfg_.cycles_per_sec);
            return ev;
        }
        ev.enabled = true;

        // 1. Sequence monotonicity + no gaps check
        bool is_replay_or_rollback = false;
        if (cfg_.check_sequence) {
            if (frame_seq == 0U) {
                ev.seq_ok = false;
                std::snprintf(ev.verdict, sizeof(ev.verdict), "%s", "BLOCK_SEQ_INVALID");
            } else if (has_prev_) {
                if (frame_seq <= prev_seq_) {
                    ev.seq_ok = false;
                    is_replay_or_rollback = true;
                    std::snprintf(ev.verdict, sizeof(ev.verdict), "%s", "BLOCK_SEQ_REPLAY");
                } else if (frame_seq != prev_seq_ + 1U) {
                    ev.seq_ok = false;
                    std::snprintf(ev.verdict, sizeof(ev.verdict), "%s", "BLOCK_SEQ_GAP");
                }
            }
        }

        // 2. Inter-frame ClockCycles interval bounds + p50/p99 tracking
        if (has_prev_) {
            if (frame_cycles < prev_cycles_) {
                if (cfg_.check_timing) {
                    ev.timing_ok = false;
                    if (ev.seq_ok) {
                        std::snprintf(
                            ev.verdict, sizeof(ev.verdict), "%s", "BLOCK_TIMING_NON_MONOTONIC");
                    }
                }
            } else {
                const uint64_t delta = frame_cycles - prev_cycles_;
                ev.interval_cycles = delta;
                ev.interval_us = cycles_to_us(delta, cfg_.cycles_per_sec);
                tracker_.record(delta);
                if (cfg_.check_timing) {
                    const uint64_t min_c = cfg_.effective_min_cycles();
                    const uint64_t max_c = cfg_.effective_max_cycles();
                    if ((min_c > 0ULL && delta < min_c) || (max_c > 0ULL && delta > max_c)) {
                        ev.timing_ok = false;
                        if (ev.seq_ok) {
                            std::snprintf(
                                ev.verdict, sizeof(ev.verdict), "%s", "BLOCK_TIMING_OUT_OF_BOUNDS");
                        }
                    }
                }
            }
        }

        // Advance high-water marks except on replay/rollback attempts.
        if (!has_prev_) {
            has_prev_ = true;
            prev_seq_ = frame_seq;
            prev_cycles_ = frame_cycles;
        } else if (!is_replay_or_rollback) {
            if (frame_seq > prev_seq_) {
                prev_seq_ = frame_seq;
            }
            if (frame_cycles > prev_cycles_) {
                prev_cycles_ = frame_cycles;
            }
        }

        // 3. Challenge-response exposure/gain check: HMAC(secret, frame_seq)
        if (cfg_.check_challenge) {
            ev.expected_gain = compute_challenge_gain(
                cfg_.shared_secret.data(), cfg_.shared_secret.size(), frame_seq);
            ev.expected_mean_intensity = cfg_.baseline_intensity * ev.expected_gain;
            const double tol = std::max(
                cfg_.intensity_tolerance_min,
                ev.expected_mean_intensity * cfg_.intensity_tolerance_ratio);
            if (!bayer_raw || num_pixels == 0U ||
                std::fabs(ev.measured_mean_intensity - ev.expected_mean_intensity) > tol) {
                ev.challenge_ok = false;
                if (ev.seq_ok && ev.timing_ok) {
                    std::snprintf(
                        ev.verdict, sizeof(ev.verdict), "%s", "BLOCK_CHALLENGE_MODULATION");
                }
            }
        }

        if (!ev.seq_ok || !ev.timing_ok) {
            ++seq_timing_failures_;
        }
        if (!ev.challenge_ok) {
            ++challenge_failures_;
        }

        ev.all_ok = ev.seq_ok && ev.timing_ok && ev.challenge_ok;
        ev.interval_stats = tracker_.compute(cfg_.cycles_per_sec);
        return ev;
    }

private:
    ExtraSignalConfig cfg_;
    bool has_prev_ = false;
    uint32_t prev_seq_ = 0U;
    uint64_t prev_cycles_ = 0ULL;
    uint64_t seq_timing_failures_ = 0ULL;
    uint64_t challenge_failures_ = 0ULL;
    IntervalStatsTracker tracker_;
};

struct CombinedVerifyResult {
    mdfp::ingest::VerifyDecision prnu;
    ExtraSignalEvaluation signals;
};

// Combined host-testable evaluation pipeline used by md-verify:
// 1. Always checks SHA-256 over the private copy + PRNU correlation.
// 2. When extra signals are disabled (default), behaves identically to verify_private_frame().
// 3. When extra signals are enabled, independently validates sequence monotonicity/no-gaps,
//    inter-frame ClockCycles bounds (reporting p50/p99), and HMAC(secret, frame_seq)
//    mean-intensity modulation, rejecting replays and wrong-modulation spoofs even when PRNU matches.
inline CombinedVerifyResult verify_frame_with_extra_signals(
    uint32_t frame_seq,
    uint32_t scenario,
    uint32_t payload_bytes,
    const char expected_frame_sha256[65],
    const uint16_t private_bayer_raw[MDFP_PRNU_SIZE],
    const double k_ref[MDFP_PRNU_SIZE],
    uint64_t hw_eof_cycles,
    SignalMonitor* monitor,
    double ncc_threshold = MDFP_NCC_THRESHOLD,
    double pce_threshold_linear = MDFP_PCE_THRESHOLD_LINEAR) {
    CombinedVerifyResult out;
    out.prnu = mdfp::ingest::verify_private_frame(
        frame_seq,
        scenario,
        payload_bytes,
        expected_frame_sha256,
        private_bayer_raw,
        k_ref,
        ncc_threshold,
        pce_threshold_linear);

    if (!out.prnu.hash_verified) {
        if (monitor) {
            out.signals.interval_stats = monitor->current_stats();
        }
        return out;
    }

    if (monitor && monitor->config().any_active()) {
        out.signals = monitor->evaluate(
            frame_seq, hw_eof_cycles, private_bayer_raw, MDFP_PRNU_SIZE);
        if (out.prnu.allow && !out.signals.all_ok) {
            out.prnu.allow = false;
            out.prnu.status = 2U;  // REJECTED_TIMING
            mdfp::ingest::copy_cstr_bounded(
                out.prnu.verdict, sizeof(out.prnu.verdict), out.signals.verdict);
        }
    } else if (monitor) {
        out.signals.interval_stats = monitor->current_stats();
    }
    return out;
}

}  // namespace signals
}  // namespace mdfp
