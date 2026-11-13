#include "../../qnx/common/mdfp_signals.h"

#include <array>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

void synthesize_test_frame(
    const double k_ref[MDFP_PRNU_SIZE],
    double gain,
    uint32_t seed_init,
    uint16_t out_pixels[MDFP_PRNU_SIZE],
    char out_sha256[65]) {
    uint32_t seed = seed_init;
    const double illum = mdfp::signals::DEFAULT_BASELINE_INTENSITY * gain;
    for (int i = 0; i < MDFP_PRNU_SIZE; ++i) {
        seed = seed * 1103515245u + 12345u;
        double shot_noise = ((static_cast<double>((seed >> 16) & 0x7FFFu) / 16384.0) - 1.0) * 8.0;
        double val = illum * (1.0 + k_ref[i]) + shot_noise;
        if (val < 0.0) val = 0.0;
        if (val > 65535.0) val = 65535.0;
        out_pixels[i] = static_cast<uint16_t>(val);
    }
    std::string hex = MdfpSha256::hash_hex(
        reinterpret_cast<const uint8_t*>(out_pixels), MDFP_RAW_BYTES);
    mdfp::ingest::copy_cstr_bounded(out_sha256, 65, hex.c_str());
}

void test_rfc4231_hmac_sha256_kats() {
    // Case 1: 20-byte 0x0b key, "Hi There"
    std::vector<uint8_t> k1(20, 0x0BU);
    const char d1[] = "Hi There";
    auto h1 = mdfp::signals::hmac_sha256(
        k1.data(), k1.size(), reinterpret_cast<const uint8_t*>(d1), sizeof(d1) - 1U);
    assert(mdfp::signals::bytes32_to_hex(h1) ==
           "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    // Case 2: "Jefe", "what do ya want for nothing?"
    const char k2[] = "Jefe";
    const char d2[] = "what do ya want for nothing?";
    auto h2 = mdfp::signals::hmac_sha256(
        reinterpret_cast<const uint8_t*>(k2), sizeof(k2) - 1U,
        reinterpret_cast<const uint8_t*>(d2), sizeof(d2) - 1U);
    assert(mdfp::signals::bytes32_to_hex(h2) ==
           "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    // Case 3: 20-byte 0xaa key, 50-byte 0xdd data
    std::vector<uint8_t> k3(20, 0xAAU);
    std::vector<uint8_t> d3(50, 0xDDU);
    auto h3 = mdfp::signals::hmac_sha256(k3.data(), k3.size(), d3.data(), d3.size());
    assert(mdfp::signals::bytes32_to_hex(h3) ==
           "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    // Case 4: 25-byte 0x01..0x19 key, 50-byte 0xcd data
    std::vector<uint8_t> k4(25);
    for (size_t i = 0; i < k4.size(); ++i) k4[i] = static_cast<uint8_t>(i + 1U);
    std::vector<uint8_t> d4(50, 0xCDU);
    auto h4 = mdfp::signals::hmac_sha256(k4.data(), k4.size(), d4.data(), d4.size());
    assert(mdfp::signals::bytes32_to_hex(h4) ==
           "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");

    // Case 6: 131-byte 0xaa key (> 64-byte block size -> hashed first)
    std::vector<uint8_t> k6(131, 0xAAU);
    const char d6[] = "Test Using Larger Than Block-Size Key - Hash Key First";
    auto h6 = mdfp::signals::hmac_sha256(
        k6.data(), k6.size(), reinterpret_cast<const uint8_t*>(d6), sizeof(d6) - 1U);
    assert(mdfp::signals::bytes32_to_hex(h6) ==
           "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

    std::cout << "[PASS] RFC 4231 HMAC-SHA256 KAT vectors (Cases 1,2,3,4,6)\n";
}

void test_off_by_default_preserves_legacy_behavior() {
    double k_ref[MDFP_PRNU_SIZE]{};
    mdfp::ingest::init_simulated_k_ref(k_ref);

    auto cfg = mdfp::signals::ExtraSignalConfig::disabled_default(1000000000ULL);
    assert(!cfg.enabled);
    assert(!cfg.check_sequence);
    assert(!cfg.check_timing);
    assert(!cfg.check_challenge);
    assert(!cfg.any_active());

    mdfp::signals::SignalMonitor monitor(cfg);
    uint16_t pixels[MDFP_PRNU_SIZE]{};
    char sha[65]{};

    // Unmodulated frame + sequence gap + huge 200ms delta must still pass when OFF by default
    synthesize_test_frame(k_ref, 1.0, 0x1111u, pixels, sha);
    auto r1 = mdfp::signals::verify_frame_with_extra_signals(
        10U, mdfp::ingest::SCENARIO_NATIVE, MDFP_RAW_BYTES, sha, pixels, k_ref,
        1000000000ULL, &monitor);
    assert(r1.prnu.allow);
    assert(!r1.signals.enabled);

    // Repeat same frame_seq + huge delta + SCENARIO_SYNTH_WITH_PRNU -> still matches legacy behavior
    synthesize_test_frame(k_ref, 1.0, 0x2222u, pixels, sha);
    auto r2 = mdfp::signals::verify_frame_with_extra_signals(
        10U, mdfp::ingest::SCENARIO_SYNTH_WITH_PRNU, MDFP_RAW_BYTES, sha, pixels, k_ref,
        1200000000ULL, &monitor);
    assert(r2.prnu.allow);
    assert(std::strcmp(r2.prnu.verdict, "BOUNDARY_PRNU_PASSED_CADENCE_FLAGGED") == 0);
    assert(monitor.seq_timing_failures() == 0ULL);
    assert(monitor.challenge_failures() == 0ULL);

    std::cout << "[PASS] Extra signals OFF by default preserves legacy verification\n";
}

void test_challenge_gain_band_and_authentic_stream_p50_p99() {
    double k_ref[MDFP_PRNU_SIZE]{};
    mdfp::ingest::init_simulated_k_ref(k_ref);

    auto cfg = mdfp::signals::ExtraSignalConfig::enabled_sim_default(1000000000ULL);
    assert(cfg.any_active());

    // Ensure every generated gain stays >= 15% away from neutral 1.0
    for (uint32_t s = 1U; s <= 200U; ++s) {
        double g = mdfp::signals::compute_challenge_gain(
            cfg.shared_secret.data(), cfg.shared_secret.size(), s);
        assert((g >= 0.65 && g <= 0.85) || (g >= 1.15 && g <= 1.35));
        assert(std::fabs(g - 1.0) >= 0.149999);
    }

    mdfp::signals::SignalMonitor monitor(cfg);
    uint16_t pixels[MDFP_PRNU_SIZE]{};
    char sha[65]{};

    uint64_t cycles = 1000000000ULL;
    // Feed 101 frames -> 100 inter-frame intervals:
    // 99 intervals at 33,000,000 cycles (33,000 us) + 1 tail interval at 50,000,000 cycles (50,000 us).
    for (uint32_t seq = 1U; seq <= 101U; ++seq) {
        if (seq > 1U) {
            cycles += (seq == 101U) ? 50000000ULL : 33000000ULL;
        }
        double g = mdfp::signals::compute_challenge_gain(
            cfg.shared_secret.data(), cfg.shared_secret.size(), seq);
        synthesize_test_frame(k_ref, g, 0x55AA0000u + seq, pixels, sha);

        auto res = mdfp::signals::verify_frame_with_extra_signals(
            seq, mdfp::ingest::SCENARIO_NATIVE, MDFP_RAW_BYTES, sha, pixels, k_ref,
            cycles, &monitor);
        assert(res.prnu.hash_verified);
        assert(res.prnu.ncc >= MDFP_NCC_THRESHOLD);
        assert(res.prnu.pce_linear >= MDFP_PCE_THRESHOLD_LINEAR);
        assert(res.signals.enabled);
        assert(res.signals.seq_ok);
        assert(res.signals.timing_ok);
        assert(res.signals.challenge_ok);
        assert(res.signals.all_ok);
        assert(res.prnu.allow);
        assert(std::strcmp(res.prnu.verdict, "VERIFIED_AUTHENTIC_SILICON") == 0);
    }

    const auto st = monitor.current_stats();
    assert(st.sample_count == 100ULL);
    assert(st.p50_cycles == 33000000ULL);
    // 99th percentile at index 0.99 * 99 = 98.01 -> 33,000,000*0.99 + 50,000,000*0.01 = 33,170,000
    assert(st.p99_cycles == 33170000ULL);
    assert(std::fabs(st.p50_us - 33000.0) < 1e-6);
    assert(std::fabs(st.p99_us - 33170.0) < 1e-6);
    assert(monitor.seq_timing_failures() == 0ULL);
    assert(monitor.challenge_failures() == 0ULL);

    std::cout << "[PASS] 101 modulated authentic frames + exact p50/p99 cycle/us stats\n";
}

void test_replay_and_wrong_modulation_and_timing_failures() {
    double k_ref[MDFP_PRNU_SIZE]{};
    mdfp::ingest::init_simulated_k_ref(k_ref);

    auto cfg = mdfp::signals::ExtraSignalConfig::enabled_sim_default(1000000000ULL);
    mdfp::signals::SignalMonitor monitor(cfg);

    struct Saved {
        uint32_t seq;
        std::array<uint16_t, MDFP_PRNU_SIZE> pixels;
        char sha[65];
        double gain;
    };
    std::vector<Saved> recorded;
    uint64_t cycles = 5000000000ULL;

    // 1. Establish 6 valid frames first
    for (uint32_t seq = 1U; seq <= 6U; ++seq) {
        if (seq > 1U) cycles += 33333000ULL;
        Saved item{};
        item.seq = seq;
        item.gain = mdfp::signals::compute_challenge_gain(
            cfg.shared_secret.data(), cfg.shared_secret.size(), seq);
        synthesize_test_frame(k_ref, item.gain, 0x7700u + seq, item.pixels.data(), item.sha);
        auto res = mdfp::signals::verify_frame_with_extra_signals(
            seq, mdfp::ingest::SCENARIO_NATIVE, MDFP_RAW_BYTES, item.sha,
            item.pixels.data(), k_ref, cycles, &monitor);
        assert(res.prnu.allow);
        recorded.push_back(item);
    }

    // 2. Verbatim replay of recorded frame #3 (same pixels + same old seq = 3)
    cycles += 33333000ULL;
    auto replay_verbatim = mdfp::signals::verify_frame_with_extra_signals(
        recorded[2].seq, mdfp::ingest::SCENARIO_NATIVE, MDFP_RAW_BYTES,
        recorded[2].sha, recorded[2].pixels.data(), k_ref, cycles, &monitor);
    assert(replay_verbatim.prnu.ncc >= MDFP_NCC_THRESHOLD);
    assert(!replay_verbatim.prnu.allow);
    assert(!replay_verbatim.signals.seq_ok);
    assert(std::strcmp(replay_verbatim.prnu.verdict, "BLOCK_SEQ_REPLAY") == 0);
    assert(monitor.seq_timing_failures() == 1ULL);

    // 3. Recorded authentic frame re-injected with incremented seq = 7 -> modulation mismatch
    uint32_t next_seq = 7U;
    double target_gain_7 = mdfp::signals::compute_challenge_gain(
        cfg.shared_secret.data(), cfg.shared_secret.size(), next_seq);
    size_t mismatch_idx = 0U;
    for (size_t k = 0; k < recorded.size(); ++k) {
        if (std::fabs(recorded[k].gain - target_gain_7) > 0.15) {
            mismatch_idx = k;
            break;
        }
    }
    cycles += 33333000ULL;
    auto replay_bumped_seq = mdfp::signals::verify_frame_with_extra_signals(
        next_seq, mdfp::ingest::SCENARIO_NATIVE, MDFP_RAW_BYTES,
        recorded[mismatch_idx].sha, recorded[mismatch_idx].pixels.data(), k_ref, cycles, &monitor);
    assert(replay_bumped_seq.signals.seq_ok);
    assert(replay_bumped_seq.signals.timing_ok);
    assert(!replay_bumped_seq.signals.challenge_ok);
    assert(!replay_bumped_seq.prnu.allow);
    assert(std::strcmp(replay_bumped_seq.prnu.verdict, "BLOCK_CHALLENGE_MODULATION") == 0);
    assert(monitor.challenge_failures() == 1ULL);

    // 4. Synthetic frame with correct K_REF (SCENARIO_SYNTH_WITH_PRNU) & flat intensity (gain = 1.0)
    uint16_t synth_pixels[MDFP_PRNU_SIZE]{};
    char synth_sha[65]{};
    synthesize_test_frame(k_ref, 1.0, 0x8800u, synth_pixels, synth_sha);
    cycles += 33333000ULL;
    auto synth_flat = mdfp::signals::verify_frame_with_extra_signals(
        8U, mdfp::ingest::SCENARIO_SYNTH_WITH_PRNU, MDFP_RAW_BYTES,
        synth_sha, synth_pixels, k_ref, cycles, &monitor);
    assert(synth_flat.prnu.ncc >= MDFP_NCC_THRESHOLD);
    assert(synth_flat.prnu.pce_linear >= MDFP_PCE_THRESHOLD_LINEAR);
    assert(!synth_flat.signals.challenge_ok);
    assert(!synth_flat.prnu.allow);
    assert(std::strcmp(synth_flat.prnu.verdict, "BLOCK_CHALLENGE_MODULATION") == 0);

    // 5. Synthetic frame with correct K_REF modulated using wrong secret
    const std::string wrong_secret = "WRONG-ATTACKER-SECRET";
    double wrong_gain = mdfp::signals::compute_challenge_gain(
        reinterpret_cast<const uint8_t*>(wrong_secret.data()), wrong_secret.size(), 9U);
    if (std::fabs(wrong_gain - mdfp::signals::compute_challenge_gain(
            cfg.shared_secret.data(), cfg.shared_secret.size(), 9U)) < 0.08) {
        // Ensure intentional wrong gain regardless of HMAC coincidence
        wrong_gain = (wrong_gain > 1.0) ? 0.70 : 1.30;
    }
    synthesize_test_frame(k_ref, wrong_gain, 0x9900u, synth_pixels, synth_sha);
    cycles += 33333000ULL;
    auto synth_wrong_secret = mdfp::signals::verify_frame_with_extra_signals(
        9U, mdfp::ingest::SCENARIO_NATIVE, MDFP_RAW_BYTES,
        synth_sha, synth_pixels, k_ref, cycles, &monitor);
    assert(!synth_wrong_secret.signals.challenge_ok);
    assert(!synth_wrong_secret.prnu.allow);
    assert(std::strcmp(synth_wrong_secret.prnu.verdict, "BLOCK_CHALLENGE_MODULATION") == 0);

    // 6. Sequence gap (9 -> 12) + valid modulation -> BLOCK_SEQ_GAP
    double g12 = mdfp::signals::compute_challenge_gain(
        cfg.shared_secret.data(), cfg.shared_secret.size(), 12U);
    synthesize_test_frame(k_ref, g12, 0xAA00u, synth_pixels, synth_sha);
    cycles += 33333000ULL;
    auto seq_gap = mdfp::signals::verify_frame_with_extra_signals(
        12U, mdfp::ingest::SCENARIO_NATIVE, MDFP_RAW_BYTES,
        synth_sha, synth_pixels, k_ref, cycles, &monitor);
    assert(!seq_gap.signals.seq_ok);
    assert(seq_gap.signals.challenge_ok);
    assert(!seq_gap.prnu.allow);
    assert(std::strcmp(seq_gap.prnu.verdict, "BLOCK_SEQ_GAP") == 0);

    // 7. Out-of-bounds ClockCycles intervals: too fast (2ms < 10ms) and too slow (90ms > 75ms)
    double g13 = mdfp::signals::compute_challenge_gain(
        cfg.shared_secret.data(), cfg.shared_secret.size(), 13U);
    synthesize_test_frame(k_ref, g13, 0xAB00u, synth_pixels, synth_sha);
    cycles += 2000000ULL; // 2 ms
    auto too_fast = mdfp::signals::verify_frame_with_extra_signals(
        13U, mdfp::ingest::SCENARIO_NATIVE, MDFP_RAW_BYTES,
        synth_sha, synth_pixels, k_ref, cycles, &monitor);
    assert(too_fast.signals.seq_ok);
    assert(!too_fast.signals.timing_ok);
    assert(!too_fast.prnu.allow);
    assert(std::strcmp(too_fast.prnu.verdict, "BLOCK_TIMING_OUT_OF_BOUNDS") == 0);

    double g14 = mdfp::signals::compute_challenge_gain(
        cfg.shared_secret.data(), cfg.shared_secret.size(), 14U);
    synthesize_test_frame(k_ref, g14, 0xAC00u, synth_pixels, synth_sha);
    cycles += 90000000ULL; // 90 ms
    auto too_slow = mdfp::signals::verify_frame_with_extra_signals(
        14U, mdfp::ingest::SCENARIO_NATIVE, MDFP_RAW_BYTES,
        synth_sha, synth_pixels, k_ref, cycles, &monitor);
    assert(!too_slow.signals.timing_ok);
    assert(!too_slow.prnu.allow);
    assert(std::strcmp(too_slow.prnu.verdict, "BLOCK_TIMING_OUT_OF_BOUNDS") == 0);

    // 8. Non-monotonic cycles (hw_eof_cycles regresses)
    double g15 = mdfp::signals::compute_challenge_gain(
        cfg.shared_secret.data(), cfg.shared_secret.size(), 15U);
    synthesize_test_frame(k_ref, g15, 0xAD00u, synth_pixels, synth_sha);
    auto non_mono = mdfp::signals::verify_frame_with_extra_signals(
        15U, mdfp::ingest::SCENARIO_NATIVE, MDFP_RAW_BYTES,
        synth_sha, synth_pixels, k_ref, cycles - 1000ULL, &monitor);
    assert(!non_mono.signals.timing_ok);
    assert(!non_mono.prnu.allow);
    assert(std::strcmp(non_mono.prnu.verdict, "BLOCK_TIMING_NON_MONOTONIC") == 0);

    // 9. Recovery: next authentic frame (16) at nominal 33ms recovers cleanly
    double g16 = mdfp::signals::compute_challenge_gain(
        cfg.shared_secret.data(), cfg.shared_secret.size(), 16U);
    synthesize_test_frame(k_ref, g16, 0xAE00u, synth_pixels, synth_sha);
    cycles += 33000000ULL;
    auto recovered = mdfp::signals::verify_frame_with_extra_signals(
        16U, mdfp::ingest::SCENARIO_NATIVE, MDFP_RAW_BYTES,
        synth_sha, synth_pixels, k_ref, cycles, &monitor);
    assert(recovered.prnu.allow);
    assert(recovered.signals.all_ok);
    assert(std::strcmp(recovered.prnu.verdict, "VERIFIED_AUTHENTIC_SILICON") == 0);

    std::cout << "[PASS] Replay, K_REF wrong-modulation, seq gap, timing OOB & recovery checks\n";
}

void test_interval_ring_wraparound() {
    mdfp::signals::IntervalStatsTracker tracker;
    for (uint64_t i = 1ULL; i <= 1500ULL; ++i) {
        // First 500 values are huge (900000), latest 1000 values are 10000..11000
        tracker.record(i * 1000ULL);
    }
    auto st = tracker.compute(1000000000ULL);
    assert(st.sample_count == 1500ULL);
    // Ring holds latest 1024 values: 477,000 .. 1,500,000 -> p50 near 988,500 (excluding early <477,000)
    assert(st.p50_cycles >= 980000ULL && st.p50_cycles <= 995000ULL);
    assert(st.p99_cycles >= 1485000ULL && st.p99_cycles <= 1500000ULL);
    std::cout << "[PASS] IntervalStatsTracker 1024-sample ring wraparound\n";
}

}  // namespace

int main() {
    test_rfc4231_hmac_sha256_kats();
    test_off_by_default_preserves_legacy_behavior();
    test_challenge_gain_band_and_authentic_stream_p50_p99();
    test_replay_and_wrong_modulation_and_timing_failures();
    test_interval_ring_wraparound();
    return 0;
}
