#include "../../qnx/common/mdfp_ingest.h"

#include <atomic>
#include <cassert>
#include <cmath>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

void fill_authentic_frame(uint16_t* dst, uint32_t frame_seq, const double k_ref[MDFP_PRNU_SIZE]) {
    uint32_t noise_seed = 0x55AA55AAu + frame_seq * 97u;
    for (int i = 0; i < MDFP_PRNU_SIZE; ++i) {
        noise_seed = noise_seed * 1103515245u + 12345u;
        double shot_noise = ((static_cast<double>((noise_seed >> 16) & 0x7FFFu) / 16384.0) - 1.0) * 8.0;
        double pix = 2048.0 * (1.0 + k_ref[i] * 64.0 * 0.015) + shot_noise;
        if (pix < 0.0) pix = 0.0;
        if (pix > 65535.0) pix = 65535.0;
        dst[i] = static_cast<uint16_t>(pix);
    }
}

void init_synth_raw_pattern(double k_raw[MDFP_PRNU_SIZE]) {
    uint32_t seed = 0x20261111u;
    for (int i = 0; i < MDFP_PRNU_SIZE; ++i) {
        seed = seed * 1664525u + 1013904223u;
        k_raw[i] = ((static_cast<double>(seed & 0xFFFFu) / 32768.0) - 1.0) * 0.015;
    }
}

void test_post_copy_shm_mutation_cannot_break_hash_or_verify() {
    double k_ref[MDFP_PRNU_SIZE] = {};
    double k_raw[MDFP_PRNU_SIZE] = {};
    mdfp::ingest::init_simulated_k_ref(k_ref);
    init_synth_raw_pattern(k_raw);

    std::vector<uint16_t> simulated_shm(MDFP_PRNU_SIZE, 0);
    for (int i = 0; i < MDFP_PRNU_SIZE; ++i) {
        double pix = 2048.0 * (1.0 + k_raw[i]) + ((i % 7) - 3);
        simulated_shm[static_cast<size_t>(i)] = static_cast<uint16_t>(pix);
    }
    const std::string original_hash = MdfpSha256::hash_hex(
        reinterpret_cast<const uint8_t*>(simulated_shm.data()), MDFP_RAW_BYTES);

    mdfp::ingest::PrivateFrameSnapshot snap;
    mdfp::ingest::capture_copy_from_shm_and_hash(
        0x4D444650u,
        42u,
        mdfp::ingest::SCENARIO_NATIVE,
        100000ULL,
        1700000000000000000ULL,
        MDFP_SENSOR_WIDTH,
        MDFP_SENSOR_HEIGHT,
        MDFP_RAW_BYTES,
        simulated_shm.data(),
        100500ULL,
        1700000000000001000ULL,
        "sensor-cam-front",
        &snap);

    // Hostile producer zeroes/overwrites shared memory immediately after ingestion copy!
    std::fill(simulated_shm.begin(), simulated_shm.end(), static_cast<uint16_t>(0xBEEF));

    assert(std::string(snap.frame_sha256) == original_hash);
    assert(snap.frame_seq == 42u);
    assert(snap.capture_cycles == 100500ULL);
    assert(std::string(snap.sensor_id) == "sensor-cam-front");

    // md-verify operates strictly on snap.bayer_raw (no SHM read at all) and re-checks hash.
    mdfp::ingest::VerifyDecision dec = mdfp::ingest::verify_private_frame(
        snap.frame_seq,
        snap.scenario,
        snap.payload_bytes,
        snap.frame_sha256,
        snap.bayer_raw,
        k_ref,
        0.75,
        60.0);

    assert(dec.hash_verified);
    assert(dec.allow);
    assert(dec.status == 0u);
    assert(std::string(dec.frame_sha256) == original_hash);
    assert(std::string(dec.verdict) == "VERIFIED_AUTHENTIC_SILICON");
}

void test_tampered_private_buffer_or_hash_fails_closed() {
    double k_ref[MDFP_PRNU_SIZE] = {};
    mdfp::ingest::init_simulated_k_ref(k_ref);

    std::vector<uint16_t> buf(MDFP_PRNU_SIZE, 2048);
    fill_authentic_frame(buf.data(), 7u, k_ref);

    mdfp::ingest::PrivateFrameSnapshot snap;
    mdfp::ingest::capture_copy_from_shm_and_hash(
        0x4D444650u,
        7u,
        mdfp::ingest::SCENARIO_NATIVE,
        1000ULL,
        2000ULL,
        64u,
        64u,
        MDFP_RAW_BYTES,
        buf.data(),
        1100ULL,
        2100ULL,
        MDFP_DEFAULT_SENSOR_ID,
        &snap);

    // Corrupt 1 pixel inside message after hashing -> verify MUST reject
    mdfp::ingest::PrivateFrameSnapshot bad_pix = snap;
    bad_pix.bayer_raw[123] ^= 1U;
    mdfp::ingest::VerifyDecision d1 = mdfp::ingest::verify_private_frame(
        bad_pix.frame_seq,
        bad_pix.scenario,
        bad_pix.payload_bytes,
        bad_pix.frame_sha256,
        bad_pix.bayer_raw,
        k_ref);
    assert(!d1.hash_verified);
    assert(!d1.allow);
    assert(d1.status == 3u);
    assert(std::string(d1.verdict) == "BLOCK_INGEST_HASH_MISMATCH");

    // Corrupt 1 nibble in frame_sha256 -> verify MUST reject
    mdfp::ingest::PrivateFrameSnapshot bad_hash = snap;
    bad_hash.frame_sha256[0] = (bad_hash.frame_sha256[0] == 'a') ? 'b' : 'a';
    mdfp::ingest::VerifyDecision d2 = mdfp::ingest::verify_private_frame(
        bad_hash.frame_seq,
        bad_hash.scenario,
        bad_hash.payload_bytes,
        bad_hash.frame_sha256,
        bad_hash.bayer_raw,
        k_ref);
    assert(!d2.hash_verified);
    assert(!d2.allow);
    assert(d2.status == 3u);
    assert(std::string(d2.verdict) == "BLOCK_INGEST_HASH_MISMATCH");

    // Invalid payload size -> reject
    mdfp::ingest::VerifyDecision d3 = mdfp::ingest::verify_private_frame(
        snap.frame_seq,
        snap.scenario,
        1024u,
        snap.frame_sha256,
        snap.bayer_raw,
        k_ref);
    assert(!d3.allow);
    assert(d3.status == 3u);
    assert(std::string(d3.verdict) == "BLOCK_INVALID_FRAME_PAYLOAD");
}

void test_concurrent_producer_mutation_preserves_private_self_consistency() {
    double k_ref[MDFP_PRNU_SIZE] = {};
    mdfp::ingest::init_simulated_k_ref(k_ref);

    // Protected synchronization for TSan cleanliness while exercising rapid SHM churn
    std::vector<uint16_t> shared_frame(MDFP_PRNU_SIZE, 1024);
    std::atomic<bool> stop{false};

    for (uint32_t iter = 1; iter <= 15; ++iter) {
        std::atomic<uint16_t> tag{static_cast<uint16_t>(iter)};
        mdfp::ingest::PrivateFrameSnapshot snap;

        mdfp::ingest::capture_copy_from_shm_and_hash(
            0x4D444650u,
            iter,
            (iter % 2 == 0) ? mdfp::ingest::SCENARIO_SYNTH_NO_PRNU : mdfp::ingest::SCENARIO_FOREIGN,
            iter * 100ULL,
            iter * 1000ULL,
            64u,
            64u,
            MDFP_RAW_BYTES,
            shared_frame.data(),
            iter * 105ULL,
            iter * 1010ULL,
            MDFP_DEFAULT_SENSOR_ID,
            &snap);

        // Mutate shared buffer on a separate thread after capture copy returned
        std::thread mutator([&]() {
            uint16_t v = tag.load(std::memory_order_relaxed);
            for (size_t i = 0; i < MDFP_PRNU_SIZE; ++i) {
                shared_frame[i] = static_cast<uint16_t>(v + i);
            }
        });

        mdfp::ingest::VerifyDecision dec = mdfp::ingest::verify_private_frame(
            snap.frame_seq,
            snap.scenario,
            snap.payload_bytes,
            snap.frame_sha256,
            snap.bayer_raw,
            k_ref);
        mutator.join();

        assert(dec.hash_verified);
        assert(!dec.allow);
    }
    (void)stop;
}

}  // namespace

int main() {
    test_post_copy_shm_mutation_cannot_break_hash_or_verify();
    test_tampered_private_buffer_or_hash_fails_closed();
    test_concurrent_producer_mutation_preserves_private_self_consistency();
    std::cout << "[PASS] Ingestion trust boundary (private snapshot + SHA-256 re-check) verified."
              << std::endl;
    return 0;
}
