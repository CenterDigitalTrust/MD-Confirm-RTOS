#include "../../qnx/common/mdfp_seqlock.h"

#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>

namespace {

MdfpStatsPayload make_payload(uint32_t seq) {
    MdfpStatsPayload p{};
    p.magic = MDFP_STATS_MAGIC_VALUE;
    p.last_frame_seq = seq;
    p.last_scenario = (seq % 5U) + 1U;
    p.last_pce_db = static_cast<double>(seq) * 0.125;
    p.last_pce_linear = static_cast<double>(seq) * 2.5 + 1.0;
    p.last_ncc = 0.5 + static_cast<double>(seq % 100U) * 0.004;
    p.last_latency_b_us = static_cast<double>(seq % 500U) * 0.5;
    p.last_jitter_us = static_cast<double>(seq % 97U) * 0.25;
    p.last_cycles_delta = static_cast<uint64_t>(seq) * 65537ULL + 13ULL;
    std::snprintf(p.last_verdict, sizeof(p.last_verdict), "VERDICT_%08u", seq);
    std::snprintf(p.last_frame_sha256, sizeof(p.last_frame_sha256), "%064x", seq);
    std::snprintf(p.last_merkle_root, sizeof(p.last_merkle_root), "%064x", seq ^ 0x5A5A5A5AU);
    p.total_frames = static_cast<uint64_t>(seq) * 1000003ULL + 7ULL;
    p.total_blocked = static_cast<uint64_t>(seq) + 11ULL;
    p.total_ghosts = static_cast<uint64_t>(seq / 3U);
    for (uint32_t k = 0; k < 10U; ++k) {
        p.hist_bins[k] = seq + k;
    }
    p.hist_total_samples = static_cast<uint64_t>(seq) * 10ULL;
    p.hist_min_us = 0.25;
    p.hist_max_us = static_cast<double>(seq) + 10.0;
    p.hist_mean_us = static_cast<double>(seq) * 0.5;
    return p;
}

void verify_payload_consistency(const MdfpStatsPayload& p) {
    assert(p.magic == MDFP_STATS_MAGIC_VALUE);
    const uint32_t seq = p.last_frame_seq;
    assert(p.last_scenario == (seq % 5U) + 1U);
    assert(p.last_pce_db == static_cast<double>(seq) * 0.125);
    assert(p.last_pce_linear == static_cast<double>(seq) * 2.5 + 1.0);
    assert(p.last_ncc == 0.5 + static_cast<double>(seq % 100U) * 0.004);
    assert(p.last_latency_b_us == static_cast<double>(seq % 500U) * 0.5);
    assert(p.last_jitter_us == static_cast<double>(seq % 97U) * 0.25);
    assert(p.last_cycles_delta == static_cast<uint64_t>(seq) * 65537ULL + 13ULL);
    assert(p.total_frames == static_cast<uint64_t>(seq) * 1000003ULL + 7ULL);
    assert(p.total_blocked == static_cast<uint64_t>(seq) + 11ULL);
    assert(p.total_ghosts == static_cast<uint64_t>(seq / 3U));
    for (uint32_t k = 0; k < 10U; ++k) {
        assert(p.hist_bins[k] == seq + k);
    }
    assert(p.hist_total_samples == static_cast<uint64_t>(seq) * 10ULL);
    assert(p.hist_min_us == 0.25);
    assert(p.hist_max_us == static_cast<double>(seq) + 10.0);
    assert(p.hist_mean_us == static_cast<double>(seq) * 0.5);

    char expected_verdict[48];
    char expected_sha[65];
    char expected_root[65];
    std::snprintf(expected_verdict, sizeof(expected_verdict), "VERDICT_%08u", seq);
    std::snprintf(expected_sha, sizeof(expected_sha), "%064x", seq);
    std::snprintf(expected_root, sizeof(expected_root), "%064x", seq ^ 0x5A5A5A5AU);
    assert(std::strcmp(p.last_verdict, expected_verdict) == 0);
    assert(std::strcmp(p.last_frame_sha256, expected_sha) == 0);
    assert(std::strcmp(p.last_merkle_root, expected_root) == 0);
}

void test_basic_states() {
    MdfpStatsShared shm{};
    MdfpStatsPayload snap{};

    // Zero-initialized SHM must fail magic check
    assert(!mdfp_seqlock_try_read(&shm, &snap));

    // Odd sequence means write in progress -> spin reader must fail cleanly
    mdfp_seqlock_init(&shm, make_payload(1));
    shm.seqlock_version.store(3U, std::memory_order_release);
    assert(!mdfp_seqlock_try_read(&shm, &snap));
    assert(!mdfp_seqlock_read_spin(&shm, &snap, 16));

    // Normal publish and const read
    const MdfpStatsShared* ro_shm = &shm;
    mdfp_seqlock_init(&shm, make_payload(42));
    assert(mdfp_seqlock_try_read(ro_shm, &snap));
    assert(snap.last_frame_seq == 42U);
    verify_payload_consistency(snap);
}

void test_threaded_stress() {
    MdfpStatsShared shm{};
    mdfp_seqlock_init(&shm, make_payload(1));
    const MdfpStatsShared* ro_shm = &shm;

    constexpr uint32_t kTotalWrites = 120000;
    constexpr int kReaderCount = 4;

    std::atomic<bool> done{false};
    std::atomic<uint64_t> total_successful_reads{0};

    std::vector<std::thread> readers;
    readers.reserve(kReaderCount);
    for (int r = 0; r < kReaderCount; ++r) {
        readers.emplace_back([ro_shm, &done, &total_successful_reads]() {
            MdfpStatsPayload snap{};
            uint32_t last_seen_seq = 0;
            uint64_t ok_reads = 0;
            while (!done.load(std::memory_order_acquire)) {
                if (mdfp_seqlock_try_read(ro_shm, &snap)) {
                    verify_payload_consistency(snap);
                    assert(snap.last_frame_seq >= last_seen_seq);
                    last_seen_seq = snap.last_frame_seq;
                    ++ok_reads;
                }
            }
            // Final read after writer completed must succeed and match kTotalWrites
            assert(mdfp_seqlock_read_spin(ro_shm, &snap, 1000));
            verify_payload_consistency(snap);
            assert(snap.last_frame_seq == kTotalWrites);
            total_successful_reads.fetch_add(ok_reads + 1ULL, std::memory_order_relaxed);
        });
    }

    std::thread writer([&shm, &done]() {
        for (uint32_t seq = 2; seq <= kTotalWrites; ++seq) {
            mdfp_seqlock_write(&shm, make_payload(seq));
        }
        done.store(true, std::memory_order_release);
    });

    writer.join();
    for (auto& t : readers) {
        t.join();
    }

    assert(total_successful_reads.load() >= kReaderCount);
    std::cout << "[PASS] test_seqlock: " << kTotalWrites << " writes, "
              << total_successful_reads.load() << " consistent concurrent reads across "
              << kReaderCount << " threads\n";
}

} // namespace

int main() {
    test_basic_states();
    test_threaded_stress();
    return 0;
}
