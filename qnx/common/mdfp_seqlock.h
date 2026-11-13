// mdfp_seqlock.h
// Portable Lock-Free Seqlock Protocol for /mdfp_stats_shm
// C++17 Data-Race-Free Implementation (atomic version + atomic relaxed payload words + acquire/release fences)

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

#ifndef MDFP_STATS_MAGIC_VALUE
#define MDFP_STATS_MAGIC_VALUE 0x4D444650U // 'MDFP'
#endif

// Plain trivially-copyable snapshot struct passed between producer/consumer code.
// Explicit reserved padding ensures size is an exact multiple of 8 bytes with zero implicit holes.
struct MdfpStatsPayload {
    uint32_t magic;                // MDFP_STATS_MAGIC_VALUE once initialized
    uint32_t last_frame_seq;
    uint32_t last_scenario;
    uint32_t reserved0;
    double last_pce_db;
    double last_pce_linear;
    double last_ncc;
    double last_latency_b_us;
    double last_jitter_us;
    uint64_t last_cycles_delta;
    char last_verdict[48];
    char last_frame_sha256[65];
    char last_merkle_root[65];
    char reserved1[6];
    uint64_t total_frames;
    uint64_t total_blocked;
    uint64_t total_ghosts;
    uint32_t hist_bins[10];
    uint64_t hist_total_samples;
    double hist_min_us;
    double hist_max_us;
    double hist_mean_us;
};

static_assert(std::is_trivially_copyable<MdfpStatsPayload>::value,
              "MdfpStatsPayload must be trivially copyable");
static_assert(sizeof(MdfpStatsPayload) == 344,
              "MdfpStatsPayload must remain 344 bytes without implicit compiler padding");
static_assert((sizeof(MdfpStatsPayload) % sizeof(uint64_t)) == 0,
              "MdfpStatsPayload size must be a multiple of 8 bytes");

constexpr size_t MDFP_STATS_WORDS = sizeof(MdfpStatsPayload) / sizeof(uint64_t);

// Shared-memory layout mapped RW by md-capture and PROT_READ by md-telemetry.
// Every shared field accessed concurrently uses lock-free std::atomic to eliminate C++ data-race UB.
struct MdfpStatsShared {
    std::atomic<uint32_t> seqlock_version; // Odd = write in progress; Even = stable snapshot
    uint32_t reserved_pad;
    std::atomic<uint64_t> words[MDFP_STATS_WORDS];
};

typedef struct MdfpStatsShared MdfpTelemetryShared; // Backwards-compatible alias

static_assert(std::atomic<uint32_t>::is_always_lock_free,
              "Lock-free 32-bit atomics are required for cross-process mmap SHM");
static_assert(std::atomic<uint64_t>::is_always_lock_free,
              "Lock-free 64-bit atomics are required for cross-process mmap SHM");
static_assert(std::is_standard_layout<MdfpStatsShared>::value,
              "MdfpStatsShared must be standard-layout");
static_assert(std::is_trivially_destructible<MdfpStatsShared>::value,
              "MdfpStatsShared must be trivially destructible");

// Initialize shared memory with an atomic even sequence and valid initial payload.
// Avoids memset() on std::atomic members.
inline void mdfp_seqlock_init(MdfpStatsShared* shm, const MdfpStatsPayload& initial) {
    if (!shm) return;
    uint64_t buf[MDFP_STATS_WORDS];
    std::memcpy(buf, &initial, sizeof(MdfpStatsPayload));

    shm->seqlock_version.store(1U, std::memory_order_relaxed);
    std::atomic_thread_fence(std::memory_order_release);
    for (size_t i = 0; i < MDFP_STATS_WORDS; ++i) {
        shm->words[i].store(buf[i], std::memory_order_relaxed);
    }
    std::atomic_thread_fence(std::memory_order_release);
    shm->seqlock_version.store(2U, std::memory_order_release);
}

// Single-writer lock-free seqlock publish: never waits on readers.
// Ordering:
//   1. Store odd version before writing payload words (release fence orders odd store before words).
//   2. Write payload words as relaxed atomics.
//   3. Release store even version after writing payload words.
inline void mdfp_seqlock_write(MdfpStatsShared* shm, const MdfpStatsPayload& src) {
    if (!shm) return;
    uint64_t buf[MDFP_STATS_WORDS];
    std::memcpy(buf, &src, sizeof(MdfpStatsPayload));

    uint32_t cur = shm->seqlock_version.load(std::memory_order_relaxed);
    uint32_t odd = ((cur & 1U) == 0U) ? (cur + 1U) : (cur + 2U);

    shm->seqlock_version.store(odd, std::memory_order_relaxed);
    std::atomic_thread_fence(std::memory_order_release);

    for (size_t i = 0; i < MDFP_STATS_WORDS; ++i) {
        shm->words[i].store(buf[i], std::memory_order_relaxed);
    }

    std::atomic_thread_fence(std::memory_order_release);
    shm->seqlock_version.store(odd + 1U, std::memory_order_release);
}

// Single non-blocking read attempt from PROT_READ or RW shared memory.
// Returns true only if a consistent, non-torn, initialized snapshot was read.
inline bool mdfp_seqlock_try_read(const MdfpStatsShared* shm,
                                  MdfpStatsPayload* out,
                                  uint32_t expected_magic = MDFP_STATS_MAGIC_VALUE) {
    if (!shm || !out) return false;

    uint32_t v1 = shm->seqlock_version.load(std::memory_order_acquire);
    if ((v1 & 1U) != 0U) {
        return false; // Write in progress
    }

    uint64_t buf[MDFP_STATS_WORDS];
    for (size_t i = 0; i < MDFP_STATS_WORDS; ++i) {
        buf[i] = shm->words[i].load(std::memory_order_relaxed);
    }

    std::atomic_thread_fence(std::memory_order_acquire);
    uint32_t v2 = shm->seqlock_version.load(std::memory_order_acquire);

    if (v1 != v2 || (v2 & 1U) != 0U) {
        return false; // Torn or concurrent write observed
    }

    MdfpStatsPayload candidate;
    std::memcpy(&candidate, buf, sizeof(MdfpStatsPayload));
    if (expected_magic != 0U && candidate.magic != expected_magic) {
        return false; // Shared memory not yet initialized by producer
    }

    *out = candidate;
    return true;
}

// OS-agnostic bounded retry spin reader (for environments without backoff callbacks).
inline bool mdfp_seqlock_read_spin(const MdfpStatsShared* shm,
                                   MdfpStatsPayload* out,
                                   int max_retries = 1000,
                                   uint32_t expected_magic = MDFP_STATS_MAGIC_VALUE) {
    for (int i = 0; i < max_retries; ++i) {
        if (mdfp_seqlock_try_read(shm, out, expected_magic)) {
            return true;
        }
    }
    return false;
}
