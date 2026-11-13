// md-capture.cpp
// Hard Real-Time Camera Ingestion & Timing Engine (ASIL-D Compliant Microkernel Thread)
// Project: MD-Confirm RTOS (QNX Global Hackathon) | Track: Automotive & Mobility

#define _QNX_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <iostream>
#include <iomanip>
#include <memory>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/neutrino.h>
#include <sys/dispatch.h>
#include <sys/sched.h>

#include "../common/mdfp_protocol.h"
#include "../common/mdfp_crypto.h"

int main() {
    std::cout << "========================================================\n"
              << " [md-capture] Hard Real-Time Frame Ingestion Engine      \n"
              << " Policy: SCHED_FIFO Priority " << MDFP_PRIO_CAPTURE << " (Hard IRQ Service)      \n"
              << " Decoupling: Zero Network Code (Pure Real-Time Path)    \n"
              << " Statistics Export: Seqlock Lock-Free SHM (" << MDFP_STATS_SHM_NAME << ")\n"
              << "========================================================\n" << std::endl;

    // Strict Hard Real-Time Scheduling
    struct sched_param param;
    param.sched_priority = MDFP_PRIO_CAPTURE;
    sched_setscheduler(0, SCHED_FIFO, &param);

    name_attach_t* attach = name_attach(nullptr, MDFP_ATTACH_CAPTURE, 0);
    if (!attach) {
        perror("name_attach(mdfp_capture)");
        return 1;
    }
    std::cout << "[md-capture] Registered QNX channel: " << MDFP_ATTACH_CAPTURE << std::endl;

    // Zero-Copy Frame Shared Memory
    int shm_fd = -1;
    MdfpSharedMemory* shm = nullptr;
    for (int attempt = 0; attempt < 30; ++attempt) {
        shm_fd = shm_open(MDFP_SHM_NAME, O_RDONLY, 0666);
        if (shm_fd >= 0) break;
        usleep(100000);
    }
    if (shm_fd >= 0) {
        shm = (MdfpSharedMemory*)mmap(nullptr, sizeof(MdfpSharedMemory), PROT_READ, MAP_SHARED, shm_fd, 0);
        std::cout << "[md-capture] Attached to zero-copy frame shm: " << MDFP_SHM_NAME << std::endl;
    }

    // Lock-Free Statistics Shared Memory with Seqlock (Exposed to decoupled md-telemetry)
    int stats_fd = shm_open(MDFP_STATS_SHM_NAME, O_RDWR | O_CREAT, 0666);
    MdfpStatsShared* stats = nullptr;
    if (stats_fd >= 0) {
        if (ftruncate(stats_fd, sizeof(MdfpStatsShared)) == 0) {
            stats = (MdfpStatsShared*)mmap(nullptr, sizeof(MdfpStatsShared), PROT_READ | PROT_WRITE, MAP_SHARED, stats_fd, 0);
        }
        close(stats_fd);
    }
    MdfpStatsPayload local_stats{};
    local_stats.magic = MDFP_MAGIC;
    local_stats.hist_min_us = 999999.0;
    std::strncpy(local_stats.last_verdict, "WAITING_FRAMES", sizeof(local_stats.last_verdict) - 1);
    std::strncpy(local_stats.last_frame_sha256, "0000000000000000000000000000000000000000000000000000000000000000", sizeof(local_stats.last_frame_sha256) - 1);
    if (stats && stats != MAP_FAILED) {
        mdfp_seqlock_init(stats, local_stats);
        std::cout << "[md-capture] Initialized atomic seqlock stats shm: " << MDFP_STATS_SHM_NAME << std::endl;
    }

    // Connect to md-verify channel
    int verify_coid = -1;
    for (int attempt = 0; attempt < 30; ++attempt) {
        verify_coid = name_open(MDFP_ATTACH_VERIFY, 0);
        if (verify_coid >= 0) break;
        usleep(100000);
    }
    if (verify_coid >= 0) {
        std::cout << "[md-capture] Connected to md-verify! coid=" << verify_coid << std::endl;
    }

    // Connect to md-watchdog channel
    int watchdog_coid = name_open(MDFP_ATTACH_WATCHDOG, 0);
    if (watchdog_coid >= 0) {
        std::cout << "[md-capture] Connected to md-watchdog! coid=" << watchdog_coid << std::endl;
    }

    uint64_t prev_eof_ns = 0;
    uint64_t cycles_per_sec = mdfp_cycles_per_sec();
    auto snapshot = std::make_unique<mdfp::ingest::PrivateFrameSnapshot>();
    auto verify_msg = std::make_unique<MdfpVerifyMsg>();

    while (true) {
        struct _pulse pulse;
        int rcvid = MsgReceive(attach->chid, &pulse, sizeof(pulse), nullptr);
        if (rcvid < 0) continue;

        if (rcvid == 0) {
            if (pulse.code == MDFP_PULSE_EOF_IRQ) {
                uint64_t capture_wakeup_cycles = ClockCycles();
                uint64_t capture_wakeup_ns = mdfp_get_ns();
                uint32_t seq = pulse.value.sival_int;

                if (!shm) {
                    int sfd = shm_open(MDFP_SHM_NAME, O_RDONLY, 0666);
                    if (sfd >= 0) {
                        shm = (MdfpSharedMemory*)mmap(nullptr, sizeof(MdfpSharedMemory), PROT_READ, MAP_SHARED, sfd, 0);
                    }
                }

                // TRUST BOUNDARY: copy frame out of shared memory into a process-private
                // buffer FIRST and compute SHA-256 over that private copy. Never re-read shm.
                if (shm && shm != MAP_FAILED) {
                    const volatile MdfpSharedMemory* vshm = shm;
                    mdfp::ingest::capture_copy_from_shm_and_hash(
                        vshm->magic,
                        seq,
                        vshm->scenario,
                        vshm->hw_eof_cycles,
                        vshm->hw_eof_ns,
                        vshm->width,
                        vshm->height,
                        vshm->payload_bytes ? vshm->payload_bytes : MDFP_RAW_BYTES,
                        vshm->bayer_raw,
                        capture_wakeup_cycles,
                        capture_wakeup_ns,
                        MDFP_DEFAULT_SENSOR_ID,
                        snapshot.get());
                } else {
                    mdfp::ingest::capture_copy_from_shm_and_hash(
                        MDFP_MAGIC,
                        seq,
                        1U,
                        capture_wakeup_cycles,
                        capture_wakeup_ns,
                        MDFP_SENSOR_WIDTH,
                        MDFP_SENSOR_HEIGHT,
                        0U,
                        nullptr,
                        capture_wakeup_cycles,
                        capture_wakeup_ns,
                        MDFP_DEFAULT_SENSOR_ID,
                        snapshot.get());
                }

                uint64_t hw_eof_cycles = snapshot->hw_eof_cycles;
                uint64_t hw_eof_ns = snapshot->hw_eof_ns;
                uint32_t scenario = snapshot->scenario;

                // Latency (b): EOF IRQ to md-capture wakeup
                uint64_t latency_b_ns = (capture_wakeup_cycles > hw_eof_cycles)
                    ? ((capture_wakeup_cycles - hw_eof_cycles) * 1000000000ULL / cycles_per_sec)
                    : 15000ULL;
                double latency_b_us = double(latency_b_ns) / 1000.0;

                // Inter-frame interval (a) & Jitter
                double jitter_us = 0.0;
                if (prev_eof_ns > 0) {
                    uint64_t interval_ns = hw_eof_ns - prev_eof_ns;
                    int64_t diff = labs((int64_t)interval_ns - (int64_t)MDFP_NOMINAL_INTERVAL_NS);
                    jitter_us = double(diff) / 1000.0;
                }
                prev_eof_ns = hw_eof_ns;

                // Send heartbeat to watchdog
                if (watchdog_coid >= 0) {
                    MsgSendPulse(watchdog_coid, 10, MDFP_PULSE_WATCHDOG_HEART, seq);
                }

                // Forward private snapshot + SHA-256 + seq + capture cycle count via MsgSend()
                if (verify_coid >= 0) {
                    std::memset(verify_msg.get(), 0, sizeof(*verify_msg));
                    verify_msg->type = 0x0100;
                    verify_msg->subtype = 0x0001;
                    verify_msg->frame_seq = seq;
                    verify_msg->scenario = scenario;
                    verify_msg->hw_eof_cycles = hw_eof_cycles;
                    verify_msg->hw_eof_ns = hw_eof_ns;
                    verify_msg->capture_wakeup_cycles = capture_wakeup_cycles;
                    verify_msg->capture_wakeup_ns = capture_wakeup_ns;
                    verify_msg->width = snapshot->width;
                    verify_msg->height = snapshot->height;
                    verify_msg->payload_bytes = snapshot->payload_bytes;
                    mdfp::ingest::copy_cstr_bounded(
                        verify_msg->sensor_id, sizeof(verify_msg->sensor_id), snapshot->sensor_id);
                    mdfp::ingest::copy_cstr_bounded(
                        verify_msg->frame_sha256, sizeof(verify_msg->frame_sha256), snapshot->frame_sha256);
                    std::memcpy(verify_msg->bayer_raw, snapshot->bayer_raw, MDFP_RAW_BYTES);

                    MdfpVerifyReply reply;
                    int status = MsgSend(verify_coid, verify_msg.get(), sizeof(*verify_msg), &reply, sizeof(reply));
                    if (status >= 0) {
                        // Reuse the exact private-copy SHA-256 (zero second SHM read).
                        // Atomic Seqlock Update for Lock-Free Reader md-telemetry
                        local_stats.last_frame_seq = seq;
                        local_stats.last_scenario = scenario;
                        local_stats.last_pce_db = reply.pce_db;
                        local_stats.last_pce_linear = reply.pce_linear;
                        local_stats.last_ncc = reply.ncc;
                        local_stats.last_latency_b_us = latency_b_us;
                        local_stats.last_jitter_us = jitter_us;
                        local_stats.last_cycles_delta = (capture_wakeup_cycles > hw_eof_cycles) ? (capture_wakeup_cycles - hw_eof_cycles) : 0;
                        local_stats.extra_signals_enabled = reply.extra_signals_enabled;
                        local_stats.interval_cycles_p50 = reply.interval_cycles_p50;
                        local_stats.interval_cycles_p99 = reply.interval_cycles_p99;
                        local_stats.interval_us_p50 = reply.interval_us_p50;
                        local_stats.interval_us_p99 = reply.interval_us_p99;
                        local_stats.interval_samples = reply.interval_samples;
                        local_stats.seq_timing_failures = reply.seq_timing_failures;
                        local_stats.challenge_failures = reply.challenge_failures;
                        mdfp::ingest::copy_cstr_bounded(
                            local_stats.last_verdict, sizeof(local_stats.last_verdict), reply.verdict);
                        mdfp::ingest::copy_cstr_bounded(
                            local_stats.last_frame_sha256, sizeof(local_stats.last_frame_sha256), snapshot->frame_sha256);
                        if (reply.status == 0) local_stats.total_frames++;
                        else local_stats.total_blocked++;

                        local_stats.hist_total_samples++;
                        if (jitter_us < local_stats.hist_min_us) local_stats.hist_min_us = jitter_us;
                        if (jitter_us > local_stats.hist_max_us) local_stats.hist_max_us = jitter_us;
                        local_stats.hist_mean_us = (local_stats.hist_mean_us * (local_stats.hist_total_samples - 1) + jitter_us) / local_stats.hist_total_samples;

                        if (jitter_us < 2.0) local_stats.hist_bins[0]++;
                        else if (jitter_us < 4.0) local_stats.hist_bins[1]++;
                        else if (jitter_us < 6.0) local_stats.hist_bins[2]++;
                        else if (jitter_us < 8.0) local_stats.hist_bins[3]++;
                        else if (jitter_us < 10.0) local_stats.hist_bins[4]++; // Hard Deadline
                        else if (jitter_us < 20.0) local_stats.hist_bins[5]++;
                        else if (jitter_us < 50.0) local_stats.hist_bins[6]++;
                        else if (jitter_us < 100.0) local_stats.hist_bins[7]++;
                        else if (jitter_us < 1000.0) local_stats.hist_bins[8]++;
                        else local_stats.hist_bins[9]++; // Anomaly (> 1 ms)

                        if (stats && stats != MAP_FAILED) {
                            mdfp_seqlock_write(stats, local_stats);
                        }

                        std::cout << "[md-capture] Frame #" << seq 
                                  << " (Scen " << scenario << ")"
                                  << " | EOF->Capture: " << std::fixed << std::setprecision(1) << latency_b_us << " µs"
                                  << " | Jitter: " << jitter_us << " µs"
                                  << " | PCE: " << reply.pce_db << " dB (" << (int)reply.pce_linear << " lin)"
                                  << " | NCC: " << std::setprecision(3) << reply.ncc
                                  << " | Status: " << reply.verdict << std::endl;
                    }
                }
            }
        }
    }

    name_detach(attach, 0);
    return 0;
}
