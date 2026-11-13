// md-sensor-sim.cpp
#define _QNX_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <iostream>
#include <vector>
#include <cmath>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/neutrino.h>
#include <sys/dispatch.h>
#include <signal.h>
#include <time.h>

#include "../common/mdfp_protocol.h"
#include "../common/mdfp_crypto.h"
#include "../common/mdfp_signals.h"

struct SimSignalOptions {
    mdfp::signals::ExtraSignalConfig cfg;
    uint32_t seq_start = 1U;
    bool force_replay = false;
    bool force_bad_modulation = false;
    bool force_seq_gap = false;
    bool force_timing_anomaly = false;
    uint32_t positional_scenario = SCENARIO_1_NATIVE_SENSOR;
    int positional_frames = 100000000;
};

static SimSignalOptions parse_sim_options(int argc, char* argv[], uint64_t cycles_per_sec) {
    SimSignalOptions opts;
    // OFF by default per Task 7 specification
    opts.cfg = mdfp::signals::ExtraSignalConfig::disabled_default(cycles_per_sec);

    const char* env_extra = std::getenv("MDFP_EXTRA_SIGNALS");
    if (env_extra && std::strcmp(env_extra, "1") == 0) {
        opts.cfg = mdfp::signals::ExtraSignalConfig::enabled_sim_default(cycles_per_sec);
    }
    const char* env_secret = std::getenv("MDFP_CHALLENGE_SECRET");
    if (env_secret && env_secret[0] != '\0') {
        opts.cfg.shared_secret.assign(
            reinterpret_cast<const uint8_t*>(env_secret),
            reinterpret_cast<const uint8_t*>(env_secret) + std::strlen(env_secret));
    }

    int pos_idx = 0;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--extra-signals") {
            opts.cfg.enabled = true;
            opts.cfg.check_sequence = true;
            opts.cfg.check_timing = true;
            opts.cfg.check_challenge = true;
        } else if (arg == "--enable-seq-check") {
            opts.cfg.enabled = true;
            opts.cfg.check_sequence = true;
            opts.cfg.check_timing = true;
        } else if (arg == "--enable-challenge-response") {
            opts.cfg.enabled = true;
            opts.cfg.check_challenge = true;
        } else if (arg == "--hmac-secret" && i + 1 < argc) {
            const char* s = argv[++i];
            opts.cfg.shared_secret.assign(
                reinterpret_cast<const uint8_t*>(s),
                reinterpret_cast<const uint8_t*>(s) + std::strlen(s));
        } else if (arg == "--seq-start" && i + 1 < argc) {
            long val = std::atol(argv[++i]);
            if (val > 0) opts.seq_start = static_cast<uint32_t>(val);
        } else if (arg == "--replay") {
            opts.force_replay = true;
        } else if (arg == "--bad-modulation") {
            opts.force_bad_modulation = true;
        } else if (arg == "--seq-gap") {
            opts.force_seq_gap = true;
        } else if (arg == "--timing-anomaly") {
            opts.force_timing_anomaly = true;
        } else if (!arg.empty() && arg[0] != '-') {
            if (pos_idx == 0) {
                opts.positional_scenario = static_cast<uint32_t>(std::atoi(arg.c_str()));
            } else if (pos_idx == 1) {
                opts.positional_frames = std::atoi(arg.c_str());
            }
            ++pos_idx;
        }
    }
    return opts;
}

static double g_k_ref[MDFP_PRNU_SIZE];
static double g_k_rogue[MDFP_PRNU_SIZE];

void init_prnu_maps() {
    uint32_t seed_a = 0x20261111u;
    for (int i = 0; i < MDFP_PRNU_SIZE; ++i) {
        seed_a = seed_a * 1664525u + 1013904223u;
        g_k_ref[i] = ((double(seed_a & 0xFFFF) / 32768.0) - 1.0) * 0.015;
    }
    uint32_t seed_b = 0x98765432u;
    for (int i = 0; i < MDFP_PRNU_SIZE; ++i) {
        seed_b = seed_b * 214013u + 2531011u;
        g_k_rogue[i] = ((double(seed_b & 0xFFFF) / 32768.0) - 1.0) * 0.015;
    }
}

int main(int argc, char* argv[]) {
    std::cout << "========================================================\n"
              << " [md-sensor-sim] Starting Simulated MIPI CSI-2 Sensor   \n"
              << " STATUS: Honest Simulation (Synthetic RAW Bayer + PRNU) \n"
              << " QNX Mechanism: timer_create (EOF pulse) + POSIX shm    \n"
              << "========================================================\n" << std::endl;

    signal(SIGPIPE, SIG_IGN);
    init_prnu_maps();

    int shm_fd = shm_open(MDFP_SHM_NAME, O_RDWR | O_CREAT, 0666);
    if (shm_fd < 0) {
        perror("shm_open");
        return 1;
    }
    ftruncate(shm_fd, sizeof(MdfpSharedMemory));
    MdfpSharedMemory* shm = (MdfpSharedMemory*)mmap(nullptr, sizeof(MdfpSharedMemory), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    std::memset(shm, 0, sizeof(MdfpSharedMemory));
    shm->magic = MDFP_MAGIC;
    shm->width = MDFP_SENSOR_WIDTH;
    shm->height = MDFP_SENSOR_HEIGHT;
    shm->payload_bytes = MDFP_RAW_BYTES;

    std::cout << "[md-sensor-sim] Connecting to QNX channel: " << MDFP_ATTACH_CAPTURE << "..." << std::endl;
    int coid = -1;
    for (int attempt = 0; attempt < 30; ++attempt) {
        coid = name_open(MDFP_ATTACH_CAPTURE, 0);
        if (coid >= 0) break;
        usleep(100000);
    }
    if (coid < 0) {
        std::cerr << "[md-sensor-sim] Error: md-capture not reachable.\n";
        return 1;
    }
    std::cout << "[md-sensor-sim] Connected successfully! coid=" << coid << std::endl;

    uint64_t cycles_per_sec = mdfp_cycles_per_sec();
    SimSignalOptions opts = parse_sim_options(argc, argv, cycles_per_sec);

    uint32_t active_scenario = opts.positional_scenario;
    if (opts.force_replay) active_scenario = SCENARIO_7_REPLAY_FRAME;
    int num_frames = opts.positional_frames;

    std::cout << "[md-sensor-sim] Streaming frames at ~" << MDFP_NOMINAL_FPS << " FPS..." << std::endl;
    std::cout << "[md-sensor-sim] Extra Signals (SIMULATED, off by default): "
              << (opts.cfg.any_active() ? "ENABLED" : "DISABLED")
              << " (per-frame sensor control unverified; shared-secret demo)\n";

    struct RecordedSimFrame {
        uint32_t frame_seq = 0U;
        double gain = 1.0;
        std::vector<uint16_t> pixels;
    };
    std::vector<RecordedSimFrame> recorded_frames;
    size_t replay_idx = 0U;

    uint32_t noise_seed = 0x55AA55AAu;
    uint32_t next_seq = opts.seq_start;

    for (int iter = 0; iter < num_frames; ++iter) {
        // Poll for dynamic scenario switch request
        FILE* fsc = fopen("/tmp/mdfp_active_scenario", "r");
        if (fsc) {
            int sc = 1;
            if (fscanf(fsc, "%d", &sc) == 1) {
                if (sc >= 1 && sc <= 8) active_scenario = static_cast<uint32_t>(sc);
            }
            fclose(fsc);
        }

        // Scenario 5: Physical Cable Cut / Hardware Sabotage
        if (active_scenario == SCENARIO_5_CABLE_SABOTAGE) {
            std::cout << "\n[!] SCENARIO 5 TRIGGERED: Simulating Physical Cable Cut! Pausing 120 ms...\n";
            usleep(120000); // Exceeds 50 ms watchdog deadline
            // Reset scenario back to 1
            FILE* fr = fopen("/tmp/mdfp_active_scenario", "w");
            if (fr) { fprintf(fr, "1\n"); fclose(fr); }
            active_scenario = SCENARIO_1_NATIVE_SENSOR;
            continue;
        }

        uint32_t emit_seq = next_seq++;
        if (opts.force_seq_gap || (active_scenario == SCENARIO_8_SEQ_TIMING_ANOMALY && (iter % 2 == 1))) {
            emit_seq += 2U;
            next_seq += 2U;
        }

        if (opts.force_timing_anomaly || (active_scenario == SCENARIO_8_SEQ_TIMING_ANOMALY && (iter % 2 == 0))) {
            usleep(95000); // Forces >75 ms interval delta to trigger timing bounds check
        }

        uint32_t effective_scenario = active_scenario;
        bool did_replay = false;
        if (active_scenario == SCENARIO_7_REPLAY_FRAME) {
            if (!recorded_frames.empty()) {
                did_replay = true;
                size_t pick = replay_idx % recorded_frames.size();
                if (replay_idx % 2U == 0U) {
                    // Verbatim replay of recorded frame_seq + pixel buffer -> BLOCK_SEQ_REPLAY
                    emit_seq = recorded_frames[pick].frame_seq;
                    std::memcpy(
                        shm->bayer_raw,
                        recorded_frames[pick].pixels.data(),
                        MDFP_PRNU_SIZE * sizeof(uint16_t));
                } else {
                    // Replay recorded pixel buffer under bumped frame_seq -> BLOCK_CHALLENGE_MODULATION
                    const double target_gain = (opts.cfg.any_active() && opts.cfg.check_challenge)
                        ? mdfp::signals::compute_challenge_gain(
                              opts.cfg.shared_secret.data(), opts.cfg.shared_secret.size(), emit_seq)
                        : 1.0;
                    for (size_t k = 0; k < recorded_frames.size(); ++k) {
                        if (std::fabs(recorded_frames[k].gain - target_gain) > 0.15) {
                            pick = k;
                            break;
                        }
                    }
                    std::memcpy(
                        shm->bayer_raw,
                        recorded_frames[pick].pixels.data(),
                        MDFP_PRNU_SIZE * sizeof(uint16_t));
                }
                ++replay_idx;
            } else {
                // Bootstrap one authentic recorded frame before replaying on subsequent iterations
                effective_scenario = SCENARIO_1_NATIVE_SENSOR;
            }
        }

        if (!did_replay) {
            double base_illumination = mdfp::signals::DEFAULT_BASELINE_INTENSITY;
            double gain = 1.0;
            if (opts.cfg.any_active() && opts.cfg.check_challenge) {
                const bool omit_modulation =
                    opts.force_bad_modulation ||
                    (effective_scenario == SCENARIO_4_SYNTHETIC_WITH_PRNU);
                if (!omit_modulation) {
                    gain = mdfp::signals::compute_challenge_gain(
                        opts.cfg.shared_secret.data(),
                        opts.cfg.shared_secret.size(),
                        emit_seq);
                }
            }
            const double effective_illumination = base_illumination * gain;

            for (int i = 0; i < MDFP_PRNU_SIZE; ++i) {
                noise_seed = noise_seed * 1103515245u + 12345u;
                double shot_noise = ((double((noise_seed >> 16) & 0x7FFF) / 16384.0) - 1.0) * 8.0;
                double pix_val = effective_illumination;

                if (effective_scenario == SCENARIO_1_NATIVE_SENSOR) {
                    pix_val = effective_illumination * (1.0 + g_k_ref[i]) + shot_noise;
                } else if (effective_scenario == SCENARIO_2_FOREIGN_SENSOR) {
                    pix_val = effective_illumination * (1.0 + g_k_rogue[i]) + shot_noise;
                } else if (effective_scenario == SCENARIO_3_SYNTHETIC_NO_PRNU) {
                    pix_val = effective_illumination + shot_noise * 0.2;
                } else if (effective_scenario == SCENARIO_4_SYNTHETIC_WITH_PRNU) {
                    pix_val = effective_illumination * (1.0 + g_k_ref[i]) + shot_noise;
                    usleep(3000);
                } else {
                    pix_val = effective_illumination * (1.0 + g_k_ref[i]) + shot_noise;
                }

                if (pix_val < 0.0) pix_val = 0.0;
                if (pix_val > 65535.0) pix_val = 65535.0;
                shm->bayer_raw[i] = (uint16_t)pix_val;
            }

            if (effective_scenario == SCENARIO_1_NATIVE_SENSOR && !opts.force_bad_modulation) {
                RecordedSimFrame rec;
                rec.frame_seq = emit_seq;
                rec.gain = gain;
                rec.pixels.assign(shm->bayer_raw, shm->bayer_raw + MDFP_PRNU_SIZE);
                if (recorded_frames.size() >= 16U) {
                    recorded_frames.erase(recorded_frames.begin());
                }
                recorded_frames.push_back(std::move(rec));
            }
        }

        shm->frame_seq = emit_seq;
        // Replayed / timing-anomalous frames carry genuine K_REF PRNU so PRNU alone cannot flag them;
        // md-verify catches them only when simulated extra signals are enabled.
        shm->scenario = (effective_scenario == SCENARIO_7_REPLAY_FRAME ||
                         effective_scenario == SCENARIO_8_SEQ_TIMING_ANOMALY)
                            ? static_cast<uint32_t>(SCENARIO_1_NATIVE_SENSOR)
                            : effective_scenario;
        shm->hw_eof_cycles = mdfp_cycles();
        shm->hw_eof_ns = mdfp_get_ns();

        int pulse_rc = MsgSendPulse(coid, 10, MDFP_PULSE_EOF_IRQ, static_cast<int>(emit_seq));
        if (pulse_rc < 0) {
            // Reconnect if capture daemon reloaded
            name_close(coid);
            usleep(50000);
            coid = name_open(MDFP_ATTACH_CAPTURE, 0);
            if (coid < 0) {
                usleep(100000);
                continue;
            }
        }

        usleep(33333);
    }

    if (coid >= 0) name_close(coid);
    munmap(shm, sizeof(MdfpSharedMemory));
    close(shm_fd);
    return 0;
}
