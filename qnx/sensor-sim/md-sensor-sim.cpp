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

    uint32_t active_scenario = SCENARIO_1_NATIVE_SENSOR;
    int num_frames = 100000000;
    if (argc > 1) active_scenario = std::atoi(argv[1]);
    if (argc > 2) num_frames = std::atoi(argv[2]);

    std::cout << "[md-sensor-sim] Streaming frames at ~" << MDFP_NOMINAL_FPS << " FPS..." << std::endl;

    uint32_t noise_seed = 0x55AA55AAu;

    for (int f = 1; f <= num_frames; ++f) {
        // Poll for dynamic scenario switch request
        FILE* fsc = fopen("/tmp/mdfp_active_scenario", "r");
        if (fsc) {
            int sc = 1;
            if (fscanf(fsc, "%d", &sc) == 1) {
                if (sc >= 1 && sc <= 6) active_scenario = sc;
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

        double base_illumination = 2048.0;
        for (int i = 0; i < MDFP_PRNU_SIZE; ++i) {
            noise_seed = noise_seed * 1103515245u + 12345u;
            double shot_noise = ((double((noise_seed >> 16) & 0x7FFF) / 16384.0) - 1.0) * 8.0;
            double pix_val = base_illumination;

            if (active_scenario == SCENARIO_1_NATIVE_SENSOR) {
                pix_val = base_illumination * (1.0 + g_k_ref[i]) + shot_noise;
            } else if (active_scenario == SCENARIO_2_FOREIGN_SENSOR) {
                pix_val = base_illumination * (1.0 + g_k_rogue[i]) + shot_noise;
            } else if (active_scenario == SCENARIO_3_SYNTHETIC_NO_PRNU) {
                pix_val = base_illumination + shot_noise * 0.2;
            } else if (active_scenario == SCENARIO_4_SYNTHETIC_WITH_PRNU) {
                pix_val = base_illumination * (1.0 + g_k_ref[i]) + shot_noise;
                usleep(3000);
            } else {
                pix_val = base_illumination * (1.0 + g_k_ref[i]) + shot_noise;
            }

            if (pix_val < 0.0) pix_val = 0.0;
            if (pix_val > 65535.0) pix_val = 65535.0;
            shm->bayer_raw[i] = (uint16_t)pix_val;
        }

        shm->frame_seq = f;
        shm->scenario = active_scenario;
        shm->hw_eof_cycles = mdfp_cycles();
        shm->hw_eof_ns = mdfp_get_ns();

        int pulse_rc = MsgSendPulse(coid, 10, MDFP_PULSE_EOF_IRQ, f);
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
