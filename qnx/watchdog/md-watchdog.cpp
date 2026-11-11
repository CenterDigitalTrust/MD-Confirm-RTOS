// md-watchdog.cpp
// Hardware Sabotage & Cable-Cut Watchdog (QNX Asynchronous Pulses & Timers)
// Project: MD-Confirm RTOS (QNX Global Hackathon) | Track: Automotive & Mobility

#define _QNX_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/neutrino.h>
#include <sys/dispatch.h>
#include <signal.h>
#include <time.h>

#include "../common/mdfp_protocol.h"
#include "../common/mdfp_crypto.h"

int main() {
    std::cout << "========================================================\n"
              << " [md-watchdog] Hardware Sabotage & Cable-Cut Watchdog   \n"
              << " QNX Technology: timer_create + SIGEV_PULSE             \n"
              << " Timeout: 50 ms (detects missing frame at 30 fps)       \n"
              << " Action: Emergency Evidence Sealing (GHOST_EVENT)       \n"
              << "========================================================\n" << std::endl;

    name_attach_t* attach = name_attach(nullptr, MDFP_ATTACH_WATCHDOG, 0);
    if (!attach) {
        perror("name_attach(mdfp_watchdog)");
        return 1;
    }
    std::cout << "[md-watchdog] Registered QNX channel: " << MDFP_ATTACH_WATCHDOG << std::endl;

    int seal_coid = -1;
    for (int attempt = 0; attempt < 30; ++attempt) {
        seal_coid = name_open(MDFP_ATTACH_SEAL, 0);
        if (seal_coid >= 0) break;
        usleep(100000);
    }
    if (seal_coid >= 0) {
        std::cout << "[md-watchdog] Connected to md-seal! coid=" << seal_coid << std::endl;
    }

    int timer_coid = ConnectAttach(0, 0, attach->chid, _NTO_SIDE_CHANNEL, 0);
    if (timer_coid < 0) {
        perror("ConnectAttach(timer_coid)");
        return 1;
    }

    struct sigevent event;
    SIGEV_PULSE_INIT(&event, timer_coid, 15, MDFP_PULSE_WATCHDOG_TICK, 0);

    timer_t timer_id;
    if (timer_create(CLOCK_MONOTONIC, &event, &timer_id) < 0) {
        perror("timer_create");
        return 1;
    }

    struct itimerspec itime;
    itime.it_value.tv_sec = 0;
    itime.it_value.tv_nsec = 10000000; // 10 ms
    itime.it_interval.tv_sec = 0;
    itime.it_interval.tv_nsec = 10000000;
    timer_settime(timer_id, 0, &itime, nullptr);

    std::cout << "[md-watchdog] Hardware watchdog armed (10 ms tick).\n" << std::endl;

    uint64_t last_heartbeat_ns = mdfp_get_ns();
    uint32_t last_seen_seq = 0;
    bool ghost_fired = false;

    while (true) {
        struct _pulse pulse;
        int rcvid = MsgReceive(attach->chid, &pulse, sizeof(pulse), nullptr);
        if (rcvid < 0) continue;

        if (rcvid == 0) {
            uint64_t now_ns = mdfp_get_ns();

            if (pulse.code == MDFP_PULSE_WATCHDOG_HEART) {
                last_heartbeat_ns = now_ns;
                last_seen_seq = pulse.value.sival_int;
                ghost_fired = false;
            } else if (pulse.code == MDFP_PULSE_WATCHDOG_TICK) {
                uint64_t elapsed_since_frame = now_ns - last_heartbeat_ns;

                if (elapsed_since_frame > 50000000ULL && last_seen_seq > 0 && !ghost_fired) {
                    ghost_fired = true;
                    std::cout << "\n************************************************************************\n"
                              << " [!] EMERGENCY WATCHDOG ALARM: SENSOR DISCONNECT / CABLE CUT DETECTED!   \n"
                              << " Elapsed Time Without Frame Pulse: " << (elapsed_since_frame / 1000000ULL) << " ms (> 50 ms limit)\n"
                              << " Last Verified Frame Sequence: #" << last_seen_seq << "\n"
                              << " Triggering Emergency Evidence Sealing (GHOST_EVENT_WATCHDOG)...       \n"
                              << "************************************************************************\n" << std::endl;

                    if (seal_coid >= 0) {
                        MdfpSealMsg smsg;
                        std::memset(&smsg, 0, sizeof(smsg));
                        smsg.type = 0x0200;
                        smsg.frame_seq = last_seen_seq + 1;
                        smsg.scenario = SCENARIO_5_CABLE_SABOTAGE;
                        smsg.hw_eof_ns = now_ns;
                        smsg.ncc = 0.0;
                        smsg.pce_linear = 0.0;
                        smsg.pce_db = 0.0;
                        smsg.verify_duration_ns = 0;
                        std::strcpy(smsg.verdict, "GHOST_EVENT_WATCHDOG_TRIPPED");
                        smsg.is_ghost_event = true;
                        std::strcpy(smsg.raw_sha256, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

                        MdfpSealReply sreply;
                        MsgSend(seal_coid, &smsg, sizeof(smsg), &sreply, sizeof(sreply));
                        std::cout << "[md-watchdog] GHOST_EVENT sealed into Merkle Leaf #" 
                                  << sreply.leaf_index << " | Root: " << std::string(sreply.merkle_root).substr(0, 16) << "..." << std::endl;
                    }
                }
            }
        }
    }

    ConnectDetach(timer_coid);
    name_detach(attach, 0);
    return 0;
}
