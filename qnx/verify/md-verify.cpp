// md-verify.cpp
// Silicon PRNU Wafer Fingerprint & PCE / NCC Correlation Process
// Project: MD-Confirm RTOS (QNX Global Hackathon) | Track: Automotive & Mobility
// Works exclusively on the private frame copy sent over QNX IPC by md-capture
// and re-verifies frame_sha256 before correlation (zero reads from /mdfp_frame_shm).

#ifndef _QNX_SOURCE
#define _QNX_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <iostream>
#include <memory>
#include <vector>
#include <cmath>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <sys/neutrino.h>
#include <sys/dispatch.h>

#include "../common/mdfp_protocol.h"
#include "../common/mdfp_crypto.h"
#include "../common/mdfp_signals.h"

static double g_k_ref[MDFP_PRNU_SIZE];

static mdfp::signals::ExtraSignalConfig parse_verify_signal_config(
    int argc, char* argv[], uint64_t cycles_per_sec) {
    // OFF by default per Task 7 specification
    mdfp::signals::ExtraSignalConfig cfg =
        mdfp::signals::ExtraSignalConfig::disabled_default(cycles_per_sec);

    const char* env_extra = std::getenv("MDFP_EXTRA_SIGNALS");
    if (env_extra && std::strcmp(env_extra, "1") == 0) {
        cfg = mdfp::signals::ExtraSignalConfig::enabled_sim_default(cycles_per_sec);
    }
    const char* env_secret = std::getenv("MDFP_CHALLENGE_SECRET");
    if (env_secret && env_secret[0] != '\0') {
        cfg.shared_secret.assign(
            reinterpret_cast<const uint8_t*>(env_secret),
            reinterpret_cast<const uint8_t*>(env_secret) + std::strlen(env_secret));
    }

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--extra-signals") {
            cfg.enabled = true;
            cfg.check_sequence = true;
            cfg.check_timing = true;
            cfg.check_challenge = true;
        } else if (arg == "--enable-seq-check") {
            cfg.enabled = true;
            cfg.check_sequence = true;
            cfg.check_timing = true;
        } else if (arg == "--enable-challenge-response") {
            cfg.enabled = true;
            cfg.check_challenge = true;
        } else if (arg == "--min-interval-ms" && i + 1 < argc) {
            cfg.min_interval_ms = std::atof(argv[++i]);
        } else if (arg == "--max-interval-ms" && i + 1 < argc) {
            cfg.max_interval_ms = std::atof(argv[++i]);
        } else if (arg == "--hmac-secret" && i + 1 < argc) {
            const char* s = argv[++i];
            cfg.shared_secret.assign(
                reinterpret_cast<const uint8_t*>(s),
                reinterpret_cast<const uint8_t*>(s) + std::strlen(s));
        }
    }
    return cfg;
}

int main(int argc, char* argv[]) {
    uint64_t cycles_per_sec = mdfp_cycles_per_sec();
    mdfp::signals::ExtraSignalConfig sig_cfg =
        parse_verify_signal_config(argc, argv, cycles_per_sec);
    mdfp::signals::SignalMonitor signal_monitor(sig_cfg);

    std::cout << "========================================================\n"
              << " [md-verify] Statistical PRNU & PCE Correlation Engine  \n"
              << " Ingestion: Private IPC Frame Snapshot + SHA-256 Re-Check\n"
              << " PCE Units: Dimensionless energy ratio (literature std) \n"
              << " Thresholds: PCE >= " << MDFP_PCE_THRESHOLD_LINEAR
              << ", NCC >= " << MDFP_NCC_THRESHOLD << "\n"
              << " Extra Signals (SIMULATED, off by default): "
              << (sig_cfg.any_active() ? "ENABLED" : "DISABLED") << "\n"
              << "========================================================\n" << std::endl;

    mdfp::ingest::init_simulated_k_ref(g_k_ref);

    name_attach_t* attach = name_attach(nullptr, MDFP_ATTACH_VERIFY, 0);
    if (!attach) {
        perror("name_attach(mdfp_verify)");
        return 1;
    }
    std::cout << "[md-verify] Registered QNX channel: " << MDFP_ATTACH_VERIFY << std::endl;

    int seal_coid = -1;
    for (int attempt = 0; attempt < 30; ++attempt) {
        seal_coid = name_open(MDFP_ATTACH_SEAL, 0);
        if (seal_coid >= 0) break;
        usleep(100000);
    }
    if (seal_coid >= 0) {
        std::cout << "[md-verify] Connected to md-seal! coid=" << seal_coid << std::endl;
    }

    auto msg = std::make_unique<MdfpVerifyMsg>();
    auto smsg = std::make_unique<MdfpSealMsg>();

    while (true) {
        std::memset(msg.get(), 0, sizeof(struct _pulse));
        int rcvid = MsgReceive(attach->chid, msg.get(), sizeof(*msg), nullptr);
        if (rcvid < 0) continue;
        if (rcvid == 0) {
            struct _pulse p{};
            std::memcpy(&p, msg.get(), sizeof(p));
            if (p.code == _PULSE_CODE_DISCONNECT) {
                ConnectDetach(p.scoid);
            }
            continue;
        }
        if (msg->type != 0x0100) {
            MsgError(rcvid, ENOSYS);
            continue;
        }

        uint64_t t_verify_start = mdfp_cycles();

        mdfp::signals::CombinedVerifyResult combined =
            mdfp::signals::verify_frame_with_extra_signals(
                msg->frame_seq,
                msg->scenario,
                msg->payload_bytes,
                msg->frame_sha256,
                msg->bayer_raw,
                g_k_ref,
                msg->hw_eof_cycles,
                &signal_monitor,
                MDFP_NCC_THRESHOLD,
                MDFP_PCE_THRESHOLD_LINEAR);
        const mdfp::ingest::VerifyDecision& dec = combined.prnu;

        uint64_t t_verify_end = mdfp_cycles();
        uint64_t verify_duration_ns = (t_verify_end > t_verify_start)
            ? ((t_verify_end - t_verify_start) * 1000000000ULL / cycles_per_sec)
            : 45000ULL;

        MdfpVerifyReply reply;
        std::memset(&reply, 0, sizeof(reply));
        reply.status = dec.status;
        mdfp::ingest::copy_cstr_bounded(reply.verdict, sizeof(reply.verdict), dec.verdict);
        reply.ncc = dec.ncc;
        reply.pce_linear = dec.pce_linear;
        reply.pce_db = dec.pce_db;
        reply.ncc_threshold = dec.ncc_threshold;
        reply.pce_threshold_linear = dec.pce_threshold_linear;
        reply.pce_threshold_db = MDFP_PCE_THRESHOLD_DB;
        mdfp::ingest::copy_cstr_bounded(reply.k_ref_id, sizeof(reply.k_ref_id), MDFP_DEFAULT_KREF_ID);
        mdfp::ingest::copy_cstr_bounded(reply.k_ref_version, sizeof(reply.k_ref_version), MDFP_DEFAULT_KREF_VERSION);
        reply.verify_start_cycles = t_verify_start;
        reply.verify_end_cycles = t_verify_end;
        reply.verify_duration_ns = verify_duration_ns;
        reply.extra_signals_enabled = sig_cfg.any_active() ? 1U : 0U;
        reply.interval_cycles_p50 = combined.signals.interval_stats.p50_cycles;
        reply.interval_cycles_p99 = combined.signals.interval_stats.p99_cycles;
        reply.interval_us_p50 = combined.signals.interval_stats.p50_us;
        reply.interval_us_p99 = combined.signals.interval_stats.p99_us;
        reply.interval_samples = combined.signals.interval_stats.sample_count;
        reply.seq_timing_failures = signal_monitor.seq_timing_failures();
        reply.challenge_failures = signal_monitor.challenge_failures();

        MsgReply(rcvid, 0, &reply, sizeof(reply));

        if (dec.allow) {
            std::memset(smsg.get(), 0, sizeof(*smsg));
            smsg->type = 0x0200;
            smsg->frame_seq = msg->frame_seq;
            smsg->scenario = msg->scenario;
            smsg->hw_eof_ns = msg->hw_eof_ns;
            smsg->capture_cycles = msg->capture_wakeup_cycles;
            smsg->ncc = dec.ncc;
            smsg->pce_linear = dec.pce_linear;
            smsg->pce_db = dec.pce_db;
            smsg->ncc_threshold = dec.ncc_threshold;
            smsg->pce_threshold_linear = dec.pce_threshold_linear;
            smsg->verify_duration_ns = verify_duration_ns;
            mdfp::ingest::copy_cstr_bounded(smsg->verdict, sizeof(smsg->verdict), dec.verdict);
            smsg->is_ghost_event = false;

            mdfp::ingest::copy_cstr_bounded(smsg->raw_sha256, sizeof(smsg->raw_sha256), dec.frame_sha256);
            mdfp::ingest::copy_cstr_bounded(smsg->sensor_id, sizeof(smsg->sensor_id), msg->sensor_id);
            mdfp::ingest::copy_cstr_bounded(smsg->k_ref_id, sizeof(smsg->k_ref_id), MDFP_DEFAULT_KREF_ID);
            mdfp::ingest::copy_cstr_bounded(smsg->k_ref_version, sizeof(smsg->k_ref_version), MDFP_DEFAULT_KREF_VERSION);

            MdfpSealReply sreply;
            std::memset(&sreply, 0, sizeof(sreply));
            mdfp_qnx_send_retry(
                &seal_coid, MDFP_ATTACH_SEAL,
                smsg.get(), sizeof(*smsg),
                &sreply, sizeof(sreply));
        }
    }

    name_detach(attach, 0);
    return 0;
}
