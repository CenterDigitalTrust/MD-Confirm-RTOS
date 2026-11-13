// md-seal.cpp
// RFC 6962 Merkle Tree Sealing, Tamper-Evident Journal & Software Ed25519 Signing
// Project: MD-Confirm RTOS (QNX Global Hackathon) | Track: Automotive & Mobility
// Signer Backend: FileSigner (software TweetNaCl, NO hardware key protection).

#define _QNX_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <sys/neutrino.h>
#include <sys/dispatch.h>
#include <sys/stat.h>

#include "../common/mdfp_protocol.h"
#include "../common/mdfp_crypto.h"
#include "../common/mdfp_canon.h"
#include "../common/mdfp_merkle.h"
#include "../common/mdfp_seal_core.h"
#include "../common/mdfp_signer.h"

extern "C" {
#include "../common/tweetnacl.h"

void randombytes(unsigned char* x, unsigned long long xlen) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, x, static_cast<size_t>(xlen));
        (void)n;
        close(fd);
    }
}
}

// Deterministic DEMO Device Ed25519 Keypair (SOFTWARE DEMO ONLY - NO HARDWARE PROTECTION)
// Seed: SHA-256("QNX_NEUTRINO_8.0_ADAS_DEVICE_KEY_SEED_2026")
static const unsigned char g_demo_seed[32] = {
    0xf3,0x80,0x22,0x1e,0x5e,0x91,0xe1,0xbb,0xfd,0xe4,0xee,0xbd,0xc1,0xae,0x5d,0xc5,
    0xc9,0x45,0x17,0x11,0xbb,0xc4,0xd7,0x4f,0x31,0xce,0x69,0x28,0x0c,0x18,0x11,0xe8
};
static const unsigned char g_demo_pub[32] = {
    0x7e,0xa8,0x1a,0xc6,0xc1,0xfc,0x3a,0x9a,0x56,0x7a,0x76,0x93,0xe3,0xd9,0x30,0xa5,
    0xc1,0x40,0xa3,0xa0,0x5f,0xa2,0x70,0xd7,0x63,0xf2,0x91,0x16,0x06,0x96,0xa4,0x68
};

int main(int argc, char** argv) {
    std::string key_file = MDFP_DEFAULT_KEY_FILE_PATH;
    bool explicit_key_file = false;
    if (const char* env_key = std::getenv("MDFP_KEY_FILE")) {
        if (*env_key != '\0') {
            key_file = env_key;
            explicit_key_file = true;
        }
    }
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--key-file" && i + 1 < argc) {
            key_file = argv[++i];
            explicit_key_file = true;
        }
    }

    // Create persistent directory on QNX6 /data partition before default key provisioning
    mkdir("/data", 0755);
    mkdir("/data/mdfp_evidence", 0755);

    std::string err;
    std::unique_ptr<mdfp::FileSigner> signer = mdfp::FileSigner::open_or_provision_demo_0600(
        key_file, explicit_key_file, g_demo_seed, g_demo_pub, &err);
    if (!signer) {
        std::cerr << "[md-seal] REFUSING TO START: " << err << std::endl;
        return 1;
    }

    const std::string journal_path = MDFP_PERSISTENT_JOURNAL_PATH;
    std::cout << "========================================================\n"
              << " [md-seal] Merkle Tree (RFC 6962) & Ed25519 (RFC 8032)  \n"
              << " Signer Backend: " << signer->backend_name() << "\n"
              << " Key File (0600): " << key_file << "\n"
              << " Public Key     : " << signer->public_key_hex() << "\n"
              << "========================================================\n" << std::endl;

    mdfp::SealConfig cfg;
    cfg.journal_path = journal_path;
    cfg.sth_path = MDFP_PERSISTENT_STH_PATH;
    cfg.outbox_path = MDFP_PERSISTENT_OUTBOX_PATH;
    cfg.device_id = "qnx-8.0-adas-node-01";
    cfg.key_id = signer->key_id();
    cfg.sth_interval = MDFP_STH_INTERVAL_LEAVES;

    mdfp::SealEngine engine(cfg, [&signer](const std::string& m) {
        return signer->sign_hex(m);
    });

    name_attach_t* attach = name_attach(nullptr, MDFP_ATTACH_SEAL, 0);
    if (!attach) {
        perror("name_attach(mdfp_seal)");
        return 1;
    }
    std::cout << "[md-seal] Registered QNX channel: " << MDFP_ATTACH_SEAL << std::endl;

    while (true) {
        MdfpSealMsg msg;
        int rcvid = MsgReceive(attach->chid, &msg, sizeof(msg), nullptr);
        if (rcvid < 0) continue;

        mdfp::SealInput in;
        in.hw_eof_ns = msg.hw_eof_ns;
        in.capture_cycles = msg.capture_cycles;
        in.is_ghost_event = (msg.is_ghost_event != 0);
        in.frame_seq = msg.frame_seq;
        in.sensor_id = std::string(msg.sensor_id, mdfp::ingest::safe_strnlen(msg.sensor_id, sizeof(msg.sensor_id)));
        if (in.sensor_id.empty()) in.sensor_id = MDFP_DEFAULT_SENSOR_ID;
        in.k_ref_id = std::string(msg.k_ref_id, mdfp::ingest::safe_strnlen(msg.k_ref_id, sizeof(msg.k_ref_id)));
        if (in.k_ref_id.empty()) in.k_ref_id = MDFP_DEFAULT_KREF_ID;
        in.k_ref_version = std::string(msg.k_ref_version, mdfp::ingest::safe_strnlen(msg.k_ref_version, sizeof(msg.k_ref_version)));
        if (in.k_ref_version.empty()) in.k_ref_version = MDFP_DEFAULT_KREF_VERSION;
        in.ncc_threshold = (msg.ncc_threshold > 0.0) ? msg.ncc_threshold : MDFP_NCC_THRESHOLD;
        in.pce_threshold_linear = (msg.pce_threshold_linear > 0.0) ? msg.pce_threshold_linear : MDFP_PCE_THRESHOLD_LINEAR;
        in.ncc = msg.ncc;
        in.pce_db = msg.pce_db;
        in.pce_linear = msg.pce_linear;
        in.raw_sha256 = std::string(msg.raw_sha256, mdfp::ingest::safe_strnlen(msg.raw_sha256, sizeof(msg.raw_sha256)));
        in.scenario = msg.scenario;
        in.verdict = std::string(msg.verdict, mdfp::ingest::safe_strnlen(msg.verdict, sizeof(msg.verdict)));

        mdfp::SealOutput sealed = engine.seal_record(in);

        std::cout << "[md-seal] Sealed Leaf #" << sealed.leaf_index
                  << " (Frame #" << msg.frame_seq << ")"
                  << " | Leaf: " << sealed.leaf_hash.substr(0, 16) << "..."
                  << " | Root: " << sealed.merkle_root.substr(0, 16) << "..."
                  << " | Sig: " << sealed.record_sig.substr(0, 16) << "..."
                  << (sealed.emitted_sth ? " | STH+OUTBOX: YES" : "")
                  << " | Journal: /data/mdfp_evidence" << std::endl;

        MdfpSealReply reply;
        std::memset(&reply, 0, sizeof(reply));
        reply.status = sealed.io_ok ? 0 : -1;
        reply.leaf_index = sealed.leaf_index;
        mdfp::ingest::copy_cstr_bounded(reply.leaf_sha256, sizeof(reply.leaf_sha256), sealed.leaf_hash.c_str());
        mdfp::ingest::copy_cstr_bounded(reply.merkle_root, sizeof(reply.merkle_root), sealed.merkle_root.c_str());
        mdfp::ingest::copy_cstr_bounded(reply.signature_ed25519, sizeof(reply.signature_ed25519), sealed.record_sig.c_str());
        mdfp::ingest::copy_cstr_bounded(reply.journal_path, sizeof(reply.journal_path), journal_path.c_str());

        MsgReply(rcvid, 0, &reply, sizeof(reply));
    }

    name_detach(attach, 0);
    return 0;
}
