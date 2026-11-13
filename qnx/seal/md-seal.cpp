// md-seal.cpp
// RFC 6962 Merkle Tree Sealing, Tamper-Evident Journal & RFC 8032 Ed25519 Signing
// Project: MD-Confirm RTOS (QNX Global Hackathon) | Track: Automotive & Mobility

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

extern "C" {
#include "../common/tweetnacl.h"

void randombytes(unsigned char* x, unsigned long long xlen) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, x, xlen);
        close(fd);
    }
}
}

// Deterministic Device Root-of-Trust Ed25519 Keypair
// Seed: SHA-256("QNX_NEUTRINO_8.0_ADAS_DEVICE_KEY_SEED_2026")
static const unsigned char g_device_seed[32] = {
    0xf3,0x80,0x22,0x1e,0x5e,0x91,0xe1,0xbb,0xfd,0xe4,0xee,0xbd,0xc1,0xae,0x5d,0xc5,
    0xc9,0x45,0x17,0x11,0xbb,0xc4,0xd7,0x4f,0x31,0xce,0x69,0x28,0x0c,0x18,0x11,0xe8
};
static const unsigned char g_device_pub[32] = {
    0x7e,0xa8,0x1a,0xc6,0xc1,0xfc,0x3a,0x9a,0x56,0x7a,0x76,0x93,0xe3,0xd9,0x30,0xa5,
    0xc1,0x40,0xa3,0xa0,0x5f,0xa2,0x70,0xd7,0x63,0xf2,0x91,0x16,0x06,0x96,0xa4,0x68
};
static unsigned char g_device_sk[64];

static std::string tweetnacl_sign_hex(const std::string& message) {
    std::vector<unsigned char> signed_buf(message.size() + 64U);
    unsigned long long signed_len = 0;
    crypto_sign(
        signed_buf.data(),
        &signed_len,
        reinterpret_cast<const unsigned char*>(message.data()),
        static_cast<unsigned long long>(message.size()),
        g_device_sk);

    // TweetNaCl places the 64-byte signature at the beginning of signed_buf
    std::ostringstream sig_hex_stream;
    sig_hex_stream << std::hex << std::setfill('0');
    for (int i = 0; i < 64; ++i) {
        sig_hex_stream << std::setw(2) << static_cast<int>(signed_buf[i]);
    }
    return sig_hex_stream.str();
}

int main() {
    std::cout << "========================================================\n"
              << " [md-seal] Merkle Tree (RFC 6962) & Ed25519 (RFC 8032)  \n"
              << " Storage: Persistent QNX6 /data Partition (Survives Reboot)\n"
              << " Device Public Key: 7ea81ac6c1fc3a9a567a7693e3d930a5... \n"
              << "========================================================\n" << std::endl;

    // Initialize TweetNaCl Ed25519 Signing Key (seed + pub)
    std::memcpy(g_device_sk, g_device_seed, 32);
    std::memcpy(g_device_sk + 32, g_device_pub, 32);

    // Create persistent directory on QNX6 /data partition
    mkdir("/data/mdfp_evidence", 0755);
    const std::string journal_path = MDFP_PERSISTENT_JOURNAL_PATH;

    mdfp::SealConfig cfg;
    cfg.journal_path = journal_path;
    cfg.sth_path = MDFP_PERSISTENT_STH_PATH;
    cfg.outbox_path = MDFP_PERSISTENT_OUTBOX_PATH;
    cfg.device_id = "qnx-8.0-adas-node-01";
    cfg.key_id = mdfp::key_id_from_pubkey_bytes(g_device_pub);
    cfg.sth_interval = MDFP_STH_INTERVAL_LEAVES;

    mdfp::SealEngine engine(cfg, tweetnacl_sign_hex);

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
        in.is_ghost_event = (msg.is_ghost_event != 0);
        in.frame_seq = msg.frame_seq;
        in.ncc = msg.ncc;
        in.pce_db = msg.pce_db;
        in.pce_linear = msg.pce_linear;
        in.raw_sha256 = std::string(msg.raw_sha256, strnlen(msg.raw_sha256, sizeof(msg.raw_sha256)));
        in.scenario = msg.scenario;
        in.verdict = std::string(msg.verdict, strnlen(msg.verdict, sizeof(msg.verdict)));

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
        std::strncpy(reply.leaf_sha256, sealed.leaf_hash.c_str(), 64);
        std::strncpy(reply.merkle_root, sealed.merkle_root.c_str(), 64);
        std::strncpy(reply.signature_ed25519, sealed.record_sig.c_str(), 128);
        std::strncpy(reply.journal_path, journal_path.c_str(), 127);

        MsgReply(rcvid, 0, &reply, sizeof(reply));
    }

    name_detach(attach, 0);
    return 0;
}
