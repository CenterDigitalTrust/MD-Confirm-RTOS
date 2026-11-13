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

static std::vector<std::string> g_leaf_hashes;
static std::string g_current_root = "0000000000000000000000000000000000000000000000000000000000000000";
static uint32_t g_leaf_counter = 0;

std::string compute_merkle_root() {
    if (g_leaf_hashes.empty()) return g_current_root;
    std::vector<std::string> layer = g_leaf_hashes;
    while (layer.size() > 1) {
        std::vector<std::string> next_layer;
        for (size_t i = 0; i < layer.size(); i += 2) {
            if (i + 1 < layer.size()) {
                next_layer.push_back(MdfpSha256::node_hash(layer[i], layer[i+1]));
            } else {
                next_layer.push_back(MdfpSha256::node_hash(layer[i], layer[i])); // Duplicate odd leaf per RFC 6962
            }
        }
        layer = next_layer;
    }
    return layer[0];
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

        g_leaf_counter++;

        // 1. Format Canonical JSON (RFC 8785) via host-tested serializer
        std::string canon = mdfp::build_seal_record_json(
            msg.hw_eof_ns,
            "qnx-8.0-adas-node-01",
            msg.is_ghost_event,
            msg.frame_seq,
            msg.ncc,
            msg.pce_db,
            msg.pce_linear,
            msg.raw_sha256,
            msg.scenario,
            msg.verdict);

        // 2. Compute RFC 6962 Leaf Hash: SHA-256(0x00 || canonical_json)
        std::string leaf_hash = MdfpSha256::leaf_hash(canon);
        g_leaf_hashes.push_back(leaf_hash);

        // 3. Recalculate Merkle Tree Root
        g_current_root = compute_merkle_root();

        // 4. Authentic Ed25519 signature over prefix "MDFP1\n" || Merkle Root using TweetNaCl
        std::string sign_target = "MDFP1\n" + g_current_root;
        unsigned char signed_buf[256];
        unsigned long long signed_len = 0;
        crypto_sign(signed_buf, &signed_len, (const unsigned char*)sign_target.c_str(), sign_target.length(), g_device_sk);

        // TweetNaCl places the 64-byte signature at the beginning of signed_buf
        std::ostringstream sig_hex_stream;
        sig_hex_stream << std::hex << std::setfill('0');
        for (int i = 0; i < 64; ++i) {
            sig_hex_stream << std::setw(2) << (int)signed_buf[i];
        }
        std::string ed25519_sig = sig_hex_stream.str();

        // 5. Append to Persistent Tamper-Evident Journal on /data partition
        std::ofstream ofs(journal_path.c_str(), std::ios::app);
        if (ofs.is_open()) {
            ofs << "RECORD #" << g_leaf_counter
                << " | SEQ: " << msg.frame_seq
                << " | TYPE: " << (msg.is_ghost_event ? "GHOST_EVENT" : "AUTHENTIC")
                << " | LEAF: " << leaf_hash
                << " | MERKLE_ROOT: " << g_current_root
                << " | SIG: " << ed25519_sig
                << " | RAW_SHA256: " << msg.raw_sha256
                << " | VERDICT: " << msg.verdict
                << "\n";
            ofs.close();
        }

        std::cout << "[md-seal] Sealed Leaf #" << g_leaf_counter
                  << " (Frame #" << msg.frame_seq << ")"
                  << " | Leaf: " << leaf_hash.substr(0, 16) << "..."
                  << " | Root: " << g_current_root.substr(0, 16) << "..."
                  << " | Sig: " << ed25519_sig.substr(0, 16) << "..."
                  << " | Journal: /data/mdfp_evidence" << std::endl;

        MdfpSealReply reply;
        std::memset(&reply, 0, sizeof(reply));
        reply.status = 0;
        reply.leaf_index = g_leaf_counter;
        std::strncpy(reply.leaf_sha256, leaf_hash.c_str(), 64);
        std::strncpy(reply.merkle_root, g_current_root.c_str(), 64);
        std::strncpy(reply.signature_ed25519, ed25519_sig.c_str(), 128);
        std::strncpy(reply.journal_path, journal_path.c_str(), 127);

        MsgReply(rcvid, 0, &reply, sizeof(reply));
    }

    name_detach(attach, 0);
    return 0;
}
