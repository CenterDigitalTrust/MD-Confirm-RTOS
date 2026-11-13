#include "../../qnx/common/mdfp_crypto.h"
#include "../../qnx/common/mdfp_canon.h"
#include "../../qnx/common/mdfp_merkle.h"
#include "../../qnx/common/mdfp_seal_core.h"

extern "C" {
#include "../../qnx/common/tweetnacl.h"

void randombytes(unsigned char* x, unsigned long long xlen) {
    for (unsigned long long i = 0; i < xlen; ++i) {
        x[i] = static_cast<unsigned char>(i & 0xFFU);
    }
}
}

#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

const unsigned char kDeviceSeed[32] = {
    0xf3,0x80,0x22,0x1e,0x5e,0x91,0xe1,0xbb,0xfd,0xe4,0xee,0xbd,0xc1,0xae,0x5d,0xc5,
    0xc9,0x45,0x17,0x11,0xbb,0xc4,0xd7,0x4f,0x31,0xce,0x69,0x28,0x0c,0x18,0x11,0xe8
};
const unsigned char kDevicePub[32] = {
    0x7e,0xa8,0x1a,0xc6,0xc1,0xfc,0x3a,0x9a,0x56,0x7a,0x76,0x93,0xe3,0xd9,0x30,0xa5,
    0xc1,0x40,0xa3,0xa0,0x5f,0xa2,0x70,0xd7,0x63,0xf2,0x91,0x16,0x06,0x96,0xa4,0x68
};

std::string hex_byte_vec(const uint8_t* p, size_t n) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < n; ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(p[i]);
    }
    return oss.str();
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    assert(hex.size() % 2 == 0);
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
    }
    return out;
}

bool verify_ed25519_hex(const std::string& message, const std::string& sig_hex) {
    std::vector<uint8_t> sig = hex_to_bytes(sig_hex);
    if (sig.size() != 64) {
        return false;
    }
    std::vector<uint8_t> sm(64 + message.size());
    std::memcpy(sm.data(), sig.data(), 64);
    if (!message.empty()) {
        std::memcpy(sm.data() + 64, message.data(), message.size());
    }
    std::vector<uint8_t> m_out(64 + message.size());
    unsigned long long mlen = 0;
    return crypto_sign_open(m_out.data(), &mlen, sm.data(), sm.size(), kDevicePub) == 0 &&
           mlen == message.size();
}

size_t count_lines(const std::string& path) {
    std::ifstream ifs(path.c_str());
    std::string line;
    size_t n = 0;
    while (std::getline(ifs, line)) {
        if (!line.empty()) {
            ++n;
        }
    }
    return n;
}

void test_merkle_tree_rfc6962() {
    assert(mdfp::merkle::merkle_tree_hash({}) ==
           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    std::vector<std::string> leaves;
    for (int i = 0; i < 5; ++i) {
        leaves.push_back(MdfpSha256::leaf_hash("leaf-" + std::to_string(i)));
    }

    assert(mdfp::merkle::merkle_tree_hash({leaves[0]}) == leaves[0]);

    std::string h01 = MdfpSha256::node_hash(leaves[0], leaves[1]);
    assert(mdfp::merkle::merkle_tree_hash({leaves[0], leaves[1]}) == h01);

    // n=3 must use left-complete split k=2: H(0x01 || H(l0,l1) || l2), never odd duplication
    std::string h012 = MdfpSha256::node_hash(h01, leaves[2]);
    assert(mdfp::merkle::merkle_tree_hash({leaves[0], leaves[1], leaves[2]}) == h012);

    std::string h23 = MdfpSha256::node_hash(leaves[2], leaves[3]);
    std::string h0123 = MdfpSha256::node_hash(h01, h23);
    assert(mdfp::merkle::merkle_tree_hash({leaves[0], leaves[1], leaves[2], leaves[3]}) == h0123);

    std::string h01234 = MdfpSha256::node_hash(h0123, leaves[4]);
    assert(mdfp::merkle::merkle_tree_hash(leaves) == h01234);
}

void test_seal_engine_sth_outbox_and_recovery() {
    uint8_t sk[64];
    std::memcpy(sk, kDeviceSeed, 32);
    std::memcpy(sk + 32, kDevicePub, 32);

    auto sign_fn = [&](const std::string& msg) -> std::string {
        std::vector<uint8_t> sm(msg.size() + 64U);
        unsigned long long smlen = 0;
        crypto_sign(
            sm.data(),
            &smlen,
            reinterpret_cast<const uint8_t*>(msg.data()),
            msg.size(),
            sk);
        return hex_byte_vec(sm.data(), 64);
    };

    const std::string jpath = "tmp_test_seal_journal.log";
    const std::string spath = "tmp_test_seal_sth.log";
    const std::string opath = "tmp_test_seal_outbox.jsonl";
    std::remove(jpath.c_str());
    std::remove(spath.c_str());
    std::remove(opath.c_str());

    mdfp::SealConfig cfg;
    cfg.journal_path = jpath;
    cfg.sth_path = spath;
    cfg.outbox_path = opath;
    cfg.device_id = "qnx-8.0-adas-node-01";
    cfg.key_id = mdfp::key_id_from_pubkey_bytes(kDevicePub);
    cfg.sth_interval = 32;
    assert(cfg.key_id == "7ea81ac6c1fc3a9a");

    std::string sth32_sha256;
    {
        mdfp::SealEngine engine(cfg, sign_fn);
        for (uint32_t seq = 1; seq <= 35; ++seq) {
            mdfp::SealInput in;
            in.hw_eof_ns = 1700000000000000000ULL + static_cast<uint64_t>(seq) * 1000000ULL;
            in.capture_cycles = 500000ULL + static_cast<uint64_t>(seq) * 100ULL;
            in.is_ghost_event = (seq == 7);
            in.frame_seq = seq;
            in.sensor_id = "sim-bayer-64x64-01";
            in.k_ref_id = "kref-sim-0x20261111";
            in.k_ref_version = "sim-1d-v1";
            in.ncc_threshold = 0.75;
            in.pce_threshold_linear = 60.0;
            in.ncc = in.is_ghost_event ? 0.12 : 0.91;
            in.pce_db = in.is_ghost_event ? 1.5 : 32.0;
            in.pce_linear = in.is_ghost_event ? 1.4 : 1584.9;
            in.raw_sha256 = MdfpSha256::hash_hex(
                reinterpret_cast<const uint8_t*>(&seq), sizeof(seq));
            in.scenario = in.is_ghost_event ? 2U : 1U;
            in.verdict = in.is_ghost_event ? "SPOOF_REJECTED" : "AUTHENTIC";

            mdfp::SealOutput out = engine.seal_record(in);
            assert(out.io_ok);
            assert(out.leaf_index == seq);
            assert(MdfpSha256::leaf_hash(out.canonical_json) == out.leaf_hash);
            assert(out.canonical_json.find("\"frame_sha256\":\"" + in.raw_sha256 + "\"") != std::string::npos);
            assert(out.canonical_json.find("\"clock_cycles\":") != std::string::npos);
            assert(out.canonical_json.find("\"k_ref_id\":\"kref-sim-0x20261111\"") != std::string::npos);
            assert(out.journal_line.find(" | CANON: " + out.canonical_json) != std::string::npos);
            assert(verify_ed25519_hex("MDFP1\n" + out.merkle_root, out.record_sig));

            if (seq == 7 || seq == 32) {
                assert(out.emitted_sth);
                assert(verify_ed25519_hex("MDFP1-STH\n" + out.sth_canonical_json, out.sth_sig));
                if (seq == 7) {
                    assert(out.sth_canonical_json.find("\"prev_sth_sha256\":\"" + std::string(64, '0') + "\"") !=
                           std::string::npos);
                    assert(out.outbox_line.find("\"event\":\"GHOST_EVENT\"") != std::string::npos);
                } else {
                    sth32_sha256 = out.sth_sha256;
                    assert(out.sth_canonical_json.find("\"tree_size\":32") != std::string::npos);
                    assert(out.sth_canonical_json.find("\"timestamp\":1700000000032000000") != std::string::npos);
                    assert(out.outbox_line.find("\"event\":\"PERIODIC_STH\"") != std::string::npos);
                }
            } else {
                assert(!out.emitted_sth);
            }
        }
    }

    assert(count_lines(jpath) == 35);
    assert(count_lines(spath) == 2);
    assert(count_lines(opath) == 2);

    // Simulate process restart and verify index + prev_sth_sha256 chain continue monotonically
    {
        mdfp::SealEngine recovered(cfg, sign_fn);
        assert(recovered.leaf_count() == 35);
        assert(recovered.last_sth_sha256() == sth32_sha256);

        mdfp::SealInput in;
        in.hw_eof_ns = 1700000099000000000ULL;
        in.is_ghost_event = true;
        in.frame_seq = 36;
        in.ncc = 0.05;
        in.pce_db = 0.8;
        in.pce_linear = 1.2;
        in.raw_sha256 = std::string(64, 'a');
        in.scenario = 2;
        in.verdict = "SPOOF_REJECTED";

        mdfp::SealOutput out = recovered.seal_record(in);
        assert(out.io_ok);
        assert(out.leaf_index == 36);
        assert(out.emitted_sth);
        assert(out.sth_canonical_json.find("\"prev_sth_sha256\":\"" + sth32_sha256 + "\"") !=
               std::string::npos);
        assert(verify_ed25519_hex("MDFP1-STH\n" + out.sth_canonical_json, out.sth_sig));
    }

    assert(count_lines(jpath) == 36);
    assert(count_lines(spath) == 3);
    assert(count_lines(opath) == 3);

    std::remove(jpath.c_str());
    std::remove(spath.c_str());
    std::remove(opath.c_str());
}

}  // namespace

int main() {
    test_merkle_tree_rfc6962();
    test_seal_engine_sth_outbox_and_recovery();
    std::cout << "[PASS] RFC 6962 Merkle & SealEngine (STH/outbox/restart recovery) verified."
              << std::endl;
    return 0;
}
