#include "../../qnx/common/mdfp_signer.h"

extern "C" {
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
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace {

const uint8_t kDemoSeed[32] = {
    0xf3,0x80,0x22,0x1e,0x5e,0x91,0xe1,0xbb,0xfd,0xe4,0xee,0xbd,0xc1,0xae,0x5d,0xc5,
    0xc9,0x45,0x17,0x11,0xbb,0xc4,0xd7,0x4f,0x31,0xce,0x69,0x28,0x0c,0x18,0x11,0xe8
};
const uint8_t kDemoPub[32] = {
    0x7e,0xa8,0x1a,0xc6,0xc1,0xfc,0x3a,0x9a,0x56,0x7a,0x76,0x93,0xe3,0xd9,0x30,0xa5,
    0xc1,0x40,0xa3,0xa0,0x5f,0xa2,0x70,0xd7,0x63,0xf2,0x91,0x16,0x06,0x96,0xa4,0x68
};

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    assert(hex.size() % 2 == 0);
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
    }
    return out;
}

bool verify_sig(const std::string& msg, const std::string& sig_hex, const uint8_t pub[32]) {
    std::vector<uint8_t> sig = hex_to_bytes(sig_hex);
    if (sig.size() != 64U) return false;
    std::vector<uint8_t> sm(64U + msg.size());
    std::memcpy(sm.data(), sig.data(), 64U);
    std::memcpy(sm.data() + 64U, msg.data(), msg.size());
    std::vector<uint8_t> out(64U + msg.size());
    unsigned long long mlen = 0;
    return crypto_sign_open(out.data(), &mlen, sm.data(), sm.size(), pub) == 0 && mlen == msg.size();
}

void test_in_memory_signer_and_stub() {
    std::string err;
    auto signer = mdfp::FileSigner::from_seed_and_pub(kDemoSeed, kDemoPub, &err);
    assert(signer != nullptr);
    assert(signer->key_id() == "7ea81ac6c1fc3a9a");
    assert(signer->public_key_hex() ==
           "7ea81ac6c1fc3a9a567a7693e3d930a5c140a3a05fa270d763f291160696a468");

    std::string sig_hex = signer->sign_hex("MDFP1\nhello");
    assert(verify_sig("MDFP1\nhello", sig_hex, kDemoPub));

    // Mismatched seed vs pub must fail self-check
    uint8_t bad_pub[32];
    std::memcpy(bad_pub, kDemoPub, 32);
    bad_pub[0] ^= 0xFFU;
    std::string bad_err;
    auto bad_signer = mdfp::FileSigner::from_seed_and_pub(kDemoSeed, bad_pub, &bad_err);
    assert(bad_signer == nullptr);
    assert(!bad_err.empty());

    // Documented PKCS#11 / TPM 2.0 / SE stub must be unimplemented and throw cleanly
    mdfp::HardwareTokenSignerStub stub("PKCS11", "pkcs11:token=demo;object=ed25519");
    assert(!mdfp::HardwareTokenSignerStub::is_implemented());
    bool threw = false;
    try {
        (void)stub.sign_hex("probe");
    } catch (const std::runtime_error&) {
        threw = true;
    }
    assert(threw);
}

void test_key_file_permissions_and_loading() {
    const std::string key_path = "tmp_test_device_signer.key";
    const std::string raw_path = "tmp_test_device_signer_raw.key";
    std::remove(key_path.c_str());
    std::remove(raw_path.c_str());

    std::string err;
    // Explicit missing key path must refuse to start
    auto missing = mdfp::FileSigner::open_or_provision_demo_0600(
        key_path, true, kDemoSeed, kDemoPub, &err);
    assert(missing == nullptr);

    // Non-explicit boot creates 0600 key file cleanly and loads it
    auto provisioned = mdfp::FileSigner::open_or_provision_demo_0600(
        key_path, false, kDemoSeed, kDemoPub, &err);
    assert(provisioned != nullptr);
    assert(verify_sig("MDFP1-STH\ntest", provisioned->sign_hex("MDFP1-STH\ntest"), kDemoPub));

#ifndef _WIN32
    struct stat st {};
    assert(::stat(key_path.c_str(), &st) == 0);
    assert((st.st_mode & 0077) == 0);

    // Refuses 0644 (world readable)
    assert(::chmod(key_path.c_str(), 0644) == 0);
    auto refused_644 = mdfp::FileSigner::from_key_file(key_path, &err);
    assert(refused_644 == nullptr);
    assert(err.find("group- or world") != std::string::npos);

    // Refuses 0640 (group readable)
    assert(::chmod(key_path.c_str(), 0640) == 0);
    auto refused_640 = mdfp::FileSigner::from_key_file(key_path, &err);
    assert(refused_640 == nullptr);

    // Refuses 0604 (world readable only)
    assert(::chmod(key_path.c_str(), 0604) == 0);
    auto refused_604 = mdfp::FileSigner::from_key_file(key_path, &err);
    assert(refused_604 == nullptr);

    // Accepts 0400 (owner read-only)
    assert(::chmod(key_path.c_str(), 0400) == 0);
    auto ok_400 = mdfp::FileSigner::from_key_file(key_path, &err);
    assert(ok_400 != nullptr);
    assert(ok_400->key_id() == "7ea81ac6c1fc3a9a");

    // Restore write bit before removal
    ::chmod(key_path.c_str(), 0600);
#endif

    // Test 64-byte raw binary key file format
    {
        std::ofstream ofs(raw_path.c_str(), std::ios::binary | std::ios::trunc);
        ofs.write(reinterpret_cast<const char*>(kDemoSeed), 32);
        ofs.write(reinterpret_cast<const char*>(kDemoPub), 32);
        ofs.close();
#ifndef _WIN32
        ::chmod(raw_path.c_str(), 0600);
#endif
        auto raw_signer = mdfp::FileSigner::from_key_file(raw_path, &err);
        assert(raw_signer != nullptr);
        assert(verify_sig("raw", raw_signer->sign_hex("raw"), kDemoPub));
    }

    std::remove(key_path.c_str());
    std::remove(raw_path.c_str());
}

}  // namespace

int main() {
    test_in_memory_signer_and_stub();
    test_key_file_permissions_and_loading();
    std::cout << "[PASS] Signer abstraction, POSIX key permission checks, and HW stub verified."
              << std::endl;
    return 0;
}
