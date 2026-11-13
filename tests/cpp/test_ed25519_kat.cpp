#include "../../qnx/common/mdfp_crypto.h"

extern "C" {
#include "../../qnx/common/tweetnacl.h"

void randombytes(unsigned char* x, unsigned long long xlen) {
    for (unsigned long long i = 0; i < xlen; ++i) {
        x[i] = static_cast<unsigned char>(i & 0xFFU);
    }
}
}

#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    assert(hex.size() % 2 == 0);
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
    }
    return out;
}

std::string bytes_to_hex(const uint8_t* data, size_t len) {
    static const char h[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(h[(data[i] >> 4) & 0x0F]);
        out.push_back(h[data[i] & 0x0F]);
    }
    return out;
}

struct Ed25519KatVector {
    const char* name;
    const char* sk_seed_hex;
    const char* pk_hex;
    const char* msg_hex;
    const char* sig_hex;
};

// Official RFC 8032 Section 7.1 Test Vectors for Ed25519
const Ed25519KatVector kRfc8032Vectors[] = {
    {
        "RFC8032-7.1 TEST 1 (empty message)",
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    },
    {
        "RFC8032-7.1 TEST 2 (1-byte 0x72)",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    },
    {
        "RFC8032-7.1 TEST 3 (2-byte 0xaf82)",
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
    },
    {
        "RFC8032-7.1 TEST SHA(abc) (64 bytes)",
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
        "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"
    }
};

void test_rfc8032_ed25519() {
    for (const auto& v : kRfc8032Vectors) {
        std::vector<uint8_t> seed = hex_to_bytes(v.sk_seed_hex);
        std::vector<uint8_t> pk = hex_to_bytes(v.pk_hex);
        std::vector<uint8_t> msg = hex_to_bytes(v.msg_hex);
        std::vector<uint8_t> expected_sig = hex_to_bytes(v.sig_hex);

        assert(seed.size() == 32);
        assert(pk.size() == 32);
        assert(expected_sig.size() == 64);

        uint8_t sk[64];
        std::memcpy(sk, seed.data(), 32);
        std::memcpy(sk + 32, pk.data(), 32);

        std::vector<uint8_t> signed_msg(64 + msg.size(), 0);
        unsigned long long smlen = 0;
        int sign_rc = crypto_sign(
            signed_msg.data(),
            &smlen,
            msg.empty() ? reinterpret_cast<const uint8_t*>("") : msg.data(),
            static_cast<unsigned long long>(msg.size()),
            sk);
        assert(sign_rc == 0);
        assert(smlen == 64ULL + msg.size());
        assert(bytes_to_hex(signed_msg.data(), 64) == v.sig_hex);

        std::vector<uint8_t> opened(64 + msg.size(), 0);
        unsigned long long mlen = 0;
        int open_rc = crypto_sign_open(opened.data(), &mlen, signed_msg.data(), smlen, pk.data());
        assert(open_rc == 0);
        assert(mlen == msg.size());
        if (!msg.empty()) {
            assert(std::memcmp(opened.data(), msg.data(), msg.size()) == 0);
        }

        // Flip 1 bit in signature -> verification must fail
        std::vector<uint8_t> tampered = signed_msg;
        tampered[0] ^= 0x01U;
        assert(crypto_sign_open(opened.data(), &mlen, tampered.data(), smlen, pk.data()) != 0);

        // Flip 1 bit in message (if non-empty) -> verification must fail
        if (!msg.empty()) {
            std::vector<uint8_t> bad_msg = signed_msg;
            bad_msg[64] ^= 0x80U;
            assert(crypto_sign_open(opened.data(), &mlen, bad_msg.data(), smlen, pk.data()) != 0);
        }

        std::cout << "[PASS] " << v.name << "\n";
    }
}

void test_sha256_and_rfc6962_kats() {
    // NIST FIPS 180-4 / RFC 6234 known SHA-256 answers
    assert(MdfpSha256::hash_hex(nullptr, 0) ==
           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    const char* abc = "abc";
    assert(MdfpSha256::hash_hex(reinterpret_cast<const uint8_t*>(abc), 3) ==
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    const char* msg448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    assert(MdfpSha256::hash_hex(reinterpret_cast<const uint8_t*>(msg448), std::strlen(msg448)) ==
           "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    // RFC 6962 domain separation: SHA-256(0x00 || data) != SHA-256(data)
    std::string leaf = MdfpSha256::leaf_hash("abc");
    const uint8_t leaf_raw[4] = {0x00, 'a', 'b', 'c'};
    assert(leaf == MdfpSha256::hash_hex(leaf_raw, 4));
    assert(leaf != MdfpSha256::hash_hex(reinterpret_cast<const uint8_t*>(abc), 3));

    // RFC 6962 interior node: SHA-256(0x01 || left || right)
    std::string node = MdfpSha256::node_hash(leaf, leaf);
    std::vector<uint8_t> expected_in = {0x01};
    auto leaf_bytes = hex_to_bytes(leaf);
    expected_in.insert(expected_in.end(), leaf_bytes.begin(), leaf_bytes.end());
    expected_in.insert(expected_in.end(), leaf_bytes.begin(), leaf_bytes.end());
    assert(node == MdfpSha256::hash_hex(expected_in.data(), expected_in.size()));
    assert(node != leaf);

    std::cout << "[PASS] SHA-256 + RFC 6962 domain separation KATs\n";
}

} // namespace

int main() {
    test_rfc8032_ed25519();
    test_sha256_and_rfc6962_kats();
    return 0;
}
