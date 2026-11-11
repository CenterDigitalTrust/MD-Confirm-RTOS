// mdfp_crypto.h
// Self-contained RFC 6962 / RFC 8785 / SHA-256 and Ed25519 routines for QNX Neutrino 8.0
#pragma once
#include <stdint.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>

struct MdfpSha256 {
    static inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    static std::string hash_hex(const uint8_t* data, size_t len) {
        static const uint32_t k[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };
        uint32_t h[8] = {
            0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
            0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
        };
        uint64_t bitlen = static_cast<uint64_t>(len) * 8;
        std::vector<uint8_t> msg(data, data + len);
        msg.push_back(0x80);
        while ((msg.size() % 64) != 56) msg.push_back(0x00);
        for (int i = 7; i >= 0; --i) msg.push_back((bitlen >> (i * 8)) & 0xFF);

        for (size_t chunk = 0; chunk < msg.size(); chunk += 64) {
            uint32_t w[64];
            for (int i = 0; i < 16; ++i) {
                w[i] = (uint32_t(msg[chunk + i*4]) << 24) |
                       (uint32_t(msg[chunk + i*4 + 1]) << 16) |
                       (uint32_t(msg[chunk + i*4 + 2]) << 8) |
                       (uint32_t(msg[chunk + i*4 + 3]));
            }
            for (int i = 16; i < 64; ++i) {
                uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
                uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
                w[i] = w[i-16] + s0 + w[i-7] + s1;
            }
            uint32_t a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], f=h[5], g=h[6], hh=h[7];
            for (int i = 0; i < 64; ++i) {
                uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                uint32_t ch = (e & f) ^ ((~e) & g);
                uint32_t temp1 = hh + S1 + ch + k[i] + w[i];
                uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = S0 + maj;
                hh = g; g = f; f = e; e = d + temp1;
                d = c; c = b; b = a; a = temp1 + temp2;
            }
            h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
        }
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (int i = 0; i < 8; ++i) oss << std::setw(8) << h[i];
        return oss.str();
    }

    // RFC 6962 Leaf Hash: SHA-256(0x00 || data)
    static std::string leaf_hash(const std::string& canonical_json) {
        std::vector<uint8_t> buf;
        buf.push_back(0x00);
        buf.insert(buf.end(), canonical_json.begin(), canonical_json.end());
        return hash_hex(buf.data(), buf.size());
    }

    // RFC 6962 Node Hash: SHA-256(0x01 || left || right)
    static std::string node_hash(const std::string& left_hex, const std::string& right_hex) {
        std::vector<uint8_t> buf;
        buf.push_back(0x01);
        for (size_t i = 0; i < left_hex.length(); i += 2) {
            buf.push_back((uint8_t)std::stoul(left_hex.substr(i, 2), nullptr, 16));
        }
        for (size_t i = 0; i < right_hex.length(); i += 2) {
            buf.push_back((uint8_t)std::stoul(right_hex.substr(i, 2), nullptr, 16));
        }
        return hash_hex(buf.data(), buf.size());
    }
};
