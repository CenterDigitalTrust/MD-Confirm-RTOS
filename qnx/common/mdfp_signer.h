// mdfp_signer.h
// Signer Abstraction (sign, public_key, key_id) for md-seal
//
// Backends:
//   - FileSigner: Software TweetNaCl Ed25519 key stored on filesystem with strict
//     permissions (refuses group- or world-readable key files, i.e., mode & 0077 != 0).
//     NOTE: FileSigner provides NO hardware key protection.
//   - HardwareTokenSignerStub: Documented unimplemented stub for future PKCS#11 HSM,
//     TPM 2.0 (where swtpm is strictly emulation, not hardware protection), or Secure Element.
#pragma once

#include <array>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

extern "C" {
#include "tweetnacl.h"
}

namespace mdfp {

inline std::string bytes_to_lower_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    return oss.str();
}

inline std::string compute_key_id(const std::array<uint8_t, 32>& pub) {
    return bytes_to_lower_hex(pub.data(), 8U);
}

class Signer {
public:
    virtual ~Signer() = default;

    virtual std::vector<uint8_t> sign(const uint8_t* msg, size_t len) = 0;
    virtual std::array<uint8_t, 32> public_key() const = 0;
    virtual std::string key_id() const = 0;
    virtual std::string backend_name() const = 0;

    std::string sign_hex(const std::string& message) {
        std::vector<uint8_t> sig = sign(
            reinterpret_cast<const uint8_t*>(message.data()), message.size());
        return bytes_to_lower_hex(sig.data(), sig.size());
    }

    std::string public_key_hex() const {
        auto pk = public_key();
        return bytes_to_lower_hex(pk.data(), pk.size());
    }
};

// Verify key file exists, is a regular file, and is NOT group- or world-readable/writable/executable.
inline bool check_key_file_permissions(const std::string& path, std::string* err_out) {
#ifdef _WIN32
    struct _stat st {};
    if (::_stat(path.c_str(), &st) != 0) {
        if (err_out) {
            *err_out = "Cannot stat key file '" + path + "': " + std::strerror(errno);
        }
        return false;
    }
    if ((st.st_mode & _S_IFREG) == 0) {
        if (err_out) {
            *err_out = "Key file '" + path + "' is not a regular file";
        }
        return false;
    }
    return true;
#else
    struct stat st {};
    if (::stat(path.c_str(), &st) != 0) {
        if (err_out) {
            *err_out = "Cannot stat key file '" + path + "': " + std::strerror(errno);
        }
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        if (err_out) {
            *err_out = "Key path '" + path + "' is not a regular file";
        }
        return false;
    }
    if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        if (err_out) {
            std::ostringstream oss;
            oss << "Refusing insecure key file '" << path << "' with mode 0"
                << std::oct << (st.st_mode & 0777)
                << ": key file must not be group- or world-accessible (require 0600 or 0400)";
            *err_out = oss.str();
        }
        return false;
    }
    if (::geteuid() != 0 && st.st_uid != ::geteuid()) {
        if (err_out) {
            *err_out = "Refusing key file '" + path + "': owner UID does not match effective UID";
        }
        return false;
    }
    return true;
#endif
}

// Software Ed25519 signer backed by TweetNaCl.
// WARNING: Keys reside in process RAM and disk files; provides NO hardware protection.
class FileSigner final : public Signer {
public:
    ~FileSigner() override {
        volatile uint8_t* p = sk_.data();
        for (size_t i = 0; i < sk_.size(); ++i) {
            p[i] = 0U;
        }
    }

    static std::unique_ptr<FileSigner> from_seed_and_pub(
        const uint8_t seed[32],
        const uint8_t pub[32],
        std::string* err_out = nullptr) {
        if (!seed || !pub) {
            if (err_out) {
                *err_out = "Null key buffer";
            }
            return nullptr;
        }
        auto signer = std::unique_ptr<FileSigner>(new FileSigner());
        std::memcpy(signer->sk_.data(), seed, 32U);
        std::memcpy(signer->sk_.data() + 32U, pub, 32U);
        std::memcpy(signer->pk_.data(), pub, 32U);

        // Self-check seed <-> public key consistency via TweetNaCl sign + open.
        const uint8_t probe[14] = {'m','d','f','p','-','k','e','y','-','c','h','e','c','k'};
        std::vector<uint8_t> signed_msg = signer->sign(probe, sizeof(probe));
        if (signed_msg.size() != 64U) {
            if (err_out) {
                *err_out = "Ed25519 self-check failed to produce 64-byte signature";
            }
            return nullptr;
        }
        uint8_t sm[64U + sizeof(probe)] = {};
        uint8_t opened[64U + sizeof(probe)] = {};
        std::memcpy(sm, signed_msg.data(), 64U);
        std::memcpy(sm + 64U, probe, sizeof(probe));
        unsigned long long mlen = 0;
        if (crypto_sign_open(opened, &mlen, sm, sizeof(sm), signer->pk_.data()) != 0 ||
            mlen != sizeof(probe)) {
            if (err_out) {
                *err_out = "Ed25519 key file mismatch: private seed does not correspond to public key";
            }
            return nullptr;
        }
        return signer;
    }

    // Load NaCl 64-byte raw secret key (seed||pub) OR 128-char lowercase/uppercase hex string.
    static std::unique_ptr<FileSigner> from_key_file(
        const std::string& path,
        std::string* err_out = nullptr) {
        if (!check_key_file_permissions(path, err_out)) {
            return nullptr;
        }

        std::ifstream ifs(path.c_str(), std::ios::binary);
        if (!ifs.is_open()) {
            if (err_out) {
                *err_out = "Unable to open key file '" + path + "'";
            }
            return nullptr;
        }
        std::vector<uint8_t> raw(
            (std::istreambuf_iterator<char>(ifs)),
            std::istreambuf_iterator<char>());

        uint8_t keypair[64] = {};
        if (raw.size() == 64U) {
            std::memcpy(keypair, raw.data(), 64U);
        } else {
            std::string trimmed;
            trimmed.reserve(raw.size());
            for (uint8_t b : raw) {
                if (!std::isspace(static_cast<unsigned char>(b))) {
                    trimmed.push_back(static_cast<char>(b));
                }
            }
            if (trimmed.size() != 128U) {
                if (err_out) {
                    *err_out = "Key file must contain 64 raw bytes or 128 hex chars (seed||pub)";
                }
                return nullptr;
            }
            for (size_t i = 0; i < 64U; ++i) {
                char hi = trimmed[i * 2U];
                char lo = trimmed[i * 2U + 1U];
                if (!std::isxdigit(static_cast<unsigned char>(hi)) ||
                    !std::isxdigit(static_cast<unsigned char>(lo))) {
                    if (err_out) {
                        *err_out = "Non-hexadecimal byte in key file '" + path + "'";
                    }
                    return nullptr;
                }
                unsigned int byte_val = 0;
                std::istringstream iss(trimmed.substr(i * 2U, 2U));
                iss >> std::hex >> byte_val;
                keypair[i] = static_cast<uint8_t>(byte_val & 0xFFU);
            }
        }

        auto res = from_seed_and_pub(keypair, keypair + 32U, err_out);
        volatile uint8_t* kp = keypair;
        for (size_t i = 0; i < sizeof(keypair); ++i) {
            kp[i] = 0U;
        }
        return res;
    }

    static bool write_hex_key_file_strict_0600(
        const std::string& path,
        const uint8_t seed[32],
        const uint8_t pub[32],
        std::string* err_out = nullptr) {
        std::string hex_line =
            bytes_to_lower_hex(seed, 32U) + bytes_to_lower_hex(pub, 32U) + "\n";
#ifdef _WIN32
        std::ofstream ofs(path.c_str(), std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) {
            if (err_out) {
                *err_out = "Cannot create key file '" + path + "'";
            }
            return false;
        }
        ofs.write(hex_line.data(), static_cast<std::streamsize>(hex_line.size()));
        ofs.close();
        return ofs.good();
#else
        int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            if (err_out) {
                *err_out = "Cannot create key file '" + path + "': " + std::strerror(errno);
            }
            return false;
        }
        if (::fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
            ::close(fd);
            if (err_out) {
                *err_out = "fchmod(0600) failed on '" + path + "'";
            }
            return false;
        }
        size_t written = 0;
        while (written < hex_line.size()) {
            ssize_t n = ::write(fd, hex_line.data() + written, hex_line.size() - written);
            if (n <= 0) {
                ::close(fd);
                if (err_out) {
                    *err_out = "Write failed on '" + path + "'";
                }
                return false;
            }
            written += static_cast<size_t>(n);
        }
        ::fsync(fd);
        ::close(fd);
        return true;
#endif
    }

    // Load signer from key_path, refusing insecure (group/world-accessible) files.
    // If explicit_path==false and the file does not exist yet on a clean bench boot,
    // provision the 0600 demo keypair once and then reload/verify via from_key_file().
    static std::unique_ptr<FileSigner> open_or_provision_demo_0600(
        const std::string& key_path,
        bool explicit_path,
        const uint8_t demo_seed[32],
        const uint8_t demo_pub[32],
        std::string* err_out = nullptr) {
#ifdef _WIN32
        struct _stat st {};
        bool exists = (::_stat(key_path.c_str(), &st) == 0);
#else
        struct stat st {};
        bool exists = (::lstat(key_path.c_str(), &st) == 0);
#endif
        if (!exists && !explicit_path && demo_seed && demo_pub) {
            if (!write_hex_key_file_strict_0600(key_path, demo_seed, demo_pub, err_out)) {
                return nullptr;
            }
        }
        return from_key_file(key_path, err_out);
    }

    std::vector<uint8_t> sign(const uint8_t* msg, size_t len) override {
        std::vector<uint8_t> signed_buf(len + 64U);
        unsigned long long smlen = 0;
        if (crypto_sign(
                signed_buf.data(),
                &smlen,
                msg,
                static_cast<unsigned long long>(len),
                sk_.data()) != 0) {
            throw std::runtime_error("TweetNaCl crypto_sign failed");
        }
        return std::vector<uint8_t>(signed_buf.begin(), signed_buf.begin() + 64);
    }

    std::array<uint8_t, 32> public_key() const override { return pk_; }

    std::string key_id() const override { return compute_key_id(pk_); }

    std::string backend_name() const override {
        return "FileSigner(software-TweetNaCl, NO-hardware-protection)";
    }

private:
    FileSigner() = default;
    std::array<uint8_t, 64> sk_{};
    std::array<uint8_t, 32> pk_{};
};

// Documented UNIMPLEMENTED stub for hardware-backed signing backends:
//   - PKCS#11 HSM / smartcard token (C_SignInit / C_Sign with CKM_EDDSA)
//   - TPM 2.0 (ESAPI Esys_Sign / persistent handle; note: swtpm is EMULATION ONLY)
//   - Automotive Secure Element (SHE / HSM / TEE TA)
// No hardware key protection exists in the current MD-Confirm RTOS build.
class HardwareTokenSignerStub final : public Signer {
public:
    explicit HardwareTokenSignerStub(
        std::string backend = "PKCS11",
        std::string handle_uri = "pkcs11:token=unconfigured")
        : backend_(std::move(backend)), handle_uri_(std::move(handle_uri)) {}

    static constexpr bool is_implemented() { return false; }

    std::vector<uint8_t> sign(const uint8_t* /*msg*/, size_t /*len*/) override {
        throw std::runtime_error(
            "HardwareTokenSignerStub (" + backend_ + " @ " + handle_uri_ +
            "): UNIMPLEMENTED - no PKCS#11 / TPM 2.0 / secure element backend is linked "
            "(if tested with swtpm, label strictly as emulation, not hardware key protection)");
    }

    std::array<uint8_t, 32> public_key() const override {
        throw std::runtime_error(
            "HardwareTokenSignerStub (" + backend_ + "): UNIMPLEMENTED");
    }

    std::string key_id() const override {
        throw std::runtime_error(
            "HardwareTokenSignerStub (" + backend_ + "): UNIMPLEMENTED");
    }

    std::string backend_name() const override {
        return "HardwareTokenSignerStub(" + backend_ + ":UNIMPLEMENTED)";
    }

private:
    std::string backend_;
    std::string handle_uri_;
};

}  // namespace mdfp
