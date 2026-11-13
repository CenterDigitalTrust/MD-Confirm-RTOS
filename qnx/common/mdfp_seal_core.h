// mdfp_seal_core.h
// Host-testable RFC 6962 / RFC 8785 journal sealing, STH emission, and anchor outbox logic.
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include "mdfp_canon.h"
#include "mdfp_crypto.h"
#include "mdfp_merkle.h"

namespace mdfp {

struct SealInput {
    uint64_t hw_eof_ns = 0;
    bool is_ghost_event = false;
    uint32_t frame_seq = 0;
    double ncc = 0.0;
    double pce_db = 0.0;
    double pce_linear = 0.0;
    std::string raw_sha256;
    uint32_t scenario = 0;
    std::string verdict;
};

struct SthRecord {
    uint64_t version = 1;
    std::string device_id;
    uint64_t tree_size = 0;
    std::string root_hash;
    uint64_t timestamp = 0;
    std::string prev_sth_sha256;
    std::string key_id;
};

struct SealConfig {
    std::string journal_path;
    std::string sth_path;
    std::string outbox_path;
    std::string device_id = "qnx-8.0-adas-node-01";
    std::string key_id = "7ea81ac6c1fc3a9a";
    uint32_t sth_interval = 32;
};

struct SealOutput {
    uint32_t leaf_index = 0;
    std::string canonical_json;
    std::string leaf_hash;
    std::string merkle_root;
    std::string record_sig;
    std::string journal_line;
    bool emitted_sth = false;
    std::string sth_canonical_json;
    std::string sth_sha256;
    std::string sth_sig;
    std::string sth_line;
    std::string outbox_line;
    bool io_ok = true;
};

inline std::string sha256_utf8_hex(const std::string& text) {
    return MdfpSha256::hash_hex(
        reinterpret_cast<const uint8_t*>(text.data()), text.size());
}

inline std::string build_sth_canonical_json(const SthRecord& sth) {
    return mdfp::jcs::canonicalize(mdfp::jcs::JsonValue::make_object({
        {"version", mdfp::jcs::JsonValue::make_uint(sth.version)},
        {"device_id", mdfp::jcs::JsonValue::make_string(sth.device_id)},
        {"tree_size", mdfp::jcs::JsonValue::make_uint(sth.tree_size)},
        {"root_hash", mdfp::jcs::JsonValue::make_string(sth.root_hash)},
        {"timestamp", mdfp::jcs::JsonValue::make_uint(sth.timestamp)},
        {"prev_sth_sha256", mdfp::jcs::JsonValue::make_string(sth.prev_sth_sha256)},
        {"key_id", mdfp::jcs::JsonValue::make_string(sth.key_id)},
    }));
}

inline std::string build_outbox_json(
    const std::string& event_kind,
    const SthRecord& sth,
    const std::string& sth_sha256) {
    return mdfp::jcs::canonicalize(mdfp::jcs::JsonValue::make_object({
        {"event", mdfp::jcs::JsonValue::make_string(event_kind)},
        {"device_id", mdfp::jcs::JsonValue::make_string(sth.device_id)},
        {"tree_size", mdfp::jcs::JsonValue::make_uint(sth.tree_size)},
        {"root_hash", mdfp::jcs::JsonValue::make_string(sth.root_hash)},
        {"sth_sha256", mdfp::jcs::JsonValue::make_string(sth_sha256)},
        {"timestamp", mdfp::jcs::JsonValue::make_uint(sth.timestamp)},
    }));
}

inline std::string key_id_from_pubkey_bytes(const uint8_t pub[32]) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 8; ++i) {
        oss << std::setw(2) << static_cast<unsigned int>(pub[i]);
    }
    return oss.str();
}

namespace detail {

inline bool append_line_durable(const std::string& path, const std::string& line) {
    if (path.empty()) {
        return true;
    }
    std::FILE* fp = std::fopen(path.c_str(), "ab");
    if (!fp) {
        return false;
    }
    std::string payload = line + "\n";
    size_t written = std::fwrite(payload.data(), 1, payload.size(), fp);
    bool ok = (written == payload.size());
    if (std::fflush(fp) != 0) {
        ok = false;
    }
#ifdef _WIN32
    if (::_commit(::_fileno(fp)) != 0) {
        ok = false;
    }
#else
    if (::fsync(::fileno(fp)) != 0) {
        // Non-regular files (e.g. pipes in tests) may fail fsync with EINVAL; ignore only if flushed.
    }
#endif
    if (std::fclose(fp) != 0) {
        ok = false;
    }
    return ok;
}

inline bool extract_sth_object_from_ndjson_line(const std::string& line, std::string& out_obj) {
    const std::string marker = "\"sth\":";
    size_t pos = line.find(marker);
    if (pos == std::string::npos) {
        return false;
    }
    size_t i = pos + marker.size();
    while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) {
        ++i;
    }
    if (i >= line.size() || line[i] != '{') {
        return false;
    }
    size_t start = i;
    int depth = 0;
    bool in_str = false;
    bool escape = false;
    for (; i < line.size(); ++i) {
        char c = line[i];
        if (escape) {
            escape = false;
            continue;
        }
        if (in_str) {
            if (c == '\\') {
                escape = true;
            } else if (c == '"') {
                in_str = false;
            }
            continue;
        }
        if (c == '"') {
            in_str = true;
        } else if (c == '{') {
            ++depth;
        } else if (c == '}') {
            --depth;
            if (depth == 0) {
                out_obj = line.substr(start, i - start + 1);
                return true;
            }
        }
    }
    return false;
}

}  // namespace detail

class SealEngine {
public:
    using SignCallback = std::function<std::string(const std::string&)>;

    SealEngine(const SealConfig& config, SignCallback sign_fn)
        : config_(config), sign_fn_(std::move(sign_fn)) {
        if (config_.sth_interval == 0) {
            config_.sth_interval = 32;
        }
        last_sth_sha256_ = std::string(64, '0');
        current_root_ = mdfp::merkle::empty_root_hex();
        recover_existing_state();
    }

    uint32_t leaf_count() const { return static_cast<uint32_t>(leaf_hashes_.size()); }
    const std::string& current_root() const { return current_root_; }
    const std::string& last_sth_sha256() const { return last_sth_sha256_; }

    SealOutput seal_record(const SealInput& in) {
        SealOutput out;
        uint32_t idx = static_cast<uint32_t>(leaf_hashes_.size()) + 1U;
        out.leaf_index = idx;

        out.canonical_json = mdfp::build_seal_record_json(
            in.hw_eof_ns,
            config_.device_id,
            in.is_ghost_event,
            in.frame_seq,
            in.ncc,
            in.pce_db,
            in.pce_linear,
            in.raw_sha256,
            in.scenario,
            in.verdict);

        out.leaf_hash = MdfpSha256::leaf_hash(out.canonical_json);
        leaf_hashes_.push_back(out.leaf_hash);

        current_root_ = mdfp::merkle::merkle_tree_hash(leaf_hashes_);
        out.merkle_root = current_root_;

        out.record_sig = sign_fn_("MDFP1\n" + out.merkle_root);

        std::ostringstream line_oss;
        line_oss << "RECORD #" << out.leaf_index
                 << " | SEQ: " << in.frame_seq
                 << " | TYPE: " << (in.is_ghost_event ? "GHOST_EVENT" : "AUTHENTIC")
                 << " | LEAF: " << out.leaf_hash
                 << " | MERKLE_ROOT: " << out.merkle_root
                 << " | SIG: " << out.record_sig
                 << " | RAW_SHA256: " << in.raw_sha256
                 << " | VERDICT: " << in.verdict
                 << " | CANON: " << out.canonical_json;
        out.journal_line = line_oss.str();

        bool ok = detail::append_line_durable(config_.journal_path, out.journal_line);

        bool should_emit_sth = in.is_ghost_event || ((out.leaf_index % config_.sth_interval) == 0);
        if (should_emit_sth) {
            out.emitted_sth = true;
            SthRecord sth;
            sth.version = 1;
            sth.device_id = config_.device_id;
            sth.tree_size = out.leaf_index;
            sth.root_hash = out.merkle_root;
            sth.timestamp = in.hw_eof_ns;
            sth.prev_sth_sha256 = last_sth_sha256_;
            sth.key_id = config_.key_id;

            out.sth_canonical_json = build_sth_canonical_json(sth);
            out.sth_sha256 = sha256_utf8_hex(out.sth_canonical_json);
            out.sth_sig = sign_fn_("MDFP1-STH\n" + out.sth_canonical_json);

            out.sth_line = std::string("{\"sth\":") + out.sth_canonical_json +
                           ",\"sig\":\"" + out.sth_sig + "\"}";
            if (!detail::append_line_durable(config_.sth_path, out.sth_line)) {
                ok = false;
            }

            std::string event_kind = in.is_ghost_event ? "GHOST_EVENT" : "PERIODIC_STH";
            out.outbox_line = build_outbox_json(event_kind, sth, out.sth_sha256);
            if (!detail::append_line_durable(config_.outbox_path, out.outbox_line)) {
                ok = false;
            }

            last_sth_sha256_ = out.sth_sha256;
        }

        out.io_ok = ok;
        return out;
    }

private:
    void recover_existing_state() {
        if (!config_.journal_path.empty()) {
            std::ifstream jfs(config_.journal_path.c_str());
            std::string line;
            while (std::getline(jfs, line)) {
                size_t pos = line.find("| LEAF: ");
                if (pos == std::string::npos) {
                    continue;
                }
                size_t hstart = pos + 8;
                if (hstart + 64 <= line.size()) {
                    leaf_hashes_.push_back(line.substr(hstart, 64));
                }
            }
            if (!leaf_hashes_.empty()) {
                current_root_ = mdfp::merkle::merkle_tree_hash(leaf_hashes_);
            }
        }
        if (!config_.sth_path.empty()) {
            std::ifstream sfs(config_.sth_path.c_str());
            std::string line;
            std::string last_obj;
            while (std::getline(sfs, line)) {
                std::string obj;
                if (detail::extract_sth_object_from_ndjson_line(line, obj)) {
                    last_obj = obj;
                }
            }
            if (!last_obj.empty()) {
                last_sth_sha256_ = sha256_utf8_hex(last_obj);
            }
        }
    }

    SealConfig config_;
    SignCallback sign_fn_;
    std::vector<std::string> leaf_hashes_;
    std::string current_root_;
    std::string last_sth_sha256_;
};

}  // namespace mdfp
