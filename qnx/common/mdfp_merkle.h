// mdfp_merkle.h
// Strict RFC 6962 Section 2.1 Merkle Tree Hash for QNX & host unit tests.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "mdfp_crypto.h"

namespace mdfp {
namespace merkle {

inline size_t largest_power_of_two_less_than(size_t n) {
    size_t k = 1;
    while ((k << 1) < n) {
        k <<= 1;
    }
    return k;
}

inline std::string empty_root_hex() {
    return MdfpSha256::hash_hex(nullptr, 0);
}

inline std::string merkle_tree_hash_range(
    const std::vector<std::string>& leaf_hashes_hex,
    size_t start,
    size_t end) {
    if (end <= start) {
        return empty_root_hex();
    }
    size_t count = end - start;
    if (count == 1) {
        return leaf_hashes_hex[start];
    }
    size_t k = largest_power_of_two_less_than(count);
    return MdfpSha256::node_hash(
        merkle_tree_hash_range(leaf_hashes_hex, start, start + k),
        merkle_tree_hash_range(leaf_hashes_hex, start + k, end));
}

inline std::string merkle_tree_hash(const std::vector<std::string>& leaf_hashes_hex) {
    return merkle_tree_hash_range(leaf_hashes_hex, 0, leaf_hashes_hex.size());
}

}  // namespace merkle
}  // namespace mdfp
