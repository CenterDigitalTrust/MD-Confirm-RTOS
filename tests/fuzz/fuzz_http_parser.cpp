#include "../../qnx/common/mdfp_http.h"

#include <cassert>
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    mdfp::HttpRequest req = mdfp::parse_http_request(reinterpret_cast<const char*>(data), size);
    if (req.status == mdfp::HttpParseStatus::OK) {
        assert(req.method == "GET");
        assert(!req.raw_target.empty() && req.raw_target[0] == '/');
        assert(req.raw_target.size() <= mdfp::MDFP_HTTP_MAX_TARGET_BYTES);
        assert(req.version == "HTTP/1.1" || req.version == "HTTP/1.0");
    }
    return 0;
}
