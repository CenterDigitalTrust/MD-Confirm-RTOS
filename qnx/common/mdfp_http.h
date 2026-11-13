// mdfp_http.h
// Standalone HTTP/1.x GET Request-Line & Header Parser for md-telemetry
// Zero OS/socket dependencies so it compiles and fuzzes directly on host Linux/macOS/Windows.

#pragma once

#include <cctype>
#include <cstddef>
#include <cstring>
#include <string>

namespace mdfp {

constexpr size_t MDFP_HTTP_MAX_REQUEST_BYTES = 4096;
constexpr size_t MDFP_HTTP_MAX_TARGET_BYTES = 1024;
constexpr size_t MDFP_HTTP_MAX_HEADERS = 64;

enum class HttpRoute {
    NONE = 0,
    JOURNAL, // /api/journal or /journal
    HEALTH,  // /api/health
    STATS    // /api/stats or /status
};

enum class HttpParseStatus {
    INCOMPLETE = 0,
    OK,
    METHOD_NOT_ALLOWED,
    BAD_REQUEST,
    URI_TOO_LONG
};

struct HttpRequest {
    HttpParseStatus status = HttpParseStatus::BAD_REQUEST;
    HttpRoute route = HttpRoute::NONE;
    std::string method;
    std::string raw_target;
    std::string path;
    std::string query;
    std::string version;
};

namespace detail {

inline bool is_http_tchar(unsigned char c) {
    if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
        return true;
    }
    switch (c) {
        case '!': case '#': case '$': case '%': case '&': case '\'': case '*':
        case '+': case '-': case '.': case '^': case '_': case '`': case '|':
        case '~':
            return true;
        default:
            return false;
    }
}

inline bool is_valid_method(const std::string& m) {
    if (m.empty() || m.size() > 16) return false;
    for (unsigned char c : m) {
        if (!is_http_tchar(c)) return false;
    }
    return true;
}

inline bool is_valid_header_line(const char* line, size_t len) {
    size_t colon = 0;
    while (colon < len && line[colon] != ':') {
        ++colon;
    }
    if (colon == 0 || colon >= len) return false;
    for (size_t i = 0; i < colon; ++i) {
        if (!is_http_tchar(static_cast<unsigned char>(line[i]))) return false;
    }
    for (size_t i = colon + 1; i < len; ++i) {
        unsigned char c = static_cast<unsigned char>(line[i]);
        if (c == 0x7F || (c < 0x20 && c != '\t')) return false;
    }
    return true;
}

inline bool find_header_end(const char* data, size_t len, size_t* header_end_offset, size_t* sep_len) {
    for (size_t i = 0; i < len; ++i) {
        if (i + 3 < len &&
            data[i] == '\r' && data[i + 1] == '\n' &&
            data[i + 2] == '\r' && data[i + 3] == '\n') {
            *header_end_offset = i + 4;
            *sep_len = 4;
            return true;
        }
        if (i + 1 < len && data[i] == '\n' && data[i + 1] == '\n') {
            *header_end_offset = i + 2;
            *sep_len = 2;
            return true;
        }
    }
    return false;
}

inline bool has_traversal_or_bad_target_chars(const std::string& target) {
    if (target.empty() || target[0] != '/') return true;
    for (size_t i = 0; i < target.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(target[i]);
        if (c <= 0x20 || c >= 0x7F || c == '\\') {
            return true;
        }
    }
    // Extract path component before '?' for dot-segment checking
    size_t qpos = target.find('?');
    size_t path_len = (qpos == std::string::npos) ? target.size() : qpos;
    // Scan slash-delimited segments
    size_t pos = 0;
    while (pos < path_len) {
        while (pos < path_len && target[pos] == '/') ++pos;
        if (pos >= path_len) break;
        size_t end = pos;
        while (end < path_len && target[end] != '/') ++end;
        size_t seg_len = end - pos;
        if ((seg_len == 1 && target[pos] == '.') ||
            (seg_len == 2 && target[pos] == '.' && target[pos + 1] == '.')) {
            return true;
        }
        pos = end;
    }
    // Also reject percent-encoded path traversal (%2e%2e / %2E%2E)
    for (size_t i = 0; i + 2 < path_len; ++i) {
        if (target[i] == '%' && target[i + 1] == '2' &&
            (target[i + 2] == 'e' || target[i + 2] == 'E')) {
            return true;
        }
    }
    return false;
}

} // namespace detail

// Used by socket receive loop to determine whether full HTTP headers have arrived or buffer limit is hit.
inline bool has_complete_http_headers(const char* data, size_t len, size_t max_bytes = MDFP_HTTP_MAX_REQUEST_BYTES) {
    if (!data || len == 0) return false;
    if (len >= max_bytes) return true;
    if (std::memchr(data, '\0', len) != nullptr) return true;
    size_t end_off = 0;
    size_t sep_len = 0;
    return detail::find_header_end(data, len, &end_off, &sep_len);
}

inline HttpRequest parse_http_request(const char* data,
                                      size_t len,
                                      size_t max_bytes = MDFP_HTTP_MAX_REQUEST_BYTES) {
    HttpRequest out;
    if (!data || len == 0) {
        out.status = HttpParseStatus::INCOMPLETE;
        return out;
    }
    if (len > max_bytes) {
        out.status = HttpParseStatus::BAD_REQUEST;
        return out;
    }
    if (std::memchr(data, '\0', len) != nullptr) {
        out.status = HttpParseStatus::BAD_REQUEST;
        return out;
    }

    size_t header_end = 0;
    size_t sep_len = 0;
    if (!detail::find_header_end(data, len, &header_end, &sep_len)) {
        out.status = (len >= max_bytes) ? HttpParseStatus::BAD_REQUEST : HttpParseStatus::INCOMPLETE;
        return out;
    }

    // Find end of request line
    size_t line_end = 0;
    while (line_end < header_end && data[line_end] != '\n') {
        ++line_end;
    }
    if (line_end == header_end) {
        out.status = HttpParseStatus::BAD_REQUEST;
        return out;
    }

    size_t raw_line_len = line_end;
    if (raw_line_len > 0 && data[raw_line_len - 1] == '\r') {
        --raw_line_len;
    }
    // Reject stray '\r' inside request line
    if (std::memchr(data, '\r', raw_line_len) != nullptr) {
        out.status = HttpParseStatus::BAD_REQUEST;
        return out;
    }

    // Parse exact "METHOD SP REQUEST-TARGET SP HTTP/x.y"
    size_t sp1 = 0;
    while (sp1 < raw_line_len && data[sp1] != ' ') ++sp1;
    if (sp1 == 0 || sp1 >= raw_line_len) {
        out.status = HttpParseStatus::BAD_REQUEST;
        return out;
    }

    size_t sp2 = sp1 + 1;
    while (sp2 < raw_line_len && data[sp2] != ' ') ++sp2;
    if (sp2 <= sp1 + 1 || sp2 >= raw_line_len) {
        out.status = HttpParseStatus::BAD_REQUEST;
        return out;
    }

    // Reject additional spaces after version
    for (size_t i = sp2 + 1; i < raw_line_len; ++i) {
        if (data[i] == ' ') {
            out.status = HttpParseStatus::BAD_REQUEST;
            return out;
        }
    }

    out.method.assign(data, sp1);
    if (!detail::is_valid_method(out.method)) {
        out.status = HttpParseStatus::BAD_REQUEST;
        return out;
    }

    size_t target_len = sp2 - (sp1 + 1);
    if (target_len > MDFP_HTTP_MAX_TARGET_BYTES) {
        out.status = HttpParseStatus::URI_TOO_LONG;
        return out;
    }
    out.raw_target.assign(data + sp1 + 1, target_len);

    out.version.assign(data + sp2 + 1, raw_line_len - (sp2 + 1));
    if (out.version != "HTTP/1.1" && out.version != "HTTP/1.0") {
        out.status = HttpParseStatus::BAD_REQUEST;
        return out;
    }

    if (detail::has_traversal_or_bad_target_chars(out.raw_target)) {
        out.status = HttpParseStatus::BAD_REQUEST;
        return out;
    }

    // Validate header lines strictly inside [line_end + 1 .. header_end - sep_len]
    size_t headers_stop = header_end - sep_len;
    size_t cursor = line_end + 1;
    size_t header_count = 0;
    while (cursor <= headers_stop) {
        size_t next_nl = cursor;
        while (next_nl < header_end && data[next_nl] != '\n') ++next_nl;
        size_t hlen = next_nl - cursor;
        if (hlen > 0 && data[cursor + hlen - 1] == '\r') {
            --hlen;
        }
        if (hlen == 0) break;
        if (std::memchr(data + cursor, '\r', hlen) != nullptr) {
            out.status = HttpParseStatus::BAD_REQUEST;
            return out;
        }
        if (++header_count > MDFP_HTTP_MAX_HEADERS || !detail::is_valid_header_line(data + cursor, hlen)) {
            out.status = HttpParseStatus::BAD_REQUEST;
            return out;
        }
        cursor = next_nl + 1;
    }

    if (out.method != "GET") {
        out.status = HttpParseStatus::METHOD_NOT_ALLOWED;
        return out;
    }

    size_t qpos = out.raw_target.find('?');
    if (qpos == std::string::npos) {
        out.path = out.raw_target;
    } else {
        out.path = out.raw_target.substr(0, qpos);
        out.query = out.raw_target.substr(qpos + 1);
    }

    if (out.path == "/api/journal" || out.path == "/journal") {
        out.route = HttpRoute::JOURNAL;
    } else if (out.path == "/api/health") {
        out.route = HttpRoute::HEALTH;
    } else if (out.path == "/api/stats" || out.path == "/status") {
        out.route = HttpRoute::STATS;
    } else {
        out.route = HttpRoute::NONE;
    }

    out.status = HttpParseStatus::OK;
    return out;
}

} // namespace mdfp
