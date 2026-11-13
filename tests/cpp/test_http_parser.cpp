#include "../../qnx/common/mdfp_http.h"

#include <cassert>
#include <cstring>
#include <iostream>
#include <string>

namespace {

using mdfp::HttpParseStatus;
using mdfp::HttpRequest;
using mdfp::HttpRoute;
using mdfp::has_complete_http_headers;
using mdfp::parse_http_request;

void test_valid_routes() {
    const char* r1 = "GET /api/stats HTTP/1.1\r\nHost: 127.0.0.1:9090\r\nUser-Agent: test\r\n\r\n";
    assert(has_complete_http_headers(r1, std::strlen(r1)));
    HttpRequest req = parse_http_request(r1, std::strlen(r1));
    assert(req.status == HttpParseStatus::OK);
    assert(req.route == HttpRoute::STATS);
    assert(req.path == "/api/stats");
    assert(req.query.empty());

    const char* r2 = "GET /status HTTP/1.0\r\nHost: localhost\r\n\r\n";
    req = parse_http_request(r2, std::strlen(r2));
    assert(req.status == HttpParseStatus::OK);
    assert(req.route == HttpRoute::STATS);
    assert(req.version == "HTTP/1.0");

    const char* r3 = "GET /api/journal?tail=100 HTTP/1.1\r\nHost: x\r\n\r\n";
    req = parse_http_request(r3, std::strlen(r3));
    assert(req.status == HttpParseStatus::OK);
    assert(req.route == HttpRoute::JOURNAL);
    assert(req.path == "/api/journal");
    assert(req.query == "tail=100");

    const char* r4 = "GET /journal HTTP/1.1\r\n\r\n";
    req = parse_http_request(r4, std::strlen(r4));
    assert(req.status == HttpParseStatus::OK);
    assert(req.route == HttpRoute::JOURNAL);

    const char* r5 = "GET /api/health HTTP/1.1\r\n\r\n";
    req = parse_http_request(r5, std::strlen(r5));
    assert(req.status == HttpParseStatus::OK);
    assert(req.route == HttpRoute::HEALTH);
}

void test_unknown_and_header_smuggling() {
    // Prefix ambiguity rejected
    const char* r1 = "GET /api/journalFOO HTTP/1.1\r\nHost: a\r\n\r\n";
    HttpRequest req = parse_http_request(r1, std::strlen(r1));
    assert(req.status == HttpParseStatus::OK);
    assert(req.route == HttpRoute::NONE);

    // Header substring containing "GET /api/stats" must NOT match STATS route
    const char* r2 = "GET /unknown HTTP/1.1\r\nX-Injected: GET /api/stats\r\n\r\n";
    req = parse_http_request(r2, std::strlen(r2));
    assert(req.status == HttpParseStatus::OK);
    assert(req.route == HttpRoute::NONE);
}

void test_methods_and_errors() {
    const char* post_req = "POST /api/stats HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n";
    assert(parse_http_request(post_req, std::strlen(post_req)).status == HttpParseStatus::METHOD_NOT_ALLOWED);

    const char* head_req = "HEAD /api/health HTTP/1.1\r\n\r\n";
    assert(parse_http_request(head_req, std::strlen(head_req)).status == HttpParseStatus::METHOD_NOT_ALLOWED);

    // Incomplete headers
    const char* partial = "GET /api/stats HTTP/1.1\r\nHost: a\r\n";
    assert(!has_complete_http_headers(partial, std::strlen(partial)));
    assert(parse_http_request(partial, std::strlen(partial)).status == HttpParseStatus::INCOMPLETE);

    // Path traversal / encoded dots / backslashes
    const char* trav1 = "GET /api/../stats HTTP/1.1\r\n\r\n";
    assert(parse_http_request(trav1, std::strlen(trav1)).status == HttpParseStatus::BAD_REQUEST);

    const char* trav2 = "GET /api/%2e%2e/journal HTTP/1.1\r\n\r\n";
    assert(parse_http_request(trav2, std::strlen(trav2)).status == HttpParseStatus::BAD_REQUEST);

    const char* bslash = "GET /api\\stats HTTP/1.1\r\n\r\n";
    assert(parse_http_request(bslash, std::strlen(bslash)).status == HttpParseStatus::BAD_REQUEST);

    // Embedded NUL byte
    const char nul_req[] = "GET /api/stats\0HTTP/1.1\r\n\r\n";
    assert(parse_http_request(nul_req, sizeof(nul_req) - 1).status == HttpParseStatus::BAD_REQUEST);

    // Bad version / extra spaces
    const char* bad_ver = "GET /api/stats HTTP/2.0\r\n\r\n";
    assert(parse_http_request(bad_ver, std::strlen(bad_ver)).status == HttpParseStatus::BAD_REQUEST);

    const char* extra_sp = "GET  /api/stats HTTP/1.1\r\n\r\n";
    assert(parse_http_request(extra_sp, std::strlen(extra_sp)).status == HttpParseStatus::BAD_REQUEST);

    // Oversized URI (> 1024)
    std::string long_uri = "GET /" + std::string(1100, 'a') + " HTTP/1.1\r\n\r\n";
    assert(parse_http_request(long_uri.data(), long_uri.size()).status == HttpParseStatus::URI_TOO_LONG);

    // Oversized request (> 4096)
    std::string too_big(5000, 'A');
    assert(parse_http_request(too_big.data(), too_big.size()).status == HttpParseStatus::BAD_REQUEST);
}

} // namespace

int main() {
    test_valid_routes();
    test_unknown_and_header_smuggling();
    test_methods_and_errors();
    std::cout << "[PASS] HTTP request parser unit tests\n";
    return 0;
}
