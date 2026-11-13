#include "../../qnx/common/mdfp_canon.h"

#include <cassert>
#include <cmath>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

namespace {

using mdfp::jcs::JsonValue;

void test_string_escaping_kat() {
    // RFC 8785 §3.2.2.2: mandatory escapes, lowercase \u00xx for controls, '/' unescaped
    assert(mdfp::jcs::encode_string("hello/world") == "\"hello/world\"");
    assert(mdfp::jcs::encode_string("a\"b\\c") == "\"a\\\"b\\\\c\"");
    assert(mdfp::jcs::encode_string("\b\f\n\r\t") == "\"\\b\\f\\n\\r\\t\"");

    std::string with_ctrl("x", 1);
    with_ctrl.push_back('\0');
    with_ctrl.push_back('\x0b');
    with_ctrl.push_back('\x1f');
    with_ctrl.append("y");
    assert(mdfp::jcs::encode_string(with_ctrl) == "\"x\\u0000\\u000b\\u001fy\"");

    // Non-ASCII UTF-8 preserved literally without unnecessary \u escaping
    assert(mdfp::jcs::encode_string("\xE2\x82\xAC\xF0\x9F\x98\x80") == "\"\xE2\x82\xAC\xF0\x9F\x98\x80\"");
}

void test_key_sorting_kat() {
    // RFC 8785 Section 3.2.3 official UTF-16 code unit ordering test:
    // Order: "\r" (0x000D) < "1" (0x0031) < "a" (0x0061) < U+0080 (0x0080)
    //      < U+20AC "€" (0x20AC) < U+1F600 "😀" (0xD83D 0xDE00) < U+FB33 "דּ" (0xFB33)
    JsonValue obj = JsonValue::make_object({
        {"\xEF\xAC\xB3", JsonValue::make_string("fb33")},          // U+FB33 (UTF-16 0xFB33 > 0xD83D)
        {"\xF0\x9F\x98\x80", JsonValue::make_string("emoji")},     // U+1F600 (UTF-16 0xD83D 0xDE00)
        {"\xE2\x82\xAC", JsonValue::make_string("euro")},          // U+20AC
        {"a", JsonValue::make_int(1)},
        {"\xC2\x80", JsonValue::make_string("ctrl80")},            // U+0080
        {"1", JsonValue::make_int(2)},
        {"\r", JsonValue::make_string("cr")},
    });

    std::string expected =
        "{\"\\r\":\"cr\","
        "\"1\":2,"
        "\"a\":1,"
        "\"\xC2\x80\":\"ctrl80\","
        "\"\xE2\x82\xAC\":\"euro\","
        "\"\xF0\x9F\x98\x80\":\"emoji\","
        "\"\xEF\xAC\xB3\":\"fb33\"}";
    assert(mdfp::jcs::canonicalize(obj) == expected);

    // Nested object/array canonicalization
    JsonValue nested = JsonValue::make_object({
        {"z", JsonValue::make_array({
            JsonValue::make_object({{"b", JsonValue::make_null()}, {"a", JsonValue::make_bool(false)}}),
            JsonValue::make_bool(true),
        })},
        {"a", JsonValue::make_int(-42)},
    });
    assert(mdfp::jcs::canonicalize(nested) == "{\"a\":-42,\"z\":[{\"a\":false,\"b\":null},true]}");
}

void test_number_formatting_kat() {
    // RFC 8785 §3.2.2.3 & Appendix B / ES6 Number.prototype.toString vectors
    assert(mdfp::jcs::format_number(0.0) == "0");
    assert(mdfp::jcs::format_number(-0.0) == "0");
    assert(mdfp::jcs::format_number(4.50) == "4.5");
    assert(mdfp::jcs::format_number(333333333.33333329) == "333333333.3333333");
    assert(mdfp::jcs::format_number(1e30) == "1e+30");
    assert(mdfp::jcs::format_number(1e20) == "100000000000000000000");
    assert(mdfp::jcs::format_number(1e21) == "1e+21");
    assert(mdfp::jcs::format_number(1e-6) == "0.000001");
    assert(mdfp::jcs::format_number(1e-7) == "1e-7");
    assert(mdfp::jcs::format_number(-1e-5) == "-0.00001");
    assert(mdfp::jcs::format_number(1e-3) == "0.001");

    // Non-finite numbers must throw
    bool threw_nan = false;
    try {
        (void)mdfp::jcs::format_number(std::numeric_limits<double>::quiet_NaN());
    } catch (const std::invalid_argument&) {
        threw_nan = true;
    }
    assert(threw_nan);

    bool threw_inf = false;
    try {
        (void)mdfp::jcs::format_number(std::numeric_limits<double>::infinity());
    } catch (const std::invalid_argument&) {
        threw_inf = true;
    }
    assert(threw_inf);
}

void test_seal_record_serializer() {
    std::string json = mdfp::build_seal_record_json(
        1700000000000ULL,
        "qnx-8.0-adas-node-01",
        false,
        42U,
        0.75,
        18.25,
        66.5,
        "abcd",
        1U,
        "OK\"WITH\\QUOTE\nAND\tTAB");

    std::string expected =
        "{\"client_time_ns\":1700000000000,"
        "\"device_id\":\"qnx-8.0-adas-node-01\","
        "\"event_type\":\"AUTHENTIC_FRAME\","
        "\"frame_seq\":42,"
        "\"ncc\":0.75,"
        "\"pce_db\":18.25,"
        "\"pce_linear\":66.5,"
        "\"raw_sha256\":\"abcd\","
        "\"scenario\":1,"
        "\"verdict\":\"OK\\\"WITH\\\\QUOTE\\nAND\\tTAB\"}";
    assert(json == expected);

    // Full Task 5 Trust-Boundary leaf schema including ClockCycles, sensor_id,
    // K_REF id/version, thresholds, frame_sha256, and seq.
    std::string full_json = mdfp::build_seal_record_json(
        1700000000000ULL,
        987654321ULL,
        "qnx-8.0-adas-node-01",
        false,
        42U,
        "sim-bayer-64x64-01",
        "kref-sim-0x20261111",
        "sim-1d-v1",
        0.75,
        60.0,
        0.8125,
        18.25,
        66.5,
        "abcd",
        1U,
        "VERIFIED_AUTHENTIC_SILICON");
    std::string expected_full =
        "{\"client_time_ns\":1700000000000,"
        "\"clock_cycles\":987654321,"
        "\"device_id\":\"qnx-8.0-adas-node-01\","
        "\"event_type\":\"AUTHENTIC_FRAME\","
        "\"frame_seq\":42,"
        "\"frame_sha256\":\"abcd\","
        "\"k_ref_id\":\"kref-sim-0x20261111\","
        "\"k_ref_version\":\"sim-1d-v1\","
        "\"ncc\":0.8125,"
        "\"ncc_threshold\":0.75,"
        "\"pce_db\":18.25,"
        "\"pce_linear\":66.5,"
        "\"pce_threshold_linear\":60,"
        "\"raw_sha256\":\"abcd\","
        "\"scenario\":1,"
        "\"sensor_id\":\"sim-bayer-64x64-01\","
        "\"seq\":42,"
        "\"verdict\":\"VERIFIED_AUTHENTIC_SILICON\"}";
    assert(full_json == expected_full);
}

} // namespace

int main() {
    test_string_escaping_kat();
    test_key_sorting_kat();
    test_number_formatting_kat();
    test_seal_record_serializer();
    std::cout << "[PASS] RFC 8785 JCS canonicalization KATs\n";
    return 0;
}
