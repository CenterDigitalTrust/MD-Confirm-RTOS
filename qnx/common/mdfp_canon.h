// mdfp_canon.h
// Self-contained RFC 8785 JSON Canonicalization Scheme (JCS) & Seal Record Serializer
// Zero external dependencies; host-compilable (Linux/macOS/Windows) and QNX 8.0 compatible.

#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace mdfp {
namespace jcs {

// Escape a UTF-8 string according to RFC 8785 §3.2.2.2 / RFC 8259 §7.
// Note: lowercase hex is mandated for \u00xx control escapes; '/' is not escaped.
inline std::string encode_string(const std::string& input) {
    static const char hex_digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(input.size() + 4);
    out.push_back('"');

    for (unsigned char c : input) {
        switch (c) {
            case '"':  out.append("\\\""); break;
            case '\\': out.append("\\\\"); break;
            case '\b': out.append("\\b");  break;
            case '\f': out.append("\\f");  break;
            case '\n': out.append("\\n");  break;
            case '\r': out.append("\\r");  break;
            case '\t': out.append("\\t");  break;
            default:
                if (c < 0x20) {
                    out.append("\\u00");
                    out.push_back(hex_digits[(c >> 4) & 0x0F]);
                    out.push_back(hex_digits[c & 0x0F]);
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }

    out.push_back('"');
    return out;
}

// Convert UTF-8 bytes into UTF-16 code units for RFC 8785 §3.2.3 property sorting.
inline std::vector<uint16_t> utf8_to_utf16_units(const std::string& s) {
    std::vector<uint16_t> units;
    units.reserve(s.size());

    size_t i = 0;
    const size_t n = s.size();
    while (i < n) {
        uint8_t b0 = static_cast<uint8_t>(s[i]);
        uint32_t cp = 0;
        if (b0 < 0x80) {
            cp = b0;
            i += 1;
        } else if ((b0 & 0xE0) == 0xC0 && i + 1 < n) {
            uint8_t b1 = static_cast<uint8_t>(s[i + 1]);
            if ((b1 & 0xC0) != 0x80) throw std::invalid_argument("Invalid UTF-8 sequence");
            cp = ((b0 & 0x1FU) << 6) | (b1 & 0x3FU);
            if (cp < 0x80) throw std::invalid_argument("Overlong UTF-8 sequence");
            i += 2;
        } else if ((b0 & 0xF0) == 0xE0 && i + 2 < n) {
            uint8_t b1 = static_cast<uint8_t>(s[i + 1]);
            uint8_t b2 = static_cast<uint8_t>(s[i + 2]);
            if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80) throw std::invalid_argument("Invalid UTF-8 sequence");
            cp = ((b0 & 0x0FU) << 12) | ((b1 & 0x3FU) << 6) | (b2 & 0x3FU);
            if (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)) throw std::invalid_argument("Invalid UTF-8 codepoint");
            i += 3;
        } else if ((b0 & 0xF8) == 0xF0 && i + 3 < n) {
            uint8_t b1 = static_cast<uint8_t>(s[i + 1]);
            uint8_t b2 = static_cast<uint8_t>(s[i + 2]);
            uint8_t b3 = static_cast<uint8_t>(s[i + 3]);
            if ((b1 & 0xC0) != 0x80 || (b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80) {
                throw std::invalid_argument("Invalid UTF-8 sequence");
            }
            cp = ((b0 & 0x07U) << 18) | ((b1 & 0x3FU) << 12) | ((b2 & 0x3FU) << 6) | (b3 & 0x3FU);
            if (cp < 0x10000 || cp > 0x10FFFF) throw std::invalid_argument("Invalid UTF-8 codepoint");
            i += 4;
        } else {
            throw std::invalid_argument("Truncated or invalid UTF-8 sequence");
        }

        if (cp <= 0xFFFF) {
            units.push_back(static_cast<uint16_t>(cp));
        } else {
            uint32_t v = cp - 0x10000;
            units.push_back(static_cast<uint16_t>(0xD800 + (v >> 10)));
            units.push_back(static_cast<uint16_t>(0xDC00 + (v & 0x3FF)));
        }
    }
    return units;
}

inline bool key_less(const std::string& a, const std::string& b) {
    return utf8_to_utf16_units(a) < utf8_to_utf16_units(b);
}

// Serialize finite IEEE-754 double according to RFC 8785 §3.2.2.3 / ECMAScript Number::toString.
inline std::string format_number(double v) {
    if (!std::isfinite(v)) {
        throw std::invalid_argument("Non-finite floating point number in JCS");
    }
    if (v == 0.0) {
        return "0"; // Collapses both +0.0 and -0.0
    }

    const bool negative = v < 0.0;
    const double abs_v = std::fabs(v);

    // Find shortest decimal scientific form "%.*e" that round-trips identically through IEEE-754 strtod.
    char sci_buf[64] = {};
    bool roundtrip_ok = false;
    for (int prec = 0; prec <= 16; ++prec) {
        std::snprintf(sci_buf, sizeof(sci_buf), "%.*e", prec, abs_v);
        char* endp = nullptr;
        double reparsed = std::strtod(sci_buf, &endp);
        if (reparsed == abs_v) {
            roundtrip_ok = true;
            break;
        }
    }
    if (!roundtrip_ok) {
        std::snprintf(sci_buf, sizeof(sci_buf), "%.16e", abs_v);
    }

    // Extract digits string 's' and exponent 'exp10' from sci_buf ("d[.digits]e[+-]dd")
    std::string digits;
    digits.reserve(20);
    const char* p = sci_buf;
    while (*p && *p != 'e' && *p != 'E') {
        if (*p >= '0' && *p <= '9') {
            digits.push_back(*p);
        }
        ++p;
    }
    long exp10 = 0;
    if (*p == 'e' || *p == 'E') {
        exp10 = std::strtol(p + 1, nullptr, 10);
    }

    // Strip trailing zeros from digits
    while (digits.size() > 1 && digits.back() == '0') {
        digits.pop_back();
    }

    // Following ECMA-262 §7.1.12.1 Number.prototype.toString:
    // n such that abs_v = 0.<digits> * 10^n  =>  n = exp10 + 1
    long n = exp10 + 1;
    long k = static_cast<long>(digits.size());

    std::string body;
    if (k <= n && n <= 21) {
        body = digits;
        body.append(static_cast<size_t>(n - k), '0');
    } else if (0 < n && n <= 21) {
        body = digits.substr(0, static_cast<size_t>(n));
        body.push_back('.');
        body.append(digits.substr(static_cast<size_t>(n)));
    } else if (-6 < n && n <= 0) {
        body = "0.";
        body.append(static_cast<size_t>(-n), '0');
        body.append(digits);
    } else {
        body.push_back(digits[0]);
        if (k > 1) {
            body.push_back('.');
            body.append(digits.substr(1));
        }
        body.push_back('e');
        if (n - 1 >= 0) {
            body.push_back('+');
        }
        body.append(std::to_string(n - 1));
    }

    return negative ? ("-" + body) : body;
}

class JsonValue {
public:
    enum class Type {
        NULL_VAL,
        BOOL_VAL,
        INT_VAL,
        UINT_VAL,
        DOUBLE_VAL,
        STRING_VAL,
        ARRAY_VAL,
        OBJECT_VAL
    };

    using ArrayType = std::vector<JsonValue>;
    using ObjectType = std::vector<std::pair<std::string, JsonValue>>;

    JsonValue() : type_(Type::NULL_VAL) {}
    static JsonValue make_null() { return JsonValue(); }
    static JsonValue make_bool(bool b) {
        JsonValue v;
        v.type_ = Type::BOOL_VAL;
        v.bool_val_ = b;
        return v;
    }
    static JsonValue make_int(int64_t i) {
        JsonValue v;
        v.type_ = Type::INT_VAL;
        v.int_val_ = i;
        return v;
    }
    static JsonValue make_uint(uint64_t u) {
        JsonValue v;
        v.type_ = Type::UINT_VAL;
        v.uint_val_ = u;
        return v;
    }
    static JsonValue make_double(double d) {
        JsonValue v;
        v.type_ = Type::DOUBLE_VAL;
        v.double_val_ = d;
        return v;
    }
    static JsonValue make_string(const std::string& s) {
        JsonValue v;
        v.type_ = Type::STRING_VAL;
        v.str_val_ = s;
        return v;
    }
    static JsonValue make_array(ArrayType arr) {
        JsonValue v;
        v.type_ = Type::ARRAY_VAL;
        v.arr_val_ = std::move(arr);
        return v;
    }
    static JsonValue make_object(ObjectType obj) {
        JsonValue v;
        v.type_ = Type::OBJECT_VAL;
        v.obj_val_ = std::move(obj);
        return v;
    }

    Type type() const { return type_; }
    bool bool_val() const { return bool_val_; }
    int64_t int_val() const { return int_val_; }
    uint64_t uint_val() const { return uint_val_; }
    double double_val() const { return double_val_; }
    const std::string& str_val() const { return str_val_; }
    const ArrayType& arr_val() const { return arr_val_; }
    const ObjectType& obj_val() const { return obj_val_; }

private:
    Type type_;
    bool bool_val_ = false;
    int64_t int_val_ = 0;
    uint64_t uint_val_ = 0;
    double double_val_ = 0.0;
    std::string str_val_;
    ArrayType arr_val_;
    ObjectType obj_val_;
};

inline void canonicalize_into(const JsonValue& val, std::string* out) {
    switch (val.type()) {
        case JsonValue::Type::NULL_VAL:
            out->append("null");
            break;
        case JsonValue::Type::BOOL_VAL:
            out->append(val.bool_val() ? "true" : "false");
            break;
        case JsonValue::Type::INT_VAL:
            out->append(std::to_string(val.int_val()));
            break;
        case JsonValue::Type::UINT_VAL:
            out->append(std::to_string(val.uint_val()));
            break;
        case JsonValue::Type::DOUBLE_VAL:
            out->append(format_number(val.double_val()));
            break;
        case JsonValue::Type::STRING_VAL:
            out->append(encode_string(val.str_val()));
            break;
        case JsonValue::Type::ARRAY_VAL: {
            out->push_back('[');
            const auto& arr = val.arr_val();
            for (size_t i = 0; i < arr.size(); ++i) {
                if (i > 0) out->push_back(',');
                canonicalize_into(arr[i], out);
            }
            out->push_back(']');
            break;
        }
        case JsonValue::Type::OBJECT_VAL: {
            std::vector<const std::pair<std::string, JsonValue>*> entries;
            entries.reserve(val.obj_val().size());
            for (const auto& kv : val.obj_val()) {
                entries.push_back(&kv);
            }
            // Stable sort then deduplicate (last value wins) or check keys in RFC 8785 UTF-16 order
            std::stable_sort(entries.begin(), entries.end(),
                             [](const auto* a, const auto* b) { return key_less(a->first, b->first); });
            out->push_back('{');
            bool first = true;
            for (size_t i = 0; i < entries.size(); ++i) {
                // Skip shadowed duplicate keys if present (keep last occurrence per stable_sort)
                if (i + 1 < entries.size() && entries[i]->first == entries[i + 1]->first) {
                    continue;
                }
                if (!first) out->push_back(',');
                first = false;
                out->append(encode_string(entries[i]->first));
                out->push_back(':');
                canonicalize_into(entries[i]->second, out);
            }
            out->push_back('}');
            break;
        }
    }
}

inline std::string canonicalize(const JsonValue& val) {
    std::string out;
    canonicalize_into(val, &out);
    return out;
}

} // namespace jcs

// Canonical RFC 8785 leaf metadata serializer used by md-seal.
inline std::string build_seal_record_json(uint64_t client_time_ns,
                                          const std::string& device_id,
                                          bool is_ghost_event,
                                          uint32_t frame_seq,
                                          double ncc,
                                          double pce_db,
                                          double pce_linear,
                                          const std::string& raw_sha256,
                                          uint32_t scenario,
                                          const std::string& verdict) {
    using jcs::JsonValue;
    // Construct sorted RFC 8785 object (canonicalize() also enforces UTF-16 sort & ES6 numbers)
    JsonValue obj = JsonValue::make_object({
        {"client_time_ns", JsonValue::make_uint(client_time_ns)},
        {"device_id",      JsonValue::make_string(device_id)},
        {"event_type",     JsonValue::make_string(is_ghost_event ? "GHOST_EVENT_WATCHDOG" : "AUTHENTIC_FRAME")},
        {"frame_seq",      JsonValue::make_uint(frame_seq)},
        {"ncc",            JsonValue::make_double(ncc)},
        {"pce_db",         JsonValue::make_double(pce_db)},
        {"pce_linear",     JsonValue::make_double(pce_linear)},
        {"raw_sha256",     JsonValue::make_string(raw_sha256)},
        {"scenario",       JsonValue::make_uint(scenario)},
        {"verdict",        JsonValue::make_string(verdict)},
    });
    return jcs::canonicalize(obj);
}

} // namespace mdfp
