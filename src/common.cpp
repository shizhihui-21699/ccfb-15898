// SPDX-License-Identifier: Apache-2.0
#include "rp/common.hpp"

namespace rp {

const char* to_string(Status s) {
  switch (s) {
    case Status::Ok: return "ok";
    case Status::BadMagic: return "bad-magic";
    case Status::BadVersion: return "bad-version";
    case Status::Truncated: return "truncated";
    case Status::BadLength: return "bad-length";
    case Status::BadTag: return "bad-tag";
    case Status::BadChecksum: return "bad-checksum";
    case Status::HashMismatch: return "hash-mismatch";
    case Status::SignatureInvalid: return "signature-invalid";
    case Status::ChainBroken: return "chain-broken";
    case Status::SeqGap: return "seq-gap";
    case Status::PolicyViolation: return "policy-violation";
    case Status::Capacity: return "capacity";
    case Status::NotFound: return "not-found";
    case Status::IoError: return "io-error";
    case Status::CryptoFailure: return "crypto-failure";
    case Status::Unauthorized: return "unauthorized";
  }
  return "unknown";
}

void secure_wipe(void* p, std::size_t n) {
  volatile std::uint8_t* v = static_cast<volatile std::uint8_t*>(p);
  while (n--) *v++ = 0;
}

std::string hex(Slice v) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string out;
  out.resize(v.n * 2);
  for (std::size_t i = 0; i < v.n; ++i) {
    out[i * 2] = digits[v.p[i] >> 4];
    out[i * 2 + 1] = digits[v.p[i] & 0xf];
  }
  return out;
}

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool from_hex(std::string_view s, Bytes* out) {
  if (s.size() % 2 != 0) return false;
  out->clear();
  out->reserve(s.size() / 2);
  for (std::size_t i = 0; i < s.size(); i += 2) {
    int hi = hexval(s[i]), lo = hexval(s[i + 1]);
    if (hi < 0 || lo < 0) return false;
    out->push_back(std::uint8_t((hi << 4) | lo));
  }
  return true;
}

}  // namespace rp
