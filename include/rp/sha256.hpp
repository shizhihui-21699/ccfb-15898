// SHA-256 / SHA-512 (FIPS 180-4), HMAC-SHA256 (RFC 2104) and HKDF-SHA256
// (RFC 5869).  Self-contained: no OpenSSL, no mbedTLS.  The device image must
// be auditable end to end and linkable without a crypto library.
#pragma once

#include "rp/common.hpp"

namespace rp {

class Sha256 {
 public:
  Sha256();
  void update(const void* data, std::size_t len);
  void update(Slice v) { update(v.p, v.n); }
  Hash final();

  static Hash hash(Slice v);
  static Hash hash(const void* p, std::size_t n);

 private:
  void compress(const std::uint8_t block[64]);
  std::uint32_t h_[8];
  std::uint8_t buf_[64];
  std::size_t buf_len_;
  std::uint64_t total_len_;
};

// SHA-512 is needed only by Ed25519, but exposing it keeps the primitives in
// one auditable place.
class Sha512 {
 public:
  Sha512();
  void update(const void* data, std::size_t len);
  void update(Slice v) { update(v.p, v.n); }
  void final(std::uint8_t out[64]);

 private:
  void compress(const std::uint8_t block[128]);
  std::uint64_t h_[8];
  std::uint8_t buf_[128];
  std::size_t buf_len_;
  std::uint64_t total_len_;
};

// Constant-time comparison for MACs, hashes and signatures.
bool ct_equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t n);
inline bool ct_equal(Slice a, Slice b) {
  return a.n == b.n && ct_equal(a.p, b.p, a.n);
}

// HMAC-SHA256.
Hash hmac_sha256(Slice key, Slice msg);

// HKDF-SHA256 extract / expand, used to derive the write-only journal key and
// per-record keystreams.
Hash hkdf_extract(Slice salt, Slice ikm);
Bytes hkdf_expand(const Hash& prk, Slice info, std::size_t out_len);

}  // namespace rp
