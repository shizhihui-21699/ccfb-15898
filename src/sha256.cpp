// SPDX-License-Identifier: Apache-2.0
#include "rp/sha256.hpp"

#include <cstring>

namespace rp {

namespace {

constexpr std::uint32_t rotr32(std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
constexpr std::uint64_t rotr64(std::uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

constexpr std::uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

constexpr std::uint64_t K512[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
    0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
    0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
    0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
    0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
    0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
    0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
    0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
    0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
    0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
    0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
    0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull};

}  // namespace

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------
Sha256::Sha256() : buf_len_(0), total_len_(0) {
  static constexpr std::uint32_t init[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  std::memcpy(h_, init, sizeof(h_));
}

void Sha256::compress(const std::uint8_t block[64]) {
  std::uint32_t w[64];
  for (int i = 0; i < 16; ++i)
    w[i] = (std::uint32_t(block[i * 4]) << 24) | (std::uint32_t(block[i * 4 + 1]) << 16) |
           (std::uint32_t(block[i * 4 + 2]) << 8) | std::uint32_t(block[i * 4 + 3]);
  for (int i = 16; i < 64; ++i) {
    std::uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
    std::uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
  std::uint32_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];
  for (int i = 0; i < 64; ++i) {
    std::uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    std::uint32_t ch = (e & f) ^ (~e & g);
    std::uint32_t t1 = h + S1 + ch + K256[i] + w[i];
    std::uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    std::uint32_t t2 = S0 + maj;
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }
  h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
  h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
}

void Sha256::update(const void* data, std::size_t len) {
  const auto* p = static_cast<const std::uint8_t*>(data);
  total_len_ += len;
  while (len > 0) {
    std::size_t space = 64 - buf_len_;
    std::size_t take = len < space ? len : space;
    std::memcpy(buf_ + buf_len_, p, take);
    buf_len_ += take;
    p += take;
    len -= take;
    if (buf_len_ == 64) {
      compress(buf_);
      buf_len_ = 0;
    }
  }
}

Hash Sha256::final() {
  std::uint64_t bits = total_len_ * 8;
  std::uint8_t pad = 0x80;
  update(&pad, 1);
  std::uint8_t zero = 0;
  while (buf_len_ != 56) update(&zero, 1);
  std::uint8_t lenbe[8];
  for (int i = 0; i < 8; ++i) lenbe[i] = std::uint8_t(bits >> (56 - i * 8));
  update(lenbe, 8);
  Hash out{};
  for (int i = 0; i < 8; ++i) {
    out[i * 4] = std::uint8_t(h_[i] >> 24);
    out[i * 4 + 1] = std::uint8_t(h_[i] >> 16);
    out[i * 4 + 2] = std::uint8_t(h_[i] >> 8);
    out[i * 4 + 3] = std::uint8_t(h_[i]);
  }
  return out;
}

Hash Sha256::hash(Slice v) { return hash(v.p, v.n); }

Hash Sha256::hash(const void* p, std::size_t n) {
  Sha256 s;
  s.update(p, n);
  return s.final();
}

// ---------------------------------------------------------------------------
// SHA-512
// ---------------------------------------------------------------------------
Sha512::Sha512() : buf_len_(0), total_len_(0) {
  static constexpr std::uint64_t init[8] = {
      0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
      0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull};
  std::memcpy(h_, init, sizeof(h_));
}

void Sha512::compress(const std::uint8_t block[128]) {
  std::uint64_t w[80];
  for (int i = 0; i < 16; ++i) {
    std::uint64_t v = 0;
    for (int j = 0; j < 8; ++j) v = (v << 8) | block[i * 8 + j];
    w[i] = v;
  }
  for (int i = 16; i < 80; ++i) {
    std::uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
    std::uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  std::uint64_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
  std::uint64_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];
  for (int i = 0; i < 80; ++i) {
    std::uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
    std::uint64_t ch = (e & f) ^ (~e & g);
    std::uint64_t t1 = h + S1 + ch + K512[i] + w[i];
    std::uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
    std::uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
    std::uint64_t t2 = S0 + maj;
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }
  h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
  h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
}

void Sha512::update(const void* data, std::size_t len) {
  const auto* p = static_cast<const std::uint8_t*>(data);
  total_len_ += len;
  while (len > 0) {
    std::size_t space = 128 - buf_len_;
    std::size_t take = len < space ? len : space;
    std::memcpy(buf_ + buf_len_, p, take);
    buf_len_ += take;
    p += take;
    len -= take;
    if (buf_len_ == 128) {
      compress(buf_);
      buf_len_ = 0;
    }
  }
}

void Sha512::final(std::uint8_t out[64]) {
  // SHA-512 encodes a 128-bit length; the high 64 bits are zero for any
  // message the device can hold, but we write them for spec conformance.
  std::uint64_t bits = total_len_ * 8;
  std::uint8_t pad = 0x80;
  update(&pad, 1);
  std::uint8_t zero = 0;
  while (buf_len_ != 112) update(&zero, 1);
  std::uint8_t lenbe[16] = {};
  for (int i = 0; i < 8; ++i) lenbe[15 - i] = std::uint8_t(bits >> (i * 8));
  update(lenbe, 16);
  for (int i = 0; i < 8; ++i)
    for (int j = 0; j < 8; ++j) out[i * 8 + j] = std::uint8_t(h_[i] >> (56 - j * 8));
}

// ---------------------------------------------------------------------------
// Constant-time compare / HMAC / HKDF
// ---------------------------------------------------------------------------
bool ct_equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t n) {
  std::uint8_t diff = 0;
  for (std::size_t i = 0; i < n; ++i) diff |= std::uint8_t(a[i] ^ b[i]);
  return diff == 0;
}

Hash hmac_sha256(Slice key, Slice msg) {
  std::uint8_t k0[64] = {};
  if (key.n > 64) {
    Hash kh = Sha256::hash(key);
    std::memcpy(k0, kh.data(), 32);
  } else if (key.n > 0) {
    std::memcpy(k0, key.p, key.n);
  }
  std::uint8_t ipad[64], opad[64];
  for (int i = 0; i < 64; ++i) {
    ipad[i] = std::uint8_t(k0[i] ^ 0x36);
    opad[i] = std::uint8_t(k0[i] ^ 0x5c);
  }
  Sha256 inner;
  inner.update(ipad, 64);
  inner.update(msg.p, msg.n);
  Hash ih = inner.final();
  Sha256 outer;
  outer.update(opad, 64);
  outer.update(ih.data(), 32);
  return outer.final();
}

Hash hkdf_extract(Slice salt, Slice ikm) {
  if (salt.empty()) {
    static const std::uint8_t zeros[32] = {};
    return hmac_sha256(Slice(zeros, 32), ikm);
  }
  return hmac_sha256(salt, ikm);
}

Bytes hkdf_expand(const Hash& prk, Slice info, std::size_t out_len) {
  Bytes out;
  out.reserve(out_len);
  std::uint8_t t[32];
  std::size_t t_len = 0;
  std::uint8_t counter = 1;
  while (out.size() < out_len) {
    Bytes block;
    block.reserve(t_len + info.n + 1);
    if (t_len) block.insert(block.end(), t, t + t_len);
    if (info.n) block.insert(block.end(), info.p, info.p + info.n);
    block.push_back(counter);
    Hash h = hmac_sha256(prk, block);
    std::memcpy(t, h.data(), 32);
    t_len = 32;
    std::size_t take = out_len - out.size();
    if (take > 32) take = 32;
    out.insert(out.end(), t, t + take);
    ++counter;
  }
  return out;
}

}  // namespace rp
