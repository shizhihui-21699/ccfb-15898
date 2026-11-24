// SPDX-License-Identifier: Apache-2.0
#include "rp/aead.hpp"

#include <cstring>

#include "rp/sha256.hpp"
#include "field25519.hpp"

namespace rp {

// ---------------------------------------------------------------------------
// ChaCha20 (RFC 8439 §2.3)
// ---------------------------------------------------------------------------
namespace {

constexpr std::uint32_t rotl32(std::uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

void chacha_quarter(std::uint32_t* s, int a, int b, int c, int d) {
  s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 16);
  s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 12);
  s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 8);
  s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 7);
}

void chacha_core(const std::uint8_t key[32], std::uint32_t counter,
                 const std::uint8_t nonce[12], std::uint32_t out[16]) {
  std::uint32_t st[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
  for (int i = 0; i < 8; ++i)
    st[4 + i] = std::uint32_t(key[i * 4]) | (std::uint32_t(key[i * 4 + 1]) << 8) |
                (std::uint32_t(key[i * 4 + 2]) << 16) | (std::uint32_t(key[i * 4 + 3]) << 24);
  st[12] = counter;
  for (int i = 0; i < 3; ++i)
    st[13 + i] = std::uint32_t(nonce[i * 4]) | (std::uint32_t(nonce[i * 4 + 1]) << 8) |
                 (std::uint32_t(nonce[i * 4 + 2]) << 16) | (std::uint32_t(nonce[i * 4 + 3]) << 24);
  std::uint32_t w[16];
  std::memcpy(w, st, sizeof(w));
  for (int i = 0; i < 10; ++i) {
    chacha_quarter(w, 0, 4, 8, 12);
    chacha_quarter(w, 1, 5, 9, 13);
    chacha_quarter(w, 2, 6, 10, 14);
    chacha_quarter(w, 3, 7, 11, 15);
    chacha_quarter(w, 0, 5, 10, 15);
    chacha_quarter(w, 1, 6, 11, 12);
    chacha_quarter(w, 2, 7, 8, 13);
    chacha_quarter(w, 3, 4, 9, 14);
  }
  for (int i = 0; i < 16; ++i) out[i] = w[i] + st[i];
}

// Poly1305 (RFC 8439 §2.5), 26-bit limbs, one-shot over a contiguous buffer.
// `msg` is processed in 16-byte blocks; any trailing partial block is padded
// with a 0x01 byte then zeros, which is exactly the RFC's `add 1 bit` rule.
struct Poly1305 {
  std::uint32_t r[5];
  std::uint32_t h[5];
  std::uint32_t pad[4];
  std::uint8_t buf[16];
  std::size_t buf_len;

  static std::uint32_t le32(const std::uint8_t* p) {
    return std::uint32_t(p[0]) | (std::uint32_t(p[1]) << 8) |
           (std::uint32_t(p[2]) << 16) | (std::uint32_t(p[3]) << 24);
  }

  void init(const std::uint8_t key[32]) {
    r[0] = (le32(key + 0)) & 0x3ffffff;
    r[1] = ((le32(key + 3) >> 2)) & 0x3ffff03;
    r[2] = ((le32(key + 6) >> 4)) & 0x3ffc0ff;
    r[3] = ((le32(key + 9) >> 6)) & 0x3f03fff;
    r[4] = ((le32(key + 12) >> 8)) & 0x00fffff;
    for (int i = 0; i < 5; ++i) h[i] = 0;
    for (int i = 0; i < 4; ++i) pad[i] = le32(key + 16 + i * 4);
    buf_len = 0;
  }

  // Absorb exactly 16 bytes; `hibit` is 1<<24 for a full block, 0 for the
  // final block whose 0x01 byte already sits in the buffer.
  void block(const std::uint8_t* m, std::uint32_t hibit) {
    const std::uint32_t s1 = r[1] * 5, s2 = r[2] * 5, s3 = r[3] * 5, s4 = r[4] * 5;
    std::uint32_t t0 = le32(m + 0) & 0x3ffffff;
    std::uint32_t t1 = (le32(m + 3) >> 2) & 0x3ffffff;
    std::uint32_t t2 = (le32(m + 6) >> 4) & 0x3ffffff;
    std::uint32_t t3 = (le32(m + 9) >> 6) & 0x3ffffff;
    std::uint32_t t4 = (le32(m + 12) >> 8) | hibit;

    std::uint64_t d0 = std::uint64_t(h[0]) + t0;
    std::uint64_t d1 = std::uint64_t(h[1]) + t1;
    std::uint64_t d2 = std::uint64_t(h[2]) + t2;
    std::uint64_t d3 = std::uint64_t(h[3]) + t3;
    std::uint64_t d4 = std::uint64_t(h[4]) + t4;

    std::uint64_t m0 = d0 * r[0] + d1 * s4 + d2 * s3 + d3 * s2 + d4 * s1;
    std::uint64_t m1 = d0 * r[1] + d1 * r[0] + d2 * s4 + d3 * s3 + d4 * s2;
    std::uint64_t m2 = d0 * r[2] + d1 * r[1] + d2 * r[0] + d3 * s4 + d4 * s3;
    std::uint64_t m3 = d0 * r[3] + d1 * r[2] + d2 * r[1] + d3 * r[0] + d4 * s4;
    std::uint64_t m4 = d0 * r[4] + d1 * r[3] + d2 * r[2] + d3 * r[1] + d4 * r[0];

    std::uint32_t c = std::uint32_t(m0 >> 26); h[0] = std::uint32_t(m0) & 0x3ffffff;
    m1 += c; c = std::uint32_t(m1 >> 26); h[1] = std::uint32_t(m1) & 0x3ffffff;
    m2 += c; c = std::uint32_t(m2 >> 26); h[2] = std::uint32_t(m2) & 0x3ffffff;
    m3 += c; c = std::uint32_t(m3 >> 26); h[3] = std::uint32_t(m3) & 0x3ffffff;
    m4 += c; c = std::uint32_t(m4 >> 26); h[4] = std::uint32_t(m4) & 0x3ffffff;
    h[0] += c * 5; c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c;
  }

  void finish(std::uint8_t out[16]) {
    std::uint32_t c;
    c = h[1] >> 26; h[1] &= 0x3ffffff; h[2] += c;
    c = h[2] >> 26; h[2] &= 0x3ffffff; h[3] += c;
    c = h[3] >> 26; h[3] &= 0x3ffffff; h[4] += c;
    c = h[4] >> 26; h[4] &= 0x3ffffff; h[0] += c * 5;
    c = h[0] >> 26; h[0] &= 0x3ffffff; h[1] += c;

    std::uint32_t g0 = h[0] + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    std::uint32_t g1 = h[1] + c; c = g1 >> 26; g1 &= 0x3ffffff;
    std::uint32_t g2 = h[2] + c; c = g2 >> 26; g2 &= 0x3ffffff;
    std::uint32_t g3 = h[3] + c; c = g3 >> 26; g3 &= 0x3ffffff;
    std::uint32_t g4 = h[4] + c - (1u << 26);

    // If g4 borrowed (its top bit set) keep h, else take g.  mask is all-ones
    // when g is the valid (already reduced) value.
    std::uint32_t mask = (g4 >> 31) - 1;
    std::uint32_t nmask = ~mask;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    h[0] = (h[0] & nmask) | g0;
    h[1] = (h[1] & nmask) | g1;
    h[2] = (h[2] & nmask) | g2;
    h[3] = (h[3] & nmask) | g3;
    h[4] = (h[4] & nmask) | g4;

    // Repack the 26-bit limbs into four 32-bit words.  Each word must be
    // masked to 32 bits before the pad is added, otherwise the high bits of
    // one limb contaminate the next word through the carry.
    std::uint32_t f0 = (std::uint32_t(h[0]) | (std::uint32_t(h[1]) << 26)) & 0xffffffffu;
    std::uint32_t f1 = (std::uint32_t(h[1]) >> 6 | (std::uint32_t(h[2]) << 20)) & 0xffffffffu;
    std::uint32_t f2 = (std::uint32_t(h[2]) >> 12 | (std::uint32_t(h[3]) << 14)) & 0xffffffffu;
    std::uint32_t f3 = (std::uint32_t(h[3]) >> 18 | (std::uint32_t(h[4]) << 8)) & 0xffffffffu;

    std::uint64_t f = std::uint64_t(f0) + pad[0];
    std::uint32_t o0 = std::uint32_t(f);
    f = std::uint64_t(f1) + pad[1] + (f >> 32);
    std::uint32_t o1 = std::uint32_t(f);
    f = std::uint64_t(f2) + pad[2] + (f >> 32);
    std::uint32_t o2 = std::uint32_t(f);
    f = std::uint64_t(f3) + pad[3] + (f >> 32);
    std::uint32_t o3 = std::uint32_t(f);

    for (int i = 0; i < 4; ++i) {
      out[i + 0] = std::uint8_t(o0 >> (i * 8));
      out[i + 4] = std::uint8_t(o1 >> (i * 8));
      out[i + 8] = std::uint8_t(o2 >> (i * 8));
      out[i + 12] = std::uint8_t(o3 >> (i * 8));
    }
  }

  void update(const std::uint8_t* m, std::size_t len) {
    while (len >= 16) {
      block(m, 1u << 24);
      m += 16;
      len -= 16;
    }
    if (len) {
      std::uint8_t last[16];
      std::memcpy(last, m, len);
      last[len] = 1;
      for (std::size_t i = len + 1; i < 16; ++i) last[i] = 0;
      block(last, 0);
    }
  }
};

void poly1305_oneshot(const std::uint8_t key[32], Slice msg, Tag* out) {
  Poly1305 p;
  p.init(key);
  p.update(msg.p, msg.n);
  p.finish(out->data());
}

}  // namespace

void chacha20_block(const std::uint8_t key[32], std::uint32_t counter,
                    const std::uint8_t nonce[12], std::uint8_t out[64]) {
  std::uint32_t w[16];
  chacha_core(key, counter, nonce, w);
  for (int i = 0; i < 16; ++i) {
    out[i * 4] = std::uint8_t(w[i]);
    out[i * 4 + 1] = std::uint8_t(w[i] >> 8);
    out[i * 4 + 2] = std::uint8_t(w[i] >> 16);
    out[i * 4 + 3] = std::uint8_t(w[i] >> 24);
  }
}

void chacha20_xor(const std::uint8_t key[32], std::uint32_t counter,
                  const std::uint8_t nonce[12], std::uint8_t* buf, std::size_t len) {
  std::uint8_t ks[64];
  std::size_t off = 0;
  while (off < len) {
    chacha20_block(key, counter++, nonce, ks);
    std::size_t take = len - off < 64 ? len - off : 64;
    for (std::size_t i = 0; i < take; ++i) buf[off + i] ^= ks[i];
    off += take;
  }
  secure_wipe(ks, sizeof(ks));
}

// ---------------------------------------------------------------------------
// AEAD construction per RFC 8439 §2.8
// ---------------------------------------------------------------------------
namespace {
void build_mac_data(Slice aad, Slice ct, Bytes* out) {
  out->clear();
  append(out, aad);
  std::size_t pad = (16 - (aad.n % 16)) % 16;
  for (std::size_t i = 0; i < pad; ++i) out->push_back(0);
  append(out, ct);
  pad = (16 - (ct.n % 16)) % 16;
  for (std::size_t i = 0; i < pad; ++i) out->push_back(0);
  // RFC 8439 §2.8: the length block is little-endian 64-bit lengths.
  auto put_le64 = [&](std::uint64_t v) {
    for (int i = 0; i < 8; ++i) out->push_back(std::uint8_t(v >> (i * 8)));
  };
  put_le64(aad.n);
  put_le64(ct.n);
}
}  // namespace

bool aead_seal(const Key& key, const Nonce& nonce, Slice aad, Slice plaintext, Bytes* out) {
  std::uint8_t polykey[64];
  chacha20_block(key.data(), 0, nonce.data(), polykey);
  out->assign(plaintext.p, plaintext.p + plaintext.n);
  chacha20_xor(key.data(), 1, nonce.data(), out->data(), out->size());

  Bytes mac_data;
  build_mac_data(aad, Slice(*out), &mac_data);
  Tag tag;
  poly1305_oneshot(polykey, mac_data, &tag);
  out->insert(out->end(), tag.begin(), tag.end());
  secure_wipe(polykey, sizeof(polykey));
  return true;
}

Status aead_open(const Key& key, const Nonce& nonce, Slice aad, Slice sealed, Bytes* out) {
  if (sealed.n < kTagLen) return Status::Truncated;
  std::size_t ct_len = sealed.n - kTagLen;
  Slice ct(sealed.p, ct_len);
  Slice tag_in(sealed.p + ct_len, kTagLen);

  std::uint8_t polykey[64];
  chacha20_block(key.data(), 0, nonce.data(), polykey);
  Bytes mac_data;
  build_mac_data(aad, ct, &mac_data);
  Tag tag;
  poly1305_oneshot(polykey, mac_data, &tag);
  secure_wipe(polykey, sizeof(polykey));

  if (!ct_equal(tag.data(), tag_in.p, kTagLen)) return Status::BadTag;

  out->assign(ct.p, ct.p + ct.n);
  chacha20_xor(key.data(), 1, nonce.data(), out->data(), out->size());
  return Status::Ok;
}

// ---------------------------------------------------------------------------
// X25519 (RFC 7748), Montgomery ladder over GF(2^255-19) built on the same
// 16-limb field arithmetic as Ed25519 (see field25519.hpp).
// ---------------------------------------------------------------------------
namespace {

using gf = field25519::gf;
using field25519::set25519;
using field25519::pack25519;
using field25519::unpack25519;
using field25519::sel25519;
using field25519::A;
using field25519::Z;
using field25519::M;
using field25519::S;
using field25519::inv25519;

// r = a^(p-2) reduces to inverse; already provided as inv25519.

constexpr gf GF0 = {0};
constexpr gf GF1 = {1};

void x25519_scalarmult(std::uint8_t out[32], const std::uint8_t scalar[32],
                       const std::uint8_t point[32]) {
  std::uint8_t e[32];
  std::memcpy(e, scalar, 32);
  e[0] &= 248;
  e[31] &= 127;
  e[31] |= 64;

  gf x1, x2, z2, x3, z3, a, aa, b, bb, ee, c, d, da, cb, t;
  unpack25519(x1, point);
  set25519(x2, GF1);
  set25519(z2, GF0);
  set25519(x3, x1);
  set25519(z3, GF1);

  for (int pos = 254; pos >= 0; --pos) {
    std::uint8_t bit = (e[pos / 8] >> (pos & 7)) & 1;
    sel25519(x2, x3, bit);
    sel25519(z2, z3, bit);
    A(a, x2, z2); S(aa, a);
    Z(b, x2, z2); S(bb, b);
    Z(ee, aa, bb);
    A(c, x3, z3);
    Z(d, x3, z3);
    M(da, d, a);
    M(cb, c, b);
    A(x3, da, cb); S(x3, x3);
    Z(z3, da, cb); S(z3, z3); M(z3, z3, x1);
    M(x2, aa, bb);
    // z2 = ee * (aa + 121665 * ee)
    static const field25519::i64 a24[16] = {121665};
    gf a24f; set25519(a24f, a24);
    M(t, a24f, ee);
    A(t, aa, t);
    M(z2, ee, t);
    sel25519(x2, x3, bit);
    sel25519(z2, z3, bit);
  }
  inv25519(z2, z2);
  M(x2, x2, z2);
  pack25519(out, x2);
  secure_wipe(e, sizeof(e));
}

}  // namespace

bool x25519_base(const Seed& scalar, PubKey* out) {
  static const std::uint8_t base[32] = {9};
  x25519_scalarmult(out->data(), scalar.data(), base);
  return true;
}

bool x25519(const Seed& scalar, const PubKey& peer, PubKey* shared) {
  x25519_scalarmult(shared->data(), scalar.data(), peer.data());
  return true;
}

// ---------------------------------------------------------------------------
// Shamir secret sharing over GF(256), poly x^8+x^4+x^3+x+1 (0x11b).
// ---------------------------------------------------------------------------
namespace {

std::uint8_t gf_mul(std::uint8_t a, std::uint8_t b) {
  std::uint8_t p = 0;
  for (int i = 0; i < 8; ++i) {
    if (b & 1) p ^= a;
    std::uint8_t hi = a & 0x80;
    a <<= 1;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

std::uint8_t gf_inv(std::uint8_t a) {
  if (a == 0) return 0;
  std::uint8_t r = 1;
  for (int i = 0; i < 254; ++i) r = gf_mul(r, a);  // a^254 = a^-1
  return r;
}

struct SplitMix64 {
  std::uint64_t s;
  explicit SplitMix64(std::uint64_t seed) : s(seed) {}
  std::uint64_t next() {
    std::uint64_t z = (s += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
  }
  std::uint8_t byte() { return std::uint8_t(next() >> 56); }
};

}  // namespace

std::vector<Share> shamir_split(Slice secret, std::uint8_t threshold, std::uint8_t n,
                                std::uint64_t seed_for_rng) {
  std::vector<Share> out;
  if (threshold < 2 || threshold > n) return out;
  SplitMix64 rng(seed_for_rng);
  // Coefficients per byte position: coeff[0] = secret, coeff[k] random.
  // Generate on the fly: for each share x, evaluate the polynomial.
  out.resize(n);
  for (std::uint8_t i = 0; i < n; ++i) out[i].id = std::uint8_t(i + 1);
  // Precompute coefficients so every share uses the same polynomial.
  Bytes coeffs(secret.n * threshold);
  for (std::size_t b = 0; b < secret.n; ++b) {
    coeffs[b * threshold] = secret.p[b];
    for (std::uint8_t k = 1; k < threshold; ++k) coeffs[b * threshold + k] = rng.byte();
  }
  for (std::uint8_t s = 0; s < n; ++s) {
    std::uint8_t x = std::uint8_t(s + 1);
    out[s].value.resize(secret.n);
    for (std::size_t b = 0; b < secret.n; ++b) {
      // Horner evaluation
      std::uint8_t acc = coeffs[b * threshold + threshold - 1];
      for (int k = threshold - 2; k >= 0; --k) acc = std::uint8_t(gf_mul(acc, x) ^ coeffs[b * threshold + k]);
      out[s].value[b] = acc;
    }
  }
  secure_wipe(coeffs.data(), coeffs.size());
  return out;
}

bool shamir_combine(const std::vector<Share>& shares, Bytes* secret) {
  if (shares.empty()) return false;
  std::size_t len = shares[0].value.size();
  for (const auto& s : shares)
    if (s.value.size() != len || s.id == 0) return false;
  secret->assign(len, 0);
  // Lagrange interpolation at x=0 for each byte.
  for (std::size_t b = 0; b < len; ++b) {
    std::uint8_t acc = 0;
    for (std::size_t i = 0; i < shares.size(); ++i) {
      std::uint8_t num = 1, den = 1;
      for (std::size_t j = 0; j < shares.size(); ++j) {
        if (i == j) continue;
        num = gf_mul(num, shares[j].id);
        den = gf_mul(den, std::uint8_t(shares[i].id ^ shares[j].id));
      }
      std::uint8_t li = gf_mul(num, gf_inv(den));
      acc ^= gf_mul(shares[i].value[b], li);
    }
    (*secret)[b] = acc;
  }
  return true;
}

}  // namespace rp
