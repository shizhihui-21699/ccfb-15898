// SPDX-License-Identifier: Apache-2.0
// Shared GF(2^255-19) arithmetic for Ed25519 and X25519.
//
// 16 limbs of 16 bits, little-endian, exactly as in the public-domain
// TweetNaCl reference.  Reusing one field implementation for both curves
// means there is a single arithmetic core to audit, which is the whole point
// of shipping our own crypto here.
//
// Internal header: not installed, not part of the public API.
#pragma once

#include <cstdint>
#include <cstring>

#include "rp/common.hpp"
#include "rp/sha256.hpp"

namespace rp {
namespace field25519 {

using i64 = std::int64_t;
using gf = i64[16];

inline void set25519(gf r, const gf a) {
  for (int i = 0; i < 16; ++i) r[i] = a[i];
}

inline void car25519(gf o) {
  for (int i = 0; i < 16; ++i) {
    o[i] += (1LL << 16);
    i64 c = o[i] >> 16;
    o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
    o[i] -= c * 65536;
  }
}

inline void sel25519(gf p, gf q, int b) {
  i64 c = ~(b - 1);
  for (int i = 0; i < 16; ++i) {
    i64 t = c & (p[i] ^ q[i]);
    p[i] ^= t;
    q[i] ^= t;
  }
}

inline void pack25519(std::uint8_t* o, const gf n) {
  gf m, t;
  for (int i = 0; i < 16; ++i) t[i] = n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  for (int j = 0; j < 2; ++j) {
    m[0] = t[0] - 0xffed;
    for (int i = 1; i < 15; ++i) {
      m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
      m[i - 1] &= 0xffff;
    }
    m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
    int b = int((m[15] >> 16) & 1);
    m[14] &= 0xffff;
    sel25519(t, m, 1 - b);
  }
  for (int i = 0; i < 16; ++i) {
    o[2 * i] = std::uint8_t(t[i] & 0xff);
    o[2 * i + 1] = std::uint8_t(t[i] >> 8);
  }
}

inline int neq25519(const gf a, const gf b) {
  std::uint8_t c[32], d[32];
  pack25519(c, a);
  pack25519(d, b);
  return ct_equal(c, d, 32) ? 0 : 1;
}

inline std::uint8_t par25519(const gf a) {
  std::uint8_t d[32];
  pack25519(d, a);
  return d[0] & 1;
}

inline void unpack25519(gf o, const std::uint8_t* n) {
  for (int i = 0; i < 16; ++i) o[i] = n[2 * i] + (i64(n[2 * i + 1]) << 8);
  o[15] &= 0x7fff;
}

inline void A(gf o, const gf a, const gf b) {
  for (int i = 0; i < 16; ++i) o[i] = a[i] + b[i];
}
inline void Z(gf o, const gf a, const gf b) {
  for (int i = 0; i < 16; ++i) o[i] = a[i] - b[i];
}
inline void M(gf o, const gf a, const gf b) {
  i64 t[31];
  for (int i = 0; i < 31; ++i) t[i] = 0;
  for (int i = 0; i < 16; ++i)
    for (int j = 0; j < 16; ++j) t[i + j] += a[i] * b[j];
  for (int i = 0; i < 15; ++i) t[i] += 38 * t[i + 16];
  for (int i = 0; i < 16; ++i) o[i] = t[i];
  car25519(o);
  car25519(o);
}
inline void S(gf o, const gf a) { M(o, a, a); }

inline void inv25519(gf o, const gf i) {
  gf c;
  for (int a = 0; a < 16; ++a) c[a] = i[a];
  for (int a = 253; a >= 0; --a) {
    S(c, c);
    if (a != 2 && a != 4) M(c, c, i);
  }
  for (int a = 0; a < 16; ++a) o[a] = c[a];
}

}  // namespace field25519
}  // namespace rp
