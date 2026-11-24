// SPDX-License-Identifier: Apache-2.0
// RadPriv — device-side privacy envelope for mmWave vital-sign monitoring.
//
// Common types shared by every subsystem.  Deliberately dependency-free:
// the target hardware is a Cortex-M7 class MCU with ~512 KiB SRAM, no MMU,
// no heap worth speaking of, and no trusted OS.  Everything here must be
// expressible with the C++17 freestanding subset plus <array>/<cstdint>.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace rp {

using Bytes = std::vector<std::uint8_t>;

// Non-owning view of immutable bytes.  Implicit conversions from every
// container used in the codebase keep call sites readable.
struct Slice {
  const std::uint8_t* p = nullptr;
  std::size_t n = 0;

  Slice() = default;
  Slice(const std::uint8_t* ptr, std::size_t len) : p(ptr), n(len) {}
  Slice(const Bytes& b) : p(b.data()), n(b.size()) {}
  template <std::size_t N>
  Slice(const std::array<std::uint8_t, N>& a) : p(a.data()), n(N) {}
  Slice(const void* ptr, std::size_t len)
      : p(static_cast<const std::uint8_t*>(ptr)), n(len) {}

  const std::uint8_t* begin() const { return p; }
  const std::uint8_t* end() const { return p + n; }
  const std::uint8_t* data() const { return p; }
  std::size_t size() const { return n; }
  bool empty() const { return n == 0; }
};

// ---------------------------------------------------------------------------
// Error handling
//
// The hot path must never throw: the real-time classifier runs on a 1 kHz
// budget and an exception unwind is an unbounded latency spike.  Errors are
// returned as Status.  The CLI/test harnesses may throw on programmer error
// (std::logic_error), never on data-dependent paths.
// ---------------------------------------------------------------------------
enum class Status : std::uint8_t {
  Ok = 0,
  BadMagic,
  BadVersion,
  Truncated,
  BadLength,
  BadTag,
  BadChecksum,
  HashMismatch,
  SignatureInvalid,
  ChainBroken,
  SeqGap,
  PolicyViolation,
  Capacity,
  NotFound,
  IoError,
  CryptoFailure,
  Unauthorized,
};

const char* to_string(Status s);
inline bool ok(Status s) { return s == Status::Ok; }

// ---------------------------------------------------------------------------
// Time.  Monotonic microseconds since device boot for the real-time path;
// wall clock is only consulted when sealing a ledger record, and only through
// a callback so that a failed RTC cannot stall the pipeline.
// ---------------------------------------------------------------------------
using Ticks = std::uint64_t;   // microseconds, monotonic, never reordered
using WallUs = std::int64_t;   // microseconds since Unix epoch

constexpr std::size_t kHashLen = 32;                 // SHA-256
constexpr std::size_t kSigLen = 64;                  // Ed25519
constexpr std::size_t kPubLen = 32;
constexpr std::size_t kSeedLen = 32;

using Hash = std::array<std::uint8_t, kHashLen>;
using Signature = std::array<std::uint8_t, kSigLen>;
using PubKey = std::array<std::uint8_t, kPubLen>;
using Seed = std::array<std::uint8_t, kSeedLen>;

inline Hash zero_hash() {
  Hash h{};
  return h;
}

// Best-effort secure wipe that the optimiser is not allowed to elide.
void secure_wipe(void* p, std::size_t n);

// Hex helpers used by the CLI and by the on-disk formats.
std::string hex(Slice v);
bool from_hex(std::string_view s, Bytes* out);

// ---------------------------------------------------------------------------
// Canonical encoding helpers.  Every integer inside a hash-covered structure
// is fixed-width big-endian; there is exactly one encoding of any value, which
// is what makes the Merkle leaves and checkpoint hashes reproducible across
// architectures and compilers.
// ---------------------------------------------------------------------------
inline void put_be64(Bytes* out, std::uint64_t v) {
  for (int i = 7; i >= 0; --i)
    out->push_back(static_cast<std::uint8_t>(v >> (i * 8)));
}
inline void put_be32(Bytes* out, std::uint32_t v) {
  for (int i = 3; i >= 0; --i)
    out->push_back(static_cast<std::uint8_t>(v >> (i * 8)));
}
inline void put_be16(Bytes* out, std::uint16_t v) {
  out->push_back(static_cast<std::uint8_t>(v >> 8));
  out->push_back(static_cast<std::uint8_t>(v));
}
inline std::uint64_t get_be64(const std::uint8_t* p) {
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
  return v;
}
inline std::uint32_t get_be32(const std::uint8_t* p) {
  std::uint32_t v = 0;
  for (int i = 0; i < 4; ++i) v = (v << 8) | p[i];
  return v;
}
inline std::uint16_t get_be16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

inline void append(Bytes* out, Slice s) {
  out->insert(out->end(), s.p, s.p + s.n);
}
inline void append(Bytes* out, std::string_view s) {
  out->insert(out->end(), s.begin(), s.end());
}
inline void append_u8(Bytes* out, std::uint8_t v) { out->push_back(v); }
inline void append_hash(Bytes* out, const Hash& h) { append(out, Slice(h)); }

}  // namespace rp
