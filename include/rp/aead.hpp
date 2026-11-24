// ChaCha20-Poly1305 AEAD (RFC 8439), plus X25519 and Shamir secret sharing.
//
// These serve the dispute-retrace path only, not the 1 kHz hot path:
//   * ChaCha20-Poly1305 encrypts the encrypted journal that an adjudicator can
//     decrypt *only* with a court-ordered key share, so the caregiver or the
//     vendor cannot read room activity at will.
//   * X25519 wraps that journal key to the adjudicator's public key.
//   * Shamir shares the wrapping key between the care home, the resident's
//     guardian and the regulator, so no single party (and not the vendor) can
//     open the journal alone.
#pragma once

#include "rp/common.hpp"

namespace rp {

constexpr std::size_t kKeyLen = 32;
constexpr std::size_t kNonceLen = 12;
constexpr std::size_t kTagLen = 16;
using Key = std::array<std::uint8_t, kKeyLen>;
using Nonce = std::array<std::uint8_t, kNonceLen>;
using Tag = std::array<std::uint8_t, kTagLen>;

void chacha20_block(const std::uint8_t key[32], std::uint32_t counter,
                    const std::uint8_t nonce[12], std::uint8_t out[64]);

// XOR keystream into `buf` in place (counter starts at `counter`).
void chacha20_xor(const std::uint8_t key[32], std::uint32_t counter,
                  const std::uint8_t nonce[12], std::uint8_t* buf, std::size_t len);

// One-shot AEAD.  `out` receives ciphertext || 16-byte tag, sized len+16.
// AAD is authenticated but not encrypted.  Returns false on misuse only.
bool aead_seal(const Key& key, const Nonce& nonce, Slice aad, Slice plaintext,
               Bytes* out);
// Returns Status::BadTag if authentication fails; `out` is untouched then.
Status aead_open(const Key& key, const Nonce& nonce, Slice aad, Slice sealed,
                 Bytes* out);

// ---------------------------------------------------------------------------
// X25519 (RFC 7748).  Used to wrap journal keys to an adjudicator keypair.
// ---------------------------------------------------------------------------
bool x25519_base(const Seed& scalar, PubKey* out);
bool x25519(const Seed& scalar, const PubKey& peer, PubKey* shared);

// ---------------------------------------------------------------------------
// Shamir secret sharing over GF(256).  A k-of-n split of a 32-byte key.
// Each share is `id` (1..255) || share_value.  Recombination is pure
// arithmetic and needs no secret held by the vendor.
// ---------------------------------------------------------------------------
struct Share {
  std::uint8_t id = 0;
  Bytes value;   // same length as the secret
};

std::vector<Share> shamir_split(Slice secret, std::uint8_t threshold,
                                std::uint8_t n, std::uint64_t seed_for_rng);
bool shamir_combine(const std::vector<Share>& shares, Bytes* secret);

}  // namespace rp
