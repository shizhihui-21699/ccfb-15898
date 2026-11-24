// Ed25519 (RFC 8032) signatures, self-contained.
//
// Why not OpenSSL: the verifier image — the thing a regulator re-runs — should
// be a few thousand lines that fit in a reviewer's head.  A full TLS stack
// with 200 kLOC of parsing code defeats the auditability requirement.
//
// This is a straight port of the reference implementation's arithmetic with
// named limbs; it is not constant-time across all paths because signing runs
// only at boot and checkpoint time, on a device with no other secret-bearing
// code path an attacker could time against.  Verification handles only public
// data and is branch-normalised on the final comparison.
#pragma once

#include "rp/common.hpp"

namespace rp {

struct Ed25519KeyPair {
  Seed seed{};           // 32-byte private seed (keep in tamper-protected OTP)
  PubKey pub{};
};

// Derive the public key from a seed (the only operation that needs the seed
// on the signing path; the expanded secret is cached in the signer).
bool ed25519_public_key(const Seed& seed, PubKey* out);

// Sign `msg`.  Returns false only on internal failure.
bool ed25519_sign(const Seed& seed, Slice msg, Signature* out);

// Verify `sig` over `msg` under `pub`.  Returns false for any invalid input;
// never throws.
bool ed25519_verify(const PubKey& pub, Slice msg, const Signature& sig);

}  // namespace rp
