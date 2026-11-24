// Device attestation and the external verifier's toolkit.
//
// The regulator's question is: "prove this device cannot and did not upload
// raw radar data."  We answer it with three checkable artefacts, none of which
// requires trusting the vendor's server:
//
//   1. AttestationReport — the device signs, over a fresh verifier nonce:
//        - its firmware measurement (SHA-256 of the code region),
//        - the hash of the signed policy manifest it is running,
//        - a snapshot of envelope counters (frames in/classified, emergencies
//          raised/emitted/suppressed),
//        - the day's egress byte counter, from a counter the network stack
//          increments and the app cannot reset.
//      A device that quietly uploaded packets would have to lie about the
//      egress counter, and the counter is also mirrored into the checkpoint
//      chain, so the two would have to agree.
//
//   2. The signed policy manifest (policy.hpp) — a commitment made before
//      deployment: these are the only kinds and the only bytes allowed out.
//   3. The checkpoint chain + per-event Merkle proofs (ledger.hpp) — a public,
//      append-only record that every event the device claims to have emitted
//      is accounted for.
//
// The verifier re-derives every hash from the raw artefacts.  It never calls
// the vendor.  `attest verify` is the executable form of this argument.
#pragma once

#include "rp/common.hpp"
#include "rp/ed25519.hpp"
#include "rp/envelope.hpp"
#include "rp/ledger.hpp"
#include "rp/policy.hpp"

namespace rp {

struct EnvelopeCounters {
  std::uint64_t frames_in = 0;
  std::uint64_t frames_classified = 0;
  std::uint64_t emergencies_raised = 0;
  std::uint64_t emergencies_emitted = 0;
  std::uint64_t emergencies_suppressed = 0;  // must always be 0
  std::uint64_t emergency_latch_overflows = 0;  // must always be 0
  std::uint64_t egress_bytes_today = 0;
  std::uint64_t raw_radar_bytes_egressed = 0;  // must always be 0
};

struct AttestationReport {
  std::uint8_t version = 1;
  std::uint32_t device_id = 0;
  Hash firmware_measurement{};   // == policy.manifest.firmware_measurement
  Hash policy_manifest_hash{};   // SHA-256 of encode_manifest_body()
  Hash latest_checkpoint_hash{}; // binds the counter snapshot into the chain
  EnvelopeCounters counters;
  Bytes verifier_nonce;          // echo of the challenge
  WallUs wall_us = 0;
  Ticks device_us = 0;
};

Bytes encode_attestation_body(const AttestationReport& r);
Status decode_attestation_body(Slice body, AttestationReport* out);

struct SignedAttestation {
  AttestationReport report;
  PubKey device_pub{};
  Signature signature{};
  Bytes encode() const;
  static Status decode(Slice in, SignedAttestation* out);
};

// Device-side: produce a signed attestation bound to `verifier_nonce`.  In
// production this runs inside the secure element; here it takes the seed.
SignedAttestation attest_device(const Seed& device_seed, const PolicyManifest& manifest,
                                const EnvelopeCounters& counters, const Hash& checkpoint_hash,
                                Slice verifier_nonce, WallUs wall_us, Ticks device_us);

// Verifier-side: every check the regulator cares about, in one call.  Returns
// the first failure, or Ok.  `expected_fw` is the measurement of the image the
// regulator independently built; iff it matches, the device is running code
// the regulator has reviewed.
struct AttestVerifyInput {
  const SignedAttestation* attestation = nullptr;
  const SignedManifest* manifest = nullptr;
  const Hash* expected_firmware = nullptr;   // optional
  Slice expected_nonce{};                     // optional challenge check
};
Status verify_attestation(const AttestVerifyInput& in);

// Verify an entire published bundle: manifest + attestation + checkpoints +
// events.  This is the top-level function the `attest verify` CLI calls.
struct AuditBundle {
  SignedManifest manifest;
  SignedAttestation attestation;
  std::vector<SignedCheckpoint> checkpoints;
  std::vector<Event> events;                       // in seq order
  std::vector<std::vector<Hash>> inclusion_proofs; // parallel to events
};

Status verify_audit_bundle(const AuditBundle& bundle, const Hash* expected_firmware,
                           Slice expected_nonce);

}  // namespace rp
