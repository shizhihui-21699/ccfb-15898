// SPDX-License-Identifier: Apache-2.0
#include "rp/attest.hpp"

#include <cstring>

#include "rp/sha256.hpp"

namespace rp {

//   'AT' | ver(1) | device_id(4) | fw(32) | manifest_hash(32)
//   | checkpoint_hash(32) | frames_in(8) | classified(8) | raised(8)
//   | emitted(8) | suppressed(8) | overflow(8) | egress(8) | raw_egress(8)
//   | nonce_len(1) | nonce | wall(8) | device_us(8)
namespace {
constexpr std::uint8_t kAttestVersion = 1;
constexpr std::size_t kAttestFixedLen =
    2 + 1 + 4 + 32 + 32 + 32 + 8 * 8 + 1 + 8 + 8;
}  // namespace

Bytes encode_attestation_body(const AttestationReport& r) {
  Bytes out;
  out.reserve(kAttestFixedLen + r.verifier_nonce.size());
  out.push_back('A');
  out.push_back('T');
  out.push_back(kAttestVersion);
  put_be32(&out, r.device_id);
  append_hash(&out, r.firmware_measurement);
  append_hash(&out, r.policy_manifest_hash);
  append_hash(&out, r.latest_checkpoint_hash);
  put_be64(&out, r.counters.frames_in);
  put_be64(&out, r.counters.frames_classified);
  put_be64(&out, r.counters.emergencies_raised);
  put_be64(&out, r.counters.emergencies_emitted);
  put_be64(&out, r.counters.emergencies_suppressed);
  put_be64(&out, r.counters.emergency_latch_overflows);
  put_be64(&out, r.counters.egress_bytes_today);
  put_be64(&out, r.counters.raw_radar_bytes_egressed);
  out.push_back(static_cast<std::uint8_t>(r.verifier_nonce.size()));
  append(&out, Slice(r.verifier_nonce));
  put_be64(&out, static_cast<std::uint64_t>(r.wall_us));
  put_be64(&out, r.device_us);
  return out;
}

Status decode_attestation_body(Slice body, AttestationReport* out) {
  std::size_t o = 0;
  if (body.n < 3) return Status::Truncated;
  if (body.p[0] != 'A' || body.p[1] != 'T') return Status::BadMagic;
  if (body.p[2] != kAttestVersion) return Status::BadVersion;
  o = 3;
  auto need = [&](std::size_t n) { return o + n <= body.n; };
  if (!need(4)) return Status::Truncated;
  out->device_id = get_be32(body.p + o); o += 4;
  if (!need(32 * 3)) return Status::Truncated;
  std::memcpy(out->firmware_measurement.data(), body.p + o, 32); o += 32;
  std::memcpy(out->policy_manifest_hash.data(), body.p + o, 32); o += 32;
  std::memcpy(out->latest_checkpoint_hash.data(), body.p + o, 32); o += 32;
  if (!need(8 * 8)) return Status::Truncated;
  out->counters.frames_in = get_be64(body.p + o); o += 8;
  out->counters.frames_classified = get_be64(body.p + o); o += 8;
  out->counters.emergencies_raised = get_be64(body.p + o); o += 8;
  out->counters.emergencies_emitted = get_be64(body.p + o); o += 8;
  out->counters.emergencies_suppressed = get_be64(body.p + o); o += 8;
  out->counters.emergency_latch_overflows = get_be64(body.p + o); o += 8;
  out->counters.egress_bytes_today = get_be64(body.p + o); o += 8;
  out->counters.raw_radar_bytes_egressed = get_be64(body.p + o); o += 8;
  if (!need(1)) return Status::Truncated;
  std::size_t nlen = body.p[o++];
  if (!need(nlen)) return Status::Truncated;
  out->verifier_nonce.assign(body.p + o, body.p + o + nlen); o += nlen;
  if (!need(16)) return Status::Truncated;
  out->wall_us = static_cast<WallUs>(get_be64(body.p + o)); o += 8;
  out->device_us = get_be64(body.p + o); o += 8;
  if (o != body.n) return Status::BadLength;
  return Status::Ok;
}

Bytes SignedAttestation::encode() const {
  Bytes out = encode_attestation_body(report);
  out.insert(out.end(), device_pub.begin(), device_pub.end());
  out.insert(out.end(), signature.begin(), signature.end());
  return out;
}

Status SignedAttestation::decode(Slice in, SignedAttestation* out) {
  // Need at least the fixed part + pub + sig to locate the variable tail.
  // Largest possible nonce is 255; try lengths from the end.
  if (in.n < kAttestFixedLen + kPubLen + kSigLen) return Status::Truncated;
  std::size_t body_len = in.n - kPubLen - kSigLen;
  Status s = decode_attestation_body(Slice(in.p, body_len), &out->report);
  if (!ok(s)) return s;
  std::memcpy(out->device_pub.data(), in.p + body_len, kPubLen);
  std::memcpy(out->signature.data(), in.p + body_len + kPubLen, kSigLen);
  return Status::Ok;
}

SignedAttestation attest_device(const Seed& device_seed, const PolicyManifest& manifest,
                                const EnvelopeCounters& counters, const Hash& checkpoint_hash,
                                Slice verifier_nonce, WallUs wall_us, Ticks device_us) {
  SignedAttestation sa;
  sa.report.device_id = manifest.device_id;
  sa.report.firmware_measurement = manifest.firmware_measurement;
  sa.report.policy_manifest_hash = Sha256::hash(Slice(encode_manifest_body(manifest)));
  sa.report.latest_checkpoint_hash = checkpoint_hash;
  sa.report.counters = counters;
  sa.report.verifier_nonce.assign(verifier_nonce.p, verifier_nonce.p + verifier_nonce.n);
  sa.report.wall_us = wall_us;
  sa.report.device_us = device_us;
  ed25519_public_key(device_seed, &sa.device_pub);
  Bytes body = encode_attestation_body(sa.report);
  ed25519_sign(device_seed, Slice(body), &sa.signature);
  return sa;
}

Status verify_attestation(const AttestVerifyInput& in) {
  const SignedAttestation& sa = *in.attestation;
  const SignedManifest& sm = *in.manifest;

  // 1. The attestation's own signature must verify under its stated key.
  Bytes body = encode_attestation_body(sa.report);
  if (!ed25519_verify(sa.device_pub, Slice(body), sa.signature)) return Status::SignatureInvalid;

  // 2. Policy manifest must be validly signed by both parties.
  Status s = verify_manifest(sm);
  if (!ok(s)) return s;

  // 3. The attestation must be about the policy we were given.
  Hash mh = Sha256::hash(Slice(encode_manifest_body(sm.manifest)));
  if (!ct_equal(mh.data(), sa.report.policy_manifest_hash.data(), kHashLen))
    return Status::PolicyViolation;

  // 4. Firmware measurement must match the independently built image, and
  //    must be the image the policy was signed for.
  if (in.expected_firmware) {
    if (!ct_equal(in.expected_firmware->data(), sa.report.firmware_measurement.data(), kHashLen))
      return Status::HashMismatch;
  }
  if (!ct_equal(sm.manifest.firmware_measurement.data(), sa.report.firmware_measurement.data(),
                kHashLen))
    return Status::PolicyViolation;

  // 5. Challenge nonce must echo exactly.
  if (!in.expected_nonce.empty()) {
    if (in.expected_nonce.n != sa.report.verifier_nonce.size()) return Status::PolicyViolation;
    if (!ct_equal(in.expected_nonce.p, sa.report.verifier_nonce.data(), in.expected_nonce.n))
      return Status::PolicyViolation;
  }

  // 6. The inviolable invariants.
  if (sa.report.counters.emergencies_suppressed != 0) return Status::PolicyViolation;
  if (sa.report.counters.emergency_latch_overflows != 0) return Status::PolicyViolation;
  if (sa.report.counters.raw_radar_bytes_egressed != 0) return Status::PolicyViolation;

  // 6b. The attestation's wall time must fall inside the policy's validity
  //     window.  A zero window (both ends 0) means "no window specified" and is
  //     allowed for tests; a specified window is enforced.
  if (sm.manifest.valid_from_us != 0 || sm.manifest.valid_until_us != 0) {
    if (sa.report.wall_us < sm.manifest.valid_from_us ||
        sa.report.wall_us > sm.manifest.valid_until_us)
      return Status::PolicyViolation;
  }

  // 7. Policy egress ceiling respected.  (Per-minute ceiling is checked at the
  //    network stack; here we sanity-check the day total cannot exceed 1440x.)
  std::uint64_t day_cap = std::uint64_t(sm.manifest.egress.max_bytes_per_minute) * 1440;
  if (sa.report.counters.egress_bytes_today > day_cap) return Status::PolicyViolation;

  return Status::Ok;
}

Status verify_audit_bundle(const AuditBundle& bundle, const Hash* expected_firmware,
                           Slice expected_nonce) {
  // 1. Attestation + manifest.
  AttestVerifyInput in;
  in.attestation = &bundle.attestation;
  in.manifest = &bundle.manifest;
  in.expected_firmware = expected_firmware;
  in.expected_nonce = expected_nonce;
  Status s = verify_attestation(in);
  if (!ok(s)) return s;

  // 2. Checkpoints: each must be signed, chain to its predecessor, and have a
  //    non-decreasing tree size.
  const SignedManifest& sm = bundle.manifest;
  if (bundle.checkpoints.empty() && !bundle.events.empty()) return Status::ChainBroken;
  Hash prev{};
  std::uint64_t last_size = 0;
  for (std::size_t i = 0; i < bundle.checkpoints.size(); ++i) {
    const SignedCheckpoint& sc = bundle.checkpoints[i];
    Bytes body = encode_checkpoint_body(sc.checkpoint);
    if (!ed25519_verify(bundle.attestation.device_pub, Slice(body), sc.signature))
      return Status::SignatureInvalid;
    if (i > 0) {
      Hash prev_body = Sha256::hash(Slice(encode_checkpoint_body(bundle.checkpoints[i - 1].checkpoint)));
      if (!ct_equal(sc.checkpoint.prev_checkpoint_hash.data(), prev_body.data(), kHashLen))
        return Status::ChainBroken;
    } else {
      // First checkpoint binds to the manifest hash.
      if (!ct_equal(sc.checkpoint.prev_checkpoint_hash.data(),
                    bundle.attestation.report.policy_manifest_hash.data(), kHashLen))
        return Status::ChainBroken;
    }
    if (sc.checkpoint.tree_size < last_size) return Status::ChainBroken;
    last_size = sc.checkpoint.tree_size;
    prev = Sha256::hash(Slice(encode_checkpoint_body(sc.checkpoint)));
  }

  // 3. Final checkpoint root must equal the attestation's checkpoint hash.
  if (!bundle.checkpoints.empty()) {
    if (!ct_equal(prev.data(), bundle.attestation.report.latest_checkpoint_hash.data(), kHashLen))
      return Status::ChainBroken;
  }

  // 4. Every event seq must be strictly increasing and each must have an
  //    inclusion proof against the final checkpoint root.
  Hash final_root{};
  std::uint64_t final_size = 0;
  if (!bundle.checkpoints.empty()) {
    final_root = bundle.checkpoints.back().checkpoint.root;
    final_size = bundle.checkpoints.back().checkpoint.tree_size;
  }
  std::uint32_t last_seq = 0;
  for (std::size_t i = 0; i < bundle.events.size(); ++i) {
    const Event& e = bundle.events[i];
    if (i > 0 && e.seq <= last_seq) return Status::SeqGap;
    last_seq = e.seq;
    // Policy: only manifest-allowed kinds.
    if ((sm.manifest.allowed_event_kinds & kind_bit(e.kind)) == 0) return Status::PolicyViolation;
    if (i < bundle.inclusion_proofs.size() && final_size > 0) {
      Hash leaf = leaf_hash(Slice(encode_event_body(e)));
      if (i >= final_size) return Status::HashMismatch;
      if (!MerkleTree::verify_inclusion(leaf, i, final_size, bundle.inclusion_proofs[i],
                                        final_root))
        return Status::HashMismatch;
    }
  }

  // 5. Every leaf in the committed tree is an event, so the revealed event
  //    count must EQUAL the final tree size.  A device that committed to N
  //    leaves and revealed fewer is withholding events; a device that reveals
  //    more than it committed is inconsistent.  Either way, reject.
  if (final_size != bundle.events.size()) return Status::HashMismatch;
  // And each event must have an inclusion proof (checked above only when one
  // was present).
  if (bundle.inclusion_proofs.size() != bundle.events.size()) return Status::HashMismatch;
  return Status::Ok;
}

}  // namespace rp
