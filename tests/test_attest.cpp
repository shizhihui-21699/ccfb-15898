// Attestation / manifest / audit-bundle verification: the "prove it didn't
// exfiltrate" story, tested to fail closed.
// SPDX-License-Identifier: Apache-2.0
#include <cstring>

#include "rp/attest.hpp"
#include "rp/bundle.hpp"
#include "rp/session.hpp"
#include "rp/synth.hpp"
#include "test_framework.hpp"

using namespace rp;

namespace {

SessionKeys test_keys() {
  SessionKeys k;
  for (int i = 0; i < 32; ++i) {
    k.device_seed[i] = std::uint8_t(0x10 + i);
    k.care_home_seed[i] = std::uint8_t(0x40 + i);
    k.vendor_seed[i] = std::uint8_t(0x70 + i);
    k.recipient_x25519[i] = std::uint8_t(0xA0 + i);
    k.journal_master[i] = std::uint8_t(0xD0 + i);
  }
  return k;
}

SessionConfig test_config() {
  SessionConfig c;
  c.policy.device_id = 1234;
  for (int i = 0; i < 32; ++i) c.policy.firmware_measurement[i] = std::uint8_t(i * 3 + 1);
  c.checkpoint_every_n_events = 4;
  return c;
}

AuditBundle run_session(Slice nonce, Bytes* journal_out = nullptr) {
  auto keys = test_keys();
  auto cfg = test_config();
  DeviceSession s(cfg, keys);
  auto poses = scenes::fall_sequence(60, 20);
  WallUs wall0 = 1700000000000000LL;
  for (std::size_t i = 0; i < poses.size(); ++i) {
    RadarFrame f = synth_frame(poses[i], static_cast<Ticks>(i) * 100000ull,
                               static_cast<std::uint32_t>(i), 3u + static_cast<std::uint32_t>(i));
    EmitResult er = s.push(f, wall0 + static_cast<WallUs>(i * 100000));
    for (auto& e : er.events) s.ack_emergency(e.seq);
  }
  return s.finalize(nonce, wall0 + 6000000LL, 6000000, journal_out);
}

}  // namespace

TEST(manifest_roundtrip_and_verify) {
  auto keys = test_keys();
  auto cfg = test_config();
  DeviceSession s(cfg, keys);
  SignedManifest sm = s.manifest();
  CHECK(ok(verify_manifest(sm)));
  Bytes enc = sm.encode();
  SignedManifest dec;
  CHECK(ok(SignedManifest::decode(Slice(enc), &dec)));
  CHECK(ok(verify_manifest(dec)));
  // Tamper with the body -> both signatures fail.
  Bytes body = encode_manifest_body(dec.manifest);
  body[10] ^= 1;
  PolicyManifest m2;
  CHECK(ok(decode_manifest_body(Slice(body), &m2)));
  dec.manifest = m2;
  CHECK(!ok(verify_manifest(dec)));
}

TEST(manifest_rejects_raw_radar_policy) {
  // A manifest that permitted raw radar egress must be rejected at decode.
  PolicyManifest m;
  m.egress.allow_raw_radar_egress = true;
  Bytes body = encode_manifest_body(m);
  PolicyManifest out;
  CHECK_EQ(static_cast<int>(decode_manifest_body(Slice(body), &out)),
           static_cast<int>(Status::PolicyViolation));
}

TEST(verify_manifest_rejects_validly_signed_raw_radar) {
  // Even if the raw-radar bit is set AND both signatures are valid over that
  // body, verify_manifest must reject: signatures prove who wrote it, not that
  // the policy is in the allowed universe.
  auto keys = test_keys();
  SignedManifest sm;
  sm.manifest.device_id = 1;
  sm.manifest.egress.allow_raw_radar_egress = true;
  ed25519_public_key(keys.vendor_seed, &sm.vendor_pub);
  ed25519_public_key(keys.care_home_seed, &sm.care_home_pub);
  Bytes body = encode_manifest_body(sm.manifest);
  ed25519_sign(keys.vendor_seed, Slice(body), &sm.vendor_sig);
  ed25519_sign(keys.care_home_seed, Slice(body), &sm.care_home_sig);
  CHECK_EQ(static_cast<int>(verify_manifest(sm)), static_cast<int>(Status::PolicyViolation));
}

TEST(attestation_verifies_in_full) {
  Bytes nonce = {1, 2, 3, 4, 5};
  AuditBundle b = run_session(Slice(nonce));
  Hash fw = b.manifest.manifest.firmware_measurement;
  CHECK(ok(verify_audit_bundle(b, &fw, Slice(nonce))));
}

TEST(attestation_fails_on_wrong_firmware) {
  Bytes nonce = {9, 9, 9};
  AuditBundle b = run_session(Slice(nonce));
  Hash wrong{};
  CHECK_EQ(static_cast<int>(verify_audit_bundle(b, &wrong, Slice(nonce))),
           static_cast<int>(Status::HashMismatch));
}

TEST(attestation_fails_on_wrong_nonce) {
  Bytes nonce = {1, 1, 1};
  AuditBundle b = run_session(Slice(nonce));
  Hash fw = b.manifest.manifest.firmware_measurement;
  Bytes other = {2, 2, 2};
  CHECK(!ok(verify_audit_bundle(b, &fw, Slice(other))));
}

TEST(attestation_detects_suppressed_emergency) {
  // Manufacture an attestation claiming zero suppressed emergencies then
  // flip it; verification must reject.
  Bytes nonce = {5};
  auto keys = test_keys();
  auto cfg = test_config();
  DeviceSession s(cfg, keys);
  auto poses = scenes::fall_sequence(40, 10);
  for (std::size_t i = 0; i < poses.size(); ++i) {
    RadarFrame f = synth_frame(poses[i], static_cast<Ticks>(i) * 100000ull,
                               static_cast<std::uint32_t>(i), 1u);
    EmitResult er = s.push(f, 1700000000000000LL);
    for (auto& e : er.events) s.ack_emergency(e.seq);
  }
  SignedAttestation at = s.attest(Slice(nonce), 1700000000000000LL, 0);
  CHECK_EQ(at.report.counters.emergencies_suppressed, std::uint64_t(0));
  at.report.counters.emergencies_suppressed = 1;
  // Signature no longer valid over the modified report.
  SignedManifest sm = s.manifest();
  AttestVerifyInput in;
  in.attestation = &at;
  in.manifest = &sm;
  CHECK_EQ(static_cast<int>(verify_attestation(in)), static_cast<int>(Status::SignatureInvalid));
}

TEST(attestation_detects_raw_radar_egress_claim) {
  Bytes nonce = {6};
  auto keys = test_keys();
  auto cfg = test_config();
  DeviceSession s(cfg, keys);
  SignedAttestation at = s.attest(Slice(nonce), 1700000000000000LL, 0);
  at.report.counters.raw_radar_bytes_egressed = 1024;
  // Re-sign so only the invariant check catches it (simulating malicious but
  // correctly-keyed firmware).
  ed25519_sign(keys.device_seed, Slice(encode_attestation_body(at.report)), &at.signature);
  SignedManifest sm = s.manifest();
  AttestVerifyInput in;
  in.attestation = &at;
  in.manifest = &sm;
  CHECK_EQ(static_cast<int>(verify_attestation(in)), static_cast<int>(Status::PolicyViolation));
}

TEST(bundle_roundtrip_and_verify) {
  Bytes nonce = {0xAB, 0xCD};
  AuditBundle b = run_session(Slice(nonce));
  Bytes enc = encode_audit_bundle(b);
  AuditBundle dec;
  CHECK(ok(decode_audit_bundle(Slice(enc), &dec)));
  Hash fw = dec.manifest.manifest.firmware_measurement;
  CHECK(ok(verify_audit_bundle(dec, &fw, Slice(nonce))));
}

TEST(bundle_detects_tampered_event) {
  Bytes nonce = {0x11};
  AuditBundle b = run_session(Slice(nonce));
  CHECK(!b.events.empty());
  // Flip a payload bit in an event; its Merkle proof must no longer verify.
  b.events[0].confidence ^= 1;
  Hash fw = b.manifest.manifest.firmware_measurement;
  CHECK_EQ(static_cast<int>(verify_audit_bundle(b, &fw, Slice(nonce))),
           static_cast<int>(Status::HashMismatch));
}

TEST(bundle_detects_disallowed_event_kind) {
  Bytes nonce = {0x22};
  AuditBundle b = run_session(Slice(nonce));
  // Sign a manifest that disallows Fall, then re-sign so signatures are valid
  // but the event is outside policy.
  auto keys = test_keys();
  b.manifest.manifest.allowed_event_kinds &= ~kind_bit(EventKind::Fall);
  Bytes mbody = encode_manifest_body(b.manifest.manifest);
  ed25519_sign(keys.vendor_seed, Slice(mbody), &b.manifest.vendor_sig);
  ed25519_sign(keys.care_home_seed, Slice(mbody), &b.manifest.care_home_sig);
  Hash fw = b.manifest.manifest.firmware_measurement;
  CHECK_EQ(static_cast<int>(verify_audit_bundle(b, &fw, Slice(nonce))),
           static_cast<int>(Status::PolicyViolation));
}

TEST(bundle_detects_withheld_events) {
  // A device that committed to N leaves but reveals fewer is hiding events.
  Bytes nonce = {0x44};
  AuditBundle b = run_session(Slice(nonce));
  CHECK(b.events.size() >= 2);
  b.events.pop_back();
  b.inclusion_proofs.pop_back();
  Hash fw = b.manifest.manifest.firmware_measurement;
  CHECK_EQ(static_cast<int>(verify_audit_bundle(b, &fw, Slice(nonce))),
           static_cast<int>(Status::HashMismatch));
}

TEST(bundle_detects_broken_checkpoint_chain) {
  Bytes nonce = {0x33};
  AuditBundle b = run_session(Slice(nonce));
  CHECK(b.checkpoints.size() >= 2);
  // Break the chain link on the second checkpoint.
  b.checkpoints[1].checkpoint.prev_checkpoint_hash[0] ^= 1;
  // Re-sign so only the chain check can catch it.
  auto keys = test_keys();
  ed25519_sign(keys.device_seed, Slice(encode_checkpoint_body(b.checkpoints[1].checkpoint)),
               &b.checkpoints[1].signature);
  Hash fw = b.manifest.manifest.firmware_measurement;
  CHECK_EQ(static_cast<int>(verify_audit_bundle(b, &fw, Slice(nonce))),
           static_cast<int>(Status::ChainBroken));
}
