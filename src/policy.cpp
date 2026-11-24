// SPDX-License-Identifier: Apache-2.0
#include "rp/policy.hpp"

#include <cstring>

#include "rp/ed25519.hpp"

namespace rp {

//   'PM' | version(1) | device_id(4) | fw(32) | kinds(4) | frames(4)
//   | fall_impact(4) | fall_imm(4) | apnea_s(4) | apnea_confirm(4)
//   | max_bpm(4) | max_dest(4) | flags(1) | jk(1) | jn(1)
//   | valid_from(8) | valid_until(8)
namespace {
constexpr std::size_t kManifestBodyLen = 2 + 1 + 4 + 32 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 1 + 1 + 1 + 8 + 8;
constexpr std::uint8_t kManifestVersion = 1;

// Egress flags.
enum : std::uint8_t {
  kFlagTelemetry = 1 << 0,
  kFlagFwUpdate = 1 << 1,
  kFlagRawRadar = 1 << 2,
  kFlagJournal = 1 << 3,
};
}  // namespace

Bytes encode_manifest_body(const PolicyManifest& m) {
  Bytes out;
  out.reserve(kManifestBodyLen);
  out.push_back('P');
  out.push_back('M');
  out.push_back(kManifestVersion);
  put_be32(&out, m.device_id);
  append_hash(&out, m.firmware_measurement);
  put_be32(&out, m.allowed_event_kinds);
  put_be32(&out, m.max_frames_per_sec);
  put_be32(&out, m.fall_impact_milli);
  put_be32(&out, m.fall_immobility_milli);
  put_be32(&out, m.apnea_seconds);
  put_be32(&out, m.apnea_confirm_seconds);
  put_be32(&out, m.egress.max_bytes_per_minute);
  put_be32(&out, m.egress.max_destinations);
  std::uint8_t flags = 0;
  if (m.egress.allow_telemetry_channel) flags |= kFlagTelemetry;
  if (m.egress.allow_firmware_update) flags |= kFlagFwUpdate;
  if (m.egress.allow_raw_radar_egress) flags |= kFlagRawRadar;
  if (m.journal_enabled) flags |= kFlagJournal;
  out.push_back(flags);
  out.push_back(m.journal_k);
  out.push_back(m.journal_n);
  put_be64(&out, static_cast<std::uint64_t>(m.valid_from_us));
  put_be64(&out, static_cast<std::uint64_t>(m.valid_until_us));
  return out;
}

Status decode_manifest_body(Slice body, PolicyManifest* out) {
  if (body.n != kManifestBodyLen) return Status::BadLength;
  if (body.p[0] != 'P' || body.p[1] != 'M') return Status::BadMagic;
  if (body.p[2] != kManifestVersion) return Status::BadVersion;
  std::size_t o = 3;
  out->version = kManifestVersion;
  out->device_id = get_be32(body.p + o); o += 4;
  std::memcpy(out->firmware_measurement.data(), body.p + o, 32); o += 32;
  out->allowed_event_kinds = get_be32(body.p + o); o += 4;
  out->max_frames_per_sec = get_be32(body.p + o); o += 4;
  out->fall_impact_milli = get_be32(body.p + o); o += 4;
  out->fall_immobility_milli = get_be32(body.p + o); o += 4;
  out->apnea_seconds = get_be32(body.p + o); o += 4;
  out->apnea_confirm_seconds = get_be32(body.p + o); o += 4;
  out->egress.max_bytes_per_minute = get_be32(body.p + o); o += 4;
  out->egress.max_destinations = get_be32(body.p + o); o += 4;
  std::uint8_t flags = body.p[o++];
  out->egress.allow_telemetry_channel = (flags & kFlagTelemetry) != 0;
  out->egress.allow_firmware_update = (flags & kFlagFwUpdate) != 0;
  out->egress.allow_raw_radar_egress = (flags & kFlagRawRadar) != 0;
  out->journal_enabled = (flags & kFlagJournal) != 0;
  out->journal_k = body.p[o++];
  out->journal_n = body.p[o++];
  out->valid_from_us = static_cast<WallUs>(get_be64(body.p + o)); o += 8;
  out->valid_until_us = static_cast<WallUs>(get_be64(body.p + o)); o += 8;
  // Structural invariants: raw radar egress is forbidden by construction.
  if (out->egress.allow_raw_radar_egress) return Status::PolicyViolation;
  if (out->journal_k < 2 || out->journal_k > out->journal_n) return Status::PolicyViolation;
  return Status::Ok;
}

//   body | vendor_sig(64) | care_sig(64) | vendor_pub(32) | care_pub(32)
Bytes SignedManifest::encode() const {
  Bytes out = encode_manifest_body(manifest);
  out.insert(out.end(), vendor_sig.begin(), vendor_sig.end());
  out.insert(out.end(), care_home_sig.begin(), care_home_sig.end());
  out.insert(out.end(), vendor_pub.begin(), vendor_pub.end());
  out.insert(out.end(), care_home_pub.begin(), care_home_pub.end());
  return out;
}

Status SignedManifest::decode(Slice in, SignedManifest* out) {
  std::size_t need = kManifestBodyLen + 2 * kSigLen + 2 * kPubLen;
  if (in.n != need) return Status::BadLength;
  Status s = decode_manifest_body(Slice(in.p, kManifestBodyLen), &out->manifest);
  if (!ok(s)) return s;
  std::size_t o = kManifestBodyLen;
  std::memcpy(out->vendor_sig.data(), in.p + o, kSigLen); o += kSigLen;
  std::memcpy(out->care_home_sig.data(), in.p + o, kSigLen); o += kSigLen;
  std::memcpy(out->vendor_pub.data(), in.p + o, kPubLen); o += kPubLen;
  std::memcpy(out->care_home_pub.data(), in.p + o, kPubLen); o += kPubLen;
  return Status::Ok;
}

Status verify_manifest(const SignedManifest& sm) {
  // Structural invariants are re-checked here, not only at decode: a manifest
  // built in memory (e.g. by a malicious tooling path) and validly signed must
  // still be rejected if it would permit raw radar egress or an invalid
  // k-of-n.  Signatures prove who wrote it, not that it is within the allowed
  // universe of policies.
  if (sm.manifest.egress.allow_raw_radar_egress) return Status::PolicyViolation;
  if (sm.manifest.journal_k < 2 || sm.manifest.journal_k > sm.manifest.journal_n)
    return Status::PolicyViolation;
  Bytes body = encode_manifest_body(sm.manifest);
  if (!ed25519_verify(sm.vendor_pub, Slice(body), sm.vendor_sig)) return Status::SignatureInvalid;
  if (!ed25519_verify(sm.care_home_pub, Slice(body), sm.care_home_sig)) return Status::SignatureInvalid;
  return Status::Ok;
}

}  // namespace rp
