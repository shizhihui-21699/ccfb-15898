// Signed privacy policy / module manifest.
//
// The device is opaque and the vendor is not trusted.  The only way an outside
// party can check "this firmware really cannot upload raw radar data" is if
// the exact set of allowable egress is committed to *before* deployment, in a
// structure signed by the vendor (and co-signed by the care home), and the
// running binary proves at attestation time that it matches that commitment.
//
// The manifest binds together, under one signature:
//   * the firmware measurement (SHA-256 of the code region),
//   * the envelope configuration (thresholds, decimation, apnea window),
//   * the closed set of event kinds the device may emit,
//   * the network egress allow-list (a device that phones home fails),
//   * the journal encryption policy.
//
// A regulator's check is then: signature valid? firmware measurement matches
// the hash of the image it has? events observed ⊆ manifest kinds? If all yes,
// the device provably did not emit anything outside policy.
#pragma once

#include "rp/common.hpp"
#include "rp/event.hpp"

namespace rp {

// Absolute ceiling on egress bandwidth and destinations.  Zero means "no
// network path at all", which is the recommended default for a device whose
// only job is local alerting over a serial link.
struct EgressPolicy {
  std::uint32_t max_bytes_per_minute = 4096;
  std::uint32_t max_destinations = 1;
  // True only if a management/telemetry channel is *required* by the care
  // home.  It is a separate, audited path that can carry only checkpoints and
  // liveness, never event payloads.
  bool allow_telemetry_channel = false;
  bool allow_firmware_update = true;
  // Raw radar egress is never permitted.  The field exists so the manifest
  // can explicitly, verifiably, deny it.
  bool allow_raw_radar_egress = false;
};

struct PolicyManifest {
  std::uint8_t version = 1;
  std::uint32_t device_id = 0;
  Hash firmware_measurement{};   // SHA-256 of the code region
  // The closed set of event kinds the device may emit.  Bit i set = kind i+1
  // allowed.  The envelope's accept() consults this at runtime.
  std::uint32_t allowed_event_kinds = 0x3ff;  // all reference kinds by default
  // Envelope config as emitted fields (not floats: fixed-point integers).
  std::uint32_t max_frames_per_sec = 10;
  std::uint32_t fall_impact_milli = 620;       // 0.620
  std::uint32_t fall_immobility_milli = 350;   // 0.350
  std::uint32_t apnea_seconds = 30;
  std::uint32_t apnea_confirm_seconds = 8;
  EgressPolicy egress;
  // Journal: whether the encrypted retrace journal is enabled, and the
  // minimum number of shares required to decrypt it (k-of-n).
  bool journal_enabled = true;
  std::uint8_t journal_k = 2;
  std::uint8_t journal_n = 3;
  WallUs valid_from_us = 0;
  WallUs valid_until_us = 0;
};

// Canonical signed body of a manifest.
Bytes encode_manifest_body(const PolicyManifest& m);
Status decode_manifest_body(Slice body, PolicyManifest* out);

struct SignedManifest {
  PolicyManifest manifest;
  Signature vendor_sig{};
  Signature care_home_sig{};   // second signature; both required
  PubKey vendor_pub{};
  PubKey care_home_pub{};
  Bytes encode() const;
  static Status decode(Slice in, SignedManifest* out);
};

// Bit for an event kind in allowed_event_kinds.
inline std::uint32_t kind_bit(EventKind k) { return 1u << (static_cast<std::uint32_t>(k) - 1); }

// Verify both signatures over the body.  Returns Ok only if both are valid.
Status verify_manifest(const SignedManifest& sm);

// Runtime policy enforcement, checked by the envelope before emission.
class PolicyGate {
 public:
  explicit PolicyGate(const PolicyManifest& m) : manifest_(m) {}
  bool allows(EventKind k) const {
    return (manifest_.allowed_event_kinds & kind_bit(k)) != 0;
  }
  bool allows_raw_radar() const { return manifest_.egress.allow_raw_radar_egress; }
  const PolicyManifest& manifest() const { return manifest_; }

 private:
  PolicyManifest manifest_;
};

}  // namespace rp
