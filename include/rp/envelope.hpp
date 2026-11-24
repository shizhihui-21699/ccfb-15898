// The privacy envelope: the only code path from radar frames to events.
//
// This is the component the whole design exists for.  It sits between the DSP
// front end and the network stack and enforces, in order:
//
//   1. Fixed-rate decimation.  The pipeline never sees more frames than it
//      can classify inside the real-time budget; surplus frames are counted,
//      not silently dropped, so the audit trail can prove nothing stalled.
//   2. Feature extraction that *destroys* the raw cube as it goes.  The cube
//      buffer is overwritten with a constant ("scrub on consume") so it cannot
//      be read back later even by a code path we did not anticipate.
//   3. Classification to a small closed set of events (see event.hpp).
//   4. Emergency bypass.  Fall and apnea detection run on a separate,
//      higher-priority path that does not wait for the decimator and is never
//      subject to the "suppress if busy" rule.  Emergencies are latched and
//      retried until acknowledged onto the wire.
//   5. A hard egress check: any event whose encoding fails the schema policy
//      is rejected here, before it can reach the ledger or the network.
//
// Everything the envelope decides is observable: the counters below are sealed
// into the audit ledger, so "we never dropped a fall" is a claim the regulator
// can check, not one they must trust.
#pragma once

#include "rp/common.hpp"
#include "rp/event.hpp"
#include "rp/radar.hpp"

namespace rp {

// What the classifier is allowed to look at.  Features are computed inside the
// envelope; the classifier itself never touches a RadarFrame, which keeps the
// privacy-critical transformation in one auditable place.
struct Features {
  Ticks t = 0;
  std::uint32_t seq = 0;
  // Aggregate energy in a few coarse range bands, in dB relative to the noise
  // floor.  The banding is the privacy lever: individual range cells (which
  // map to positions in the room) never leave this struct.
  float band_energy_db[4] = {};      // near, mid, far, very-far
  // Total signal energy above the noise floor, linear.  The envelope tracks a
  // slow baseline of this to detect the sudden surge a fall produces.  It is a
  // single scalar, not a map, and is never emitted.
  float total_energy = 0.0f;
  // Fraction of above-floor energy that sits in moving Doppler bins.  Reported
  // motion is *relative to the person*, not the uniform sensor noise.
  float motion_energy = 0.0f;
  float centroid_band = 0.0f;        // 0..3 continuous, then bucketed
  // Rise of total_energy over the running baseline (0 = no surge, ~1 = a
  // strong instantaneous impact).  Computed statefully by the envelope.
  float impact_score = 0.0f;
  float height_score = 0.0f;         // 0..1, proxy for standing vs. floor
  bool valid = false;
};

// Tunables.  These are signed into the module manifest so a regulator can see
// the exact thresholds the device was running (see policy.hpp).  Changing one
// changes the signed policy and is therefore auditable.
struct EnvelopeConfig {
  std::uint32_t max_frames_per_sec = 10;   // decimation target
  float fall_impact_threshold = 0.62f;
  float fall_immobility_threshold = 0.35f;
  std::uint32_t fall_confirm_ms = 400;
  std::uint32_t apnea_seconds = 30;         // clinical default; policy-set
  std::uint32_t apnea_confirm_seconds = 8;
  float apnea_confidence_floor = 0.5f;
  std::uint8_t min_emergency_confidence = 40;
  // Bitmask of event kinds the signed policy permits (see policy.hpp
  // kind_bit).  Default: all reference kinds.  The session sets this from the
  // manifest, so a policy that disallows a kind makes the envelope refuse to
  // emit it at runtime (and count the rejection), not merely fail audit later.
  std::uint32_t allowed_event_kinds = 0x3ff;
};

// Counters sealed into every checkpoint.  These are the evidence that the
// envelope behaved: how many frames arrived, how many were classified, how
// many emergencies were raised vs. delivered, how many were suppressed (must
// always be zero for emergencies).
struct EnvelopeStats {
  std::uint64_t frames_in = 0;
  std::uint64_t frames_classified = 0;
  std::uint64_t frames_decimated = 0;
  std::uint64_t events_out = 0;
  std::uint64_t emergencies_raised = 0;
  std::uint64_t emergencies_emitted = 0;
  std::uint64_t emergencies_pending = 0;
  std::uint64_t emergency_latch_overflows = 0;  // latch was full when a new
                                                // emergency arrived (must be 0)
  std::uint64_t schema_rejections = 0;
  std::uint64_t max_classify_us = 0;   // worst-case latency observed
  std::uint64_t total_classify_us = 0;
};

// The classifier is injected so the reference build can ship a deterministic
// one and a field build can ship a network.  It receives only Features.
class Classifier {
 public:
  virtual ~Classifier() = default;
  // Returns the coarse activity plus, optionally, vitals.  Must be O(1) in
  // the number of frames; the real-time budget is ~2 ms on the target MCU.
  virtual Activity classify(const Features& f, VitalsSnapshot* vitals) = 0;
};

// A small, fully deterministic reference classifier.  No floating-point
// training artefact, no model file to leak, no phone-home.  Thresholds are
// the signed policy's, so a regulator can reproduce every decision.
class ReferenceClassifier : public Classifier {
 public:
  explicit ReferenceClassifier(const EnvelopeConfig& cfg) : cfg_(cfg) {}
  Activity classify(const Features& f, VitalsSnapshot* vitals) override;

 private:
  EnvelopeConfig cfg_;
  std::uint32_t still_frames_ = 0;
  std::uint32_t apnea_frames_ = 0;
};

// Result of pushing one frame through the envelope.
struct EmitResult {
  // Zero or more events the caller must deliver.  Emergencies are never
  // dropped; if delivery fails the caller re-pushes them (the envelope keeps
  // them latched until acknowledged).
  std::vector<Event> events;
  Status status = Status::Ok;
};

class PrivacyEnvelope {
 public:
  PrivacyEnvelope(const EnvelopeConfig& cfg, Classifier* classifier);
  PrivacyEnvelope(const PrivacyEnvelope&) = delete;
  PrivacyEnvelope& operator=(const PrivacyEnvelope&) = delete;

  // Entry point for the DSP block.  Takes the frame by reference and scrubs
  // it in place before returning, so the caller's buffer holds no radar data
  // after the call.  (This is the one place the envelope mutates its input,
  // and it is deliberate: "scrub on consume" must reach the original buffer,
  // not a copy.)
  EmitResult consume(RadarFrame& frame, WallUs wall_now);

  // Acknowledge that an emergency with this seq was durably delivered.  Until
  // this is called the event is re-offered on every consume().
  void ack_emergency(std::uint32_t seq);

  const EnvelopeStats& stats() const { return stats_; }

  // Feature extraction, exposed for property tests only.  Takes the frame by
  // const ref; the tests assert it does not mutate (it must not, but the
  // production path scrubs separately).
  static Features extract(const RadarFrame& frame);

 private:
  void emergency_scan(const Features& f, WallUs wall_now, EmitResult* out);
  void routine_scan(const Features& f, WallUs wall_now, EmitResult* out);
  bool accept(const Event& e, EmitResult* out);
  bool policy_allows(EventKind k) const {
    return (cfg_.allowed_event_kinds & (1u << (static_cast<std::uint32_t>(k) - 1))) != 0;
  }

  EnvelopeConfig cfg_;
  Classifier* classifier_;
  EnvelopeStats stats_;
  std::uint32_t next_seq_ = 1;
  Ticks last_classified_t_ = 0;
  bool have_last_ = false;

  // Emergency state machines.
  bool fall_candidate_ = false;
  Ticks fall_candidate_t_ = 0;
  // Slow baseline of total energy, used to detect the sudden surge of an
  // impact.  Fractional exponential moving average.
  float energy_baseline_ = 0.0f;
  bool have_baseline_ = false;
  // Peak impact seen while a fall candidate is open, for confidence scoring.
  float fall_candidate_peak_ = 0.0f;
  std::uint32_t apnea_run_start_s_ = 0;
  bool in_apnea_run_ = false;

  // Latched emergencies awaiting acknowledgement.  Bounded so a dead radio
  // cannot exhaust the MCU's tiny heap and crash the device (which would lose
  // *all* safety function).  When full, further emergencies are counted in
  // emergency_latch_overflows rather than silently dropped — an overflow fails
  // attestation, so the failure is loud, not hidden.
  std::vector<Event> pending_emergencies_;

 public:
  static constexpr std::size_t kMaxPendingEmergencies = 16;
 private:

  // Last emitted routine state, to emit only transitions.
  Activity last_activity_ = Activity::Unknown;
  BreathBand last_breath_ = BreathBand::Unknown;
  HeartBand last_heart_ = HeartBand::Unknown;
  Zone last_zone_ = Zone::Unknown;
  // Zone hysteresis: a candidate zone must persist for this many classified
  // frames before it is accepted, so a person near a boundary (or a moving
  // centroid) does not generate a flood of A/B flips.
  Zone zone_candidate_ = Zone::Unknown;
  std::uint8_t zone_candidate_frames_ = 0;
  static constexpr std::uint8_t kZoneStableFrames = 5;

  // Take a raw zone and return the stabilized zone, updating hysteresis state.
  Zone stabilize_zone(Zone raw);
};

}  // namespace rp
