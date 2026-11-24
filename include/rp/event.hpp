// The complete set of things this device is ever allowed to emit.
//
// This header is the privacy contract.  Every field below must be justified
// to the care home, to the resident, and — via `radpriv verify` — to a
// regulator.  Nothing here describes where in the room something happened,
// what the person was doing beyond a coarse activity class, or any raw signal.
//
// Design rules encoded in the types themselves:
//   * No float in a wire type.  Floats have many encodings per value and can
//     smuggle mantissa bits; events use integer fields with documented units.
//   * No free-form strings.  Strings are where PII leaks in.
//   * Every event carries only a coarse zone bucket (0..3), never coordinates.
//   * Vitals are bucketed to clinical bands, not reported to 0.1 bpm, because
//     a precise vitals trace is itself biometric-identifying.
#pragma once

#include "rp/common.hpp"
#include "rp/radar.hpp"

namespace rp {

// The wire event kinds.  Adding a kind is a policy change: the signed policy
// in the module header enumerates exactly these.
enum class EventKind : std::uint8_t {
  Heartbeat = 1,      // device liveness / chain anchor, no PII
  Occupancy = 2,      // someone in room, coarse
  ActivityChange = 3, // coarse activity class transition
  Fall = 4,           // emergency
  Apnea = 5,          // emergency
  VitalsBand = 6,     // coarse vitals bucket, no raw trace
  RoomState = 7,      // room-level environmental summary
  // Privacy-specific control events (always emitted, never suppressed).
  PipelineDrop = 8,   // the envelope refused to classify some frames
  SelfTest = 9,       // boot-time cryptographic self-test result
};

const char* to_string(EventKind k);
bool event_kind_from_string(std::string_view s, EventKind* out);

// Coarse zone bucket.  Four buckets only — enough to route a caregiver,
// not enough to reconstruct movement through the room.
enum class Zone : std::uint8_t { Unknown = 0, A = 1, B = 2, C = 3 };

// Clinically meaningful bands.  A precise 14.3 bpm would be a fingerprint;
// "normal-range 12..20" is what a caregiver actually acts on.
enum class BreathBand : std::uint8_t { Unknown = 0, Apnea = 1, Low = 2, Normal = 3, High = 4 };
enum class HeartBand : std::uint8_t { Unknown = 0, Low = 1, Normal = 2, High = 3 };

const char* to_string(Zone z);
const char* to_string(BreathBand b);
const char* to_string(HeartBand b);
const char* to_string(Activity a);

// A single emitted event.  This is the ONLY structure that crosses the trust
// boundary out of the device.  `payload` is a small, kind-specific byte
// string with a fixed schema (see event.cpp); it deliberately has no room for
// coordinates, timings finer than the minute, or free text.
struct Event {
  EventKind kind = EventKind::Heartbeat;
  std::uint32_t seq = 0;       // monotonic per device
  Ticks t_device_us = 0;       // monotonic capture time (for ordering)
  WallUs t_wall_us = 0;        // coarse wall clock (minute granularity on wire)
  Zone zone = Zone::Unknown;
  std::uint8_t confidence = 0; // 0..100
  Bytes payload;               // <= kMaxPayload bytes

  static constexpr std::size_t kMaxPayload = 32;
};

// Serialize an event with its canonical framing (no signature).
Bytes encode_event_body(const Event& e);
Status decode_event_body(Slice body, Event* out);

// Canonical, architecture-independent serialization of a vitals band update.
// Kept tiny: the emergency path may need to emit one per second on a bus with
// limited bandwidth.
Event make_fall_event(std::uint32_t seq, Ticks t, WallUs wall, Zone z, std::uint8_t conf);
Event make_apnea_event(std::uint32_t seq, Ticks t, WallUs wall, Zone z,
                       std::uint8_t conf, std::uint32_t apnea_seconds);
Event make_vitals_event(std::uint32_t seq, Ticks t, WallUs wall, Zone z,
                        BreathBand b, HeartBand h, std::uint8_t conf);

// Coarse mapping helpers.  These are where privacy is enforced: a continuous
// quantity is collapsed to a small enum before it can ever be emitted.
//   * The centroid band (0..3, continuous) becomes one of four zones.
//   * Breath rate maps to clinical bands only; precise bpm never escapes.
//   * Heart rate likewise.
Zone bucket_zone(float centroid_band);
BreathBand breath_band(float bpm);
HeartBand heart_band(float bpm);

// Quantize a wall-clock timestamp to whole minutes.  This is the single
// chokepoint that prevents sub-minute timing (a covert activity channel) from
// ever entering an event.  Every event constructor routes through it.
WallUs quantize_wall(WallUs t);

}  // namespace rp
