// SPDX-License-Identifier: Apache-2.0
#include "rp/event.hpp"

namespace rp {

const char* to_string(EventKind k) {
  switch (k) {
    case EventKind::Heartbeat: return "heartbeat";
    case EventKind::Occupancy: return "occupancy";
    case EventKind::ActivityChange: return "activity";
    case EventKind::Fall: return "fall";
    case EventKind::Apnea: return "apnea";
    case EventKind::VitalsBand: return "vitals";
    case EventKind::RoomState: return "room";
    case EventKind::PipelineDrop: return "pipeline-drop";
    case EventKind::SelfTest: return "self-test";
  }
  return "unknown";
}

bool event_kind_from_string(std::string_view s, EventKind* out) {
  if (s == "heartbeat") *out = EventKind::Heartbeat;
  else if (s == "occupancy") *out = EventKind::Occupancy;
  else if (s == "activity") *out = EventKind::ActivityChange;
  else if (s == "fall") *out = EventKind::Fall;
  else if (s == "apnea") *out = EventKind::Apnea;
  else if (s == "vitals") *out = EventKind::VitalsBand;
  else if (s == "room") *out = EventKind::RoomState;
  else if (s == "pipeline-drop") *out = EventKind::PipelineDrop;
  else if (s == "self-test") *out = EventKind::SelfTest;
  else return false;
  return true;
}

const char* to_string(Zone z) {
  switch (z) {
    case Zone::Unknown: return "unknown";
    case Zone::A: return "A";
    case Zone::B: return "B";
    case Zone::C: return "C";
  }
  return "unknown";
}

const char* to_string(BreathBand b) {
  switch (b) {
    case BreathBand::Unknown: return "unknown";
    case BreathBand::Apnea: return "apnea";
    case BreathBand::Low: return "low";
    case BreathBand::Normal: return "normal";
    case BreathBand::High: return "high";
  }
  return "unknown";
}

const char* to_string(HeartBand b) {
  switch (b) {
    case HeartBand::Unknown: return "unknown";
    case HeartBand::Low: return "low";
    case HeartBand::Normal: return "normal";
    case HeartBand::High: return "high";
  }
  return "unknown";
}

const char* to_string(Activity a) {
  switch (a) {
    case Activity::Empty: return "empty";
    case Activity::Still: return "still";
    case Activity::Active: return "active";
    case Activity::Fall: return "fall";
    case Activity::Unknown: return "unknown";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// Canonical event body framing.
//
//   magic(2='EP') | version(1) | kind(1) | seq(4) | t_dev(8) | t_wall(8)
//   | zone(1) | confidence(1) | payload_len(1) | payload
//
// Note t_wall is stored at minute granularity on the wire (low bits masked),
// enforced below.  This blocks a covert channel that encodes activity in the
// microsecond field.
// ---------------------------------------------------------------------------
namespace {
constexpr std::uint8_t kEventVersion = 1;
constexpr std::uint64_t kMinuteUs = 60ull * 1000000ull;
}  // namespace

WallUs quantize_wall(WallUs t) {
  // Non-negative assumption holds for any real deployment (post-1970 clocks).
  // The modulo is well-defined for negative t in C++ too, so this is safe.
  WallUs q = t - t % static_cast<WallUs>(kMinuteUs);
  return q;
}

Bytes encode_event_body(const Event& e) {
  Bytes out;
  out.reserve(26 + e.payload.size());
  out.push_back('E');
  out.push_back('P');
  out.push_back(kEventVersion);
  out.push_back(static_cast<std::uint8_t>(e.kind));
  put_be32(&out, e.seq);
  put_be64(&out, e.t_device_us);
  // Wall clock is quantized to whole minutes: no fine-grained timing leaves
  // the device.  (Negative pre-1970 values are impossible on this platform.)
  std::uint64_t wall = static_cast<std::uint64_t>(e.t_wall_us);
  wall -= wall % kMinuteUs;
  put_be64(&out, wall);
  out.push_back(static_cast<std::uint8_t>(e.zone));
  out.push_back(e.confidence);
  out.push_back(static_cast<std::uint8_t>(e.payload.size()));
  append(&out, Slice(e.payload));
  return out;
}

Status decode_event_body(Slice body, Event* out) {
  constexpr std::size_t kHeader = 27;
  if (body.n < kHeader) return Status::Truncated;
  if (body.p[0] != 'E' || body.p[1] != 'P') return Status::BadMagic;
  if (body.p[2] != kEventVersion) return Status::BadVersion;
  std::uint8_t kind = body.p[3];
  if (kind < 1 || kind > 9) return Status::BadTag;
  out->kind = static_cast<EventKind>(kind);
  out->seq = get_be32(body.p + 4);
  out->t_device_us = get_be64(body.p + 8);
  out->t_wall_us = static_cast<WallUs>(get_be64(body.p + 16));
  out->zone = static_cast<Zone>(body.p[24]);
  out->confidence = body.p[25];
  std::size_t plen = body.p[26];
  if (body.n != kHeader + plen) return Status::BadLength;
  out->payload.assign(body.p + kHeader, body.p + kHeader + plen);
  return Status::Ok;
}

Event make_fall_event(std::uint32_t seq, Ticks t, WallUs wall, Zone z, std::uint8_t conf) {
  Event e;
  e.kind = EventKind::Fall;
  e.seq = seq;
  e.t_device_us = t;
  e.t_wall_us = quantize_wall(wall);
  e.zone = z;
  e.confidence = conf;
  return e;
}

Event make_apnea_event(std::uint32_t seq, Ticks t, WallUs wall, Zone z, std::uint8_t conf,
                       std::uint32_t apnea_seconds) {
  Event e;
  e.kind = EventKind::Apnea;
  e.seq = seq;
  e.t_device_us = t;
  e.t_wall_us = quantize_wall(wall);
  e.zone = z;
  e.confidence = conf;
  put_be32(&e.payload, apnea_seconds);
  return e;
}

Event make_vitals_event(std::uint32_t seq, Ticks t, WallUs wall, Zone z, BreathBand b,
                        HeartBand h, std::uint8_t conf) {
  Event e;
  e.kind = EventKind::VitalsBand;
  e.seq = seq;
  e.t_device_us = t;
  e.t_wall_us = quantize_wall(wall);
  e.zone = z;
  e.confidence = conf;
  e.payload.push_back(static_cast<std::uint8_t>(b));
  e.payload.push_back(static_cast<std::uint8_t>(h));
  return e;
}

// ---------------------------------------------------------------------------
// Coarse mapping helpers: the privacy-preserving quantizers.
// ---------------------------------------------------------------------------
Zone bucket_zone(float centroid_band) {
  // centroid_band is 0..3; map to the three non-empty zones (A/B/C), with a
  // small dead-band so a person standing on a boundary does not flap.  The
  // mapping deliberately discards sub-band position.
  if (centroid_band < 0.15f || centroid_band > 2.95f) return Zone::Unknown;
  if (centroid_band < 1.0f) return Zone::A;
  if (centroid_band < 2.0f) return Zone::B;
  return Zone::C;
}

BreathBand breath_band(float bpm) {
  // Clinical bands: apnea (<4), bradypnea (4..<10), normal (10..25),
  // tachypnea (>25).  No fractional bpm leaves this function.
  if (bpm <= 0.0f) return BreathBand::Unknown;
  if (bpm < 4.0f) return BreathBand::Apnea;
  if (bpm < 10.0f) return BreathBand::Low;
  if (bpm <= 25.0f) return BreathBand::Normal;
  return BreathBand::High;
}

HeartBand heart_band(float bpm) {
  // Coarse cardiac bands: bradycardia (<50), normal (50..100), tachycardia.
  if (bpm <= 0.0f) return HeartBand::Unknown;
  if (bpm < 50.0f) return HeartBand::Low;
  if (bpm <= 100.0f) return HeartBand::Normal;
  return HeartBand::High;
}

}  // namespace rp
