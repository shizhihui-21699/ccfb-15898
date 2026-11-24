// The safety-critical tests: emergency detection must never miss, and the
// privacy invariants (no fine timing, no coordinates, raw cube scrubbed) must
// hold on every emitted event.
// SPDX-License-Identifier: Apache-2.0
#include <cstring>

#include "rp/envelope.hpp"
#include "rp/synth.hpp"
#include "test_framework.hpp"

using namespace rp;

namespace {

EnvelopeConfig default_cfg() {
  EnvelopeConfig c;
  // 10 Hz classification; scenarios feed at 10 Hz so nothing is decimated.
  c.max_frames_per_sec = 10;
  return c;
}

// Drive a scene through the envelope at `hz`, collecting every event.
struct Run {
  std::vector<Event> events;
  EnvelopeStats stats;
};

Run run_scene(const std::vector<Pose>& poses, const EnvelopeConfig& cfg, int hz = 10,
              WallUs wall0 = 1700000000000000LL) {
  ReferenceClassifier clf(cfg);
  PrivacyEnvelope env(cfg, &clf);
  Run r;
  Ticks dt = 1000000ull / hz;
  for (std::size_t i = 0; i < poses.size(); ++i) {
    RadarFrame f = synth_frame(poses[i], static_cast<Ticks>(i) * dt, static_cast<std::uint32_t>(i),
                               0x12345u + static_cast<std::uint32_t>(i));
    EmitResult er = env.consume(f, wall0 + static_cast<WallUs>(i * dt));
    for (auto& e : er.events) r.events.push_back(e);
  }
  r.stats = env.stats();
  return r;
}

bool has_kind(const Run& r, EventKind k) {
  for (auto& e : r.events)
    if (e.kind == k) return true;
  return false;
}

}  // namespace

TEST(fall_is_detected) {
  auto poses = scenes::fall_sequence(60, 20);
  Run r = run_scene(poses, default_cfg());
  CHECK(has_kind(r, EventKind::Fall));
  CHECK(r.stats.emergencies_raised >= 1);
  CHECK_EQ(r.stats.emergencies_raised, r.stats.emergencies_emitted);  // none lost
}

TEST(calm_night_has_no_emergency) {
  auto poses = scenes::calm_night(120);
  Run r = run_scene(poses, default_cfg());
  CHECK(!has_kind(r, EventKind::Fall));
  CHECK(!has_kind(r, EventKind::Apnea));
}

TEST(empty_room_has_no_events_of_concern) {
  auto poses = scenes::empty_room(60);
  Run r = run_scene(poses, default_cfg());
  CHECK(!has_kind(r, EventKind::Fall));
  CHECK(!has_kind(r, EventKind::Apnea));
}

TEST(apnea_is_detected) {
  // 120 frames at 10 Hz = 12 s; apnea from frame 10 -> ~11 s of stillness,
  // above the 8 s confirm window.
  auto poses = scenes::apnea_sequence(120, 10);
  Run r = run_scene(poses, default_cfg());
  CHECK(has_kind(r, EventKind::Apnea));
}

TEST(raw_cube_is_scrubbed_after_consume) {
  EnvelopeConfig cfg = default_cfg();
  ReferenceClassifier clf(cfg);
  PrivacyEnvelope env(cfg, &clf);
  RadarFrame f = synth_frame(scenes::calm_night(1)[0], 0, 0, 999);
  // Confirm non-zero before.
  float sum = 0;
  for (std::size_t i = 0; i < kCells; ++i) sum += f.amplitude[i];
  CHECK(sum > 0);
  env.consume(f, 0);
  // After consume, the caller's frame must be all zeros (defence in depth).
  for (std::size_t i = 0; i < kCells; ++i) {
    CHECK_EQ(f.amplitude[i], 0.0f);
    CHECK_EQ(f.velocity[i], 0.0f);
  }
}

TEST(emitted_events_have_no_fine_timing) {
  auto poses = scenes::fall_sequence(60, 20);
  Run r = run_scene(poses, default_cfg());
  CHECK(!r.events.empty());
  for (auto& e : r.events) {
    // Wall clock is quantized to whole minutes.
    CHECK_EQ(e.t_wall_us % (60LL * 1000000LL), 0LL);
    // Payload is tiny.
    CHECK(e.payload.size() <= Event::kMaxPayload);
    // Confidence is a byte.
    CHECK(e.confidence <= 100);
    // Zone is a small enum.
    CHECK(static_cast<int>(e.zone) <= 3);
  }
}

TEST(decimation_bounds_classification_but_keeps_emergency) {
  // Feed 100 Hz into a 10 Hz envelope: most frames must be decimated, yet a
  // fall embedded in the stream must still produce an event.
  EnvelopeConfig cfg = default_cfg();
  ReferenceClassifier clf(cfg);
  PrivacyEnvelope env(cfg, &clf);
  auto poses = scenes::fall_sequence(600, 300);  // 6 s at 100 Hz
  bool saw_fall = false;
  for (std::size_t i = 0; i < poses.size(); ++i) {
    RadarFrame f = synth_frame(poses[i], static_cast<Ticks>(i) * 10000ull,
                               static_cast<std::uint32_t>(i), 7u + static_cast<std::uint32_t>(i));
    EmitResult er = env.consume(f, 0);
    for (auto& e : er.events) {
      if (e.kind == EventKind::Fall) saw_fall = true;
    }
  }
  // Decimation must actually happen.
  CHECK(env.stats().frames_decimated > 0);
  CHECK(env.stats().frames_classified < env.stats().frames_in);
  // But the emergency must survive decimation.
  CHECK(saw_fall);
}

TEST(emergencies_are_repeated_until_acked) {
  auto poses = scenes::fall_sequence(40, 10);
  EnvelopeConfig cfg = default_cfg();
  ReferenceClassifier clf(cfg);
  PrivacyEnvelope env(cfg, &clf);
  std::uint32_t fall_seq = 0;
  bool found = false;
  for (std::size_t i = 0; i < poses.size() && !found; ++i) {
    RadarFrame f = synth_frame(poses[i], static_cast<Ticks>(i) * 100000ull,
                               static_cast<std::uint32_t>(i), 11u + static_cast<std::uint32_t>(i));
    EmitResult er = env.consume(f, 0);
    for (auto& e : er.events)
      if (e.kind == EventKind::Fall) {
        fall_seq = e.seq;
        found = true;
      }
  }
  CHECK(found);
  // Without ack, the emergency is re-offered on subsequent frames.
  bool reoffered = false;
  for (int i = 0; i < 3 && !reoffered; ++i) {
    RadarFrame f = synth_frame(scenes::calm_night(1)[0], 100000000ull + i * 100000ull, 1000 + i, 5);
    EmitResult er = env.consume(f, 0);
    for (auto& e : er.events)
      if (e.kind == EventKind::Fall && e.seq == fall_seq) reoffered = true;
  }
  CHECK(reoffered);
  // After ack, it stops being re-offered.
  env.ack_emergency(fall_seq);
  bool still = false;
  for (int i = 0; i < 3; ++i) {
    RadarFrame f = synth_frame(scenes::calm_night(1)[0], 200000000ull + i * 100000ull, 2000 + i, 5);
    EmitResult er = env.consume(f, 0);
    for (auto& e : er.events)
      if (e.kind == EventKind::Fall && e.seq == fall_seq) still = true;
  }
  CHECK(!still);
}

TEST(zone_and_vitals_bands_bucket_correctly) {
  CHECK_EQ(static_cast<int>(bucket_zone(0.5f)), static_cast<int>(Zone::A));
  CHECK_EQ(static_cast<int>(bucket_zone(1.5f)), static_cast<int>(Zone::B));
  CHECK_EQ(static_cast<int>(bucket_zone(2.5f)), static_cast<int>(Zone::C));
  CHECK_EQ(static_cast<int>(breath_band(2.0f)), static_cast<int>(BreathBand::Apnea));
  CHECK_EQ(static_cast<int>(breath_band(12.0f)), static_cast<int>(BreathBand::Normal));
  CHECK_EQ(static_cast<int>(breath_band(30.0f)), static_cast<int>(BreathBand::High));
  CHECK_EQ(static_cast<int>(heart_band(40.0f)), static_cast<int>(HeartBand::Low));
  CHECK_EQ(static_cast<int>(heart_band(70.0f)), static_cast<int>(HeartBand::Normal));
}

TEST(runtime_policy_gate_blocks_disallowed_kind) {
  // A policy that disallows Fall: the envelope must refuse to put a Fall on
  // the wire, count the rejection, and latch it (never silently lose it).
  EnvelopeConfig cfg = default_cfg();
  cfg.allowed_event_kinds = 0x3ff & ~(1u << (static_cast<std::uint32_t>(EventKind::Fall) - 1));
  ReferenceClassifier clf(cfg);
  PrivacyEnvelope env(cfg, &clf);
  auto poses = scenes::fall_sequence(60, 20);
  bool saw_fall_event = false;
  for (std::size_t i = 0; i < poses.size(); ++i) {
    RadarFrame f = synth_frame(poses[i], static_cast<Ticks>(i) * 100000ull,
                               static_cast<std::uint32_t>(i), 3u + static_cast<std::uint32_t>(i));
    EmitResult er = env.consume(f, 0);
    for (auto& e : er.events)
      if (e.kind == EventKind::Fall) saw_fall_event = true;
  }
  CHECK(!saw_fall_event);                          // never emitted
  CHECK(env.stats().schema_rejections > 0);        // rejection recorded
  CHECK(env.stats().emergencies_raised > 0);       // still recognized as an emergency
  CHECK(env.stats().emergencies_emitted == 0);     // but not emitted
  // A policy-disallowed emergency is NOT latched (that would retry forever);
  // it surfaces as suppressed = raised - emitted, which fails attestation.
  CHECK(env.stats().emergencies_pending == 0);
  CHECK(env.stats().emergencies_raised > env.stats().emergencies_emitted);
}

TEST(unacked_emergencies_are_bounded_and_counted) {
  // A persistently dead radio must not let the latch grow without bound (which
  // would OOM a 512 KiB MCU and lose *all* safety function).  The latch is
  // capped and the overflow is counted so attestation fails loudly.
  EnvelopeConfig cfg = default_cfg();
  ReferenceClassifier clf(cfg);
  PrivacyEnvelope env(cfg, &clf);
  for (int cycle = 0; cycle < 50; ++cycle) {
    auto poses = scenes::fall_sequence(40, 10);
    for (std::size_t i = 0; i < poses.size(); ++i) {
      RadarFrame f = synth_frame(poses[i], static_cast<Ticks>(cycle * 40 + i) * 100000ull,
                                 static_cast<std::uint32_t>(cycle * 40 + i), 3u);
      env.consume(f, 1700000000000000LL);  // never ack
    }
  }
  CHECK(env.stats().emergencies_pending <= PrivacyEnvelope::kMaxPendingEmergencies);
  CHECK(env.stats().emergency_latch_overflows > 0);  // the overflow is visible
}

TEST(event_roundtrip_body) {  Event e = make_apnea_event(7, 123456, 1700000000000000LL, Zone::B, 66, 42);
  Bytes body = encode_event_body(e);
  Event d;
  CHECK(ok(decode_event_body(Slice(body), &d)));
  CHECK_EQ(d.seq, e.seq);
  CHECK_EQ(d.t_device_us, e.t_device_us);
  CHECK_EQ(static_cast<int>(d.kind), static_cast<int>(e.kind));
  CHECK_BYTES(d.payload, e.payload);
  // Corrupt magic must fail.
  body[0] = 'X';
  CHECK(!ok(decode_event_body(Slice(body), &d)));
}
