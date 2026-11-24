// Synthetic radar frame generator.
//
// Used by the simulator and the test suite to drive the envelope with
// realistic-enough data.  The scenes are scripted so tests can assert on
// expected outcomes (e.g. "a fall must produce a Fall event within N ms").
//
// This lives in its own translation unit precisely so it is NOT linked into
// a production firmware image; the production device feeds real DSP output.
#pragma once

#include "rp/radar.hpp"

namespace rp {

// A scripted scene: a sequence of poses the "resident" takes.  Each pose
// shapes the reflectivity cube (where energy sits in range, how much motion
// there is in Doppler, whether there is an impact).
struct Pose {
  float range_m = 2.0f;        // distance of the dominant reflector
  float motion = 0.05f;        // 0..1 doppler spread
  float amplitude = 80.0f;     // peak linear magnitude
  bool impact = false;         // inject a broadband fall impact
  float breath_bpm = 16.0f;    // modulates phase proxy
  bool present = true;
};

// Build a frame at time t (us) and sequence seq for the given pose.
RadarFrame synth_frame(const Pose& pose, Ticks t_us, std::uint32_t seq,
                       std::uint32_t rng_state);

// A few canned scenarios used across tests and the demo.
namespace scenes {
// A calm night: presence, still, normal vitals, no events beyond transitions.
std::vector<Pose> calm_night(std::size_t frames);
// An empty room.
std::vector<Pose> empty_room(std::size_t frames);
// A fall: walking, then an impact, then immobility.
std::vector<Pose> fall_sequence(std::size_t frames, std::size_t fall_at);
// Apnea: still and present, then no chest movement for a long stretch.
std::vector<Pose> apnea_sequence(std::size_t frames, std::size_t apnea_at);
}  // namespace scenes

}  // namespace rp
