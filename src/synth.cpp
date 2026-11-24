// SPDX-License-Identifier: Apache-2.0
#include "rp/synth.hpp"

#include <cmath>
#include <cstring>

namespace rp {

namespace {
// xorshift32: deterministic, so scenes are reproducible across platforms.
std::uint32_t xs(std::uint32_t s) {
  s ^= s << 13;
  s ^= s >> 17;
  s ^= s << 5;
  return s;
}
float frand(std::uint32_t* s) {
  *s = xs(*s);
  return static_cast<float>(*s & 0xffffff) / static_cast<float>(0x1000000);
}
}  // namespace

RadarFrame synth_frame(const Pose& pose, Ticks t_us, std::uint32_t seq,
                       std::uint32_t rng_state) {
  RadarFrame f;
  f.t = t_us;
  f.seq = seq;
  f.noise_floor = 0.6f;
  f.range_res_m = 0.15f;  // 0.15 m/bin -> ~4.8 m unambiguous range, a room

  // Background: a low noise field that sits *below* the declared noise floor,
  // as real CFAR output does.  Nothing here should register as signal.
  std::uint32_t s = rng_state;
  for (std::size_t i = 0; i < kCells; ++i) {
    f.amplitude[i] = 0.3f + frand(&s) * 0.25f;  // 0.30..0.55, all < 0.6
    f.velocity[i] = (frand(&s) - 0.5f) * 0.2f;
  }

  if (!pose.present) return f;

  // A person: a cluster of energy centered on the pose's range, spread over
  // the Doppler axis according to motion.  Add breath modulation as a slow
  // wobble of the cluster amplitude over time.
  float center_bin = pose.range_m / f.range_res_m;
  float breath_phase = std::sin(static_cast<double>(t_us) * 1e-6 *
                                static_cast<double>(pose.breath_bpm) * 3.14159265 / 30.0);
  float amp = pose.amplitude * (0.9f + 0.1f * breath_phase);

  for (std::size_t r = 0; r < kRangeBins; ++r) {
    float dr = (static_cast<float>(r) - center_bin) / 2.0f;
    float range_falloff = std::exp(-dr * dr);
    for (std::size_t d = 0; d < kDopplerBins; ++d) {
      float dcenter = static_cast<float>(kDopplerBins) * 0.5f;
      float spread = 0.5f + pose.motion * 6.0f;
      float dd = (static_cast<float>(d) - dcenter) / spread;
      float doppler_falloff = std::exp(-dd * dd);
      f.amplitude[r * kDopplerBins + d] += amp * range_falloff * doppler_falloff;
      f.velocity[r * kDopplerBins + d] = (static_cast<float>(d) - dcenter) * 0.05f;
    }
  }

  // Impact: a one-frame broadband, high-amplitude burst across many bins.
  if (pose.impact) {
    for (std::size_t r = 0; r < kRangeBins; ++r) {
      for (std::size_t d = 0; d < kDopplerBins; ++d) {
        f.amplitude[r * kDopplerBins + d] += 400.0f + frand(&s) * 100.0f;
      }
    }
  }
  return f;
}

namespace scenes {

std::vector<Pose> calm_night(std::size_t frames) {
  std::vector<Pose> v(frames);
  for (auto& p : v) {
    p.present = true;
    p.range_m = 2.1f;
    p.motion = 0.02f;
    p.amplitude = 70.0f;
    p.breath_bpm = 15.0f;
  }
  return v;
}

std::vector<Pose> empty_room(std::size_t frames) {
  std::vector<Pose> v(frames);
  for (auto& p : v) p.present = false;
  return v;
}

std::vector<Pose> fall_sequence(std::size_t frames, std::size_t fall_at) {
  std::vector<Pose> v(frames);
  for (std::size_t i = 0; i < frames; ++i) {
    Pose& p = v[i];
    p.present = true;
    p.range_m = 2.0f;
    p.amplitude = 80.0f;
    p.breath_bpm = 16.0f;
    if (i < fall_at) {
      p.motion = 0.5f;   // walking: a slow back-and-forth, not a sawtooth
      float phase = static_cast<float>(i) * 0.15f;
      p.range_m = 1.6f + 0.4f * std::sin(phase);
    } else if (i == fall_at) {
      p.motion = 0.9f;
      p.impact = true;   // the impact frame
    } else {
      p.motion = 0.01f;  // immobile on the floor
      p.range_m = 1.2f;
    }
  }
  return v;
}

std::vector<Pose> apnea_sequence(std::size_t frames, std::size_t apnea_at) {
  std::vector<Pose> v(frames);
  for (std::size_t i = 0; i < frames; ++i) {
    Pose& p = v[i];
    p.present = true;
    p.range_m = 2.1f;
    p.amplitude = 70.0f;
    if (i < apnea_at) {
      p.motion = 0.03f;
      p.breath_bpm = 15.0f;
    } else {
      // Chest stops moving: motion energy collapses, no breath modulation.
      p.motion = 0.0f;
      p.breath_bpm = 0.0f;
      p.amplitude = 70.0f;
    }
  }
  return v;
}

}  // namespace scenes
}  // namespace rp
