// Radar front end: a deliberately small, dependency-free model of what the
// device's DSP block hands to the application processor.
//
// The real hardware produces a range-Doppler cube per coherent processing
// interval (CPI).  We model the post-FFT, post-CFAR output as a dense grid of
// reflectivity cells plus per-cell radial velocity, because that is the
// richest form the privacy envelope will ever see, and therefore the hardest
// case to make private.  Everything downstream is strictly a function of this
// buffer; if the envelope can hide PII here, it can hide it in any larger
// representation.
#pragma once

#include "rp/common.hpp"

namespace rp {

// Cube geometry.  Chosen to match a single 60 GHz FMCW chip with 4 Rx and a
// 32-point slow-time FFT: 32 range bins x 16 Doppler bins.  A cell is one
// (range, doppler) pair; amplitude is linear magnitude (not dB) so the
// classifier's thresholds are independent of the front-end's log mapping.
constexpr std::size_t kRangeBins = 32;
constexpr std::size_t kDopplerBins = 16;
constexpr std::size_t kCells = kRangeBins * kDopplerBins;

struct RadarFrame {
  Ticks t = 0;                       // capture timestamp, monotonic us
  std::uint32_t seq = 0;             // frame counter, detects drops
  float amplitude[kCells] = {};      // linear magnitude per (range, doppler)
  float velocity[kCells] = {};       // m/s, signed, per cell
  float range_res_m = 0.05f;         // metres per range bin
  float noise_floor = 0.0f;          // estimated per-frame noise floor
};

// One point-cloud detection, the conventional "sparse" output.
struct Detection {
  float range_m = 0.0f;
  float velocity_mps = 0.0f;
  float snr_db = 0.0f;
  float azimuth_rad = 0.0f;
  float elevation_rad = 0.0f;
};

// ACPI-style presence/activity summary derived from a window of frames.
enum class Activity : std::uint8_t {
  Empty = 0,
  Still = 1,       // present, low motion — sleep or seated
  Active = 2,      // walking, transfers
  Fall = 3,        // impact + post-impact immobility
  Unknown = 15,
};

const char* to_string(Activity a);
inline bool activity_from_string(std::string_view s, Activity* out);

struct Occupancy {
  std::uint32_t persons = 0;
  float motion_energy = 0.0f;   // 0..1 normalized
  float centroid_m = 0.0f;      // range centroid of energy
};

// Vitals derived from the phase of the chest-wall return.
struct VitalsSnapshot {
  float breath_bpm = 0.0f;
  float heart_bpm = 0.0f;
  float breath_confidence = 0.0f;   // 0..1
  float heart_confidence = 0.0f;
  bool apnea_suspected = false;
  std::uint32_t apnea_seconds = 0;
};

}  // namespace rp
