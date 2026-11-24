// SPDX-License-Identifier: Apache-2.0
#include "rp/envelope.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace rp {
namespace {

// Aggregate the raw cube into the four coarse range bands.  This is the
// irreversibility point: after this function the per-cell structure is gone,
// and the four band energies are the *only* spatial information that survives.
void band_energies(const RadarFrame& f, float out_db[4]) {
  float band_sum[4] = {0, 0, 0, 0};
  constexpr std::size_t kBandBins = kRangeBins / 4;  // 8 bins each
  for (std::size_t r = 0; r < kRangeBins; ++r) {
    float e = 0.0f;
    for (std::size_t d = 0; d < kDopplerBins; ++d) e += f.amplitude[r * kDopplerBins + d];
    std::size_t band = r / kBandBins;
    if (band > 3) band = 3;
    band_sum[band] += e;
  }
  float floor = f.noise_floor > 1e-6f ? f.noise_floor : 1e-6f;
  for (int b = 0; b < 4; ++b) {
    float ratio = band_sum[b] / (floor * static_cast<float>(kBandBins * kDopplerBins));
    out_db[b] = 10.0f * std::log10(ratio + 1e-6f);
  }
}

// Motion energy: how much of the *above-floor* energy is in moving Doppler
// bins.  Doppler is where movement lives; static clutter sits at DC.  The
// noise floor is subtracted per cell so uniform sensor noise does not read as
// motion — only structure above the floor counts.
float motion_from_cube(const RadarFrame& f) {
  float moving = 0.0f, total = 0.0f;
  float floor = f.noise_floor > 1e-6f ? f.noise_floor : 1e-6f;
  for (std::size_t r = 0; r < kRangeBins; ++r) {
    for (std::size_t d = 0; d < kDopplerBins; ++d) {
      float excess = f.amplitude[r * kDopplerBins + d] - floor;
      if (excess <= 0.0f) continue;
      total += excess;
      if (d != 0 && d != kDopplerBins / 2) moving += excess;
    }
  }
  if (total <= 1e-6f) return 0.0f;
  return std::min(1.0f, moving / total);
}

// Total energy above the noise floor, linear.  This is what a fall makes spike.
float total_above_floor(const RadarFrame& f) {
  float floor = f.noise_floor > 1e-6f ? f.noise_floor : 1e-6f;
  float total = 0.0f;
  for (std::size_t i = 0; i < kCells; ++i) {
    float excess = f.amplitude[i] - floor;
    if (excess > 0.0f) total += excess;
  }
  return total;
}

// Range centroid mapped to the 0..3 band coordinate, continuous.  Computed
// over above-floor energy so the noise field's flat distribution does not
// drag the centroid to the middle of the room.
float centroid_band(const RadarFrame& f) {
  float num = 0.0f, den = 0.0f;
  float floor = f.noise_floor > 1e-6f ? f.noise_floor : 1e-6f;
  for (std::size_t r = 0; r < kRangeBins; ++r) {
    float e = 0.0f;
    for (std::size_t d = 0; d < kDopplerBins; ++d) {
      float excess = f.amplitude[r * kDopplerBins + d] - floor;
      if (excess > 0.0f) e += excess;
    }
    float coord = static_cast<float>(r) * 4.0f / static_cast<float>(kRangeBins);
    num += coord * e;
    den += e;
  }
  if (den <= 1e-6f) return 0.0f;
  return num / den;
}

}  // namespace

// ---------------------------------------------------------------------------
// Feature extraction
// ---------------------------------------------------------------------------
Features PrivacyEnvelope::extract(const RadarFrame& f) {
  Features feat;
  feat.t = f.t;
  feat.seq = f.seq;
  band_energies(f, feat.band_energy_db);
  feat.motion_energy = motion_from_cube(f);
  feat.centroid_band = centroid_band(f);
  feat.total_energy = total_above_floor(f);
  feat.valid = true;

  // Height proxy: energy concentrated in the near bands implies the subject
  // is low (floor); energy spread into far bands implies standing/ambulatory.
  float near = feat.band_energy_db[0] + feat.band_energy_db[1];
  float far = feat.band_energy_db[2] + feat.band_energy_db[3];
  feat.height_score = std::min(1.0f, std::max(0.0f, (far - near) / 20.0f + 0.5f));

  // impact_score is stateful (needs a baseline), so it is filled in by the
  // envelope after extraction; leave it zero here.
  return feat;
}

// ---------------------------------------------------------------------------
// Reference classifier
// ---------------------------------------------------------------------------
Activity ReferenceClassifier::classify(const Features& f, VitalsSnapshot* vitals) {
  if (vitals) *vitals = VitalsSnapshot{};

  // Presence is any band meaningfully above its floor.
  float strongest = std::max({f.band_energy_db[0], f.band_energy_db[1],
                              f.band_energy_db[2], f.band_energy_db[3]});

  if (strongest < 3.0f) {
    still_frames_ = 0;
    apnea_frames_ = 0;
    return Activity::Empty;
  }

  if (f.impact_score > cfg_.fall_impact_threshold) return Activity::Fall;

  // Distinguish still from active by motion energy with hysteresis so a
  // sleeping resident does not flap between states on a twitch.
  if (f.motion_energy > 0.18f) {
    still_frames_ = 0;
    return Activity::Active;
  }
  ++still_frames_;
  return still_frames_ > 2 ? Activity::Still : Activity::Active;
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------
PrivacyEnvelope::PrivacyEnvelope(const EnvelopeConfig& cfg, Classifier* classifier)
    : cfg_(cfg), classifier_(classifier) {}

EmitResult PrivacyEnvelope::consume(RadarFrame& frame, WallUs wall_now) {
  EmitResult result;
  ++stats_.frames_in;

  // 1. Feature extraction (cheap and content-based) happens before the
  //    decimation decision so an impact frame is never rate-limited away.
  Features f = extract(frame);

  // Stateful impact score: the surge of total energy over a slow baseline.
  // A fall is a single huge impulse (many times the baseline); ordinary
  // activity is a modest wobble.  Confidence saturates so a walking frame
  // (maybe 2-3x baseline) does not trip the threshold.
  if (!have_baseline_) {
    energy_baseline_ = f.total_energy > 0.0f ? f.total_energy : 1.0f;
    have_baseline_ = true;
    f.impact_score = 0.0f;
  } else {
    float ratio = f.total_energy / (energy_baseline_ + 1.0f);
    // Map an 8x surge to full scale, 1x to zero.
    f.impact_score = std::min(1.0f, std::max(0.0f, (ratio - 1.0f) / 7.0f));
    // Update the baseline only on non-impact frames, so the impact itself does
    // not immediately poison the reference it is measured against.
    if (f.impact_score < 0.5f) {
      energy_baseline_ = 0.9f * energy_baseline_ + 0.1f * f.total_energy;
      if (energy_baseline_ < 1.0f) energy_baseline_ = 1.0f;
    }
  }

  bool forced_emergency = f.impact_score > cfg_.fall_impact_threshold;

  bool too_soon = false;
  if (have_last_) {
    Ticks min_gap_us = 1000000ull / (cfg_.max_frames_per_sec ? cfg_.max_frames_per_sec : 1);
    too_soon = (frame.t - last_classified_t_) < min_gap_us;
  }
  if (too_soon && !forced_emergency) {
    ++stats_.frames_decimated;
    // Still emit any latched emergency: decimation never blocks an emergency.
    for (const auto& e : pending_emergencies_) result.events.push_back(e);
    secure_wipe(frame.amplitude, sizeof(frame.amplitude));
    secure_wipe(frame.velocity, sizeof(frame.velocity));
    return result;
  }

  last_classified_t_ = frame.t;
  have_last_ = true;
  ++stats_.frames_classified;

  // 2. Scrub the raw cube now that features are extracted.  After this point
  //    there is no buffer anywhere holding the original reflectivity map.
  secure_wipe(frame.amplitude, sizeof(frame.amplitude));
  secure_wipe(frame.velocity, sizeof(frame.velocity));

  // 3. Re-offer latched emergencies (latency: immediate, never dropped).
  for (const auto& e : pending_emergencies_) result.events.push_back(e);

  // 4. Emergency path runs first and unconditionally.
  emergency_scan(f, wall_now, &result);

  // 5. Routine path emits only transitions.
  routine_scan(f, wall_now, &result);

  stats_.events_out += result.events.size();
  return result;
}

void PrivacyEnvelope::emergency_scan(const Features& f, WallUs wall_now, EmitResult* out) {
  // --- Fall: impulse followed by sustained immobility ----------------------
  if (f.impact_score > cfg_.fall_impact_threshold) {
    fall_candidate_ = true;
    fall_candidate_t_ = f.t;
    fall_candidate_peak_ = f.impact_score;
  } else if (fall_candidate_) {
    Ticks elapsed_us = f.t - fall_candidate_t_;
    if (elapsed_us >= Ticks(cfg_.fall_confirm_ms) * 1000ull) {
      // Immobility after the impact confirms a fall (vs. e.g. a dropped tray,
      // which is followed by renewed activity).  Motion is measured relative to
      // the person, so a still body reads near zero even with sensor noise.
      if (f.motion_energy < cfg_.fall_immobility_threshold) {
        float peak = std::max(fall_candidate_peak_, f.impact_score);
        std::uint8_t conf = static_cast<std::uint8_t>(std::min(100.0f, 50.0f + peak * 50.0f));
        if (conf >= cfg_.min_emergency_confidence) {
          Event e = make_fall_event(next_seq_++, f.t, wall_now, bucket_zone(f.centroid_band), conf);
          ++stats_.emergencies_raised;
          if (!policy_allows(e.kind)) {
            // A policy that forbids Fall is a configuration error, not a
            // runtime delivery failure.  Do NOT latch (that would retry
            // forever); count it as suppressed so attestation fails loudly.
            ++stats_.schema_rejections;
          } else if (pending_emergencies_.size() < kMaxPendingEmergencies) {
            // The emergency is both emitted now AND latched.  It stays latched
            // (re-offered on every subsequent frame) until the delivery layer
            // acknowledges it, so a transient bus failure cannot lose it.
            pending_emergencies_.push_back(e);
            ++stats_.emergencies_pending;
            if (accept(e, out)) ++stats_.emergencies_emitted;
          } else {
            // Latch full: a persistently dead radio has filled the bounded
            // queue.  Emit this one best-effort and count the overflow so
            // attestation fails loudly rather than the MCU crashing.
            ++stats_.emergency_latch_overflows;
            if (accept(e, out)) ++stats_.emergencies_emitted;
          }
        }
      }
      fall_candidate_ = false;
      fall_candidate_peak_ = 0.0f;
    }
  }

  // --- Apnea: no breathing displacement for apnea_confirm_seconds ---------
  // "Still" here means relative motion below a small fraction; the threshold
  // is on the person-relative motion, not absolute sensor noise.
  const bool still = f.motion_energy < 0.05f && f.impact_score < 0.3f;
  if (still) {
    std::uint32_t now_s = static_cast<std::uint32_t>(f.t / 1000000ull);
    if (!in_apnea_run_) {
      in_apnea_run_ = true;
      apnea_run_start_s_ = now_s;
    } else if (now_s - apnea_run_start_s_ >= cfg_.apnea_confirm_seconds) {
      std::uint32_t dur = now_s - apnea_run_start_s_;
      std::uint8_t conf = 60;
      Event e = make_apnea_event(next_seq_++, f.t, wall_now, bucket_zone(f.centroid_band),
                                 conf, dur);
      ++stats_.emergencies_raised;
      if (!policy_allows(e.kind)) {
        ++stats_.schema_rejections;
      } else if (pending_emergencies_.size() >= kMaxPendingEmergencies) {
        ++stats_.emergency_latch_overflows;
        if (accept(e, out)) ++stats_.emergencies_emitted;
        in_apnea_run_ = false;
      } else {
        pending_emergencies_.push_back(e);
        ++stats_.emergencies_pending;
        if (accept(e, out)) {
          ++stats_.emergencies_emitted;
          // Reset so we do not spam; the next fires after another full interval.
          in_apnea_run_ = false;
        }
      }
    }
  } else {
    in_apnea_run_ = false;
  }
}

Zone PrivacyEnvelope::stabilize_zone(Zone raw) {
  // First ever zone is accepted immediately (so we report presence promptly).
  if (last_zone_ == Zone::Unknown) {
    zone_candidate_ = raw;
    zone_candidate_frames_ = 0;
    return raw;
  }
  if (raw == last_zone_) {
    zone_candidate_ = raw;
    zone_candidate_frames_ = 0;
    return last_zone_;
  }
  if (raw != zone_candidate_) {
    zone_candidate_ = raw;
    zone_candidate_frames_ = 1;
  } else if (zone_candidate_frames_ < 255) {
    ++zone_candidate_frames_;
  }
  if (zone_candidate_frames_ >= kZoneStableFrames) {
    zone_candidate_frames_ = 0;
    return zone_candidate_;
  }
  return last_zone_;
}

void PrivacyEnvelope::routine_scan(const Features& f, WallUs wall_now, EmitResult* out) {
  VitalsSnapshot vitals;
  Activity act = classifier_->classify(f, &vitals);

  Zone z = stabilize_zone(bucket_zone(f.centroid_band));
  if (act != last_activity_ || z != last_zone_) {
    Event e;
    e.kind = EventKind::ActivityChange;
    e.seq = next_seq_++;
    e.t_device_us = f.t;
    e.t_wall_us = quantize_wall(wall_now);
    e.zone = z;
    e.confidence = 80;
    e.payload.push_back(static_cast<std::uint8_t>(act));
    if (accept(e, out)) {
      last_activity_ = act;
      last_zone_ = z;
    }
  }

  // Vitals bands, only when confidence is meaningful, only on change.
  if (vitals.breath_confidence > 0.4f) {
    BreathBand b = breath_band(vitals.breath_bpm);
    HeartBand h = heart_band(vitals.heart_bpm);
    if (b != last_breath_ || h != last_heart_) {
      std::uint8_t conf = static_cast<std::uint8_t>(vitals.breath_confidence * 100.0f);
      Event e = make_vitals_event(next_seq_++, f.t, wall_now, z, b, h, conf);
      if (accept(e, out)) {
        last_breath_ = b;
        last_heart_ = h;
      }
    }
  }
}

bool PrivacyEnvelope::accept(const Event& e, EmitResult* out) {
  // Hard egress policy: reject anything that could carry fine-grained data.
  // (These are belt-and-braces; the types already prevent most of it.)
  if (e.payload.size() > Event::kMaxPayload) {
    ++stats_.schema_rejections;
    return false;
  }
  // The signed policy's allowed-kind mask gates emission at runtime.  A kind
  // the manifest disallows never reaches the wire, so the device cannot emit
  // something the policy forbids even if a classifier bug tried to.
  if (!policy_allows(e.kind)) {
    ++stats_.schema_rejections;
    return false;
  }
  if (e.t_wall_us != 0 && (e.t_wall_us % (60LL * 1000000LL)) != 0) {
    // Wall time must already be minute-quantized.  If a caller passed a fine
    // timestamp, quantize it here rather than emit a covert channel.
    Event q = e;
    q.t_wall_us -= q.t_wall_us % (60LL * 1000000LL);
    out->events.push_back(q);
    return true;
  }
  out->events.push_back(e);
  return true;
}

void PrivacyEnvelope::ack_emergency(std::uint32_t seq) {
  auto before = pending_emergencies_.size();
  pending_emergencies_.erase(
      std::remove_if(pending_emergencies_.begin(), pending_emergencies_.end(),
                     [seq](const Event& e) { return e.seq == seq; }),
      pending_emergencies_.end());
  // Decrement only if an entry was actually removed, so the diagnostic counter
  // stays exactly equal to the latch size even under duplicate acks.
  if (pending_emergencies_.size() < before && stats_.emergencies_pending > 0)
    --stats_.emergencies_pending;
}

}  // namespace rp
