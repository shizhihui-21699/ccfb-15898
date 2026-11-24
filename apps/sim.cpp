// Simulator: a thin driver that runs a named scenario and prints a one-line
// machine-readable summary.  Used by CTest to assert that emergency scenarios
// reliably raise the right event.
// SPDX-License-Identifier: Apache-2.0
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include "rp/session.hpp"
#include "rp/synth.hpp"

using namespace rp;

namespace {
SessionKeys keys() {
  SessionKeys k;
  for (int i = 0; i < 32; ++i) {
    k.device_seed[i] = std::uint8_t(0x10 + i);
    k.care_home_seed[i] = std::uint8_t(0x40 + i);
    k.vendor_seed[i] = std::uint8_t(0x70 + i);
    k.recipient_x25519[i] = std::uint8_t(0xA0 + i);
    k.journal_master[i] = std::uint8_t(0xD0 + i);
  }
  return k;
}
}  // namespace

int main(int argc, char** argv) {
  const char* scene = argc > 1 ? argv[1] : "calm";
  std::vector<Pose> poses;
  if (std::strcmp(scene, "fall") == 0)
    poses = scenes::fall_sequence(80, 30);
  else if (std::strcmp(scene, "apnea") == 0)
    poses = scenes::apnea_sequence(160, 10);
  else if (std::strcmp(scene, "empty") == 0)
    poses = scenes::empty_room(60);
  else
    poses = scenes::calm_night(120);

  SessionConfig cfg;
  cfg.policy.device_id = 1;
  for (int i = 0; i < 32; ++i) cfg.policy.firmware_measurement[i] = std::uint8_t(i + 7);
  cfg.boot_epoch = static_cast<std::uint32_t>(std::time(nullptr));
  DeviceSession s(cfg, keys());

  int falls = 0, apneas = 0, total = 0;
  WallUs wall0 = 1700000000000000LL;
  for (std::size_t i = 0; i < poses.size(); ++i) {
    RadarFrame f = synth_frame(poses[i], static_cast<Ticks>(i) * 100000ull,
                               static_cast<std::uint32_t>(i), 100u + static_cast<std::uint32_t>(i));
    EmitResult er = s.push(f, wall0 + static_cast<WallUs>(i) * 100000LL);
    for (auto& e : er.events) {
      ++total;
      if (e.kind == EventKind::Fall) ++falls;
      if (e.kind == EventKind::Apnea) ++apneas;
      s.ack_emergency(e.seq);
    }
  }
  const EnvelopeStats& st = s.stats();
  std::printf("scene=%s events=%d falls=%d apneas=%d frames_in=%llu decimated=%llu "
              "raised=%llu emitted=%llu\n",
              scene, total, falls, apneas, (unsigned long long)st.frames_in,
              (unsigned long long)st.frames_decimated, (unsigned long long)st.emergencies_raised,
              (unsigned long long)st.emergencies_emitted);

  // Exit non-zero if the scenario's required event did not appear.
  if (std::strcmp(scene, "fall") == 0 && falls == 0) return 3;
  if (std::strcmp(scene, "apnea") == 0 && apneas == 0) return 3;
  if ((std::strcmp(scene, "calm") == 0 || std::strcmp(scene, "empty") == 0) &&
      (falls + apneas) != 0)
    return 4;
  return 0;
}
