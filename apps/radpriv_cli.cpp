// radpriv — command-line interface for the device-side privacy envelope.
//
// Subcommands serve the three audiences in the design:
//   simulate    -- run a scripted radar scene through the envelope (demo/test)
//   verify      -- the regulator's tool: verify a bundle offline, no vendor call
//   inspect     -- the care home's tool: view events in a bundle, no raw data
//   keygen      -- provision device / signer keys (setup)
//   manifest    -- emit a signed policy manifest for review
//   journal-open -- dispute path: decrypt a journal given the adjudicator key
//
// Every subcommand prints machine-readable output and exits non-zero on any
// integrity failure, so it composes into an automated audit pipeline.
// SPDX-License-Identifier: Apache-2.0
#include <cstdio>
#include <cstring>
#include <ctime>
#include <functional>
#include <string>
#include <vector>

#include "rp/attest.hpp"
#include "rp/bundle.hpp"
#include "rp/ed25519.hpp"
#include "rp/journal.hpp"
#include "rp/policy.hpp"
#include "rp/session.hpp"
#include "rp/sha256.hpp"
#include "rp/synth.hpp"

using namespace rp;

namespace {

int usage() {
  std::fprintf(stderr,
               "radpriv — device-side privacy envelope for mmWave monitoring\n\n"
               "usage: radpriv <command> [options]\n\n"
               "commands:\n"
               "  simulate --scene <calm|fall|apnea|empty> [--frames N] [--out FILE]\n"
               "           [--journal FILE]   run a scene, write an audit bundle\n"
               "  verify <bundle> [--firmware HEX] [--nonce HEX] [--verbose]\n"
               "           verify a bundle offline; exit 0 iff it is valid\n"
               "  inspect <bundle>      print the emitted events (no raw data)\n"
               "  manifest [--out FILE] print/emit the signed policy manifest\n"
               "  journal-open <journal> --adjudicator-seed HEX [--out FILE]\n"
               "           dispute path: decrypt and print the degraded trace\n"
               "  keygen --out DIR      generate provisioning keys (demo only)\n"
               "  selftest              run cryptographic self-tests\n");
  return 2;
}

bool read_file(const char* path, Bytes* out) {
  std::FILE* f = std::fopen(path, "rb");
  if (!f) return false;
  std::fseek(f, 0, SEEK_END);
  long n = std::ftell(f);
  std::fseek(f, 0, SEEK_SET);
  if (n < 0) {
    std::fclose(f);
    return false;
  }
  out->resize(static_cast<std::size_t>(n));
  std::size_t rd = std::fread(out->data(), 1, out->size(), f);
  std::fclose(f);
  return rd == out->size();
}

bool write_file(const char* path, Slice data) {
  std::FILE* f = std::fopen(path, "wb");
  if (!f) return false;
  std::size_t wr = std::fwrite(data.p, 1, data.n, f);
  std::fclose(f);
  return wr == data.n;
}

SessionKeys demo_keys() {
  // Deterministic demo keys.  In production these come from the secure
  // element and an offline HSM; never hard-code real keys.
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

SessionConfig demo_config() {
  SessionConfig c;
  c.policy.device_id = 1234;
  for (int i = 0; i < 32; ++i) c.policy.firmware_measurement[i] = std::uint8_t(i * 3 + 1);
  c.policy.journal_enabled = true;
  c.policy.journal_k = 2;
  c.policy.journal_n = 3;
  // Every CLI invocation is a fresh "boot".  A real device uses a persistent
  // monotonic boot counter here; using wall time makes the demo's nonces
  // unique per run, which is the property that matters.
  c.boot_epoch = static_cast<std::uint32_t>(std::time(nullptr));
  return c;
}

// Run a scene and return the finalized bundle; optionally the journal file.
AuditBundle simulate_scene(const std::string& scene, int frames, Slice nonce, Bytes* journal_out) {
  auto keys = demo_keys();
  auto cfg = demo_config();
  DeviceSession s(cfg, keys);
  std::vector<Pose> poses;
  if (scene == "calm")
    poses = scenes::calm_night(frames);
  else if (scene == "empty")
    poses = scenes::empty_room(frames);
  else if (scene == "apnea")
    poses = scenes::apnea_sequence(frames, frames / 4);
  else
    poses = scenes::fall_sequence(frames, frames / 3);

  WallUs wall0 = 1700000000000000LL;
  int emitted = 0;
  for (std::size_t i = 0; i < poses.size(); ++i) {
    RadarFrame f = synth_frame(poses[i], static_cast<Ticks>(i) * 100000ull,
                               static_cast<std::uint32_t>(i), 3u + static_cast<std::uint32_t>(i));
    EmitResult er = s.push(f, wall0 + static_cast<WallUs>(i) * 100000LL);
    for (auto& e : er.events) {
      std::printf("  event seq=%u kind=%s zone=%s conf=%u\n", e.seq, to_string(e.kind),
                  to_string(e.zone), e.confidence);
      s.ack_emergency(e.seq);
      ++emitted;
    }
  }
  const EnvelopeStats& st = s.stats();
  std::printf("  frames_in=%llu classified=%llu decimated=%llu events=%d\n",
              (unsigned long long)st.frames_in, (unsigned long long)st.frames_classified,
              (unsigned long long)st.frames_decimated, emitted);
  std::printf("  emergencies raised=%llu emitted=%llu\n",
              (unsigned long long)st.emergencies_raised,
              (unsigned long long)st.emergencies_emitted);
  return s.finalize(nonce, wall0 + static_cast<WallUs>(frames) * 100000LL,
                    static_cast<Ticks>(frames) * 100000ull, journal_out);
}

int cmd_simulate(int argc, char** argv) {
  std::string scene = "fall";
  int frames = 120;
  const char* out = nullptr;
  const char* journal = nullptr;
  for (int i = 2; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--scene" && i + 1 < argc) scene = argv[++i];
    else if (a == "--frames" && i + 1 < argc) frames = std::atoi(argv[++i]);
    else if (a == "--out" && i + 1 < argc) out = argv[++i];
    else if (a == "--journal" && i + 1 < argc) journal = argv[++i];
  }
  Bytes nonce = {0x01, 0x02, 0x03, 0x04};
  Bytes journal_bytes;
  std::printf("simulating scene '%s' (%d frames)\n", scene.c_str(), frames);
  AuditBundle b = simulate_scene(scene, frames, Slice(nonce), journal ? &journal_bytes : nullptr);

  Hash fw = b.manifest.manifest.firmware_measurement;
  Status v = verify_audit_bundle(b, &fw, Slice(nonce));
  std::printf("  self-verify: %s\n", to_string(v));
  if (!ok(v)) return 1;

  if (out) {
    Bytes enc = encode_audit_bundle(b);
    if (!write_file(out, Slice(enc))) {
      std::fprintf(stderr, "failed to write %s\n", out);
      return 1;
    }
    std::printf("  wrote audit bundle: %s (%zu bytes)\n", out, enc.size());
  }
  if (journal) {
    if (!write_file(journal, Slice(journal_bytes))) {
      std::fprintf(stderr, "failed to write %s\n", journal);
      return 1;
    }
    std::printf("  wrote encrypted journal: %s (%zu bytes)\n", journal, journal_bytes.size());
  }
  return 0;
}

int cmd_verify(int argc, char** argv) {
  if (argc < 3) return usage();
  const char* path = argv[2];
  const char* fw_hex = nullptr;
  const char* nonce_hex = nullptr;
  bool verbose = false;
  for (int i = 3; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--firmware" && i + 1 < argc) fw_hex = argv[++i];
    else if (a == "--nonce" && i + 1 < argc) nonce_hex = argv[++i];
    else if (a == "--verbose") verbose = true;
  }
  Bytes file;
  if (!read_file(path, &file)) {
    std::fprintf(stderr, "cannot read %s\n", path);
    return 1;
  }
  AuditBundle b;
  Status s = decode_audit_bundle(Slice(file), &b);
  if (!ok(s)) {
    std::fprintf(stderr, "decode failed: %s\n", to_string(s));
    return 1;
  }

  Hash fw;
  Hash* fwp = nullptr;
  if (fw_hex) {
    Bytes fwb;
    if (!from_hex(fw_hex, &fwb) || fwb.size() != 32) {
      std::fprintf(stderr, "bad --firmware (need 32-byte hex)\n");
      return 1;
    }
    std::memcpy(fw.data(), fwb.data(), 32);
    fwp = &fw;
  }
  Bytes nonce;
  if (nonce_hex) from_hex(nonce_hex, &nonce);

  s = verify_audit_bundle(b, fwp, Slice(nonce));
  std::printf("bundle: %s\n", path);
  std::printf("device_id: %u\n", b.manifest.manifest.device_id);
  std::printf("events: %zu  checkpoints: %zu\n", b.events.size(), b.checkpoints.size());
  std::printf("frames_in: %llu  emergencies raised/emitted: %llu/%llu\n",
              (unsigned long long)b.attestation.report.counters.frames_in,
              (unsigned long long)b.attestation.report.counters.emergencies_raised,
              (unsigned long long)b.attestation.report.counters.emergencies_emitted);
  if (verbose) {
    std::printf("firmware_measurement: %s\n", hex(Slice(b.attestation.report.firmware_measurement)).c_str());
    std::printf("policy_manifest_hash: %s\n", hex(Slice(b.attestation.report.policy_manifest_hash)).c_str());
    std::printf("final_checkpoint_root: %s\n",
                hex(Slice(b.checkpoints.empty() ? zero_hash() : b.checkpoints.back().checkpoint.root)).c_str());
  }
  std::printf("verdict: %s\n", to_string(s));
  return ok(s) ? 0 : 1;
}

int cmd_inspect(int argc, char** argv) {
  if (argc < 3) return usage();
  Bytes file;
  if (!read_file(argv[2], &file)) {
    std::fprintf(stderr, "cannot read %s\n", argv[2]);
    return 1;
  }
  AuditBundle b;
  Status s = decode_audit_bundle(Slice(file), &b);
  if (!ok(s)) {
    std::fprintf(stderr, "decode failed: %s\n", to_string(s));
    return 1;
  }
  std::printf("device %u — %zu events\n", b.manifest.manifest.device_id, b.events.size());
  for (const Event& e : b.events) {
    std::printf("  seq=%u t=%llu wall=%lld kind=%-13s zone=%-7s conf=%3u payload=%s\n", e.seq,
                (unsigned long long)e.t_device_us, (long long)e.t_wall_us, to_string(e.kind),
                to_string(e.zone), e.confidence, hex(Slice(e.payload)).c_str());
  }
  return 0;
}

int cmd_manifest(int argc, char** argv) {
  const char* out = nullptr;
  for (int i = 2; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--out" && i + 1 < argc) out = argv[++i];
  }
  auto keys = demo_keys();
  auto cfg = demo_config();
  DeviceSession s(cfg, keys);
  SignedManifest sm = s.manifest();
  Status v = verify_manifest(sm);
  std::printf("manifest: device_id=%u journal=%u-of-%u raw_radar_egress=%s verify=%s\n",
              sm.manifest.device_id, sm.manifest.journal_k, sm.manifest.journal_n,
              sm.manifest.egress.allow_raw_radar_egress ? "ALLOWED" : "denied", to_string(v));
  std::printf("  allowed_event_kinds: 0x%03x\n", sm.manifest.allowed_event_kinds);
  std::printf("  egress: <=%u bytes/min, <=%u destinations, telemetry=%s\n",
              sm.manifest.egress.max_bytes_per_minute, sm.manifest.egress.max_destinations,
              sm.manifest.egress.allow_telemetry_channel ? "yes" : "no");
  std::printf("  firmware_measurement: %s\n", hex(Slice(sm.manifest.firmware_measurement)).c_str());
  if (out) {
    Bytes enc = sm.encode();
    if (!write_file(out, Slice(enc))) return 1;
    std::printf("wrote %s (%zu bytes)\n", out, enc.size());
  }
  return ok(v) ? 0 : 1;
}

int cmd_journal_open(int argc, char** argv) {
  if (argc < 4) return usage();
  const char* path = argv[2];
  const char* seed_hex = nullptr;
  const char* manifest_path = nullptr;
  for (int i = 3; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--adjudicator-seed" && i + 1 < argc) seed_hex = argv[++i];
    else if (a == "--manifest" && i + 1 < argc) manifest_path = argv[++i];
  }
  if (!seed_hex) {
    std::fprintf(stderr, "need --adjudicator-seed HEX\n");
    return 1;
  }
  Bytes seedb;
  if (!from_hex(seed_hex, &seedb) || seedb.size() != 32) return 1;
  Seed seed;
  std::memcpy(seed.data(), seedb.data(), 32);

  Bytes file;
  if (!read_file(path, &file)) {
    std::fprintf(stderr, "cannot read %s\n", path);
    return 1;
  }
  JournalHeader h;
  std::vector<JournalRecord> recs;
  Status s = decode_journal_file(Slice(file), &h, &recs);
  if (!ok(s)) {
    std::fprintf(stderr, "decode failed: %s\n", to_string(s));
    return 1;
  }
  // If the adjudicator supplies the policy they reviewed, verify the journal
  // was produced under exactly that policy before decrypting anything.  This
  // binds the dispute evidence to the signed manifest the regulator has.
  if (manifest_path) {
    Bytes mfile;
    if (!read_file(manifest_path, &mfile)) {
      std::fprintf(stderr, "cannot read %s\n", manifest_path);
      return 1;
    }
    SignedManifest sm;
    Status ms = SignedManifest::decode(Slice(mfile), &sm);
    if (!ok(ms)) {
      std::fprintf(stderr, "manifest decode failed: %s\n", to_string(ms));
      return 1;
    }
    Hash want = Sha256::hash(Slice(encode_manifest_body(sm.manifest)));
    if (!ct_equal(want.data(), h.manifest_hash.data(), kHashLen)) {
      std::fprintf(stderr, "journal was NOT produced under the supplied policy manifest\n");
      return 1;
    }
    std::printf("journal policy binding: matches supplied manifest\n");
  }
  Key key;
  s = unwrap_journal_key(h, seed, &key);
  if (!ok(s)) {
    std::fprintf(stderr, "cannot unwrap journal key: %s\n", to_string(s));
    return 1;
  }
  std::printf("journal: device=%u records=%zu (%u-of-%u)\n", h.device_id, recs.size(), h.journal_k,
              h.journal_n);
  for (auto& r : recs) {
    std::vector<JournalEntry> entries;
    s = open_journal_record(key, r, &entries);
    if (!ok(s)) {
      std::fprintf(stderr, "record %llu: %s\n", (unsigned long long)r.record_index, to_string(s));
      return 1;
    }
    for (auto& e : entries) {
      std::printf("  rec=%llu t=%llu wall=%lld kind=%-11s zone=%-7s act=%-8s breath=%-7s heart=%-6s%s\n",
                  (unsigned long long)r.record_index, (unsigned long long)e.t_device_us,
                  (long long)e.t_wall_us, to_string(e.kind), to_string(e.zone),
                  to_string(e.activity), to_string(e.breath), to_string(e.heart),
                  e.emergency ? " [EMERGENCY]" : "");
    }
  }
  return 0;
}

int cmd_keygen(int argc, char** argv) {
  const char* dir = ".";
  for (int i = 2; i < argc; ++i) {
    std::string a = argv[i];
    if (a == "--out" && i + 1 < argc) dir = argv[++i];
  }
  auto keys = demo_keys();
  auto cfg = demo_config();
  DeviceSession s(cfg, keys);
  char path[512];

  PubKey dev_pub;
  ed25519_public_key(keys.device_seed, &dev_pub);
  std::snprintf(path, sizeof(path), "%s/device.pub", dir);
  write_file(path, Slice(dev_pub));
  std::snprintf(path, sizeof(path), "%s/device.seed", dir);
  write_file(path, Slice(keys.device_seed));

  std::printf("device public key: %s\n", hex(Slice(dev_pub)).c_str());
  std::printf("wrote keys under %s\n", dir);
  std::printf("NOTE: demo keys are deterministic and public. Provision real keys "
              "from a hardware RNG / secure element before deployment.\n");
  return 0;
}

int cmd_selftest(int argc, char** argv) {
  (void)argc;
  (void)argv;
  struct Check {
    const char* name;
    std::function<bool()> fn;
  };
  std::vector<Check> checks;
  checks.push_back({"sha256('abc')", [] {
                      const char* m = "abc";
                      return hex(Slice(Sha256::hash(Slice(reinterpret_cast<const std::uint8_t*>(m), 3)))) ==
                             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
                    }});
  checks.push_back({"ed25519 sign/verify", [] {
                      Seed seed{};
                      for (int i = 0; i < 32; ++i) seed[i] = std::uint8_t(i);
                      PubKey pub;
                      ed25519_public_key(seed, &pub);
                      const char* m = "selftest";
                      Signature sig;
                      ed25519_sign(seed, Slice(reinterpret_cast<const std::uint8_t*>(m), 8), &sig);
                      return ed25519_verify(pub, Slice(reinterpret_cast<const std::uint8_t*>(m), 8), sig);
                    }});
  checks.push_back({"aead roundtrip", [] {
                      Key k{};
                      Nonce n{};
                      const char* m = "x";
                      Bytes sealed, out;
                      aead_seal(k, n, Slice(), Slice(reinterpret_cast<const std::uint8_t*>(m), 1), &sealed);
                      return ok(aead_open(k, n, Slice(), Slice(sealed), &out)) && out.size() == 1 &&
                             out[0] == 'x';
                    }});
  int fails = 0;
  for (auto& c : checks) {
    bool okc = c.fn();
    std::printf("  [%s] %s\n", okc ? "PASS" : "FAIL", c.name);
    if (!okc) ++fails;
  }
  std::printf("selftest: %s\n", fails ? "FAIL" : "PASS");
  return fails ? 1 : 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) return usage();
  std::string cmd = argv[1];
  if (cmd == "simulate") return cmd_simulate(argc, argv);
  if (cmd == "verify") return cmd_verify(argc, argv);
  if (cmd == "inspect") return cmd_inspect(argc, argv);
  if (cmd == "manifest") return cmd_manifest(argc, argv);
  if (cmd == "journal-open") return cmd_journal_open(argc, argv);
  if (cmd == "keygen") return cmd_keygen(argc, argv);
  if (cmd == "selftest") return cmd_selftest(argc, argv);
  return usage();
}
