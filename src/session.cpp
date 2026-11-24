// SPDX-License-Identifier: Apache-2.0
#include "rp/session.hpp"

#include <memory>

#include "rp/sha256.hpp"

namespace rp {

namespace {
// Derive a stable per-device journal key from the master seed.  Domain
// separated so the journal key is never the same bytes as any signing key.
Key derive_journal_key(const Seed& master, std::uint32_t device_id) {
  Bytes info;
  append(&info, std::string_view("radpriv-journal-key"));
  put_be32(&info, device_id);
  Hash prk = hkdf_extract(Slice(reinterpret_cast<const std::uint8_t*>("radpriv-master"), 14),
                          Slice(master));
  Bytes okm = hkdf_expand(prk, Slice(info), kKeyLen);
  Key k{};
  std::memcpy(k.data(), okm.data(), kKeyLen);
  secure_wipe(okm.data(), okm.size());
  return k;
}

EnvelopeConfig envelope_from_manifest(const PolicyManifest& m) {
  EnvelopeConfig e;
  e.max_frames_per_sec = m.max_frames_per_sec;
  e.fall_impact_threshold = static_cast<float>(m.fall_impact_milli) / 1000.0f;
  e.fall_immobility_threshold = static_cast<float>(m.fall_immobility_milli) / 1000.0f;
  e.apnea_seconds = m.apnea_seconds;
  e.apnea_confirm_seconds = m.apnea_confirm_seconds;
  e.allowed_event_kinds = m.allowed_event_kinds;
  return e;
}
}  // namespace

DeviceSession::DeviceSession(const SessionConfig& cfg, const SessionKeys& keys)
    : cfg_(cfg), keys_(keys), journal_(cfg.boot_epoch) {
  classifier_ = std::make_unique<ReferenceClassifier>(envelope_from_manifest(cfg.policy));
  envelope_ = std::make_unique<PrivacyEnvelope>(envelope_from_manifest(cfg.policy), classifier_.get());
  journal_key_ = derive_journal_key(keys_.journal_master, cfg_.policy.device_id);

  // Build and sign the manifest (vendor + care home).
  manifest_.manifest = cfg_.policy;
  ed25519_public_key(keys_.vendor_seed, &manifest_.vendor_pub);
  ed25519_public_key(keys_.care_home_seed, &manifest_.care_home_pub);
  Bytes body = encode_manifest_body(manifest_.manifest);
  ed25519_sign(keys_.vendor_seed, Slice(body), &manifest_.vendor_sig);
  ed25519_sign(keys_.care_home_seed, Slice(body), &manifest_.care_home_sig);
}

EmitResult DeviceSession::push(RadarFrame& frame, WallUs wall_now) {
  EmitResult r = envelope_->consume(frame, wall_now);
  for (const Event& e : r.events) {
    // The envelope re-offers unacknowledged emergencies on every frame; the
    // ledger must record each distinct event exactly once.  Seq is monotonic
    // and never reused, so a high-water mark deduplicates re-offers.
    if (e.seq > last_recorded_seq_) {
      record_event(e);
      last_recorded_seq_ = e.seq;
      if (cfg_.enable_journal) {
        JournalEntry je;
        je.t_device_us = e.t_device_us;
        je.t_wall_us = e.t_wall_us;
        je.kind = e.kind;
        je.zone = e.zone;
        je.confidence = e.confidence;
        je.emergency = (e.kind == EventKind::Fall || e.kind == EventKind::Apnea);
        if (e.kind == EventKind::ActivityChange && e.payload.size() >= 1) {
          je.activity = static_cast<Activity>(e.payload[0]);
        }
        if (e.kind == EventKind::VitalsBand && e.payload.size() >= 2) {
          je.breath = static_cast<BreathBand>(e.payload[0]);
          je.heart = static_cast<HeartBand>(e.payload[1]);
        }
        journal_.append(je);
      }
    }
  }
  if (cfg_.enable_journal && journal_.pending() >= cfg_.journal_flush_every) {
    journal_tick(wall_now);
  }
  // Seal a checkpoint promptly whenever an emergency is recorded or the batch
  // reaches the configured size.  This is what makes an emergency's inclusion
  // proof available almost immediately, and guarantees the chain has multiple
  // links across a session for consistency audits.
  bool emergency = false;
  for (const Event& e : r.events)
    if (e.kind == EventKind::Fall || e.kind == EventKind::Apnea) emergency = true;
  if (emergency || current_batch_.size() >= cfg_.checkpoint_every_n_events) {
    checkpoint(wall_now);
  }
  return r;
}

void DeviceSession::record_event(const Event& e) {
  tree_.append(leaf_hash(Slice(encode_event_body(e))));
  all_events_.push_back(e);
  current_batch_.push_back(e);
}

void DeviceSession::ack_emergency(std::uint32_t seq) { envelope_->ack_emergency(seq); }

Hash DeviceSession::current_chain_head() const {
  if (have_checkpoint_) return last_checkpoint_body_hash_;
  return Sha256::hash(Slice(encode_manifest_body(manifest_.manifest)));
}

SignedCheckpoint DeviceSession::checkpoint(WallUs wall_now) {
  SignedCheckpoint sc;
  sc.checkpoint.tree_size = all_events_.size();
  sc.checkpoint.root = tree_.root();
  sc.checkpoint.prev_checkpoint_hash = current_chain_head();
  sc.checkpoint.wall_us = wall_now - wall_now % (60LL * 1000000LL);
  sc.checkpoint.device_us = all_events_.empty() ? 0 : all_events_.back().t_device_us;
  sc.checkpoint.device_id = cfg_.policy.device_id;
  sc.checkpoint.frames_in = envelope_->stats().frames_in;
  sc.checkpoint.emergencies_raised = envelope_->stats().emergencies_raised;
  sc.checkpoint.emergencies_emitted = envelope_->stats().emergencies_emitted;

  Bytes body = encode_checkpoint_body(sc.checkpoint);
  ed25519_sign(keys_.device_seed, Slice(body), &sc.signature);

  last_checkpoint_body_hash_ = Sha256::hash(Slice(body));
  have_checkpoint_ = true;
  checkpoints_.push_back(sc);
  current_batch_.clear();
  return sc;
}

SignedAttestation DeviceSession::attest(Slice nonce, WallUs wall_now, Ticks device_us) {
  EnvelopeCounters c;
  const EnvelopeStats& s = envelope_->stats();
  c.frames_in = s.frames_in;
  c.frames_classified = s.frames_classified;
  c.emergencies_raised = s.emergencies_raised;
  c.emergencies_emitted = s.emergencies_emitted;
  c.emergencies_suppressed = s.emergencies_raised - s.emergencies_emitted;
  c.emergency_latch_overflows = s.emergency_latch_overflows;
  c.egress_bytes_today = 0;  // no telemetry channel in this reference build
  c.raw_radar_bytes_egressed = 0;
  Hash head = current_chain_head();
  return attest_device(keys_.device_seed, manifest_.manifest, c, head, nonce, wall_now, device_us);
}

void DeviceSession::journal_tick(WallUs wall_now) {
  (void)wall_now;
  while (journal_.pending() >= Journal::kEntriesPerRecord) {
    JournalRecord rec;
    if (!ok(journal_.flush(journal_key_, &rec))) break;
    journal_records_.push_back(std::move(rec));
  }
}

AuditBundle DeviceSession::finalize(Slice nonce, WallUs wall_now, Ticks device_us,
                                    Bytes* journal_out) {
  // Flush any remainder into a final journal record.
  if (cfg_.enable_journal && journal_.pending() > 0) {
    JournalRecord rec;
    if (ok(journal_.flush(journal_key_, &rec))) journal_records_.push_back(std::move(rec));
  }

  // Always seal a final checkpoint so the attestation's chain head covers all
  // events.
  checkpoint(wall_now);

  AuditBundle b;
  b.manifest = manifest_;
  b.attestation = attest(nonce, wall_now, device_us);
  b.checkpoints = checkpoints_;

  // Compute inclusion proofs for every event against the final root.
  b.events = all_events_;
  b.inclusion_proofs.clear();
  std::size_t n = all_events_.size();
  // Rebuild a tree identical to tree_ to generate proofs (tree_ has all
  // leaves already, but is private to proof queries we did not cache).
  MerkleTree proof_tree;
  for (const Event& e : all_events_) proof_tree.append(leaf_hash(Slice(encode_event_body(e))));
  for (std::size_t i = 0; i < n; ++i) b.inclusion_proofs.push_back(proof_tree.proof(i));

  if (journal_out) {
    // Wrap the journal key to the adjudicator and emit the encrypted file.
    SessionKeys& k = keys_;
    PubKey recipient_pub;
    x25519_base(k.recipient_x25519, &recipient_pub);
    // Ephemeral seed derived deterministically from master + counter (in
    // production use the hw RNG; determinism here aids reproducible tests).
    Seed eph;
    Hash prk = hkdf_extract(Slice(reinterpret_cast<const std::uint8_t*>("radpriv-eph"), 11),
                            Slice(k.journal_master));
    Bytes okm = hkdf_expand(prk, Slice(reinterpret_cast<const std::uint8_t*>("eph-0"), 5), 32);
    std::memcpy(eph.data(), okm.data(), 32);
    secure_wipe(okm.data(), okm.size());

    WrappedKey wk = wrap_journal_key(journal_key_, recipient_pub, eph);
    JournalHeader jh;
    jh.device_id = cfg_.policy.device_id;
    jh.recipient_pub = recipient_pub;
    jh.ephemeral_pub = wk.ephemeral_pub;
    jh.wrapped_key = wk.ciphertext;
    jh.wrapped_nonce = wk.nonce;
    jh.journal_k = manifest_.manifest.journal_k;
    jh.journal_n = manifest_.manifest.journal_n;
    jh.manifest_hash = Sha256::hash(Slice(encode_manifest_body(manifest_.manifest)));
    *journal_out = encode_journal_file(jh, journal_records_);
    secure_wipe(eph.data(), eph.size());
  }
  return b;
}

}  // namespace rp
