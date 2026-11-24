// DeviceSession: the top-level orchestrator that runs on the device.
//
// It owns the state that must not be scattered: the privacy envelope, the
// Merkle ledger of emitted events, the encrypted retrace journal, and the
// checkpoint chain.  The public API is a single push() per frame plus
// checkpoint()/finalize() for the periodic and shutdown seals.
//
// Key design point: the session emits *signed checkpoints* and a *signed
// attestation*, but it never exposes a path that returns raw frames to any
// caller.  consume() takes the frame by value; nothing downstream sees it.
#pragma once

#include "rp/attest.hpp"
#include "rp/bundle.hpp"
#include "rp/envelope.hpp"
#include "rp/journal.hpp"
#include "rp/ledger.hpp"
#include "rp/policy.hpp"

namespace rp {

struct SessionKeys {
  Seed device_seed{};          // Ed25519 signing seed (in secure element)
  Seed care_home_seed{};       // co-signer for the manifest (kept offline)
  Seed vendor_seed{};          // vendor signer (offline)
  Seed recipient_x25519{};     // adjudicator pubkey derivation
  Seed journal_master{};       // root for journal key derivation
};

struct SessionConfig {
  EnvelopeConfig envelope;
  PolicyManifest policy;
  std::uint32_t checkpoint_every_n_events = 8;
  bool enable_journal = true;
  std::uint32_t journal_flush_every = 30;  // entries
  // Unique per boot of a device that shares a journal key.  MUST change every
  // reboot (use a persistent monotonic boot counter, or the hw RNG).  It salts
  // the journal nonce so records from different boots never collide.  See
  // Journal's constructor for why this is safety-critical.
  std::uint32_t boot_epoch = 0;
};

class DeviceSession {
 public:
  DeviceSession(const SessionConfig& cfg, const SessionKeys& keys);

  // Feed one frame.  Returns the events to deliver on the wire; emergencies
  // are also latched internally and re-offered until acked.
  EmitResult push(RadarFrame& frame, WallUs wall_now);

  // Acknowledge durable delivery of an emergency seq.
  void ack_emergency(std::uint32_t seq);

  // Seal a checkpoint over all events so far.  Called periodically and on
  // emergency.  Returns the signed checkpoint.
  SignedCheckpoint checkpoint(WallUs wall_now);

  // Produce a signed attestation bound to `nonce` and the current chain.
  SignedAttestation attest(Slice nonce, WallUs wall_now, Ticks device_us);

  // Flush journal records to the internal record list (not exposed).
  void journal_tick(WallUs wall_now);

  // Finalize: emit a last checkpoint and package everything an auditor needs
  // into a bundle.  `nonce` binds the attestation; `journal_out` (optional)
  // returns the encrypted journal file for dispute use.
  AuditBundle finalize(Slice nonce, WallUs wall_now, Ticks device_us,
                       Bytes* journal_out = nullptr);

  const EnvelopeStats& stats() const { return envelope_->stats(); }
  std::uint32_t device_id() const { return cfg_.policy.device_id; }

  // The signed manifest this session is running under (for tests/CLI).
  const SignedManifest& manifest() const { return manifest_; }

 private:
  void record_event(const Event& e);
  Hash current_chain_head() const;

  SessionConfig cfg_;
  SessionKeys keys_;
  SignedManifest manifest_;
  std::unique_ptr<Classifier> classifier_;
  std::unique_ptr<PrivacyEnvelope> envelope_;
  MerkleTree tree_;
  std::vector<Event> all_events_;
  std::vector<Event> current_batch_;      // since last checkpoint
  std::uint32_t last_recorded_seq_ = 0;   // dedupe re-offered emergencies
  std::vector<SignedCheckpoint> checkpoints_;

  Journal journal_;
  Key journal_key_{};
  std::vector<JournalRecord> journal_records_;

  Hash last_checkpoint_body_hash_{};
  bool have_checkpoint_ = false;
};

}  // namespace rp
