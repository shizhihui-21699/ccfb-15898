// Retrace journal — the "what actually happened" record for disputes,
// designed so the people afraid of misuse cannot read it at will.
//
// The tension: caregivers and the vendor must not be able to review room
// activity, yet a fall-injury dispute or a neglect allegation needs evidence
// of what the device saw *at the time*.  The resolution:
//
//   * The journal stores a *deliberately degraded* trace: coarse
//     occupancy/activity/zone at one entry per 30 s, plus every emergency with
//     its surrounding window.  Never raw radar, never per-second detail.
//   * It is encrypted with ChaCha20-Poly1305 under a per-device journal key.
//   * That key is Shamir-split k-of-n between the care home, the resident's
//     guardian, and the regulator.  The vendor holds no share.
//   * The wrapped key is additionally encrypted to the adjudicator's X25519
//     key, so even holding all shares is not enough without a court-appointed
//     recipient — or, for internal review, any k of the three parties acting
//     together.
//
// Result: nobody can casually browse it; a dispute with the right quorum can
// reconstruct exactly what the device recorded, and nothing more, because the
// journal itself never held anything finer.
#pragma once

#include "rp/aead.hpp"
#include "rp/common.hpp"
#include "rp/event.hpp"

namespace rp {

struct JournalEntry {
  Ticks t_device_us = 0;
  WallUs t_wall_us = 0;
  EventKind kind = EventKind::Heartbeat;
  Zone zone = Zone::Unknown;
  Activity activity = Activity::Unknown;
  BreathBand breath = BreathBand::Unknown;
  HeartBand heart = HeartBand::Unknown;
  std::uint8_t confidence = 0;
  bool emergency = false;
};

// Serialized, encrypted journal.  Entries are grouped into fixed-size records
// so a single record can be selectively disclosed without revealing the rest.
struct JournalRecord {
  std::uint64_t record_index = 0;
  Bytes nonce;         // 12 bytes
  Bytes ciphertext;    // AEAD(entries) || tag
  Hash plaintext_hash; // SHA-256 of the plaintext entries, for integrity
};

class Journal {
 public:
  // `boot_epoch` MUST be unique across every boot of a device that shares a
  // journal key, and must never repeat.  It is placed in every nonce alongside
  // the record index, so the (key, nonce) pair is unique across the device's
  // entire lifetime.  Derive it from a persistent monotonic boot counter (the
  // recommended source), or from the hardware RNG if no persistent counter
  // exists.  Passing a constant here reuses nonces across boots — a fatal
  // ChaCha20-Poly1305 weakness — so the session computes it from a boot
  // counter, never a literal.
  explicit Journal(std::uint32_t boot_epoch) : boot_epoch_(boot_epoch) {}

  // Append a degraded entry.  Entries are buffered; flush() seals a record.
  void append(const JournalEntry& e);

  // Seal the buffered entries into an encrypted record under `key`.  Returns
  // the record; the caller stores it (device flash).  Plaintext buffer is
  // scrubbed.
  Status flush(const Key& key, JournalRecord* out);

  // Number of entries buffered / records sealed.
  std::size_t pending() const { return pending_.size(); }
  std::uint64_t records_sealed() const { return record_index_; }

  static constexpr std::size_t kEntriesPerRecord = 30;

 private:
  std::vector<JournalEntry> pending_;
  std::uint64_t record_index_ = 0;
  std::uint32_t boot_epoch_ = 0;
};

Bytes encode_journal_entries(const std::vector<JournalEntry>& entries);
Status decode_journal_entries(Slice plaintext, std::vector<JournalEntry>* out);

// Decrypt a record with the recovered journal key.  Returns BadTag on wrong
// key or tampering.
Status open_journal_record(const Key& key, const JournalRecord& rec,
                           std::vector<JournalEntry>* out);

// File format for an on-disk journal: header + records.  Header identifies the
// device, the wrapping recipient, and the policy under which it was written.
struct JournalHeader {
  std::uint32_t device_id = 0;
  PubKey recipient_pub{};       // adjudicator X25519 public key
  PubKey ephemeral_pub{};       // device's ephemeral X25519 public key
  Bytes wrapped_key;            // AEAD(journal_key) under X25519 shared secret
  Bytes wrapped_nonce;
  std::uint8_t journal_k = 2;
  std::uint8_t journal_n = 3;
  Hash manifest_hash{};         // binds journal to the signed policy
};

Bytes encode_journal_file(const JournalHeader& h, const std::vector<JournalRecord>& recs);
Status decode_journal_file(Slice file, JournalHeader* h, std::vector<JournalRecord>* recs);

// Recover the journal key from a header using the adjudicator's X25519 private
// key.  (The adjudicator still needs the *wrapped key*, which the header
// holds; the Shamir shares reconstruct the key in the external tool, not
// here.  This path is used when the device itself was provisioned with the
// recipient key directly.)
Status unwrap_journal_key(const JournalHeader& h, const Seed& recipient_priv, Key* key);

// Wrap a journal key to a recipient X25519 public key using a one-time
// ephemeral scalar.  The caller supplies the ephemeral seed (from the hw RNG);
// it must never be reused.  Returns the ephemeral public key and the AEAD
// ciphertext of the journal key, suitable for JournalHeader.
struct WrappedKey {
  PubKey ephemeral_pub{};
  Bytes nonce;
  Bytes ciphertext;
};
WrappedKey wrap_journal_key(const Key& journal_key, const PubKey& recipient_pub,
                            const Seed& ephemeral_seed);

}  // namespace rp
