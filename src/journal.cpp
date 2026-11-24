// SPDX-License-Identifier: Apache-2.0
#include "rp/journal.hpp"

#include <cstring>

#include "rp/sha256.hpp"

namespace rp {

// ---------------------------------------------------------------------------
// Entry encoding (plaintext, inside the AEAD)
//
//   count(4) | per entry: t_dev(8) t_wall(8) kind(1) zone(1) act(1)
//   breath(1) heart(1) conf(1) emergency(1)   = 22 bytes each
// ---------------------------------------------------------------------------
namespace {
constexpr std::size_t kEntryLen = 23;
constexpr std::uint8_t kJournalVersion = 1;

// Domain separation tag for all journal AEAD operations.
const char kJournalAad[] = "radpriv-journal-v1";
constexpr std::size_t kJournalAadLen = sizeof(kJournalAad) - 1;
const char kWrapAad[] = "radpriv-wrap-v1";
constexpr std::size_t kWrapAadLen = sizeof(kWrapAad) - 1;

Nonce nonce_from_epoch_index(std::uint32_t boot_epoch, std::uint64_t index) {
  // Nonce layout: 'R','J','1' marker(3) || boot_epoch(4) || record_index(5 low
  // bytes).  The boot epoch distinguishes sessions that share a journal key
  // (the key is per-device and stable across reboots); without it, record 0 of
  // every boot would reuse the same nonce against different plaintext.  The
  // 5-byte index space (2^40 records) is far beyond any device lifetime.
  Nonce n{};
  n[0] = 'R'; n[1] = 'J'; n[2] = 0x01;
  n[3] = std::uint8_t(boot_epoch >> 24);
  n[4] = std::uint8_t(boot_epoch >> 16);
  n[5] = std::uint8_t(boot_epoch >> 8);
  n[6] = std::uint8_t(boot_epoch);
  for (int i = 0; i < 5; ++i) n[7 + i] = std::uint8_t(index >> (8 * i));
  return n;
}
}  // namespace

Bytes encode_journal_entries(const std::vector<JournalEntry>& entries) {
  Bytes out;
  put_be32(&out, static_cast<std::uint32_t>(entries.size()));
  for (const auto& e : entries) {
    put_be64(&out, e.t_device_us);
    put_be64(&out, static_cast<std::uint64_t>(e.t_wall_us));
    out.push_back(static_cast<std::uint8_t>(e.kind));
    out.push_back(static_cast<std::uint8_t>(e.zone));
    out.push_back(static_cast<std::uint8_t>(e.activity));
    out.push_back(static_cast<std::uint8_t>(e.breath));
    out.push_back(static_cast<std::uint8_t>(e.heart));
    out.push_back(e.confidence);
    out.push_back(e.emergency ? 1 : 0);
  }
  return out;
}

Status decode_journal_entries(Slice plaintext, std::vector<JournalEntry>* out) {
  if (plaintext.n < 4) return Status::Truncated;
  std::uint32_t count = get_be32(plaintext.p);
  if (plaintext.n != 4 + static_cast<std::size_t>(count) * kEntryLen) return Status::BadLength;
  out->resize(count);
  std::size_t o = 4;
  for (std::uint32_t i = 0; i < count; ++i) {
    JournalEntry& e = (*out)[i];
    e.t_device_us = get_be64(plaintext.p + o); o += 8;
    e.t_wall_us = static_cast<WallUs>(get_be64(plaintext.p + o)); o += 8;
    e.kind = static_cast<EventKind>(plaintext.p[o++]);
    e.zone = static_cast<Zone>(plaintext.p[o++]);
    e.activity = static_cast<Activity>(plaintext.p[o++]);
    e.breath = static_cast<BreathBand>(plaintext.p[o++]);
    e.heart = static_cast<HeartBand>(plaintext.p[o++]);
    e.confidence = plaintext.p[o++];
    e.emergency = plaintext.p[o++] != 0;
  }
  return Status::Ok;
}

// ---------------------------------------------------------------------------
// Journal
// ---------------------------------------------------------------------------
void Journal::append(const JournalEntry& e) {
  pending_.push_back(e);
  // Degrade on the way in: wall clock is quantized to the minute here too, so
  // even an internal bug cannot leave a fine timeline in the buffer.
  JournalEntry& b = pending_.back();
  b.t_wall_us -= b.t_wall_us % (60LL * 1000000LL);
}

Status Journal::flush(const Key& key, JournalRecord* out) {
  if (pending_.empty()) return Status::NotFound;
  Bytes plain = encode_journal_entries(pending_);

  Nonce nonce = nonce_from_epoch_index(boot_epoch_, record_index_);
  Bytes sealed;
  aead_seal(key, nonce, Slice(reinterpret_cast<const std::uint8_t*>(kJournalAad), kJournalAadLen),
            Slice(plain), &sealed);

  out->record_index = record_index_;
  out->nonce.assign(nonce.begin(), nonce.end());
  out->ciphertext = std::move(sealed);
  out->plaintext_hash = Sha256::hash(Slice(plain));

  secure_wipe(plain.data(), plain.size());
  pending_.clear();
  ++record_index_;
  return Status::Ok;
}

Status open_journal_record(const Key& key, const JournalRecord& rec,
                           std::vector<JournalEntry>* out) {
  if (rec.nonce.size() != kNonceLen) return Status::BadLength;
  Nonce nonce;
  std::memcpy(nonce.data(), rec.nonce.data(), kNonceLen);
  Bytes plain;
  Status s = aead_open(key, nonce, Slice(reinterpret_cast<const std::uint8_t*>(kJournalAad), kJournalAadLen),
                       Slice(rec.ciphertext), &plain);
  if (!ok(s)) return s;
  if (!ct_equal(Sha256::hash(Slice(plain)).data(), rec.plaintext_hash.data(), kHashLen)) {
    secure_wipe(plain.data(), plain.size());
    return Status::HashMismatch;
  }
  s = decode_journal_entries(Slice(plain), out);
  secure_wipe(plain.data(), plain.size());
  return s;
}

// ---------------------------------------------------------------------------
// Journal file format
//   'RJ' | ver(1) | device_id(4) | recipient(32) | ephemeral(32)
//   | k(1) | n(1) | manifest_hash(32) | nonce_len(1) | nonce
//   | wrapped_len(2) | wrapped
//   | record_count(4) | per record: idx(8) nonce(12) pthash(32) ct_len(4) ct
// ---------------------------------------------------------------------------
Bytes encode_journal_file(const JournalHeader& h, const std::vector<JournalRecord>& recs) {
  Bytes out;
  out.push_back('R');
  out.push_back('J');
  out.push_back(kJournalVersion);
  put_be32(&out, h.device_id);
  append(&out, Slice(h.recipient_pub));
  append(&out, Slice(h.ephemeral_pub));
  out.push_back(h.journal_k);
  out.push_back(h.journal_n);
  append_hash(&out, h.manifest_hash);
  out.push_back(static_cast<std::uint8_t>(h.wrapped_nonce.size()));
  append(&out, Slice(h.wrapped_nonce));
  put_be16(&out, static_cast<std::uint16_t>(h.wrapped_key.size()));
  append(&out, Slice(h.wrapped_key));
  put_be32(&out, static_cast<std::uint32_t>(recs.size()));
  for (const auto& r : recs) {
    put_be64(&out, r.record_index);
    append(&out, Slice(r.nonce));
    append_hash(&out, r.plaintext_hash);
    put_be32(&out, static_cast<std::uint32_t>(r.ciphertext.size()));
    append(&out, Slice(r.ciphertext));
  }
  return out;
}

Status decode_journal_file(Slice file, JournalHeader* h, std::vector<JournalRecord>* recs) {
  std::size_t o = 0;
  auto need = [&](std::size_t n) { return o + n <= file.n; };
  if (!need(2 + 1 + 4 + 32 + 32 + 2 + 32 + 1)) return Status::Truncated;
  if (file.p[0] != 'R' || file.p[1] != 'J') return Status::BadMagic;
  if (file.p[2] != kJournalVersion) return Status::BadVersion;
  o = 3;
  h->device_id = get_be32(file.p + o); o += 4;
  std::memcpy(h->recipient_pub.data(), file.p + o, 32); o += 32;
  std::memcpy(h->ephemeral_pub.data(), file.p + o, 32); o += 32;
  h->journal_k = file.p[o++];
  h->journal_n = file.p[o++];
  std::memcpy(h->manifest_hash.data(), file.p + o, 32); o += 32;
  std::size_t nlen = file.p[o++];
  if (!need(nlen)) return Status::Truncated;
  h->wrapped_nonce.assign(file.p + o, file.p + o + nlen); o += nlen;
  if (!need(2)) return Status::Truncated;
  std::size_t wlen = get_be16(file.p + o); o += 2;
  if (!need(wlen)) return Status::Truncated;
  h->wrapped_key.assign(file.p + o, file.p + o + wlen); o += wlen;
  if (!need(4)) return Status::Truncated;
  std::uint32_t count = get_be32(file.p + o); o += 4;
  recs->clear();
  recs->reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    JournalRecord r;
    if (!need(8 + kNonceLen + kHashLen + 4)) return Status::Truncated;
    r.record_index = get_be64(file.p + o); o += 8;
    r.nonce.assign(file.p + o, file.p + o + kNonceLen); o += kNonceLen;
    std::memcpy(r.plaintext_hash.data(), file.p + o, kHashLen); o += kHashLen;
    std::uint32_t clen = get_be32(file.p + o); o += 4;
    if (!need(clen)) return Status::Truncated;
    r.ciphertext.assign(file.p + o, file.p + o + clen); o += clen;
    recs->push_back(std::move(r));
  }
  if (o != file.n) return Status::BadLength;
  return Status::Ok;
}

// Wrap a journal key to a recipient X25519 public key.  `ephemeral_seed` must
// be a fresh, secret random scalar on the device; the caller is responsible
// for generating it from the hardware RNG.
WrappedKey wrap_journal_key(const Key& journal_key, const PubKey& recipient_pub,
                            const Seed& ephemeral_seed) {
  WrappedKey out;
  PubKey shared;
  x25519(ephemeral_seed, recipient_pub, &shared);
  x25519_base(ephemeral_seed, &out.ephemeral_pub);
  Hash prk = hkdf_extract(Slice(reinterpret_cast<const std::uint8_t*>("radpriv-wrap-salt"), 17),
                          Slice(shared));
  Bytes wk = hkdf_expand(prk, Slice(reinterpret_cast<const std::uint8_t*>(kWrapAad), kWrapAadLen),
                         kKeyLen);
  Key wrap_key;
  std::memcpy(wrap_key.data(), wk.data(), kKeyLen);
  Nonce nonce{};
  for (int i = 0; i < 12; ++i) nonce[i] = ephemeral_seed[i] ^ std::uint8_t(i * 37 + 11);
  aead_seal(wrap_key, nonce, Slice(reinterpret_cast<const std::uint8_t*>(kWrapAad), kWrapAadLen),
            Slice(journal_key), &out.ciphertext);
  out.nonce.assign(nonce.begin(), nonce.end());
  secure_wipe(shared.data(), shared.size());
  secure_wipe(wk.data(), wk.size());
  secure_wipe(wrap_key.data(), wrap_key.size());
  return out;
}

Status unwrap_journal_key(const JournalHeader& h, const Seed& recipient_priv, Key* key) {
  PubKey shared;
  x25519(recipient_priv, h.ephemeral_pub, &shared);
  Hash prk = hkdf_extract(Slice(reinterpret_cast<const std::uint8_t*>("radpriv-wrap-salt"), 17),
                          Slice(shared));
  Bytes wk = hkdf_expand(prk, Slice(reinterpret_cast<const std::uint8_t*>(kWrapAad), kWrapAadLen),
                         kKeyLen);
  Key wrap_key;
  std::memcpy(wrap_key.data(), wk.data(), kKeyLen);
  if (h.wrapped_nonce.size() != kNonceLen) return Status::BadLength;
  Nonce nonce;
  std::memcpy(nonce.data(), h.wrapped_nonce.data(), kNonceLen);
  Bytes plain;
  Status s = aead_open(wrap_key, nonce, Slice(reinterpret_cast<const std::uint8_t*>(kWrapAad), kWrapAadLen),
                       Slice(h.wrapped_key), &plain);
  if (ok(s) && plain.size() == kKeyLen) std::memcpy(key->data(), plain.data(), kKeyLen);
  else if (ok(s)) s = Status::BadLength;
  secure_wipe(shared.data(), shared.size());
  secure_wipe(wk.data(), wk.size());
  secure_wipe(wrap_key.data(), wrap_key.size());
  secure_wipe(plain.data(), plain.size());
  return s;
}

}  // namespace rp
