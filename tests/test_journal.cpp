// Journal encryption and dispute-recovery: no key -> no content; right key ->
// exactly the degraded trace; tampering detected.
// SPDX-License-Identifier: Apache-2.0
#include <cstring>

#include "rp/journal.hpp"
#include "rp/sha256.hpp"
#include "test_framework.hpp"

using namespace rp;

namespace {
Key test_key(std::uint8_t seed) {
  Key k{};
  for (int i = 0; i < 32; ++i) k[i] = std::uint8_t(seed + i * 7);
  return k;
}

std::vector<JournalEntry> sample_entries(int n) {
  std::vector<JournalEntry> v;
  for (int i = 0; i < n; ++i) {
    JournalEntry e;
    e.t_device_us = static_cast<Ticks>(i) * 1000000ull;
    e.t_wall_us = 1700000000000000LL + i * 30000000LL;
    e.kind = EventKind::Occupancy;
    e.zone = Zone::B;
    e.activity = Activity::Still;
    e.breath = BreathBand::Normal;
    e.heart = HeartBand::Normal;
    e.confidence = 70;
    v.push_back(e);
  }
  return v;
}
}  // namespace

TEST(journal_encrypt_decrypt) {
  Key key = test_key(1);
  Journal j(0);
  for (auto& e : sample_entries(10)) j.append(e);
  JournalRecord rec;
  CHECK(ok(j.flush(key, &rec)));
  CHECK_EQ(rec.record_index, std::uint64_t(0));
  // Ciphertext must not contain plaintext markers (sanity: length is +tag).
  auto out = std::vector<JournalEntry>{};
  CHECK(ok(open_journal_record(key, rec, &out)));
  CHECK_EQ(out.size(), std::size_t(10));
  CHECK_EQ(static_cast<int>(out[3].zone), static_cast<int>(Zone::B));
}

TEST(journal_wrong_key_fails) {
  Key key = test_key(1);
  Key wrong = test_key(2);
  Journal j(0);
  for (auto& e : sample_entries(5)) j.append(e);
  JournalRecord rec;
  CHECK(ok(j.flush(key, &rec)));
  std::vector<JournalEntry> out;
  CHECK_EQ(static_cast<int>(open_journal_record(wrong, rec, &out)),
           static_cast<int>(Status::BadTag));
}

TEST(journal_tamper_fails) {
  Key key = test_key(1);
  Journal j(0);
  for (auto& e : sample_entries(5)) j.append(e);
  JournalRecord rec;
  CHECK(ok(j.flush(key, &rec)));
  rec.ciphertext[0] ^= 1;
  std::vector<JournalEntry> out;
  CHECK_EQ(static_cast<int>(open_journal_record(key, rec, &out)),
           static_cast<int>(Status::BadTag));
}

TEST(journal_quantizes_wall_time) {
  Key key = test_key(1);
  Journal j(0);
  JournalEntry e;
  e.t_wall_us = 1700000123456789LL;  // has sub-minute bits
  e.kind = EventKind::Occupancy;
  j.append(e);
  JournalRecord rec;
  CHECK(ok(j.flush(key, &rec)));
  std::vector<JournalEntry> out;
  CHECK(ok(open_journal_record(key, rec, &out)));
  CHECK_EQ(out[0].t_wall_us % (60LL * 1000000LL), 0LL);
}

TEST(journal_nonces_are_unique_per_record) {
  Key key = test_key(1);
  Journal j(0);
  JournalRecord r0, r1;
  for (auto& e : sample_entries(3)) j.append(e);
  CHECK(ok(j.flush(key, &r0)));
  for (auto& e : sample_entries(3)) j.append(e);
  CHECK(ok(j.flush(key, &r1)));
  CHECK(r0.nonce != r1.nonce);
  CHECK_EQ(r1.record_index, std::uint64_t(1));
}

TEST(journal_nonces_unique_across_boots_same_key) {
  // The journal key is per-device and stable across reboots, so record 0 of
  // every boot would share a nonce unless the boot epoch salts it.  This is
  // the exact ChaCha20-Poly1305 nonce-reuse failure mode; assert it is closed.
  Key key = test_key(5);
  std::vector<std::vector<std::uint8_t>> nonces;
  for (std::uint32_t boot = 0; boot < 5; ++boot) {
    Journal j(boot);
    for (auto& e : sample_entries(3)) j.append(e);
    JournalRecord r;
    CHECK(ok(j.flush(key, &r)));
    for (auto& prev : nonces) CHECK(prev != r.nonce);  // no repeat
    nonces.push_back(r.nonce);
  }
}

TEST(journal_file_roundtrip) {
  // Build a header + a couple of records, encode and decode the file.
  Key jkey = test_key(9);
  Journal j(0);
  for (auto& e : sample_entries(4)) j.append(e);
  std::vector<JournalRecord> recs;
  JournalRecord r;
  CHECK(ok(j.flush(jkey, &r)));
  recs.push_back(r);

  Seed recips;
  for (int i = 0; i < 32; ++i) recips[i] = std::uint8_t(0x20 + i);
  PubKey recip_pub;
  x25519_base(recips, &recip_pub);

  Seed eph;
  for (int i = 0; i < 32; ++i) eph[i] = std::uint8_t(0x80 + i);
  WrappedKey wk = wrap_journal_key(jkey, recip_pub, eph);

  JournalHeader h;
  h.device_id = 77;
  h.recipient_pub = recip_pub;
  h.ephemeral_pub = wk.ephemeral_pub;
  h.wrapped_key = wk.ciphertext;
  h.wrapped_nonce = wk.nonce;
  h.journal_k = 2;
  h.journal_n = 3;
  for (int i = 0; i < 32; ++i) h.manifest_hash[i] = std::uint8_t(i);

  Bytes file = encode_journal_file(h, recs);
  JournalHeader h2;
  std::vector<JournalRecord> recs2;
  CHECK(ok(decode_journal_file(Slice(file), &h2, &recs2)));
  CHECK_EQ(h2.device_id, h.device_id);
  CHECK_EQ(recs2.size(), std::size_t(1));

  // The adjudicator recovers the journal key from the file alone.
  Key recovered;
  CHECK(ok(unwrap_journal_key(h2, recips, &recovered)));
  CHECK_BYTES(Slice(recovered), Slice(jkey));

  // And with the recovered key the records decrypt.
  std::vector<JournalEntry> entries;
  CHECK(ok(open_journal_record(recovered, recs2[0], &entries)));
  CHECK_EQ(entries.size(), std::size_t(4));
}

TEST(journal_wrong_recipient_cannot_unwrap) {
  Key jkey = test_key(9);
  Seed recips;
  for (int i = 0; i < 32; ++i) recips[i] = std::uint8_t(0x20 + i);
  PubKey recip_pub;
  x25519_base(recips, &recip_pub);
  Seed eph;
  for (int i = 0; i < 32; ++i) eph[i] = std::uint8_t(0x80 + i);
  WrappedKey wk = wrap_journal_key(jkey, recip_pub, eph);

  JournalHeader h;
  h.ephemeral_pub = wk.ephemeral_pub;
  h.wrapped_key = wk.ciphertext;
  h.wrapped_nonce = wk.nonce;

  Seed wrong;
  for (int i = 0; i < 32; ++i) wrong[i] = std::uint8_t(0x99 + i);
  Key out;
  CHECK_EQ(static_cast<int>(unwrap_journal_key(h, wrong, &out)), static_cast<int>(Status::BadTag));
}
