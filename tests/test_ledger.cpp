// Merkle ledger, checkpoint chain, and inclusion/consistency proof tests.
// SPDX-License-Identifier: Apache-2.0
#include <cstring>

#include "rp/ledger.hpp"
#include "rp/sha256.hpp"
#include "test_framework.hpp"

using namespace rp;

namespace {
Hash leaf_of(const char* s) {
  return leaf_hash(Slice(reinterpret_cast<const std::uint8_t*>(s), std::strlen(s)));
}
}  // namespace

TEST(merkle_root_empty_and_single) {
  CHECK_EQ(hex(Slice(empty_root())),
           std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  MerkleTree t;
  Hash l = leaf_of("a");
  t.append(l);
  CHECK_BYTES(t.root(), l);  // single-leaf root is the leaf itself
}

TEST(merkle_inclusion_all_sizes) {
  for (std::size_t n = 1; n <= 64; ++n) {
    MerkleTree t;
    std::vector<Hash> leaves;
    for (std::size_t i = 0; i < n; ++i) {
      char buf[32];
      std::snprintf(buf, sizeof(buf), "leaf-%zu", i);
      Hash l = leaf_of(buf);
      leaves.push_back(l);
      t.append(l);
    }
    Hash root = t.root();
    for (std::size_t i = 0; i < n; ++i) {
      auto proof = t.proof(i);
      CHECK(MerkleTree::verify_inclusion(leaves[i], i, n, proof, root));
      // Wrong index or root must fail.
      if (i + 1 < n)
        CHECK(!MerkleTree::verify_inclusion(leaves[i], i + 1, n, proof, root));
      CHECK(!MerkleTree::verify_inclusion(leaves[i], i, n, proof, empty_root()) || n == 1);
    }
  }
}

TEST(merkle_consistency_all_sizes) {
  for (std::size_t n = 1; n <= 48; ++n) {
    MerkleTree t;
    std::vector<Hash> leaves;
    for (std::size_t i = 0; i < n; ++i) {
      char buf[32];
      std::snprintf(buf, sizeof(buf), "item-%zu", i);
      Hash l = leaf_of(buf);
      leaves.push_back(l);
      t.append(l);
    }
    Hash root = t.root();
    for (std::size_t m = 0; m <= n; ++m) {
      std::vector<Hash> old_leaves(leaves.begin(), leaves.begin() + m);
      Hash old_root = m == 0 ? empty_root() : merkle_root_from_leaves(old_leaves);
      auto cp = m == 0 ? std::vector<Hash>{} : t.consistency_proof(m, old_leaves);
      CHECK(MerkleTree::verify_consistency(m, old_root, n, root, cp));
    }
  }
}

TEST(checkpoint_encode_roundtrip) {
  Checkpoint c;
  c.device_id = 42;
  c.tree_size = 12345;
  c.wall_us = 1700000000000000LL;
  c.device_us = 999;
  for (int i = 0; i < 32; ++i) c.root[i] = std::uint8_t(i);
  for (int i = 0; i < 32; ++i) c.prev_checkpoint_hash[i] = std::uint8_t(31 - i);
  c.frames_in = 1000;
  c.emergencies_raised = 2;
  c.emergencies_emitted = 2;
  Bytes body = encode_checkpoint_body(c);
  Checkpoint d;
  CHECK(ok(decode_checkpoint_body(Slice(body), &d)));
  CHECK_EQ(d.device_id, c.device_id);
  CHECK_EQ(d.tree_size, c.tree_size);
  CHECK_EQ(d.wall_us, c.wall_us);
  CHECK_BYTES(Slice(d.root), Slice(c.root));
  CHECK_BYTES(Slice(d.prev_checkpoint_hash), Slice(c.prev_checkpoint_hash));
  CHECK_EQ(d.frames_in, c.frames_in);
  CHECK_EQ(d.emergencies_raised, c.emergencies_raised);
}

TEST(checkpoint_detects_corruption) {
  Checkpoint c;
  c.tree_size = 5;
  Bytes body = encode_checkpoint_body(c);
  body[7] ^= 1;  // flip a byte in tree_size
  Checkpoint d;
  // Still decodes (no integrity at this layer), but the value changed — this
  // is why every checkpoint is signed and chained.
  CHECK(ok(decode_checkpoint_body(Slice(body), &d)));
  CHECK(d.tree_size != c.tree_size);
}
