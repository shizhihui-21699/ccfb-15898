// SPDX-License-Identifier: Apache-2.0
#include "rp/ledger.hpp"

#include <cstring>
#include <functional>

#include "rp/sha256.hpp"

namespace rp {

// ---------------------------------------------------------------------------
// RFC 6962 domain separation
// ---------------------------------------------------------------------------
Hash leaf_hash(Slice event_body) {
  Sha256 h;
  const std::uint8_t zero = 0x00;
  h.update(&zero, 1);
  h.update(event_body.p, event_body.n);
  return h.final();
}

Hash node_hash(const Hash& left, const Hash& right) {
  Sha256 h;
  const std::uint8_t one = 0x01;
  h.update(&one, 1);
  h.update(left.data(), left.size());
  h.update(right.data(), right.size());
  return h.final();
}

Hash empty_root() {
  static const Hash h = Sha256::hash(Slice(reinterpret_cast<const std::uint8_t*>(""), 0));
  return h;
}

namespace {

// Largest power of two strictly less than n (n >= 2).
std::size_t largest_pow2_below(std::size_t n) {
  std::size_t k = 1;
  while ((k << 1) < n) k <<= 1;
  return k;
}

// Root over the half-open leaf range [lo, hi).
Hash subtree_root(const std::vector<Hash>& leaves, std::size_t lo, std::size_t hi) {
  std::size_t n = hi - lo;
  if (n == 0) return empty_root();
  if (n == 1) return leaves[lo];
  std::size_t k = largest_pow2_below(n);
  return node_hash(subtree_root(leaves, lo, lo + k), subtree_root(leaves, lo + k, hi));
}

void build_audit_path(const std::vector<Hash>& leaves, std::size_t lo, std::size_t hi,
                      std::size_t index, std::vector<Hash>* path) {
  std::size_t n = hi - lo;
  if (n <= 1) return;
  std::size_t k = largest_pow2_below(n);
  if (index < lo + k) {
    build_audit_path(leaves, lo, lo + k, index, path);
    path->push_back(subtree_root(leaves, lo + k, hi));
  } else {
    build_audit_path(leaves, lo + k, hi, index, path);
    path->push_back(subtree_root(leaves, lo, lo + k));
  }
}

}  // namespace

Hash merkle_root_from_leaves(const std::vector<Hash>& leaves) {
  if (leaves.empty()) return empty_root();
  return subtree_root(leaves, 0, leaves.size());
}

// ---------------------------------------------------------------------------
// MerkleTree
// ---------------------------------------------------------------------------
void MerkleTree::append(const Hash& leaf) { leaves_.push_back(leaf); }

Hash MerkleTree::root() const { return merkle_root_from_leaves(leaves_); }

std::vector<Hash> MerkleTree::proof(std::size_t index) const {
  std::vector<Hash> path;
  if (index >= leaves_.size()) return path;
  build_audit_path(leaves_, 0, leaves_.size(), index, &path);
  return path;
}

std::vector<Hash> MerkleTree::consistency_proof(std::size_t old_size,
                                                const std::vector<Hash>& old_leaves) const {
  // RFC 6962 §2.1.2 SUBPROOF(m, D[n], b).  Guards against a caller passing a
  // prefix that does not actually match our leaves.
  std::vector<Hash> out;
  if (old_size == 0 || old_size > leaves_.size()) return out;
  if (old_size == leaves_.size()) return out;
  if (old_leaves.size() != old_size) return out;
  for (std::size_t i = 0; i < old_size; ++i)
    if (!ct_equal(old_leaves[i].data(), leaves_[i].data(), kHashLen)) return out;

  std::function<void(std::size_t, std::size_t, std::size_t, bool)> subproof =
      [&](std::size_t m, std::size_t lo, std::size_t n, bool b) {
        if (m == n) {
          // RFC 6962: SUBPROOF(m, D[m], true) = {} ; false = {MTH(D[m])}.
          if (!b) out.push_back(subtree_root(leaves_, lo, lo + n));
          return;
        }
        std::size_t k = largest_pow2_below(n);
        if (m <= k) {
          subproof(m, lo, k, b);
          out.push_back(subtree_root(leaves_, lo + k, lo + n));
        } else {
          subproof(m - k, lo + k, n - k, false);
          out.push_back(subtree_root(leaves_, lo, lo + k));
        }
      };
  subproof(old_size, 0, leaves_.size(), true);
  return out;
}

bool MerkleTree::verify_inclusion(const Hash& leaf, std::size_t index, std::size_t tree_size,
                                  const std::vector<Hash>& proof, const Hash& root) {
  // RFC 6962 §2.1.1 verification.
  if (index >= tree_size || tree_size == 0) return false;
  Hash r = leaf;
  std::size_t fn = index;
  std::size_t sn = tree_size - 1;
  for (const Hash& p : proof) {
    if (sn == 0) return false;
    if ((fn & 1) != 0 || fn == sn) {
      r = node_hash(p, r);
      if ((fn & 1) == 0) {
        while (fn != 0 && (fn & 1) == 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      r = node_hash(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn == 0 && ct_equal(r.data(), root.data(), kHashLen);
}

bool MerkleTree::verify_consistency(std::size_t old_size, const Hash& old_root,
                                    std::size_t new_size, const Hash& new_root,
                                    const std::vector<Hash>& proof) {
  // RFC 6962 §2.1.3 verification.
  if (old_size > new_size) return false;
  if (old_size == new_size) return proof.empty() && ct_equal(old_root.data(), new_root.data(), kHashLen);
  if (old_size == 0) return proof.empty();

  std::size_t node = old_size - 1;
  std::size_t last_node = new_size - 1;
  while ((node & 1) != 0) {
    node >>= 1;
    last_node >>= 1;
  }

  Hash node1, node2;
  std::size_t i = 0;
  if (node > 0) {
    if (proof.empty()) return false;
    node1 = proof[0];
    node2 = node1;
    i = 1;
  } else {
    node1 = old_root;
    node2 = old_root;
  }

  for (; i < proof.size(); ++i) {
    const Hash& p = proof[i];
    if (last_node == 0) return false;
    if ((node & 1) != 0 || node == last_node) {
      node1 = node_hash(p, node1);
      node2 = node_hash(p, node2);
      while (node != 0 && (node & 1) == 0) {
        node >>= 1;
        last_node >>= 1;
      }
    } else {
      node2 = node_hash(node2, p);
    }
    node >>= 1;
    last_node >>= 1;
  }
  return last_node == 0 && ct_equal(node1.data(), old_root.data(), kHashLen) &&
         ct_equal(node2.data(), new_root.data(), kHashLen);
}

// ---------------------------------------------------------------------------
// Checkpoint encoding
//
//   magic 'CP' | version(1) | device_id(4) | tree_size(8) | wall(8)
//   | device_us(8) | root(32) | prev(32) | frames_in(8) | raised(8)
//   | emitted(8)
// ---------------------------------------------------------------------------
namespace {
constexpr std::uint8_t kCpVersion = 1;
constexpr std::size_t kCpBodyLen =
    2 + 1 + 4 + 8 + 8 + 8 + 32 + 32 + 8 + 8 + 8;  // 119
}  // namespace

Bytes encode_checkpoint_body(const Checkpoint& c) {
  Bytes out;
  out.reserve(kCpBodyLen);
  out.push_back('C');
  out.push_back('P');
  out.push_back(kCpVersion);
  put_be32(&out, c.device_id);
  put_be64(&out, c.tree_size);
  put_be64(&out, static_cast<std::uint64_t>(c.wall_us));
  put_be64(&out, c.device_us);
  append_hash(&out, c.root);
  append_hash(&out, c.prev_checkpoint_hash);
  put_be64(&out, c.frames_in);
  put_be64(&out, c.emergencies_raised);
  put_be64(&out, c.emergencies_emitted);
  return out;
}

Status decode_checkpoint_body(Slice body, Checkpoint* out) {
  if (body.n != kCpBodyLen) return Status::BadLength;
  if (body.p[0] != 'C' || body.p[1] != 'P') return Status::BadMagic;
  if (body.p[2] != kCpVersion) return Status::BadVersion;
  out->device_id = get_be32(body.p + 3);
  out->tree_size = get_be64(body.p + 7);
  out->wall_us = static_cast<WallUs>(get_be64(body.p + 15));
  out->device_us = get_be64(body.p + 23);
  std::memcpy(out->root.data(), body.p + 31, kHashLen);
  std::memcpy(out->prev_checkpoint_hash.data(), body.p + 63, kHashLen);
  out->frames_in = get_be64(body.p + 95);
  out->emergencies_raised = get_be64(body.p + 103);
  out->emergencies_emitted = get_be64(body.p + 111);
  return Status::Ok;
}

Bytes SignedCheckpoint::encode() const {
  Bytes out = encode_checkpoint_body(checkpoint);
  out.insert(out.end(), signature.begin(), signature.end());
  return out;
}

Status SignedCheckpoint::decode(Slice in, SignedCheckpoint* out) {
  if (in.n != kCpBodyLen + kSigLen) return Status::BadLength;
  Status s = decode_checkpoint_body(Slice(in.p, kCpBodyLen), &out->checkpoint);
  if (!ok(s)) return s;
  std::memcpy(out->signature.data(), in.p + kCpBodyLen, kSigLen);
  return Status::Ok;
}

}  // namespace rp
