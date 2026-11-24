// Append-only Merkle transparency log.
//
// The device has no persistent attacker-proof store, so we make every event's
// inclusion *verifiable after the fact* rather than trusting device storage:
//
//   * Each event body is a leaf: leaf = SHA-256(0x00 || event_body).
//   * Leaves are combined in a binary Merkle tree (RFC 6962 domain-separated
//     hashing) to a single root per "checkpoint" (every N events, or on an
//     emergency / on demand).
//   * Each checkpoint is signed with the device's Ed25519 key, publishing
//     {tree_size, root}.  The signature also covers the previous checkpoint's
//     hash, forming a hash chain: a device cannot rewrite history without
//     breaking either a Merkle proof or the chain.
//   * An auditor only needs the published checkpoints and the event stream.
//     Every event either has an inclusion proof against some signed root, or
//     the total count is short and the mismatch is visible.
//
// This is a local, embedded analogue of Certificate Transparency's log: the
// proofs are the same, the trust anchor is the device key provisioning step.
#pragma once

#include "rp/common.hpp"
#include "rp/event.hpp"

namespace rp {

Hash leaf_hash(Slice event_body);
Hash node_hash(const Hash& left, const Hash& right);
Hash empty_root();

// A full Merkle tree built over the current batch of leaves.  Kept in memory
// only long enough to produce proofs; on the device it is rebuilt from the
// event buffer at checkpoint time.
class MerkleTree {
 public:
  void append(const Hash& leaf);
  std::size_t size() const { return leaves_.size(); }
  Hash root() const;

  // Inclusion proof for leaf `index`: the sibling hashes from the leaf up to
  // the root (in bottom-up order), plus the index.  Empty if out of range.
  std::vector<Hash> proof(std::size_t index) const;

  // RFC 6962-style consistency proof that the tree of size `old_size` (whose
  // root is `old_root`) is a prefix of this tree.  Returns the node hashes an
  // auditor needs; empty on error.
  std::vector<Hash> consistency_proof(std::size_t old_size,
                                      const std::vector<Hash>& old_leaves) const;

  static bool verify_inclusion(const Hash& leaf, std::size_t index, std::size_t tree_size,
                               const std::vector<Hash>& proof, const Hash& root);
  static bool verify_consistency(std::size_t old_size, const Hash& old_root,
                                 std::size_t new_size, const Hash& new_root,
                                 const std::vector<Hash>& proof);

 private:
  std::vector<Hash> leaves_;
};

// Compute the RFC 6962 root over an explicit leaf vector (used by checkpoints
// and by the verifier, which never stores a tree).
Hash merkle_root_from_leaves(const std::vector<Hash>& leaves);

// A signed checkpoint: this is what the device publishes on the (untrusted)
// network.  It is tiny and fixed-size in the fields that matter.
struct Checkpoint {
  std::uint64_t tree_size = 0;
  Hash root{};                 // Merkle root of all leaves 0..tree_size-1
  Hash prev_checkpoint_hash{}; // chain link (hash of the previous checkpoint's
                               // signed body; zero for the first)
  WallUs wall_us = 0;
  Ticks device_us = 0;
  std::uint32_t device_id = 0;
  // Device counters snapshot, so the regulator can confirm no frame was
  // silently shed and no emergency was suppressed (omitted from the compact
  // wire form below to keep checkpoints small).
  std::uint64_t frames_in = 0;
  std::uint64_t emergencies_raised = 0;
  std::uint64_t emergencies_emitted = 0;
};

// Canonical signed-body encoding of a checkpoint (everything except the
// signature).  This is what gets signed and what the next checkpoint chains.
Bytes encode_checkpoint_body(const Checkpoint& c);
Status decode_checkpoint_body(Slice body, Checkpoint* out);

// A checkpoint with its Ed25519 signature over encode_checkpoint_body().
struct SignedCheckpoint {
  Checkpoint checkpoint;
  Signature signature{};
  Bytes encode() const;  // body || signature, self-delimiting
  static Status decode(Slice in, SignedCheckpoint* out);
};

}  // namespace rp
