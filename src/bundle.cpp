// SPDX-License-Identifier: Apache-2.0
#include "rp/bundle.hpp"

#include <cstring>

namespace rp {

//   'RB' ver(1)
//   | u32 manifest_len | manifest bytes
//   | u32 attest_len   | attestation bytes
//   | u32 cp_count | per cp: u32 len | cp bytes
//   | u32 ev_count  | per ev: u32 body_len | body | u32 proof_len | proof_count*32
namespace {
constexpr std::uint8_t kBundleVersion = 1;

void put_blob(Bytes* out, Slice s) {
  put_be32(out, static_cast<std::uint32_t>(s.n));
  append(out, s);
}

bool take_blob(Slice* in, Slice* out) {
  if (in->n < 4) return false;
  std::uint32_t n = get_be32(in->p);
  if (in->n < 4 + static_cast<std::size_t>(n)) return false;
  *out = Slice(in->p + 4, n);
  *in = Slice(in->p + 4 + n, in->n - 4 - n);
  return true;
}
}  // namespace

Bytes encode_audit_bundle(const AuditBundle& b) {
  Bytes out;
  out.push_back('R');
  out.push_back('B');
  out.push_back(kBundleVersion);

  put_blob(&out, Slice(b.manifest.encode()));
  put_blob(&out, Slice(b.attestation.encode()));

  put_be32(&out, static_cast<std::uint32_t>(b.checkpoints.size()));
  for (const auto& cp : b.checkpoints) put_blob(&out, Slice(cp.encode()));

  put_be32(&out, static_cast<std::uint32_t>(b.events.size()));
  for (std::size_t i = 0; i < b.events.size(); ++i) {
    Bytes body = encode_event_body(b.events[i]);
    put_blob(&out, Slice(body));
    const std::vector<Hash>& pr =
        i < b.inclusion_proofs.size() ? b.inclusion_proofs[i] : std::vector<Hash>{};
    put_be32(&out, static_cast<std::uint32_t>(pr.size()));
    for (const Hash& h : pr) append_hash(&out, h);
  }
  return out;
}

Status decode_audit_bundle(Slice in, AuditBundle* out) {
  if (in.n < 3) return Status::Truncated;
  if (in.p[0] != 'R' || in.p[1] != 'B') return Status::BadMagic;
  if (in.p[2] != kBundleVersion) return Status::BadVersion;
  Slice rest(in.p + 3, in.n - 3);

  Slice mf;
  if (!take_blob(&rest, &mf)) return Status::Truncated;
  Status s = SignedManifest::decode(mf, &out->manifest);
  if (!ok(s)) return s;

  Slice at;
  if (!take_blob(&rest, &at)) return Status::Truncated;
  s = SignedAttestation::decode(at, &out->attestation);
  if (!ok(s)) return s;

  if (rest.n < 4) return Status::Truncated;
  std::uint32_t cp_count = get_be32(rest.p);
  rest = Slice(rest.p + 4, rest.n - 4);
  out->checkpoints.clear();
  for (std::uint32_t i = 0; i < cp_count; ++i) {
    Slice cb;
    if (!take_blob(&rest, &cb)) return Status::Truncated;
    SignedCheckpoint sc;
    s = SignedCheckpoint::decode(cb, &sc);
    if (!ok(s)) return s;
    out->checkpoints.push_back(sc);
  }

  if (rest.n < 4) return Status::Truncated;
  std::uint32_t ev_count = get_be32(rest.p);
  rest = Slice(rest.p + 4, rest.n - 4);
  out->events.clear();
  out->inclusion_proofs.clear();
  for (std::uint32_t i = 0; i < ev_count; ++i) {
    Slice body;
    if (!take_blob(&rest, &body)) return Status::Truncated;
    Event e;
    s = decode_event_body(body, &e);
    if (!ok(s)) return s;
    out->events.push_back(e);
    if (rest.n < 4) return Status::Truncated;
    std::uint32_t pc = get_be32(rest.p);
    rest = Slice(rest.p + 4, rest.n - 4);
    if (rest.n < std::size_t(pc) * kHashLen) return Status::Truncated;
    std::vector<Hash> proof(pc);
    for (std::uint32_t j = 0; j < pc; ++j)
      std::memcpy(proof[j].data(), rest.p + j * kHashLen, kHashLen);
    rest = Slice(rest.p + std::size_t(pc) * kHashLen, rest.n - std::size_t(pc) * kHashLen);
    out->inclusion_proofs.push_back(std::move(proof));
  }
  if (rest.n != 0) return Status::BadLength;
  return Status::Ok;
}

}  // namespace rp
