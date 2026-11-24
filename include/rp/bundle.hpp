// Bundle: the single file a device exports (and a regulator imports) so an
// audit can be reproduced offline.  It deliberately contains only public
// material: the signed manifest, the signed attestation, the signed checkpoint
// chain, the emitted events, and Merkle inclusion proofs.  Never raw radar,
// never the journal, never any key.
#pragma once

#include "rp/attest.hpp"

namespace rp {

Bytes encode_audit_bundle(const AuditBundle& b);
Status decode_audit_bundle(Slice in, AuditBundle* out);

}  // namespace rp
