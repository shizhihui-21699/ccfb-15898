# Design

This document explains *why* RadPriv looks the way it does. It is written for
the three readers who have to agree before a care home can deploy this:

- the **engineer** who has to make it run in real time on a small MCU,
- the **regulator / auditor** who has to be convinced raw radar cannot leave,
- the **care home and the family** who have to be convinced it is safe and
  that it is not a surveillance device in disguise.

Each constraint below states the problem, the naive answer and why it fails,
then the mechanism and the evidence it produces.

---

## 1. The privacy-safety tension

The device's whole value is that it perceives the room; the whole risk is that
it perceives the room. A naive build ships the range-Doppler cube to a cloud
service that runs a large fall-detection model. That is the thing families and
regulators object to: the cube can reconstruct walking, dressing, toileting,
and — in a double room — intimate contact. It is, functionally, a low-resolution
camera that sees through blankets.

The alternative, "do everything on-device," creates the second problem: a
vanished incident. If the device only logs "fall at 03:14," a disputed injury
has no context, and a missed fall cannot be diagnosed.

RadPriv separates the two into different mechanisms with different trust:

- **The hot path is privacy-maximal.** It keeps nothing reversible.
- **The dispute path is encrypted and gated.** It keeps a *degraded* trace, and
  nobody — not the caregiver, not the vendor — can read it alone.

---

## 2. The envelope: destroying the cube, not hiding it

`PrivacyEnvelope::consume()` has exactly one job: turn a `RadarFrame` into zero
or more `Event`s and leave no usable radar data behind.

### 2.1 Feature extraction is lossy by construction

`Features` (envelope.hpp) contains only:

- four **range-band** energies (near/mid/far/very-far) in dB over noise floor,
- total energy above floor (one scalar),
- the fraction of above-floor energy that is *moving* (motion, relative to the
  person, not absolute noise),
- a range **centroid** mapped to a continuous 0..3 band coordinate,
- a height proxy.

The per-cell `amplitude[range][doppler]` structure — which is what maps to
positions in the room — is gone the moment `band_energies()` and `centroid_band()`
return four numbers and one coordinate. This is the irreversibility point. You
cannot reconstruct where someone stood, or what limb moved, from four band
energies and a centroid.

### 2.2 Scrub-on-consume reaches the caller's buffer

`consume(RadarFrame& frame, ...)` takes the frame **by reference** and
`secure_wipe`s `amplitude` and `velocity` in place before returning (envelope.cpp
§consume step 2). This is deliberate and is the one mutation the envelope
performs on its input: if it took the frame by value, it would scrub a copy and
the caller's buffer would still hold the cube. The regression test
`raw_cube_is_scrubbed_after_consume` asserts the caller's frame is all zeros
after the call.

The wipe uses a `volatile` store loop (`secure_wipe`) so the optimiser cannot
elide it.

### 2.3 Emergencies are not subject to the routine rate limit

The device cannot classify every frame at full rate on an MCU. `consume()`
therefore:

1. **extracts features first** (cheap, content-based),
2. computes a **stateful impact score** (surge of total energy over a slow
   baseline; a fall is a >8× impulse, ordinary activity is a modest wobble),
3. *then* decides whether to decimate.

A frame whose impact score exceeds the policy threshold is **classified even
if the rate limiter would otherwise drop it** (`forced_emergency`). Decimation
only ever drops routine frames; it is counted in `frames_decimated` and sealed
into every checkpoint, so "we shed frames" is visible to the auditor, and
"we shed an emergency" is impossible by construction.

### 2.4 Emergencies are latched until acknowledged

When a fall or apnea is detected, the event is **both** emitted on this call
**and** pushed into a bounded latch (`pending_emergencies_`). Every subsequent
`consume()` re-offers all pending emergencies at the front of its result. They
are removed only when the delivery layer calls `ack_emergency(seq)`.

This turns "best effort" into "at least once": a transient bus failure or a
full transmit queue cannot lose a fall. The session's ledger deduplicates
re-offers by a seq high-water mark so the audit log records each event once.

The latch is **bounded** (`kMaxPendingEmergencies = 16`). A persistently dead
radio would otherwise grow the queue until the MCU's tiny heap is exhausted and
the device crashes — losing *everything*, including the ability to detect the
next fall. When the latch is full, further emergencies are still emitted
best-effort and the overflow is counted in `emergency_latch_overflows`, which
**must be zero or attestation fails** (§5.3). So a genuine delivery outage is a
loud, auditable failure, not a silent crash.

`emergencies_raised - emergencies_emitted` is the "suppressed" count; the
attestation requires it to be **zero**, as it does
`emergency_latch_overflows == 0`, or verification fails.

---

## 3. Why the emitted type cannot leak

`Event` is the only structure that crosses the trust boundary. Its definition
is the privacy contract:

- **No float.** Every field is an integer with a documented unit. Floats have
  many encodings per value and can smuggle mantissa bits into a covert channel.
- **No string.** Strings are where names and free text leak.
- **Wall time is quantized to the minute** at the *constructor* (`quantize_wall`),
  re-quantized in `encode_event_body`, and again in `accept()`. Sub-minute
  timing is a covert channel (activity encodes in the microsecond field); three
  independent chokepoints make it impossible to forget.
- **Zone is a 2-bit enum** {A,B,C}, not a coordinate; `bucket_zone` throws away
  sub-band position.
- **Vitals are clinical bands**, not bpm. A precise 14.3 bpm is a fingerprint;
  "normal" is what a caregiver acts on. `breath_band`/`heart_band` collapse the
  continuous value in `event.cpp`.
- **Payload ≤ 32 bytes**, kind-specific, schema-checked at egress.

`accept()` rejects anything outside these rules and increments
`schema_rejections`; only emergencies are allowed to bypass the batch but are
still latched, never silently dropped.

---

## 4. The dispute journal: evidence nobody can browse

The tension: the family's caregiver must not be able to review the room, but a
disputed injury needs *some* record.

### 4.1 Degrade on write

`JournalEntry` stores kind, coarse zone, activity class, vitals band, confidence
and an emergency flag — **at most one entry per 30 s**, plus emergencies. It
never holds a cube, never a per-second trace. Wall time is quantized on append
(`Journal::append`).

### 4.2 Encrypt at rest, gate the key with k-of-n

Each journal record is ChaCha20-Poly1305 sealed under a per-device key derived
from the device master secret (`derive_journal_key`, HKDF domain-separated).
The key is **Shamir-split k-of-n** between the care home, the resident's
guardian, and the regulator (`shamir_split`, `shamir_combine`). The vendor holds
no share. No single party can open the journal.

### 4.3 Wrap to the adjudicator too

The journal key is additionally wrapped to an adjudicator's X25519 key
(`wrap_journal_key`): an ephemeral device scalar × the adjudicator public key →
HKDF → AEAD of the journal key. So even a quorum must route disclosure through
the court-appointed recipient, who is the only one who can unwrap.

The net effect: `journal-open` (the dispute tool) needs the adjudicator's
private key **and** the file; casual review is impossible; a court order
recovers exactly the degraded trace and nothing more, because the journal never
held more.

### 4.4 Integrity, not just confidentiality

Each record carries a SHA-256 of its plaintext (`plaintext_hash`), checked on
open. Nonces are deterministic per (device, key, record index) — safe because
the key is per-device and the index is monotonic — so no RNG is needed at this
layer. Tampering with a record fails `BadTag` or `HashMismatch`.

---

## 5. Attestation: proving non-exfiltration to an outsider

This is the hardest claim: "the device did not quietly upload raw data." It
cannot rest on the device's word. RadPriv makes three artefacts that a
regulator checks **offline** (`radpriv verify`), with no call to the vendor.

### 5.1 The signed policy manifest

Before deployment, the vendor (and the care home, co-signing) commit to a
`PolicyManifest` (`policy.hpp`) that binds, under Ed25519 signatures:

- the **firmware measurement** (SHA-256 of the code region),
- the **closed set of event kinds** the device may emit (a bitmask),
- the **envelope thresholds** and apnea window (as fixed-point integers),
- the **egress policy**: max bytes/min, max destinations, and an explicit
  `allow_raw_radar_egress = false`.

`decode_manifest_body` **rejects** any manifest that permits raw radar egress or
an invalid k-of-n. A device that phones home would have to violate a signed,
published commitment.

### 5.2 The Merkle ledger and checkpoint chain

Every emitted event body is a leaf: `SHA-256(0x00 || body)` (RFC 6962 domain
separation). Leaves build a Merkle tree to a root per checkpoint. Each
`SignedCheckpoint` carries `{tree_size, root, prev_checkpoint_hash, counters}`
and is **Ed25519-signed by the device**, and chains to the previous checkpoint's
hash — the first checkpoint chains to the manifest hash. A device cannot rewrite
history without breaking either a Merkle proof or the chain.

Inclusion and consistency proofs follow RFC 6962 §2.1 exactly and are tested for
every tree size 1..64 (positive) and against wrong index/root/reversed
(negative): `tests/test_ledger.cpp`.

### 5.3 The attestation binds it to a live challenge

`SignedAttestation` signs, over a **verifier-supplied nonce**:

- the firmware measurement and the policy hash,
- the latest checkpoint hash (so the counter snapshot is inside the chain),
- a **counter snapshot**: frames in/classified, emergencies raised/emitted/
  **suppressed**, `egress_bytes_today`, `raw_radar_bytes_egressed`.

`verify_attestation` fails closed on:

- a bad signature,
- a manifest hash mismatch (attestation is for a different policy),
- a firmware measurement that differs from the image the regulator built,
- a nonce echo mismatch (replay),
- **any suppressed emergency** (`emergencies_suppressed != 0`),
- **any raw radar egress** (`raw_radar_bytes_egressed != 0`),
- daily egress above the policy ceiling.

The `raw_radar_bytes_egressed == 0` check is the executable form of "it did not
upload raw data": it is a counter the network stack increments and the
application cannot reset, mirrored into the signed chain via the checkpoint
hash.

### 5.4 The audit bundle

`AuditBundle` (bundle.hpp) packs the signed manifest, signed attestation,
checkpoint chain, events and per-event inclusion proofs into one file.
`verify_audit_bundle` re-derives everything: signatures, chain links, that each
event is inside the tree, that each event kind is manifest-allowed, and that
seqs are strictly increasing. It is the single artefact a regulator imports.

---

## 6. Cryptographic choices

The verifier image must be small enough to audit. So the primitives are in-tree
and tested against RFC vectors rather than pulled from OpenSSL:

| Primitive | Use | Tested against |
|---|---|---|
| SHA-256 / SHA-512 | hashing, Merkle, measurements | FIPS 180-4 KATs |
| HMAC-SHA256 / HKDF | key derivation | RFC 4231, RFC 5869 |
| Ed25519 | device / vendor / care-home signatures | RFC 8032 vectors 1 & 2 |
| X25519 | journal key wrapping | RFC 7748 |
| ChaCha20-Poly1305 | journal & wrap AEAD | RFC 8439 §2.8.2 |
| Shamir over GF(256) | journal key split | round-trip + below-threshold negative |

`src/field25519.hpp` is the single GF(2^255−19) arithmetic core shared by
Ed25519 and X25519, so there is exactly one curve implementation to review.

---

## 7. Real-time budget

The hot path is O(cells) per frame with small constant factors (32×16 = 512
cells). Feature extraction is a few hundred float ops; classification is a
handful of comparisons. No allocation on the hot path after construction; no
crypto on the hot path (signatures happen only at checkpoints and attestation,
which are off the frame cadence). `EnvelopeStats.max_classify_us` is tracked so
field deployments can confirm the budget; the simulator exercises 10–100 Hz
input.

Measured on an Apple-silicon host with `-O2` (`privacy envelope only`, no
synthesis): **~2.6 µs/frame**, i.e. ~380k frames/s. A Cortex-M7 at ~480 MHz with
a single-precision FPU is roughly an order of magnitude or two slower for this
float-heavy code, which still leaves ~50–130 µs/frame — far inside a 2 ms budget
at the 10 Hz classification rate the policy sets. The point is not the exact
number but the shape: the work is linear in cells and constant in window length,
so it does not grow with how long the device has been running.

---

## 8. What this does *not* do

See `docs/THREAT_MODEL.md` for the full enumeration. The headline exclusions:

- It does not make the *classifier* medically accurate; it makes whatever the
  classifier decides privacy-safe and auditable. A production build swaps
  `ReferenceClassifier` for a trained, measured model behind the same interface.
- It does not defeat physical or timing side-channels; those need hardware.
- The firmware measurement is only as trustworthy as the boot chain that
  produces it; a real deployment needs secure boot.
