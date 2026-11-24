# Wire formats and verification protocol

All integers are big-endian **except** where an RFC mandates otherwise (the
ChaCha20-Poly1305 length block and Ed25519 `S` are little-endian, per their
specs). All hash-covered structures have exactly one encoding, so their hashes
are reproducible across architectures and compilers.

## Event

The only structure that leaves the device. Emitted on the wire, and the leaf
input to the Merkle ledger.

```
offset size field
0      2    magic 'E','P'
2      1    version (1)
3      1    kind (1=heartbeat,2=occupancy,3=activity,4=fall,5=apnea,
                 6=vitals,7=room,8=pipeline-drop,9=self-test)
4      4    seq (monotonic per device, never reused)
8      8    t_device_us (monotonic capture tick)
16     8    t_wall_us   (QUANTIZED to whole minutes; low bits masked)
24     1    zone (0=unknown,1=A,2=B,3=C)
25     1    confidence (0..100)
26     1    payload_len (<=32)
27     N    payload (kind-specific; e.g. apnea = u32 seconds)
```

Coarse vitals payload: `breath_band(1) || heart_band(1)`.

## Merkle ledger (RFC 6962)

- `leaf  = SHA-256(0x00 || event_body)`
- `node  = SHA-256(0x01 || left || right)`
- Inclusion proof: RFC 6962 §2.1.1 `PROOF`/verification.
- Consistency proof: RFC 6962 §2.1.2 `SUBPROOF` / §2.1.3 verification.
- Empty tree root = `SHA-256("")`.

## Checkpoint (signed)

```
'CP' ver(1) device_id(4) tree_size(8) wall_us(8) device_us(8)
root(32) prev_checkpoint_hash(32) frames_in(8) emergencies_raised(8)
emergencies_emitted(8)
```
Total body = 119 bytes. `signature = Ed25519(device_key, body)` (64 bytes).
`prev_checkpoint_hash` = SHA-256 of the previous checkpoint's **body**; the
first checkpoint chains to SHA-256 of the manifest body.

## Policy manifest (doubly signed)

```
'PM' ver(1) device_id(4) firmware_measurement(32) allowed_event_kinds(4)
max_frames_per_sec(4) fall_impact_milli(4) fall_immobility_milli(4)
apnea_seconds(4) apnea_confirm_seconds(4) max_bytes_per_min(4)
max_destinations(4) flags(1) journal_k(1) journal_n(1)
valid_from_us(8) valid_until_us(8)
```
followed by `vendor_sig(64) care_home_sig(64) vendor_pub(32) care_home_pub(32)`.

flags bit 0 = telemetry channel, 1 = firmware update, 2 = raw radar egress,
3 = journal enabled. **`decode_manifest_body` rejects any manifest with the raw
radar egress bit set** (`Status::PolicyViolation`).

## Attestation (signed, nonce-bound)

```
'AT' ver(1) device_id(4) firmware_measurement(32) policy_manifest_hash(32)
latest_checkpoint_hash(32)
frames_in(8) frames_classified(8) emergencies_raised(8) emergencies_emitted(8)
emergencies_suppressed(8) emergency_latch_overflows(8)
egress_bytes_today(8) raw_radar_bytes_egressed(8)
nonce_len(1) nonce(..) wall_us(8) device_us(8)
```
followed by `device_pub(32) signature(64)`.

## Journal file (dispute path)

Header:
```
'RJ' ver(1) device_id(4) recipient_pub(32) ephemeral_pub(32)
k(1) n(1) manifest_hash(32) nonce_len(1) wrapped_nonce(..)
wrapped_len(2) wrapped_key(..) record_count(4)
```
Each record:
```
idx(8) nonce(12) plaintext_hash(32) ct_len(4) ciphertext(ct_len)
```
AEAD AAD for both record and wrap operations is a fixed ASCII tag
(`radpriv-journal-v1` / `radpriv-wrap-v1`) to prevent cross-context confusion.

The header's `manifest_hash` binds the journal to the exact policy it was
written under. `journal-open --manifest <file>` recomputes this from the signed
manifest the adjudicator holds and refuses to decrypt if it differs, so dispute
evidence cannot be presented as having been gathered under a policy it was not.

## Audit bundle

```
'RB' ver(1)
u32 manifest_len | manifest bytes (SignedManifest::encode)
u32 attest_len   | attestation bytes (SignedAttestation::encode)
u32 cp_count     | { u32 len | checkpoint bytes }*
u32 ev_count     | { u32 body_len | body | u32 proof_len | proof_len*32 }*
```

## Verification protocol (`radpriv verify`)

Given a bundle and optionally `--firmware <hex>` (the regulator's own build)
and `--nonce <hex>` (the challenge the device was asked to answer):

1. Decode the manifest; it must be internally valid (raw-radar bit clear,
   2 ≤ k ≤ n). Verify **both** signatures over the manifest body.
2. Decode the attestation. Verify its signature under its stated device key.
3. `attest.policy_manifest_hash == SHA-256(manifest body)` — the attestation is
   for *this* policy.
4. `attest.firmware_measurement == manifest.firmware_measurement`, and (if
   given) `== --firmware`.
5. `attest.verifier_nonce == --nonce` (replay protection).
6. `emergencies_suppressed == 0` **and** `emergency_latch_overflows == 0`
   **and** `raw_radar_bytes_egressed == 0`.
7. `egress_bytes_today <= max_bytes_per_min * 1440`.
8. If the manifest specifies a validity window, `attest.wall_us` is inside it.
8. Each checkpoint: signature valid; `prev_checkpoint_hash` matches the previous
   checkpoint body hash (first one matches the manifest hash); tree sizes
   non-decreasing.
9. The last checkpoint's body hash `== attest.latest_checkpoint_hash` — the
   counter snapshot is inside the chain.
10. Each event: seq strictly increasing; kind allowed by the manifest;
    Merkle inclusion proof verifies against the final checkpoint root at the
    event's index.
11. `event_count <= final tree_size`.

Any failure → non-zero exit and a specific `verdict:` string. The verifier
never contacts the vendor and never sees anything but public artefacts.

## Why every step matters

- Steps 3–4 bind "this device, this firmware, this policy" into one signature
  set; you cannot present a valid attestation for a *different* policy.
- Step 5 stops an old attestation being replayed against a new challenge.
- Step 6 is the executable claim "it did not upload raw data and it suppressed
  no emergency."
- Step 9 makes the counters part of the append-only chain: a device cannot
  report different counters at attestation time than it committed to in its
  checkpoints.
- Step 10 makes "here is every event I emitted, and here is proof each is in my
  signed log" checkable, so omitting an embarrassing event breaks a proof.
