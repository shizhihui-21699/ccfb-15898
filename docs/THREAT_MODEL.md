# Threat model

RadPriv's job is narrow and worth stating precisely: **the raw radar signal must
not leave the device, emergencies must not be lost, and an outside party must be
able to check both without trusting the vendor.** This document lists who might
attack which property, what the mechanism is, and — equally important — what is
*out of scope* so nobody over-claims.

## Assets

| Asset | Why it matters | Where it lives |
|---|---|---|
| Raw range-Doppler cube | Reconstructs room activity, dressing, toileting, intimacy | Only inside `consume()`; scrubbed before return |
| Fine-grained activity timeline | Inferring habits, presence, guests | Never created; events quantized to the minute |
| Journal plaintext | The degraded incident trace | Sealed AEAD records; key is Shamir-split + X25519-wrapped |
| Device signing key | Authenticity of checkpoints / attestations | Secure element seed (`SessionKeys::device_seed`) |
| Journal key | Decrypts the dispute trace | Derived from master; never stored in clear |

## Adversaries

### A1. Curious or malicious caregiver

*Goal:* browse the room, review what the resident does.

*Controls:* the device exposes only `Event`s (coarse, minute-quantized, no
coordinates). The journal is encrypted; a caregiver holds at most one Shamir
share (or none) and cannot open it. `inspect` on a bundle shows only the coarse
events. **Residual:** repeated coarse events still reveal a presence *pattern*
over days; this is inherent to any alerting device and is a policy decision
(retention, aggregation) rather than a device capability.

### A2. Malicious vendor (the device maker)

*Goal:* ship a covert upload path, or read the journal.

*Controls:* the vendor signs a **policy manifest** that enumerates allowed event
kinds and caps egress, with `allow_raw_radar_egress=false` enforced at decode.
The attestation reports `raw_radar_bytes_egressed` (must be 0) and
`egress_bytes_today` (must be ≤ policy ceiling), and the counter snapshot is
mirrored into the signed checkpoint chain, so a lying firmware must lie
consistently in two signed structures *and* the firmware measurement must match
a hash the regulator computes independently. The vendor holds **no** journal
share.

*Residual (important):* a malicious vendor controls the firmware measurement.
If the vendor ships firmware that lies about its own hash, **only a hardware
root of trust** (secure boot measured into an attestation register) closes this.
The software layer makes cheating *evident when the boot chain is honest*; it
cannot make a dishonest boot chain honest. This is why firmware measurement is
modelled as an injectable SHA-256 and the docs say so plainly.

### A3. Network attacker / passive eavesdropper

*Goal:* see what the device sends.

*Controls:* events contain no PII beyond coarse activity; checkpoints and
attestations are public and signed (tamper-evident, not secret). The journal is
encrypted end to end. **Residual:** traffic timing/volume metadata is not
protected; that needs a padding/cover-traffic scheme and is separate work.

### A4. Thief who steals the device / flash

*Goal:* read the stored journal, forge events.

*Controls:* journal records are AEAD-sealed; without the adjudicator key or a
k-of-n quorum the flash contents are opaque. Forging checkpoints needs the
device signing seed (secure element). **Residual:** loss of the secure element
is loss of the signing key; key rotation and revocation are out of scope here.

### A5. Accidental early/late emergency (the classifier is wrong)

*Goal:* n/a — this is a safety failure, not an attack.

*Controls:* emergencies are latched until acked, never rate-limited away, and
the "suppressed" counter must be zero or attestation fails. `bundle_detects_*`
tests prove a tampered or suppressed emergency fails verification. The
classifier's own accuracy is a separate, measurable property (see §Out of scope).

### A6. Insider at the regulator / care home colluding

*Goal:* open a journal without proper authority.

*Controls:* k-of-n means fewer than k shares reveal nothing; the X25519 wrap to
the adjudicator means even a full set of shares is not enough without the
adjudicator's key. Collusion of ≥k shares **and** the adjudicator is by
definition the court-ordered disclosure path — the design makes that action
deliberate and attributable, not silent.

## Cryptographic assumptions

- Ed25519 / X25519 / SHA-2 / ChaCha20-Poly1305 are secure as specified.
- The device RNG is a true random source (for ephemeral X25519 scalars and
  Shamir coefficients). A broken RNG breaks the wrap — called out in the code.
- Signing is not constant-time in this reference build; it runs only at boot and
  checkpoint time. See §Out of scope.

## Out of scope (stated so they are not mistaken for solved)

1. **Physical side-channels.** Power/EM/timing analysis of the MCU is not
   addressed. Mitigation requires hardware (constant-time silicon, shielding,
   RNG hardening).
2. **A dishonest boot chain / dishonest firmware measurement.** Needs secure
   boot + measured boot in hardware.
3. **Classifier accuracy.** This repo demonstrates the privacy envelope, not a
   clinically validated fall/apnea detector. Accuracy, sensitivity and
   specificity on real residents must be established separately and are a
   regulatory matter.
4. **Traffic-analysis resistance.** Message timing and size are not padded.
5. **Key lifecycle.** Provisioning, rotation, revocation of device/vendor/
   adjudicator keys are deployment operations not modelled here.
6. **Denial of service.** A jammed radio or powered-off device is a different
   failure mode (arguably the *safest* privacy failure: nothing leaves).
7. **Coercion of the k-of-n holders.** Social/legal compulsion is outside a
   device design.

## Test coverage of the claims

| Claim | Test |
|---|---|
| Raw cube scrubbed after consume | `envelope/raw_cube_is_scrubbed_after_consume` |
| No fine timing / coordinates leak | `envelope/emitted_events_have_no_fine_timing` |
| Emergency survives decimation | `envelope/decimation_bounds_classification_but_keeps_emergency` |
| Emergency re-offered until acked | `envelope/emergencies_are_repeated_until_acked` |
| Latch bounded; overflow visible | `envelope/unacked_emergencies_are_bounded_and_counted` |
| Fall / apnea detected on scripts | `envelope/fall_is_detected`, `apnea_is_detected` |
| Calm/empty raise no emergency | `envelope/calm_night_has_no_emergency`, `empty_room...` |
| Manifest rejects raw-radar policy | `attest/manifest_rejects_raw_radar_policy` |
| Attestation fails on wrong firmware/nonce | `attest/attestation_fails_on_*` |
| Suppressed emergency caught | `attest/attestation_detects_suppressed_emergency` |
| Raw-radar-egress claim caught | `attest/attestation_detects_raw_radar_egress_claim` |
| Tampered event caught by Merkle | `attest/bundle_detects_tampered_event` |
| Event outside policy caught | `attest/bundle_detects_disallowed_event_kind` |
| Broken checkpoint chain caught | `attest/bundle_detects_broken_checkpoint_chain` |
| Journal needs the right key | `journal/journal_wrong_key_fails`, `wrong_recipient...` |
| Journal tamper caught | `journal/journal_tamper_fails` |
| Primitive correctness | `crypto/*` against RFC vectors |
