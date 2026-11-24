# RadPriv — device-side privacy envelope for mmWave vital-sign monitoring

A C++17 reference implementation of the privacy layer that runs **on the radar
device itself**, between the DSP front end and the network stack, for a
care-home fall / apnea monitor. Raw radar returns never leave the device; only
a small, closed set of coarse events does. The design targets a Cortex-M7-class
MCU (~512 KiB SRAM, no MMU, no trusted OS).

It exists to answer three questions that the residents, their families and the
regulators actually ask:

1. **Can the caregiver or the vendor spy on the room?** No — raw radar is
   destroyed inside the envelope before anything else sees it, and the only
   surviving trace is coarse activity/zone buckets.
2. **Will a fall or an apnea episode be missed?** Emergencies run on a separate
   path that the routine rate-limiter cannot starve, are latched until delivered,
   and the device attests to having suppressed none.
3. **How do we resolve a dispute, and how does an outsider check the device
   isn't cheating?** A court-order-gated encrypted journal can reconstruct the
   *degraded* trace of an incident; an append-only Merkle ledger plus signed
   checkpoints and a signed policy manifest let a regulator verify offline what
   the device emitted and that it stayed inside policy.

## Why the design is shaped this way

The privacy threat and the safety threat pull in opposite directions:

| Requirement | Naive approach | What breaks | RadPriv's move |
|---|---|---|---|
| No raw data leak | Just don't send it | Firmware could have a covert upload path | Signed egress policy + attested byte counters + zero-raw-egress invariant |
| Don't miss falls | Classify every frame at full rate | MCU can't keep up; buffers drop frames silently | Content-triggered emergency bypass; latched until acked; decimation is *counted* |
| Retrace disputes | Keep a video-like log | That log *is* the surveillance risk | Encrypted, deliberately degraded, k-of-n gated, adjudicator-wrapped |
| Prove non-exfiltration | "Trust us" | Nobody does | Merkle inclusion proofs + checkpoint hash chain + firmware measurement, all verifiable offline |

Everything is **closed-world**: the code defines exactly which event kinds can
exist, the types cannot carry coordinates or fine timing, and the envelope
rejects anything outside the signed policy at egress.

## Architecture

```
        raw range-Doppler cube (never leaves this box)
                         │
                    ┌────▼─────────────────────────────────┐
   DSP front end ──▶│  PrivacyEnvelope                     │
                    │   1. extract()  -> Features (bands,  │
                    │        motion, centroid, energy)     │
                    │   2. scrub raw cube in place         │
                    │   3. emergency path (fall / apnea)   │
                    │      • content-triggered, latched    │
                    │      • never rate-limited away       │
                    │   4. routine path (transitions only) │
                    │   5. egress policy check             │
                    └────┬───────────────────┬─────────────┘
                         │ Event (tiny)      │ Event
              ┌──────────▼──────┐   ┌─────────▼──────────┐
              │ Merkle ledger   │   │ Encrypted journal  │
              │ + checkpoints   │   │ (dispute only,     │
              │ (public, signed)│   │  k-of-n + X25519)  │
              └──────────┬──────┘   └─────────┬──────────┘
                         │                    │
              ┌──────────▼────────────────────▼─────────┐
              │ Audit bundle (public artefacts only)     │  ──▶  regulator
              └──────────────────────────────────────────┘       verifies offline
```

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

No third-party dependencies: SHA-256/512, HMAC, HKDF, Ed25519, X25519,
ChaCha20-Poly1305 and Shamir secret sharing are all in-tree and tested against
published RFC vectors. The point is that the verifier image is small enough for
a reviewer to read end to end.

## Try it

```sh
# Run a scripted fall through the envelope, write an audit bundle + journal.
./build/radpriv simulate --scene fall --frames 120 \
    --out /tmp/bundle.bin --journal /tmp/journal.bin

# The regulator's tool: verify the bundle offline, no vendor contact.
./build/radpriv verify /tmp/bundle.bin --verbose

# Inspect the (coarse) events a care home is allowed to see.
./build/radpriv inspect /tmp/bundle.bin

# Dispute path: decrypt the degraded journal with the adjudicator's key,
# and check it was gathered under the policy you reviewed.
./build/radpriv journal-open /tmp/journal.bin --adjudicator-seed <64-hex> \
    --manifest /tmp/manifest.bin

# Show the signed policy the device is committed to.
./build/radpriv manifest

# Cryptographic self-tests (run at boot on the device).
./build/radpriv selftest
```

## What leaves the device

Only `rp::Event` (see `include/rp/event.hpp`). It carries: kind, monotonic seq,
device-capture tick, wall time **quantized to the minute**, a zone in {A,B,C},
a confidence byte, and ≤32 bytes of kind-specific payload (e.g. an apnea
duration). There is no float, no string, no coordinate, no per-second timeline.

## Layout

```
include/rp/    public headers (one per subsystem)
src/           implementations; field25519.hpp is the shared curve arithmetic
apps/          radpriv CLI and the simulator
tests/         RFC vector tests + the safety-critical envelope/bundle tests
docs/          DESIGN.md (the full argument), THREAT_MODEL.md, PROTOCOL.md
```

## Honest limitations

This is a reference implementation, not a certified medical device.

- The classifier is a transparent threshold model, not a trained fall detector;
  the envelope architecture is what is being demonstrated, not fall-detection
  accuracy on real bodies.
- "Firmware measurement" is modelled as a SHA-256 over a code region; a real
  deployment needs secure boot / a TPM-like root of trust to make it meaningful.
- Timing side-channels and power analysis are discussed in `docs/THREAT_MODEL.md`
  and are explicitly **out of scope** for the software layer; they require
  hardware countermeasures.
- The crypto is not constant-time on all paths (signing is boot/checkpoint only);
  see the threat model.
