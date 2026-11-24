#!/usr/bin/env bash
# End-to-end demo of the RadPriv privacy envelope.
#
# Runs a scripted scenario, then plays each of the three audiences:
#   1. the device             -- simulate, sealing events into the ledger
#   2. the regulator          -- verify the audit bundle offline (no vendor)
#   3. the family / regulator -- dispute path: decrypt the gated journal
#
# Usage: ./scripts/demo.sh [path-to-radpriv]
set -euo pipefail

RADP="${1:-./build/radpriv}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

hr() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

hr "1. DEVICE: run a fall scenario"
"$RADP" simulate --scene fall --frames 120 \
  --out "$WORK/bundle.bin" --journal "$WORK/journal.bin"

hr "2. REGULATOR: verify the bundle offline (no contact with the vendor)"
set +e
"$RADP" verify "$WORK/bundle.bin" --verbose
VERIFY_RC=$?
set -e
echo "verify exit code: $VERIFY_RC  (0 = every check passed)"

hr "3. CARE HOME: inspect only the coarse events the device is allowed to emit"
"$RADP" inspect "$WORK/bundle.bin" | head -20

hr "4. REGULATOR: tamper with one byte and re-verify (must fail closed)"
python3 - "$WORK/bundle.bin" "$WORK/tampered.bin" <<'PY'
import sys
d = bytearray(open(sys.argv[1],'rb').read())
d[len(d)//2] ^= 0xFF
open(sys.argv[2],'wb').write(d)
PY
set +e
"$RADP" verify "$WORK/tampered.bin" | tail -1
echo "tampered verify exit: $?  (non-zero = caught)"
set -e

hr "5. DISPUTE PATH: decrypt the gated journal with the adjudicator key"
"$RADP" manifest --out "$WORK/manifest.bin" >/dev/null
SEED=$(python3 -c "print(''.join('%02x'%(0xA0+i) for i in range(32)))")
"$RADP" journal-open "$WORK/journal.bin" --adjudicator-seed "$SEED" \
  --manifest "$WORK/manifest.bin"

hr "6. DEVICE: cryptographic self-test (runs at boot)"
"$RADP" selftest

hr "7. PRIVACY POLICY the device is committed to"
"$RADP" manifest

printf '\nDemo complete. Bundle was a public artefact (%s bytes); journal was encrypted at rest.\n' \
  "$(stat -c%s "$WORK/bundle.bin" 2>/dev/null || stat -f%z "$WORK/bundle.bin")"
