#!/bin/bash
# Differential matrix against the released v0.2.4 CLI.
#
# Every archive-shape combination is built by BOTH v0.2.4 and the current build,
# then each binary reads the other's archive through every read surface. Any
# behaviour change introduced by the performance work shows up as a mismatch.
#
# Volume-set invocation differs per subcommand: `verify` takes every volume
# positionally, while `list` and `extract` take one positional archive plus a
# repeated --volume flag (extra positionals there are PATH arguments).
#
# Usage: scripts/differential-matrix.sh <reference-tzap> [candidate-tzap]
#
# Build the reference from the last release tag, e.g.
#   git worktree add /tmp/tzap-v0.2.4 v0.2.4 && cargo build --release --manifest-path /tmp/tzap-v0.2.4/Cargo.toml
#
# Needs the openssl CLI for the X25519 recipient certificate.
set -u
OLD="${1:?usage: differential-matrix.sh <reference-tzap> [candidate-tzap]}"
NEW="${2:-target/release/tzap}"
OLD=$(cd "$(dirname "$OLD")" && pwd)/$(basename "$OLD")
NEW=$(cd "$(dirname "$NEW")" && pwd)/$(basename "$NEW")
WORKROOT=$(mktemp -d)
trap 'rm -rf "$WORKROOT"' EXIT
cd "$WORKROOT"

# Key material. X25519 cannot self-sign, so an Ed25519 CA issues the recipient
# certificate with -force_pubkey.
mkdir -p keys corpus/nested/deep corpus/other
"$NEW" keygen -o keys/raw.hex >/dev/null
"$NEW" signing-keygen --secret-output keys/sign.sec --public-output keys/sign.pub >/dev/null
head -c 65536 /dev/urandom > keys/dict.bin
openssl genpkey -algorithm X25519 -out keys/recip.key 2>/dev/null
openssl genpkey -algorithm ed25519 -out keys/ca.key 2>/dev/null
openssl req -new -x509 -key keys/ca.key -out keys/ca.pem -days 30 -subj "/CN=tzap-matrix-ca" 2>/dev/null
openssl pkey -in keys/recip.key -pubout -out keys/recip.pub 2>/dev/null
openssl req -new -key keys/ca.key -out keys/dummy.csr -subj "/CN=tzap-matrix-recipient" 2>/dev/null
openssl x509 -req -in keys/dummy.csr -CA keys/ca.pem -CAkey keys/ca.key -force_pubkey keys/recip.pub -out keys/recip.pem -days 30 >/dev/null 2>&1

# Corpus: nested directories, a symlink, and sizes that straddle frame boundaries.
python3 - <<'PYGEN'
import os
for i in range(60):
    d = ['corpus', 'corpus/nested', 'corpus/nested/deep', 'corpus/other'][i % 4]
    open(f'{d}/f{i:03}.bin', 'wb').write(bytes((i * 7 + b) % 251 for b in range((i * 37) % 2000)))
if not os.path.exists('corpus/link.sym'):
    os.symlink('f000.bin', 'corpus/link.sym')
PYGEN

PASS=0; FAIL=0; SKIP=0
FAILED_COMBOS=()

vols_positional() { ls "$1"/$2*.tzap 2>/dev/null | sort | tr '\n' ' '; }
vols_flagged() {
  local first="" rest=""
  for f in $(ls "$1"/$2*.tzap 2>/dev/null | sort); do
    if [ -z "$first" ]; then first="$f"; else rest="$rest --volume $f"; fi
  done
  echo "$first$rest"
}

run_combo() {
  local name="$1"; shift
  local create_args=("$@")
  local work; work=$(mktemp -d)

  if ! $OLD create "${create_args[@]}" -o "$work/old.tzap" corpus >/dev/null 2>"$work/old.err"; then
    SKIP=$((SKIP+1)); rm -rf "$work"; return
  fi
  if ! $NEW create "${create_args[@]}" -o "$work/new.tzap" corpus >/dev/null 2>"$work/new.err"; then
    echo "  FAIL [$name] new build cannot create what 0.2.4 created: $(tail -1 "$work/new.err")"
    FAIL=$((FAIL+1)); FAILED_COMBOS+=("$name:create"); rm -rf "$work"; return
  fi

  local ok=1
  # tag : binary : which archive it reads
  for spec in "NEW:$NEW:old" "OLD:$OLD:new"; do
    local tag="${spec%%:*}"; local rest="${spec#*:}"
    local bin="${rest%%:*}"; local which="${rest##*:}"
    local pos flagged
    pos=$(vols_positional "$work" "$which")
    flagged=$(vols_flagged "$work" "$which")

    if ! $bin verify $READ_KEY $pos >/dev/null 2>"$work/e"; then
      echo "  FAIL [$name] $tag verify: $(tail -1 "$work/e")"; ok=0
    fi
    if ! $bin list $READ_KEY $flagged >"$work/list.$tag" 2>"$work/e"; then
      echo "  FAIL [$name] $tag list: $(tail -1 "$work/e")"; ok=0
    fi
    rm -rf "$work/out.$tag"
    if ! $bin extract $READ_KEY -C "$work/out.$tag" $flagged >/dev/null 2>"$work/e"; then
      echo "  FAIL [$name] $tag extract: $(tail -1 "$work/e")"; ok=0
    elif ! diff -r corpus "$work/out.$tag/corpus" >/dev/null 2>&1; then
      echo "  FAIL [$name] $tag extracted tree differs from source"; ok=0
    fi
  done

  # Both binaries must describe archives of the same shape identically.
  if [ -f "$work/list.NEW" ] && [ -f "$work/list.OLD" ]; then
    diff <(sort "$work/list.NEW") <(sort "$work/list.OLD") >/dev/null || { echo "  FAIL [$name] listings differ between binaries"; ok=0; }
  fi

  # Naming every member must equal the full extraction -- this is the path the
  # performance work rewrote, so it is checked against 0.2.4's own archive.
  local paths; paths=$(cd corpus && find . -type f | sed 's|^\./|corpus/|' | sort | tr '\n' ' ')
  local old_flagged; old_flagged=$(vols_flagged "$work" old)
  rm -rf "$work/sel"
  if $NEW extract $READ_KEY -C "$work/sel" $old_flagged $paths >/dev/null 2>"$work/e"; then
    for p in $paths; do
      if ! diff -q "$p" "$work/sel/$p" >/dev/null 2>&1; then
        echo "  FAIL [$name] selected extraction differs for $p"; ok=0; break
      fi
    done
  else
    echo "  FAIL [$name] selected extraction: $(tail -1 "$work/e")"; ok=0
  fi

  # And a single named member through --stdout must match the file on disk.
  local one="corpus/f000.bin"
  if ! diff <($NEW extract $READ_KEY --stdout $old_flagged "$one" 2>/dev/null) "$one" >/dev/null; then
    echo "  FAIL [$name] --stdout bytes differ for $one"; ok=0
  fi

  if [ $ok -eq 1 ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); FAILED_COMBOS+=("$name"); fi
  rm -rf "$work"
}

for keymode in none keyfile recipient; do
  case $keymode in
    none)      CREATE_KEY=(--no-encryption);                 READ_KEY="" ;;
    keyfile)   CREATE_KEY=(--keyfile keys/raw.hex);          READ_KEY="--keyfile keys/raw.hex" ;;
    recipient) CREATE_KEY=(--recipient-cert keys/recip.pem); READ_KEY="--recipient-key keys/recip.key" ;;
  esac
  for volumes in 1 3; do
    for parity in 0 5 30; do
      for dict in off on; do
        for signing in off on; do
          args=("${CREATE_KEY[@]}" --bit-rot-buffer-pct "$parity")
          [ "$volumes" != 1 ] && args+=(--volumes "$volumes" --volume-loss-tolerance 1)
          [ "$dict" = on ] && args+=(--dictionary keys/dict.bin)
          [ "$signing" = on ] && args+=(--signing-key keys/sign.sec)
          run_combo "key=$keymode vol=$volumes parity=$parity dict=$dict sign=$signing" "${args[@]}"
        done
      done
    done
  done
done

echo
echo "=== differential matrix vs v0.2.4: pass=$PASS fail=$FAIL skipped(0.2.4 rejects the combo)=$SKIP ==="
if [ $FAIL -gt 0 ]; then printf 'failed: %s\n' "${FAILED_COMBOS[@]}"; exit 1; fi
exit 0
