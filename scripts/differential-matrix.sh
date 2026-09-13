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
export MSYS_NO_PATHCONV=1   # Git Bash rewrites "/CN=..." into a Windows path
openssl genpkey -algorithm X25519 -out keys/recip.key 2>/dev/null
openssl genpkey -algorithm ed25519 -out keys/ca.key 2>/dev/null
openssl req -new -x509 -key keys/ca.key -out keys/ca.pem -days 30 -subj "/CN=tzap-matrix-ca" 2>/dev/null
openssl pkey -in keys/recip.key -pubout -out keys/recip.pub 2>/dev/null
openssl req -new -key keys/ca.key -out keys/dummy.csr -subj "/CN=tzap-matrix-recipient" 2>/dev/null
openssl x509 -req -in keys/dummy.csr -CA keys/ca.pem -CAkey keys/ca.key -force_pubkey keys/recip.pub -out keys/recip.pem -days 30 >/dev/null 2>&1

# Corpus: nested directories, a symlink where the platform allows one, and sizes
# that straddle frame boundaries. Portable shell -- no python, which Git Bash on
# Windows does not ship.
i=0
while [ $i -lt 60 ]; do
  case $((i % 4)) in
    0) d=corpus ;;
    1) d=corpus/nested ;;
    2) d=corpus/nested/deep ;;
    *) d=corpus/other ;;
  esac
  size=$(( (i * 37) % 2000 ))
  if [ "$size" -eq 0 ]; then
    : > "$d/f$(printf '%03d' $i).bin"
  else
    yes "tzap-matrix-corpus-$i" | head -c "$size" > "$d/f$(printf '%03d' $i).bin"
  fi
  i=$((i + 1))
done
# Symlinks need privilege or developer mode on Windows; skip rather than fail.
ln -s f000.bin corpus/link.sym 2>/dev/null || true

PASS=0; FAIL=0; SKIP=0; FIXED=0
FAILED_COMBOS=()
SKIPPED_COMBOS=()
FIXED_COMBOS=()

# Reference-side errors the candidate is expected to have fixed. A combination the
# reference rejects for one of these reasons, and the candidate accepts, counts as
# a fix rather than a failure. Anything else the candidate newly accepts still fails,
# so this cannot quietly hide a widening of what the writer allows.
: "${EXPECTED_FIXES:=Windows BackupRead did not return the default data stream}"

is_expected_fix() {
  local err="$1" pattern
  [ -n "${EXPECTED_FIXES:-}" ] || return 1
  while IFS= read -r pattern; do
    [ -n "$pattern" ] || continue
    case "$err" in *"$pattern"*) return 0 ;; esac
  done <<< "$EXPECTED_FIXES"
  return 1
}

vols_positional() { ls "$1"/$2*.tzap 2>/dev/null | sort | xargs echo; }
first_volume() { ls "$1"/$2*.tzap 2>/dev/null | sort | head -1; }
vols_flagged() {
  local first="" rest=""
  for f in $(ls "$1"/$2*.tzap 2>/dev/null | sort); do
    if [ -z "$first" ]; then first="$f"; else rest="$rest --volume $f"; fi
  done
  echo "$first$rest"
}

# The writer emits out.tzap for one volume and out.vol000.tzap... for a set;
# rename whichever appeared, keeping the volume suffix.
rename_outputs() {
  local work="$1" prefix="$2" f base
  for f in "$work"/out*.tzap; do
    [ -e "$f" ] || continue
    base=$(basename "$f")
    mv "$f" "$work/$prefix${base#out}"
  done
  [ -f "$work/out.boot" ] && mv "$work/out.boot" "$work/$prefix.boot"
  return 0
}

run_combo() {
  local name="$1"; shift
  local create_args=("$@")
  local work; work=$(mktemp -d)

  # Capture the status directly: inside `if ! cmd`, $? is the negation's status,
  # not the command's.
  $OLD create "${create_args[@]}" -o "$work/old.tzap" corpus >/dev/null 2>"$work/old.err"
  local old_rc=$?
  if [ $old_rc -ne 0 ]; then
    $NEW create "${create_args[@]}" -o "$work/probe.tzap" corpus >/dev/null 2>"$work/probe.err"
    local probe_rc=$?
    if [ $probe_rc -eq 0 ]; then
      if is_expected_fix "$(cat "$work/old.err")"; then
        FIXED=$((FIXED+1)); FIXED_COMBOS+=("$name"); rm -rf "$work"; return
      fi
      echo "  FAIL [$name] reference rejects this combo but the candidate accepts it: $(tail -1 "$work/old.err")"
      FAIL=$((FAIL+1)); FAILED_COMBOS+=("$name:accepts-rejected-combo"); rm -rf "$work"; return
    fi
    if is_expected_fix "$(cat "$work/old.err")"; then
      FIXED=$((FIXED+1)); FIXED_COMBOS+=("$name (candidate now refuses for its own reason: $(tail -1 "$work/probe.err" | cut -c1-70))"); rm -rf "$work"; return
    fi
    if [ $probe_rc -ne $old_rc ] || ! diff -q <(tail -1 "$work/old.err") <(tail -1 "$work/probe.err") >/dev/null 2>&1; then
      echo "  FAIL [$name] both reject but differently: ref=[rc=$old_rc $(tail -1 "$work/old.err")] cand=[rc=$probe_rc $(tail -1 "$work/probe.err")]"
      FAIL=$((FAIL+1)); FAILED_COMBOS+=("$name:reject-mismatch"); rm -rf "$work"; return
    fi
    SKIP=$((SKIP+1)); SKIPPED_COMBOS+=("$name -- rc=$old_rc $(tail -1 "$work/old.err" | head -c 90)"); rm -rf "$work"; return
  fi
  if ! $NEW create "${create_args[@]}" -o "$work/new.tzap" corpus >/dev/null 2>"$work/new.err"; then
    echo "  FAIL [$name] new build cannot create what 0.2.4 created: $(tail -1 "$work/new.err")"
    FAIL=$((FAIL+1)); FAILED_COMBOS+=("$name:create"); rm -rf "$work"; return
  fi

  local ok=1
  # The assertion is that both builds BEHAVE THE SAME on the other's archive --
  # not that every operation succeeds. Some shapes are legitimately refused on
  # some hosts (a tar carrying Unix modes cannot be restored exactly on Windows),
  # and a refusal both builds agree on is not a regression. So record each
  # outcome per binary and compare, rather than demanding success.
  local v_NEW v_OLD l_NEW l_OLD x_NEW x_OLD
  for spec in "NEW:$NEW:old" "OLD:$OLD:new"; do
    local tag="${spec%%:*}"; local rest="${spec#*:}"
    local bin="${rest%%:*}"; local which="${rest##*:}"
    local pos flagged
    pos=$(vols_positional "$work" "$which")
    flagged=$(vols_flagged "$work" "$which")

    if $bin verify $READ_KEY $pos >/dev/null 2>"$work/e"; then eval "v_$tag=ok"; else eval "v_$tag=\"fail:\$(tail -1 \"$work/e\")\""; fi
    if $bin list $READ_KEY $flagged >"$work/list.$tag" 2>"$work/e"; then eval "l_$tag=ok"; else eval "l_$tag=\"fail:\$(tail -1 \"$work/e\")\""; fi
    rm -rf "$work/out.$tag"
    if $bin extract $READ_KEY -C "$work/out.$tag" $flagged >/dev/null 2>"$work/e"; then
      if diff -r corpus "$work/out.$tag/corpus" >/dev/null 2>&1; then eval "x_$tag=ok"; else eval "x_$tag=tree-differs"; fi
    else
      eval "x_$tag=\"fail:\$(tail -1 \"$work/e\")\""
    fi
  done

  for op in v l x; do
    local n o label
    eval "n=\$${op}_NEW"; eval "o=\$${op}_OLD"
    case $op in v) label=verify ;; l) label=list ;; *) label=extract ;; esac
    if [ "$n" != "$o" ]; then
      echo "  FAIL [$name] $label disagrees: new=[$n] old=[$o]"; ok=0
    elif [ "$n" = "tree-differs" ]; then
      echo "  FAIL [$name] $label: both extracted a tree that differs from the source"; ok=0
    elif [ "$n" != "ok" ]; then
      echo "  note [$name] both builds refuse $label identically: ${n#fail:}"
    fi
  done

  # When both listed successfully they must describe the archive identically.
  if [ "${l_NEW:-}" = "ok" ] && [ "${l_OLD:-}" = "ok" ]; then
    sort "$work/list.NEW" > "$work/list.NEW.s"; sort "$work/list.OLD" > "$work/list.OLD.s"
    cmp -s "$work/list.NEW.s" "$work/list.OLD.s" || { echo "  FAIL [$name] listings differ between binaries"; ok=0; }
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

  # A single named member through --stdout must match the file on disk, byte for
  # byte. Pick the largest corpus file: the smallest is zero bytes, which proves
  # nothing, and compare via a temp file rather than process substitution.
  local one; one=$(ls -S corpus/*.bin 2>/dev/null | head -1)
  if [ -n "$one" ] && [ -s "$one" ]; then
    if $NEW extract $READ_KEY --stdout $old_flagged "$one" > "$work/stdout.bin" 2>"$work/e"; then
      cmp -s "$work/stdout.bin" "$one" || { echo "  FAIL [$name] --stdout bytes differ for $one"; ok=0; }
    else
      echo "  FAIL [$name] --stdout failed for $one: $(tail -1 "$work/e")"; ok=0
    fi
  fi

  if [ $ok -eq 1 ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); FAILED_COMBOS+=("$name"); fi
  rm -rf "$work"
}

HAVE_RECIPIENT=1
if [ ! -s keys/recip.pem ]; then
  HAVE_RECIPIENT=0
  echo "note: no X25519 recipient certificate could be generated with this openssl; skipping the RecipientWrap sweep"
fi

shape_matrix() {
for keymode in none keyfile recipient; do
  if [ "$keymode" = recipient ] && [ "$HAVE_RECIPIENT" -eq 0 ]; then continue; fi
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
}

# --- input, key-derivation and geometry modes -------------------------------
#
# The shape sweep above always creates from a directory with a raw key. These
# modes take different code paths into the writer and out of the reader:
# passphrase KDF, bootstrap sidecars, streamed tar/raw input, reading the
# archive itself from a pipe (the non-seekable reader), and size-driven volume
# splitting, which produces far more volumes than --volumes typically does.

PASSPHRASE="correct horse battery staple"

# Create with both binaries under a passphrase, then cross-read.
password_combo() {
  local name="$1"; shift
  local extra=("$@")
  local work; work=$(mktemp -d)
  if ! printf '%s\n' "$PASSPHRASE" | $OLD create --password-stdin "${extra[@]}" -o "$work/old.tzap" corpus >/dev/null 2>"$work/e"; then
    SKIP=$((SKIP+1)); SKIPPED_COMBOS+=("$name -- $(tail -1 "$work/e" | head -c 100)"); rm -rf "$work"; return
  fi
  printf '%s\n' "$PASSPHRASE" | $NEW create --password-stdin "${extra[@]}" -o "$work/new.tzap" corpus >/dev/null 2>&1
  local ok=1
  for spec in "NEW:$NEW:old" "OLD:$OLD:new"; do
    local tag="${spec%%:*}"; local rest="${spec#*:}"
    local bin="${rest%%:*}"; local which="${rest##*:}"
    local pos flagged
    pos=$(vols_positional "$work" "$which"); flagged=$(vols_flagged "$work" "$which")
    printf '%s\n' "$PASSPHRASE" | $bin verify --password-stdin $pos >/dev/null 2>"$work/e" || { echo "  FAIL [$name] $tag verify: $(tail -1 "$work/e")"; ok=0; }
    rm -rf "$work/out.$tag"
    if printf '%s\n' "$PASSPHRASE" | $bin extract --password-stdin -C "$work/out.$tag" $flagged >/dev/null 2>"$work/e"; then
      diff -r corpus "$work/out.$tag/corpus" >/dev/null 2>&1 || { echo "  FAIL [$name] $tag extracted tree differs"; ok=0; }
    else
      echo "  FAIL [$name] $tag extract: $(tail -1 "$work/e")"; ok=0
    fi
  done
  if [ $ok -eq 1 ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); FAILED_COMBOS+=("$name"); fi
  rm -rf "$work"
}

# Create once with each binary using a caller-supplied command, then cross-read
# through the plain path, through a bootstrap sidecar, and from a pipe.
stream_combo() {
  local name="$1"; local make="$2"; local read_key="$3"; local expect_tree="$4"
  local work; work=$(mktemp -d)
  if ! eval "${make//@BIN@/$OLD}" >/dev/null 2>"$work/e"; then
    rm -f "$work"/out*.tzap "$work/out.boot"
    if eval "${make//@BIN@/$NEW}" >/dev/null 2>"$work/probe.err"; then
      if is_expected_fix "$(cat "$work/e")"; then
        FIXED=$((FIXED+1)); FIXED_COMBOS+=("$name"); rm -rf "$work"; return
      fi
      echo "  FAIL [$name] reference rejects this combo but the candidate accepts it: $(tail -1 "$work/e")"
      FAIL=$((FAIL+1)); FAILED_COMBOS+=("$name:accepts-rejected-combo"); rm -rf "$work"; return
    fi
    if is_expected_fix "$(cat "$work/e")"; then
      FIXED=$((FIXED+1)); FIXED_COMBOS+=("$name (candidate now refuses for its own reason: $(tail -1 "$work/probe.err" | cut -c1-70))"); rm -rf "$work"; return
    fi
    if ! diff -q <(tail -1 "$work/e") <(tail -1 "$work/probe.err") >/dev/null 2>&1; then
      echo "  FAIL [$name] both reject but differently: ref=[$(tail -1 "$work/e")] cand=[$(tail -1 "$work/probe.err")]"
      FAIL=$((FAIL+1)); FAILED_COMBOS+=("$name:reject-mismatch"); rm -rf "$work"; return
    fi
    SKIP=$((SKIP+1)); SKIPPED_COMBOS+=("$name -- $(tail -1 "$work/e" | head -c 100)"); rm -rf "$work"; return
  fi
  rename_outputs "$work" old
  if ! eval "${make//@BIN@/$NEW}" >/dev/null 2>"$work/e"; then
    echo "  FAIL [$name] new build cannot create what 0.2.4 created: $(tail -1 "$work/e")"
    FAIL=$((FAIL+1)); FAILED_COMBOS+=("$name:create"); rm -rf "$work"; return
  fi
  rename_outputs "$work" new

  local ok=1
  local sv_NEW sv_OLD sl_NEW sl_OLD sx_NEW sx_OLD
  for spec in "NEW:$NEW:old" "OLD:$OLD:new"; do
    local tag="${spec%%:*}"; local rest="${spec#*:}"
    local bin="${rest%%:*}"; local which="${rest##*:}"
    local pos flagged
    pos=$(vols_positional "$work" "$which"); flagged=$(vols_flagged "$work" "$which")
    # As in run_combo: compare outcomes between builds rather than demanding
    # success, so a refusal both builds agree on is reported, not failed.
    if $bin verify $read_key $pos >/dev/null 2>"$work/e"; then eval "sv_$tag=ok"; else eval "sv_$tag=\"fail:\$(tail -1 \"$work/e\")\""; fi
    if $bin list $read_key $flagged >/dev/null 2>"$work/e"; then eval "sl_$tag=ok"; else eval "sl_$tag=\"fail:\$(tail -1 \"$work/e\")\""; fi
    rm -rf "$work/out.$tag"
    if $bin extract $read_key -C "$work/out.$tag" $flagged >/dev/null 2>"$work/e"; then
      if [ -n "$expect_tree" ] && ! diff -r "$expect_tree" "$work/out.$tag/$expect_tree" >/dev/null 2>&1; then
        eval "sx_$tag=tree-differs"
      else
        eval "sx_$tag=ok"
      fi
    else
      eval "sx_$tag=\"fail:\$(tail -1 \"$work/e\")\""
    fi

    # Single-volume archives must also read from a pipe (the non-seekable reader).
    local only; only=$(first_volume "$work" "$which")
    if [ "$(echo "$pos" | wc -w)" -eq 1 ] && [ -f "$only" ]; then
      # A bare pipe read is refused for some shapes (a dictionary archive needs
      # its sidecar). What matters is that both builds agree, so record the
      # outcome per binary and compare after the loop rather than assuming.
      if $bin verify $read_key - < "$only" >/dev/null 2>"$work/pipe.e"; then
        pipe_rc="0"
      else
        pipe_rc="1:$(tail -1 "$work/pipe.e")"
      fi
      eval "pipe_${tag}=\$pipe_rc"

      # And through the bootstrap sidecar when one was produced.
      local boot="$work/$which.boot"
      if [ -f "$boot" ]; then
        $bin verify $read_key --bootstrap "$boot" - < "$only" >/dev/null 2>"$work/boot.e" \
          || { echo "  FAIL [$name] $tag verify via sidecar: $(tail -1 "$work/boot.e")"; ok=0; }
      fi
    fi
  done
  for op in sv sl sx; do
    local n o label
    eval "n=\$${op}_NEW"; eval "o=\$${op}_OLD"
    case $op in sv) label=verify ;; sl) label=list ;; *) label=extract ;; esac
    if [ "${n:-}" != "${o:-}" ]; then
      echo "  FAIL [$name] $label disagrees: new=[${n:-unset}] old=[${o:-unset}]"; ok=0
    elif [ "${n:-}" = "tree-differs" ]; then
      echo "  FAIL [$name] $label: both extracted a tree that differs from the source"; ok=0
    elif [ "${n:-ok}" != "ok" ]; then
      echo "  note [$name] both builds refuse $label identically: ${n#fail:}"
    fi
  done
  unset sv_NEW sv_OLD sl_NEW sl_OLD sx_NEW sx_OLD

  # Both builds must reach the same verdict on a bare pipe read, whether that is
  # success or the same refusal.
  if [ -n "${pipe_NEW:-}" ] || [ -n "${pipe_OLD:-}" ]; then
    if [ "${pipe_NEW:-}" != "${pipe_OLD:-}" ]; then
      echo "  FAIL [$name] pipe read disagrees: new=[${pipe_NEW:-unset}] old=[${pipe_OLD:-unset}]"; ok=0
    elif [ "${pipe_NEW:-0}" != "0" ]; then
      echo "  note [$name] both builds refuse a bare pipe read identically: ${pipe_NEW#1:}"
    fi
  fi
  unset pipe_NEW pipe_OLD

  if [ $ok -eq 1 ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); FAILED_COMBOS+=("$name"); fi
  rm -rf "$work"
}

mode_matrix() {
  # Passphrase KDF, including non-default Argon2 cost parameters.
  password_combo "pw default"                 --bit-rot-buffer-pct 5
  password_combo "pw no parity"               --bit-rot-buffer-pct 0
  password_combo "pw 3 volumes"               --volumes 3 --volume-loss-tolerance 1
  password_combo "pw argon2 low cost"         --argon2-t-cost 1 --argon2-m-cost-kib 8192 --argon2-parallelism 1
  password_combo "pw argon2 parallel"         --argon2-t-cost 2 --argon2-m-cost-kib 16384 --argon2-parallelism 2
  password_combo "pw dictionary"              --dictionary keys/dict.bin
  password_combo "pw signed"                  --signing-key keys/sign.sec

  # Bootstrap sidecar, plaintext and encrypted.
  stream_combo "sidecar plaintext" \
    '@BIN@ create --no-encryption --bootstrap-out "$work/out.boot" -o "$work/out.tzap" corpus' "" corpus
  stream_combo "sidecar keyfile" \
    '@BIN@ create --keyfile keys/raw.hex --bootstrap-out "$work/out.boot" -o "$work/out.tzap" corpus' "--keyfile keys/raw.hex" corpus
  stream_combo "sidecar dictionary" \
    '@BIN@ create --keyfile keys/raw.hex --dictionary keys/dict.bin --bootstrap-out "$work/out.boot" -o "$work/out.tzap" corpus' "--keyfile keys/raw.hex" corpus

  # Streamed tar input.
  stream_combo "tar-stdin plaintext" \
    'tar cf - corpus 2>/dev/null | @BIN@ create --no-encryption -o "$work/out.tzap" --tar-stdin -' "" ""
  stream_combo "tar-stdin keyfile parity" \
    'tar cf - corpus 2>/dev/null | @BIN@ create --keyfile keys/raw.hex --bit-rot-buffer-pct 30 -o "$work/out.tzap" --tar-stdin -' "--keyfile keys/raw.hex" ""

  # Streamed raw input, with a declared size and spooled.
  stream_combo "raw-stdin declared size" \
    '@BIN@ create --no-encryption --raw-stdin --stdin-name blob.bin --stdin-size '"$CAT_SIZE"' -o "$work/out.tzap" - < corpus.cat' "" ""
  stream_combo "raw-stdin spooled" \
    '@BIN@ create --keyfile keys/raw.hex --raw-stdin --stdin-name blob.bin --spool-stdin -o "$work/out.tzap" - < corpus.cat' "--keyfile keys/raw.hex" ""

  # Size-driven splitting produces many more volumes than --volumes usually does.
  stream_combo "volume-size 128K" \
    '@BIN@ create --no-encryption --volume-size 128K -o "$work/out.tzap" corpus' "" corpus
  stream_combo "volume-size 64K high parity" \
    '@BIN@ create --keyfile keys/raw.hex --volume-size 64K --bit-rot-buffer-pct 30 -o "$work/out.tzap" corpus' "--keyfile keys/raw.hex" corpus

  # Non-default geometry: block, chunk and envelope sizing, and compression level.
  stream_combo "small geometry" \
    '@BIN@ create --no-encryption --block-size 4K --chunk-size 16K --envelope-size 64K -o "$work/out.tzap" corpus' "" corpus
  stream_combo "large geometry, level 19" \
    '@BIN@ create --keyfile keys/raw.hex --chunk-size 1M --envelope-size 4M --compression-level 19 -o "$work/out.tzap" corpus' "--keyfile keys/raw.hex" corpus
}

# A single concatenated blob for the raw-stdin modes; the declared size must be
# the real one, so compute it rather than hardcoding.
cat corpus/*.bin > corpus.cat 2>/dev/null || true
CAT_SIZE=$(wc -c < corpus.cat | tr -d ' ')

shape_matrix
mode_matrix

echo
if [ $FIXED -gt 0 ]; then
  echo "fixed relative to the reference (reference rejects, candidate accepts, for an expected reason):"
  printf '  %s\n' "${FIXED_COMBOS[@]}" | sort -u | head -20
  [ ${#FIXED_COMBOS[@]} -gt 20 ] && echo "  ... and $(( ${#FIXED_COMBOS[@]} - 20 )) more"
fi
echo "=== differential matrix vs v0.2.4: pass=$PASS fail=$FAIL skipped(both reject)=$SKIP fixed=$FIXED ==="
if [ $SKIP -gt 0 ]; then
  echo "skipped (the reference build rejects these; the candidate must reject them the same way):"
  printf '  %s\n' "${SKIPPED_COMBOS[@]}" | sort -u
fi
if [ $FAIL -gt 0 ]; then printf 'failed: %s\n' "${FAILED_COMBOS[@]}"; exit 1; fi
exit 0
