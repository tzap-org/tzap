#!/bin/bash
#
# Cross-platform read-side differential.
#
# Some archive shapes cannot be built on every platform -- Windows could not
# collect a directory whose NTFS index had grown, so no released binary can
# produce a directory archive there. Reading is unaffected, so build the shapes
# on a host that can and compare how two binaries READ them on the host that
# cannot. That is where the extract/lookup paths live, so it is the coverage
# that matters most.
#
# Usage:
#   cross-platform-read-matrix.sh export <builder-tzap> <out-dir>
#   cross-platform-read-matrix.sh check  <reference-tzap> <candidate-tzap> <dir>
#
set -u
MODE="${1:?usage: export <builder> <out-dir> | check <reference> <candidate> <dir>}"

abspath() { ( cd "$(dirname "$1")" && printf '%s/%s' "$(pwd)" "$(basename "$1")" ); }

# name|create-args|read-key  -- read-key is applied verbatim when reading.
shapes() {
  cat <<'EOF'
plain-1vol|--no-encryption --bit-rot-buffer-pct 5|
plain-noparity|--no-encryption --bit-rot-buffer-pct 0|
plain-highparity|--no-encryption --bit-rot-buffer-pct 30|
plain-3vol|--no-encryption --volumes 3 --volume-loss-tolerance 1|
plain-4vol-highparity|--no-encryption --volumes 4 --volume-loss-tolerance 1 --bit-rot-buffer-pct 30|
plain-volsize|--no-encryption --volume-size 128K|
plain-smallgeom|--no-encryption --block-size 4K --chunk-size 16K --envelope-size 64K|
plain-largegeom|--no-encryption --chunk-size 1M --envelope-size 4M --compression-level 19|
plain-dict|--no-encryption --dictionary KEYS/dict.bin|
plain-signed|--no-encryption --signing-key KEYS/sign.sec|
key-1vol|--keyfile KEYS/raw.hex --bit-rot-buffer-pct 5|--keyfile KEYS/raw.hex
key-noparity|--keyfile KEYS/raw.hex --bit-rot-buffer-pct 0|--keyfile KEYS/raw.hex
key-highparity|--keyfile KEYS/raw.hex --bit-rot-buffer-pct 30|--keyfile KEYS/raw.hex
key-3vol|--keyfile KEYS/raw.hex --volumes 3 --volume-loss-tolerance 1|--keyfile KEYS/raw.hex
key-volsize|--keyfile KEYS/raw.hex --volume-size 128K|--keyfile KEYS/raw.hex
key-dict|--keyfile KEYS/raw.hex --dictionary KEYS/dict.bin|--keyfile KEYS/raw.hex
key-signed|--keyfile KEYS/raw.hex --signing-key KEYS/sign.sec|--keyfile KEYS/raw.hex
key-dict-signed-3vol|--keyfile KEYS/raw.hex --dictionary KEYS/dict.bin --signing-key KEYS/sign.sec --volumes 3 --volume-loss-tolerance 1|--keyfile KEYS/raw.hex
recip-1vol|--recipient-cert KEYS/recip.pem|--recipient-key KEYS/recip.key
EOF
}

# A corpus with nesting, a deep path, many small members and sizes that straddle
# frame boundaries, so extraction has real work to do on every shape.
make_corpus() {
  local root="$1"
  mkdir -p "$root/corpus/nested/deep/deeper" "$root/corpus/other"
  local i=0
  while [ $i -lt 120 ]; do
    local d
    case $((i % 5)) in
      0) d="$root/corpus" ;;
      1) d="$root/corpus/nested" ;;
      2) d="$root/corpus/nested/deep" ;;
      3) d="$root/corpus/nested/deep/deeper" ;;
      *) d="$root/corpus/other" ;;
    esac
    local size=$(( (i * 97) % 4000 ))
    if [ "$size" -eq 0 ]; then : > "$d/f$(printf '%03d' $i).bin"
    else yes "cross-platform-corpus-$i" | head -c "$size" > "$d/f$(printf '%03d' $i).bin"; fi
    i=$((i + 1))
  done
}

if [ "$MODE" = export ]; then
  BUILDER=$(abspath "${2:?builder binary}")
  OUT="${3:?output directory}"
  mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd)
  rm -rf "$OUT/corpus" "$OUT/keys" "$OUT/archives"; mkdir -p "$OUT/keys" "$OUT/archives"
  make_corpus "$OUT"

  "$BUILDER" keygen -o "$OUT/keys/raw.hex" >/dev/null
  "$BUILDER" signing-keygen --secret-output "$OUT/keys/sign.sec" --public-output "$OUT/keys/sign.pub" >/dev/null
  head -c 65536 /dev/urandom > "$OUT/keys/dict.bin"
  ( export MSYS_NO_PATHCONV=1
    openssl genpkey -algorithm X25519 -out "$OUT/keys/recip.key" 2>/dev/null
    openssl genpkey -algorithm ed25519 -out "$OUT/keys/ca.key" 2>/dev/null
    openssl req -new -x509 -key "$OUT/keys/ca.key" -out "$OUT/keys/ca.pem" -days 30 -subj "/CN=xplat-ca" 2>/dev/null
    openssl pkey -in "$OUT/keys/recip.key" -pubout -out "$OUT/keys/recip.pub" 2>/dev/null
    openssl req -new -key "$OUT/keys/ca.key" -out "$OUT/keys/d.csr" -subj "/CN=xplat-recipient" 2>/dev/null
    openssl x509 -req -in "$OUT/keys/d.csr" -CA "$OUT/keys/ca.pem" -CAkey "$OUT/keys/ca.key" \
      -force_pubkey "$OUT/keys/recip.pub" -out "$OUT/keys/recip.pem" -days 30 >/dev/null 2>&1 )

  : > "$OUT/manifest.txt"
  built=0; unsupported=0
  cd "$OUT"
  while IFS='|' read -r name args readkey; do
    [ -n "$name" ] || continue
    args=${args//KEYS/keys}; readkey=${readkey//KEYS/keys}
    mkdir -p "archives/$name"
    if "$BUILDER" create $args -o "archives/$name/a.tzap" corpus >/dev/null 2>"archives/$name/err.txt"; then
      printf '%s|%s\n' "$name" "$readkey" >> manifest.txt
      built=$((built+1))
    else
      echo "  skip [$name] builder rejects: $(tail -1 "archives/$name/err.txt" | cut -c1-90)"
      rm -rf "archives/$name"; unsupported=$((unsupported+1))
    fi
  done < <(shapes)
  echo "exported $built archive shapes to $OUT ($unsupported unsupported by the builder)"
  exit 0
fi

if [ "$MODE" = check ]; then
  REF=$(abspath "${2:?reference binary}")
  CAND=$(abspath "${3:?candidate binary}")
  DIR="${4:?exported directory}"; DIR=$(cd "$DIR" && pwd)
  cd "$DIR"
  PASS=0; FAIL=0; NOTE=0
  # An archive built on another OS carries metadata this host cannot represent
  # exactly, which the default restore policy refuses outright. That refusal is
  # correct, but it would stop the extract path -- the one the performance work
  # rewrote -- from ever running here. --allow-degraded proceeds and records
  # diagnostics for what it could not apply, so the bytes are still compared.
  DEGRADED="--allow-degraded"
  # A restored tree can carry modes that leave its own directories unwritable, so
  # clearing the previous output needs the permissions put back first.
  scrub() { [ -e "$1" ] || return 0; chmod -R u+rwX "$1" 2>/dev/null; rm -rf "$1"; }
  while IFS='|' read -r name readkey; do
    [ -n "$name" ] || continue
    local_first=$(ls "archives/$name"/a*.tzap 2>/dev/null | sort | head -1)
    flagged=$(ls "archives/$name"/a*.tzap 2>/dev/null | sort | awk 'NR==1{printf "%s",$0; next}{printf " --volume %s",$0}')
    positional=$(ls "archives/$name"/a*.tzap 2>/dev/null | sort | xargs echo)
    [ -n "$local_first" ] || { echo "  FAIL [$name] no archive present"; FAIL=$((FAIL+1)); continue; }

    ok=1
    for tag in REF CAND; do
      bin=$REF; [ "$tag" = CAND ] && bin=$CAND
      if $bin verify $readkey $positional >/dev/null 2>"/tmp/xr.e"; then v=ok; else v="fail:$(tail -1 /tmp/xr.e)"; fi
      if $bin list $readkey $flagged >"/tmp/xr.list.$tag" 2>"/tmp/xr.e"; then l=ok; else l="fail:$(tail -1 /tmp/xr.e)"; fi
      scrub "/tmp/xr.out.$tag"
      if $bin extract $readkey $DEGRADED -C "/tmp/xr.out.$tag" $flagged >/dev/null 2>"/tmp/xr.e"; then
        if diff -r corpus "/tmp/xr.out.$tag/corpus" >/dev/null 2>&1; then x=ok; else x=tree-differs; fi
      else x="fail:$(tail -1 /tmp/xr.e)"; fi
      eval "v_$tag=\$v"; eval "l_$tag=\$l"; eval "x_$tag=\$x"
    done

    for op in v l x; do
      eval "n=\$${op}_CAND"; eval "o=\$${op}_REF"
      case $op in v) label=verify ;; l) label=list ;; *) label=extract ;; esac
      if [ "$n" != "$o" ]; then
        echo "  FAIL [$name] $label disagrees: candidate=[$n] reference=[$o]"; ok=0
      elif [ "$n" = tree-differs ]; then
        echo "  FAIL [$name] $label: both extracted a tree differing from the source"; ok=0
      elif [ "$n" != ok ]; then
        echo "  note [$name] both builds refuse $label identically: ${n#fail:}"; NOTE=$((NOTE+1))
      fi
    done
    if [ "${l_CAND:-}" = ok ] && [ "${l_REF:-}" = ok ]; then
      sort /tmp/xr.list.CAND > /tmp/xr.c.s; sort /tmp/xr.list.REF > /tmp/xr.r.s
      cmp -s /tmp/xr.c.s /tmp/xr.r.s || { echo "  FAIL [$name] listings differ between builds"; ok=0; }
    fi
    # Selected extraction of every member is the path the performance work rewrote.
    if [ "${x_CAND:-}" = ok ]; then
      paths=$(cd corpus && find . -type f | sed 's|^\./|corpus/|' | sort | xargs echo)
      scrub /tmp/xr.sel
      if $CAND extract $readkey $DEGRADED -C /tmp/xr.sel $flagged $paths >/dev/null 2>/tmp/xr.e; then
        diff -r corpus /tmp/xr.sel/corpus >/dev/null 2>&1 || { echo "  FAIL [$name] selected extraction differs from full"; ok=0; }
      else
        echo "  FAIL [$name] selected extraction: $(tail -1 /tmp/xr.e)"; ok=0
      fi
    fi
    [ $ok -eq 1 ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
  done < manifest.txt
  echo
  echo "=== cross-platform read matrix: pass=$PASS fail=$FAIL (agreed refusals noted: $NOTE) ==="
  [ $FAIL -eq 0 ]
  exit $?
fi

echo "unknown mode: $MODE" >&2; exit 2
