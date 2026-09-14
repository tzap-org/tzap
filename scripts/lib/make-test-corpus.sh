#!/bin/bash
# Shared corpus generator for the differential and cross-platform matrices.
#
# Both harnesses need the same tree, and a corpus of nothing but regular files
# exercises very little of the format. This builds every entry kind the host can
# actually create, and skips the rest rather than failing: Windows needs a
# privilege or developer mode for symlinks, and device nodes and FIFOs need root
# or a POSIX host.
#
# Usage: make_test_corpus <root>   (creates <root>/corpus)
make_test_corpus() {
  local root="$1"
  local c="$root/corpus"
  rm -rf "$c"
  mkdir -p "$c/nested/deep/deeper" "$c/other" "$c/empty-dir"

  # Regular files at sizes that straddle frame and block boundaries, including
  # zero-length and one spanning several chunks.
  local i=0
  while [ $i -lt 120 ]; do
    local d
    case $((i % 5)) in
      0) d="$c" ;;
      1) d="$c/nested" ;;
      2) d="$c/nested/deep" ;;
      3) d="$c/nested/deep/deeper" ;;
      *) d="$c/other" ;;
    esac
    local size=$(( (i * 97) % 4000 ))
    if [ "$size" -eq 0 ]; then : > "$d/f$(printf '%03d' $i).bin"
    else yes "corpus-body-$i" | head -c "$size" > "$d/f$(printf '%03d' $i).bin"; fi
    i=$((i + 1))
  done
  # Spans many frames. Deliberately NOT highly compressible: the reader caps
  # extraction at ten times the archive size as a decompression-bomb guard, and a
  # `yes`-generated member compresses about 15:1, which trips it in a zero-parity
  # archive where there is no parity to pad the archive out.
  head -c 3000000 /dev/urandom > "$c/large.bin" 2>/dev/null || yes "large-member" | head -c 300000 > "$c/large.bin"
  printf '' > "$c/zero-length.bin"
  printf 'no trailing newline' > "$c/no-newline.bin"
  printf 'a\0b\0c' > "$c/embedded-nuls.bin"

  # Names that exercise path handling: unicode, spaces, dots, and a long one.
  printf 'unicode\n' > "$c/résumé-日本語-Ω.bin"
  printf 'spaces\n' > "$c/name with spaces.bin"
  printf 'dots\n' > "$c/archive.tar.gz.bin"
  printf 'leading dot\n' > "$c/.hidden"
  printf 'long\n' > "$c/$(printf 'l%.0s' $(seq 1 180)).bin"
  # Long AND non-ASCII, which is the combination neither the long ASCII name
  # above nor the short unicode names below cover. Restoring builds a temporary
  # sibling from this leaf plus a 46-byte suffix, so a name past the budget has
  # to be shortened -- and shortening it at a raw byte offset splits a character,
  # which APFS rejects outright. Every such member failed to restore, reported as
  # archive corruption, and no fixture in either matrix had this shape.
  printf 'long unicode\n' > "$c/$(printf '資%.0s' $(seq 1 80)).bin"
  mkdir -p "$c/dir with spaces/日本語"
  printf 'nested unicode\n' > "$c/dir with spaces/日本語/inner.bin"

  # Symlinks: relative, to a directory, and dangling. Windows refuses without
  # privilege, so treat failure as "this host cannot express it".
  if ln -s "f000.bin" "$c/link-relative.sym" 2>/dev/null; then
    ln -s "nested" "$c/link-to-dir.sym" 2>/dev/null || true
    ln -s "does-not-exist.bin" "$c/link-dangling.sym" 2>/dev/null || true
  fi

  # Hardlinks: two names for one inode, so the writer must store the data once.
  printf 'shared inode payload\n' > "$c/hardlink-target.bin"
  ln "$c/hardlink-target.bin" "$c/hardlink-alias.bin" 2>/dev/null || true

  # A copy-on-write clone pair, where the platform has one. Two files sharing
  # storage is the ordinary state of an APFS volume (`cp -c`, Finder duplicate,
  # every `cp` on some tools), and the writer records a clone-group hint for it.
  # Nothing in the corpus produced that hint, so the reader refusing to restore
  # the hint it had just written went unnoticed by both matrices.
  printf 'clone partner\n' > "$c/clone-source.bin"
  cp -c "$c/clone-source.bin" "$c/clone-partner.bin" 2>/dev/null \
    || cp --reflink=always "$c/clone-source.bin" "$c/clone-partner.bin" 2>/dev/null \
    || cp "$c/clone-source.bin" "$c/clone-partner.bin"

  # A sparse file where the host supports punching one.
  if command -v truncate >/dev/null 2>&1; then
    truncate -s 1048576 "$c/sparse.bin" 2>/dev/null || true
  fi

  # Read-only file: a real restriction on every host, unlike a read-only directory.
  printf 'read only\n' > "$c/read-only.bin"
  chmod 0444 "$c/read-only.bin" 2>/dev/null || true

  # Executable bit, which only POSIX hosts can express.
  printf '#!/bin/sh\necho hi\n' > "$c/executable.sh"
  chmod 0755 "$c/executable.sh" 2>/dev/null || true

  # FIFO, POSIX-only and root-free.
  mkfifo "$c/fifo.pipe" 2>/dev/null || true

  # A second tree holding only regular files and directories. Streaming tar input
  # supports those kinds and nothing else, so feeding it the full corpus makes two
  # builds refuse for different reasons -- whichever unsupported kind each notices
  # first -- which is noise rather than a difference worth reporting.
  local plain="$root/corpus-plain"
  rm -rf "$plain"
  mkdir -p "$plain/nested/deep"
  local n=0
  while [ $n -lt 24 ]; do
    local pd="$plain"
    [ $((n % 3)) -eq 1 ] && pd="$plain/nested"
    [ $((n % 3)) -eq 2 ] && pd="$plain/nested/deep"
    yes "plain-body-$n" | head -c $(( (n * 211) % 3000 + 1 )) > "$pd/p$(printf '%02d' $n).bin"
    n=$((n + 1))
  done
}

# Compare a restored tree against the source without letting `diff -r` touch an
# entry kind it cannot handle: reading a FIFO would block forever, and a dangling
# symlink has no content to read. Regular files are compared byte for byte,
# symlinks by their target, and other kinds by presence.
compare_restored_tree() {
  local src="$1" restored="$2" label="$3" rc=0
  local rel
  while IFS= read -r rel; do
    local a="$src/$rel" b="$restored/$rel"
    if [ -L "$a" ]; then
      if [ ! -L "$b" ]; then echo "  $label: $rel is not a symlink in the restored tree"; rc=1
      elif [ "$(readlink "$a")" != "$(readlink "$b")" ]; then echo "  $label: $rel symlink target differs"; rc=1; fi
    elif [ -p "$a" ]; then
      # FIFOs and device nodes restore only under the System policy; the default
      # Portable policy skips them deliberately, so their absence is not a
      # difference. Only require the kind to match when one was restored.
      if [ -e "$b" ] && [ ! -p "$b" ]; then echo "  $label: $rel restored as the wrong kind"; rc=1; fi
    elif [ -d "$a" ]; then
      [ -d "$b" ] || { echo "  $label: $rel is not a directory in the restored tree"; rc=1; }
    elif [ -f "$a" ]; then
      cmp -s "$a" "$b" || { echo "  $label: $rel content differs"; rc=1; }
    fi
  done < <(cd "$src" && find . -mindepth 1 | sed 's|^\./||')
  return $rc
}

# Emit a stable per-entry metadata fingerprint for a restored tree.
#
# `compare_restored_tree` deliberately compares only content, symlink target and
# entry kind, because a restored tree legitimately differs from its SOURCE in
# metadata the active restore policy does not apply. That left the differential
# matrix blind to metadata regressions -- in a project whose whole subject is
# metadata capture and round-trip restoration.
#
# The fix is to compare the two BUILDS against each other rather than against the
# source. Both run the same policy on the same host, so any difference is a real
# behaviour change between versions, with no policy caveat to reason about.
#
# Mode and mtime (to nanoseconds where the host's stat exposes them) are what the
# portable profile restores on every platform. Ownership is deliberately absent:
# it needs a System restore, so including it would compare zeros.
metadata_fingerprint() {
  local root="$1" flavour="" rel
  # GNU and BSD stat take different flags; Git Bash ships GNU.
  if stat -c '%a' . >/dev/null 2>&1; then flavour=gnu
  elif stat -f '%Lp' . >/dev/null 2>&1; then flavour=bsd
  else return 0; fi

  while IFS= read -r rel; do
    local target="$root/$rel"
    # Never dereference: a symlink's own mode and time are the entry's.
    if [ "$flavour" = gnu ]; then
      printf '%s\t%s\n' "$rel" "$(stat -c '%f|%.9Y' "$target" 2>/dev/null)"
    else
      printf '%s\t%s\n' "$rel" "$(stat -f '%Lp|%Fm' "$target" 2>/dev/null)"
    fi
  done < <(cd "$root" && find . -mindepth 1 | sed 's|^\./||' | LC_ALL=C sort)
}

# Compare two restored trees' metadata, reporting the first few differences.
compare_restored_metadata() {
  local left="$1" right="$2" label="$3"
  local a b
  a=$(metadata_fingerprint "$left") || return 0
  b=$(metadata_fingerprint "$right") || return 0
  # An empty fingerprint means this host has no usable stat; say nothing rather
  # than claiming agreement.
  [ -n "$a" ] || return 0
  if [ "$a" != "$b" ]; then
    echo "  $label: restored metadata differs between builds"
    diff <(printf '%s\n' "$a") <(printf '%s\n' "$b") | head -12 | sed 's/^/    /'
    return 1
  fi
  return 0
}
