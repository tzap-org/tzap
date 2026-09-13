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
