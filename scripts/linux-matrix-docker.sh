#!/bin/bash
#
# Run the tzap suite and both matrices on Linux, in Docker.
#
# There is no Linux CI runner in this workflow and no Linux reference binary on
# hand, so build both the release under test and the reference from the tag
# inside the container. The repository is mounted read-only and copied in, so a
# container can never write to the working tree.
#
# Usage: scripts/linux-matrix-docker.sh [reference-tag] [rust-image]
set -eu
TAG="${1:-v0.2.4}"
# Both projects track `stable`, so the Linux gate must too. Pinning an older
# image hid newer clippy lints here that the Windows VM (on current stable) was
# already failing on.
IMAGE="${2:-rust:latest}"
REPO=$(cd "$(dirname "$0")/.." && pwd)

# The container script arrives on stdin rather than inside a quoted -c string, so
# it needs no nested escaping and reads as ordinary bash.
exec docker run --rm -i -v "$REPO":/src:ro "$IMAGE" bash -s -- "$TAG" <<'INNER'
set -eu
TAG="$1"
export PATH=/usr/local/cargo/bin:$PATH
export CARGO_TERM_COLOR=never
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq openssl git perl >/dev/null 2>&1
# `rust:latest` ships without clippy; the versioned images carry it.
rustup component add clippy >/dev/null 2>&1 || true

status=0

# Show the output when a build fails. Silencing it meant a broken build was
# reported only as a bare exit code, with nothing to act on.
run_build() {
  local label="$1"
  shift
  local log
  log=$(mktemp)
  if ! "$@" >"$log" 2>&1; then
    echo "=== $label FAILED ==="
    tail -60 "$log"
    exit 1
  fi
  rm -f "$log"
}

cp -r /src/. /work_new
cd /work_new
run_build "build (under test)" cargo build --release --workspace --all-features

cp -r /src/. /work_old
cd /work_old
# `-f`: /work_old is a throwaway copy of the working tree, so uncommitted
# changes there must be discarded rather than aborting the whole run. Without
# it the matrix refused to start whenever anything was uncommitted -- including
# an edit to this script.
git checkout -q -f "$TAG"
run_build "build (reference $TAG)" cargo build --release --bin tzap

echo '=== clippy ==='
cd /work_new
if cargo clippy --workspace --all-targets --all-features -- -D warnings >/tmp/clippy.log 2>&1; then
  echo 'clippy: clean'
else
  echo 'clippy: FAILED'
  grep -E '^(error|warning)' /tmp/clippy.log | head -40 || true
  status=1
fi

echo '=== test suite ==='
# `cargo test` goes to a file, not through a pipe: piping into grep made the
# pipeline report grep's status, so a suite that failed to COMPILE produced an
# empty summary and an exit code of 0 -- a broken build read as a pass.
if cargo test --release --workspace --all-features --no-fail-fast >/tmp/test.log 2>&1; then
  :
else
  status=1
fi
if ! grep -qE '^test result:' /tmp/test.log; then
  echo 'test suite did not run -- no results were produced (build failure?):'
  grep -E '^error|^ *--> ' /tmp/test.log | head -40 || true
  status=1
else
  grep -E '^test result:' /tmp/test.log |
    sed -E 's/.*\. ([0-9]+) passed; ([0-9]+) failed.*/\1 \2/' |
    awk '{p+=$1; f+=$2} END {print "passed="p"  failed="f}'
  if grep -qE '^test result: FAILED'  /tmp/test.log; then
    echo '--- failing tests ---'
    grep -E '^test .* FAILED$' /tmp/test.log | head -40 || true
    status=1
  fi
fi

echo "=== differential matrix vs $TAG ==="
if ! ./scripts/differential-matrix.sh /work_old/target/release/tzap /work_new/target/release/tzap 2>&1 |
    grep -E '^===|^  FAIL'; then
  echo 'differential matrix produced no summary'
  status=1
fi

echo "=== overall: $([ "$status" -eq 0 ] && echo PASS || echo FAIL) ==="
exit "$status"
INNER
