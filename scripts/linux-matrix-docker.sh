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
IMAGE="${2:-rust:1.90-bookworm}"
REPO=$(cd "$(dirname "$0")/.." && pwd)

docker run --rm -v "$REPO":/src:ro "$IMAGE" bash -c "
  set -eu
  export PATH=/usr/local/cargo/bin:\$PATH
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq openssl git perl >/dev/null 2>&1

  cp -r /src/. /work_new
  cd /work_new && cargo build --release >/dev/null 2>&1

  cp -r /src/. /work_old
  cd /work_old && git checkout -q '$TAG' && cargo build --release --bin tzap >/dev/null 2>&1

  echo '=== test suite ==='
  cd /work_new && cargo test --release --no-fail-fast 2>&1 |
    grep -E '^test result:' |
    sed -E 's/.*\. ([0-9]+) passed; ([0-9]+) failed.*/\1 \2/' |
    awk '{p+=\$1; f+=\$2} END {print \"passed=\"p\"  failed=\"f}'

  echo '=== differential matrix vs $TAG ==='
  ./scripts/differential-matrix.sh /work_old/target/release/tzap /work_new/target/release/tzap 2>&1 |
    grep -E '^===|^  FAIL'
"
