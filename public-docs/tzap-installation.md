# tzap Installation

This document collects install paths and release artifact details for `tzap`.

## Homebrew

```sh
brew tap tzap-org/homebrew-tzap
brew install tzap
```

## crates.io

```sh
cargo install tzap
```

`tzap` requires Rust 1.85 or newer when installing from source.

## From a checkout

```sh
cargo build --release -p tzap
```

The binary will be available at:

```sh
target/release/tzap
```

## From GitHub

```sh
cargo install --git https://github.com/tzap-org/tzap tzap
```

## From GitHub release assets

```sh
VERSION=vX.Y.Z
case "$(uname -s)" in
  Linux) OS=linux ;;
  Darwin) OS=macos ;;
  *)
    echo "unsupported OS: $(uname -s)"
    exit 1
    ;;
esac

ARCH_RAW=$(uname -m)
case "$ARCH_RAW" in
  x86_64) ARCH=x86_64 ;;
  arm64 | aarch64) ARCH=aarch64 ;;
  *)
    echo "unsupported architecture: ${ARCH_RAW}"
    exit 1
    ;;
esac

if [ "$OS" = linux ]; then
  ASSET="tzap-${VERSION}-linux-${ARCH}-musl.tar.gz"
else
  ASSET="tzap-${VERSION}-${OS}-${ARCH}.tar.gz"
fi
# On Windows, pick the ".zip" artifact name from the table below.
curl -L -o tzap.tar.gz \
  "https://github.com/tzap-org/tzap/releases/download/${VERSION}/${ASSET}"
tar -xzf tzap.tar.gz
chmod +x tzap
./tzap --version
```

Supported target artifacts:

| Platform | Artifact |
| --- | --- |
| Linux x86_64 static/musl | `tzap-vX.Y.Z-linux-x86_64-musl.tar.gz` |
| Linux aarch64 static/musl | `tzap-vX.Y.Z-linux-aarch64-musl.tar.gz` |
| macOS x86_64 | `tzap-vX.Y.Z-macos-x86_64.tar.gz` |
| macOS aarch64 | `tzap-vX.Y.Z-macos-aarch64.tar.gz` |
| Windows x86_64 | `tzap-vX.Y.Z-windows-x86_64.zip` |
| Windows aarch64 | `tzap-vX.Y.Z-windows-aarch64.zip` |

Release artifacts are built on pinned baseline runners instead of moving
`*-latest` labels: `ubuntu-22.04`, `macos-15-intel`, `macos-14`, and
`windows-2022`. macOS builds set `MACOSX_DEPLOYMENT_TARGET=10.12` for
x86_64 and `MACOSX_DEPLOYMENT_TARGET=11.0` for aarch64. Linux publishes
static musl artifacts for x86_64 and aarch64; Windows release builds use the
static CRT.
