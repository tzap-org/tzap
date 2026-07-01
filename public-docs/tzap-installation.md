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
curl -L -o "$ASSET" \
  "https://github.com/tzap-org/tzap/releases/download/${VERSION}/${ASSET}"
curl -L -O "https://github.com/tzap-org/tzap/releases/download/${VERSION}/SHA256SUMS"
curl -L -O "https://github.com/tzap-org/tzap/releases/download/${VERSION}/SHA256SUMS.sigstore.json"

sha256sum -c --ignore-missing SHA256SUMS
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp 'https://github.com/tzap-org/tzap/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS
gh attestation verify "$ASSET" -R tzap-org/tzap

tar -xzf "$ASSET"
chmod +x tzap
./tzap --version
./tzap trust-info
```

On Windows, download the `.zip` asset plus `SHA256SUMS` and
`SHA256SUMS.sigstore.json`, then verify the hash with `Get-FileHash`, verify
the Sigstore bundle with `cosign verify-blob`, and verify provenance with
`gh attestation verify`.

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

Release artifacts are accompanied by:

- individual `.sha256` files
- a merged `SHA256SUMS` manifest
- a keyless Sigstore bundle for `SHA256SUMS`
- GitHub artifact attestations for release assets

The `tzap trust-info` command prints the embedded official TZAP root
fingerprint and build identity for the binary you are running.
