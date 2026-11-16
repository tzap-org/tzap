# tzap Installation

This document collects install paths and release artifact details for `tzap`.

## Homebrew

```sh
brew tap tzap-org/homebrew-tzap
brew install tzap
```

## OpenSSL for source builds

Cargo source builds require the static
[OpenSSL 3.5.9 LTS](https://github.com/openssl/openssl/releases/tag/openssl-3.5.9)
build for the Rust target with the
[upstream RSA-PSS provider alias](https://github.com/openssl/openssl/commit/af2aaf3271c0b0a193f33d5c0be07754b846759e)
backport. The CLI and plugins check the header version and the alias in
`libcrypto` during compilation.

Run these commands from a TZAP checkout with Python 3, Perl, and native C build
tools installed. The script applies the backport to the checksum-pinned release
used by CI and release builds.

```sh
target="$(rustc -vV | sed -n 's/^host: //p')"
OPENSSL_DIR="$(python3 scripts/build-openssl.py "$target")" || exit 1
export OPENSSL_DIR OPENSSL_STATIC=1 OPENSSL_NO_VENDOR=1
```

On Windows, use Developer PowerShell with the MSVC tools for the Rust target
and a native Perl distribution such as Strawberry Perl:

```powershell
$target = (rustc -vV | Select-String '^host: ').Line.Substring(6)
$env:OPENSSL_DIR = python scripts/build-openssl.py $target
if ($LASTEXITCODE -ne 0) { throw "OpenSSL build failed" }
$env:OPENSSL_STATIC = "1"
$env:OPENSSL_NO_VENDOR = "1"
```

Choose the Cargo command for your install source in the same shell.

| Source | Command |
| --- | --- |
| crates.io | `cargo install --locked tzap` |
| GitHub | `cargo install --locked --git https://github.com/tzap-org/tzap tzap` |
| Local checkout | `cargo install --locked --path crates/tzap-cli` |
| Build from a checkout | `cargo build --locked --release -p tzap` |

The build from a checkout produces `target/release/tzap` or
`target/release/tzap.exe`.

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

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c --ignore-missing SHA256SUMS
else
  grep "  ${ASSET}$" SHA256SUMS | shasum -a 256 -c -
fi
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
`*-latest` labels: `ubuntu-22.04`, `macos-15-intel`, `macos-15`, and
`windows-2022`. macOS builds set `MACOSX_DEPLOYMENT_TARGET=10.12` for
x86_64 and `MACOSX_DEPLOYMENT_TARGET=11.0` for aarch64. Linux publishes
static musl artifacts for x86_64 and aarch64; Windows release builds use the
static CRT.

The release archives include `THIRD-PARTY-NOTICES.txt` and
`OPENSSL-LICENSE.txt` alongside the executable.

Release artifacts are accompanied by:

- individual `.sha256` files
- a merged `SHA256SUMS` manifest
- a keyless Sigstore bundle for `SHA256SUMS`
- GitHub artifact attestations for release assets

The `tzap trust-info` command prints the embedded official TZAP root
fingerprint, build identity, and linked OpenSSL version for the binary you are
running.
