# tzap-plugin-signing

`tzap-plugin-signing` adds RootAuth signing profiles for tzap archives. It is
the companion crate for applications that want signed v41 RootAuth archives on
top of the standalone `tzap-core` archive foundation.

The first profile is `ed25519_raw`, which implements the v41 optional Ed25519
RootAuth authenticator (`authenticator_id = 0x0002`). The crate signs and
verifies the domain-separated v41 signing input from `tzap-core` request and
footer types. Core provides archive-root recomputation and verification gates;
this crate provides the signing profile logic.

## Install

```toml
[dependencies]
tzap-core = "0.1.1"
tzap-plugin-signing = "0.1.0"
```

## Architecture

`tzap-core` is the standalone archive foundation. Projects choose the compact
core surface for archive workflows, or add this companion crate for signed
RootAuth workflows and public no-key verification.

```text
tzap-core              archive format, RootAuth material, verifier gates
tzap-plugin-signing    Ed25519 profile and future signing profiles
tzap CLI               composes core plus signing plugin
```

Future certificate profiles can live in this crate as additional modules while
keeping core independent.

## Example

```rust
use ed25519_dalek::SigningKey;
use tzap_core::RootAuthSigningRequest;
use tzap_plugin_signing::ed25519_raw;

let signing_key = SigningKey::from_bytes(&[7; 32]);
let request = RootAuthSigningRequest {
    archive_uuid: [1; 16],
    session_id: [2; 16],
    archive_root: [3; 32],
};

let authenticator_value =
    ed25519_raw::authenticator_value_for_request(&signing_key, &request);

assert_eq!(
    authenticator_value.len(),
    ed25519_raw::ED25519_AUTHENTICATOR_VALUE_LEN as usize
);
```

## Ed25519 Raw Profile

The `ed25519_raw` module provides:

- `ED25519_AUTHENTICATOR_ID = 0x0002`
- `ED25519_AUTHENTICATOR_VALUE_LEN = 68`
- `authenticator_value_for_request` for core writer callbacks
- `verify_root_auth_footer` for core verifier callbacks
- distinct outcome types for profile data quality, reserved identity classes,
  self-signed consistency, key-holding RootAuth verification, and public no-key
  commitment verification

## More Information

- Repository: <https://github.com/frankmanzhu/tzap>
- Core crate: <https://crates.io/crates/tzap-core>
- CLI crate: <https://crates.io/crates/tzap>
- Format specification: <https://github.com/frankmanzhu/tzap/blob/main/specs/tzap-format-revisedv41.md>
