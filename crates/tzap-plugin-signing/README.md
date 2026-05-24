# tzap-plugin-signing

`tzap-plugin-signing` contains RootAuth signing profiles for tzap archives.

The first profile is `ed25519_raw`, which implements the v41 optional Ed25519
RootAuth authenticator (`authenticator_id = 0x0002`). The crate signs and
verifies a RootAuth signing input supplied by `tzap-core`; core remains
responsible for recomputing archive roots and constructing the domain-separated
v41 signing input from archive fields.

## Example

```rust
use ed25519_dalek::SigningKey;
use tzap_plugin_signing::ed25519_raw;

let signing_key = SigningKey::from_bytes(&[7; 32]);
let signing_input = [0x42; 64];
let authenticator_value = ed25519_raw::authenticator_value(&signing_key, &signing_input);

assert_eq!(
    authenticator_value.len(),
    ed25519_raw::ED25519_AUTHENTICATOR_VALUE_LEN as usize
);
```
