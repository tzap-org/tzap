# macOS release signing

The tagged release workflow signs the macOS `tzap` executable with a Developer
ID Application identity and submits a ZIP containing the executable to Apple's
notary service. Linux and Windows artifacts do not use Apple credentials.
Pull request and main-branch CI builds do not receive signing credentials.

## Configure repository secrets

Add these Actions secrets to the repository that publishes the release:

| Secret | Value |
| --- | --- |
| `APPLE_DEVELOPER_ID_P12_BASE64` | Base64-encoded PKCS#12 export containing one Developer ID Application certificate and its private key |
| `APPLE_DEVELOPER_ID_P12_PASSWORD` | Password used to protect that PKCS#12 export |
| `APPLE_API_KEY_BASE64` | Base64-encoded App Store Connect API `.p8` key with access to the developer team |
| `APPLE_API_KEY_ID` | Key ID from the `.p8` filename or App Store Connect |
| `APPLE_API_ISSUER_ID` | Issuer ID shown in App Store Connect |

Keep the certificate, private key, API key, and export password out of the
repository. The workflow imports the certificate into a temporary keychain on
the macOS runner, signs and verifies the executable, submits it for
notarization, then removes the temporary keychain and key files.

For example, encode the files locally without adding them to the checkout:

```sh
base64 < "$HOME/DevKey/Certificates.p12" | tr -d '\n' | gh secret set APPLE_DEVELOPER_ID_P12_BASE64 --repo OWNER/REPOSITORY
base64 < "$HOME/DevKey/AuthKey_KEYID.p8" | tr -d '\n' | gh secret set APPLE_API_KEY_BASE64 --repo OWNER/REPOSITORY
```

Set the P12 password, API key ID, and issuer ID as separate repository Actions
secrets. Each project or fork can configure its own credentials; the workflow
does not embed a certificate, team ID, API key, or personal identity.

## Release behavior

Only macOS artifacts produced by `.github/workflows/release.yml` are signed
and notarized. A release fails if a required secret is missing, the P12 does
not contain exactly one valid Developer ID Application identity, signature
verification fails, or Apple does not accept the notarization submission.
The release archive contains the signed CLI and its existing license files.

To test the configured secrets without publishing a release, run the
`Release` workflow manually from `main` with `notarization_test` enabled. It
builds and uploads workflow artifacts, but skips Homebrew publication and the
GitHub release step. A tagged push runs the regular release path.

Apple issues a ticket for the standalone CLI binary. Apple does not currently
support stapling tickets directly to standalone binaries, so Gatekeeper must
retrieve the ticket online when it evaluates the downloaded executable. See
[Apple's notarization workflow documentation](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).
