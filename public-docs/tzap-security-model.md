# tzap Security Model

This document explains what `tzap` is trying to protect in everyday language.
The full wire-level rules live in the v0.41 format specification.

## Plain-English promise

`tzap` is built so an archive can be private, checked, and repaired without
turning backup safety into a puzzle.

- Your file contents are encrypted.
- Your file names and archive index are encrypted.
- Archive structure is authenticated so modified data is caught before clean
  extraction.
- Safe extraction rejects dangerous archive paths before writing files.
- Optional RootAuth signing lets a verifier check who signed the archive.
- Recovery data helps repair accidental damage such as bit rot or missing
  volumes.

The short version for users:

> If the key is right and the archive verifies, `tzap` should either restore the
> original files or fail loudly before pretending damaged data is safe.

## What is encrypted

`tzap` encrypts the parts users usually care about most:

- regular file contents
- archive member names
- per-file metadata stored in the protected index
- random-access index data
- compressed payload objects

Someone without the key should not be able to browse the file list or read file
contents from a normal encrypted archive.

## What is still visible

Some outer storage facts remain visible because any archive file has to exist as
bytes on disk:

- total archive size
- number of volume files
- approximate size pattern of encrypted objects
- whether optional signing material is present
- file modification time of the archive file in the host filesystem

These do not reveal file contents, but they can reveal that an archive exists and
roughly how large it is.

## Keys and passphrases

`tzap` supports two common ways to protect an archive:

- **Passphrase mode** derives the archive key with Argon2id. This is convenient
  for people who want to remember one secret.
- **Raw-key mode** uses a 32-byte key file. This is better for automation,
  scripted backups, and systems where keys are stored in a password manager,
  secret store, or offline location.

Keep the key or passphrase separate from the archive. Losing the archive key
means losing access to the encrypted archive.

## Integrity checks

`tzap verify` checks archive structure, authentication tags, indexes, payloads,
and recovery layout. `tzap extract` also checks before it reports a clean
restore.

For normal users, that means:

- wrong key or passphrase: fails clearly
- corrupted archive bytes: detected
- unsafe restore path such as `../file`: rejected
- damaged data within recovery budget: repaired and then authenticated
- damaged data beyond recovery budget: fails instead of silently restoring junk

## Recovery is for accidents

Recovery data is meant for normal storage damage:

- bit rot
- partial media failure
- one or more missing volumes when configured for that
- corrupted blocks detected by checksums

Recovery is not a replacement for authentication. If someone deliberately edits
archive bytes and also updates unkeyed checksums, `tzap` should detect the final
authentication failure and refuse clean plaintext rather than promise repair.

## RootAuth signing

RootAuth signing answers a different question from encryption.

- Encryption asks: "Can you read this archive?"
- Verification asks: "Are these bytes intact?"
- RootAuth asks: "Was this archive signed by a trusted identity?"

The CLI supports Ed25519 raw signing keys and X.509 signing certificates through
`tzap-plugin-signing`.

## Safe extraction

`tzap extract` is conservative by default:

- it does not overwrite existing files unless `--overwrite` is supplied
- it rejects unsafe archive paths
- it validates archive material before reporting clean extraction
- selected-file restores still authenticate the data they restore

## Security reporting

Please do not publish suspected vulnerabilities in a public issue with exploit
details. Use GitHub private vulnerability reporting if it is enabled for the
repository. If private reporting is not available, open a minimal public issue
asking for a private contact path and omit sensitive details until a private
channel is arranged.

## Deeper references

- Format specification: `specs/tzap-format-revisedv41.md`
- CLI reference: `public-docs/tzap-cli-reference.md`
- Recovery matrix: `public-docs/tzap-recovery-matrix.md`
- Operational boundaries: `public-docs/tzap-operational-boundaries.md`
