# tzap Recovery Matrix

This document explains what `tzap` recovery means for normal archive users.
The detailed implementation rules live in the v0.45 format specification and
the operational boundaries document.

The current implementation is v45-compliant for documented supported recovery
workflows, including payload repair, critical-metadata-first recovery, and
multi-volume loss tolerance within the chosen recovery budget.

## Plain-English promise

`tzap` writes extra recovery data into the archive. When storage damage happens,
`tzap` can use that extra data to rebuild missing or corrupted pieces, then
authenticate the repaired result before it restores files.

Good short wording:

> `tzap` can repair accidental archive damage within the recovery budget you
> chose when the archive was created.

Avoid promising that every possible byte edit is always recoverable. Recovery is
strong, but it is still a budget.

## Quick matrix

| Situation | Expected result | User action |
| --- | --- | --- |
| Wrong passphrase or key | Fails clearly | Use the original passphrase or key file |
| One missing volume with `--volume-loss-tolerance 1` | Recovers | Run `tzap verify` or `tzap extract` with the remaining volumes |
| More missing volumes than the chosen tolerance | Fails clearly | Restore a missing volume from another copy |
| Random bit rot within `--bit-rot-buffer-pct` budget | Repairs, then authenticates | Run `tzap verify` after copying or before restoring |
| Random bit rot beyond the budget | Fails clearly | Restore the archive or volume from another copy |
| Corrupted file payload block within budget | Repairs the affected stored object | Verify before extracting important data |
| Corrupted index or directory metadata within budget | Repairs metadata, then authenticates | Verify the archive |
| Corrupted terminal metadata within CMRA budget | Repairs startup metadata | Verify the archive |
| Deliberate tamper with recomputed checksums | Authentication fails | Treat the archive as untrusted |
| Unsafe archive path during extraction | Rejected | Inspect the archive source |
| Existing destination file | Not overwritten by default | Pass `--overwrite` only when replacement is intended |

## What "5% bit-rot buffer" means

`--bit-rot-buffer-pct 5` tells `tzap` to spend about five percent of the
protected object layout on repair data. That repair data applies across payload
and metadata objects in v0.45.

For users, the practical message is:

- small random damage is usually repairable
- damage must stay within the affected object's repair budget
- many damaged bytes clustered in the same protected object can exceed the
  budget even if the whole archive looks less than five percent damaged
- recovery-enabled file-backed v45 archives can recover malformed physical
  `VolumeHeader` and `CryptoHeader` copies from the terminal CMRA image before
  trusting startup metadata in ordinary key-holding opens
- CMRA header damage such as a bad `TZCR` byte is recoverable when a valid
  locator copy supplies the decoder tuple, and malformed CMRA shard rows are
  treated as erasures once the tuple establishes exact row boundaries
- for file-backed v45 archives, once `tzap` has recovered the archive layout,
  a malformed block slot such as a damaged `TZBK` marker or reserved
  BlockRecord bytes is treated as a repair erasure, then validated after repair
- after repair, authentication still has to pass before data is trusted

The default CLI value is five percent.

## Repair order

Recovery is staged so the archive layout is repaired before file payloads are
used:

1. Locate a trusted layout authority from the physical headers, terminal CMRA,
   locators, or an allowed bootstrap authority.
2. Repair and validate critical metadata first: startup headers, CMRA
   header/shards, terminal metadata, IndexRoot, index shards, directory hints,
   and dictionary metadata when present.
3. Build the archive map from the repaired and authenticated metadata: block
   size, slot boundaries, object extents, parity classes, and file indexes.
4. Repair payload objects within their own FEC budget, then authenticate,
   decrypt, decompress, and release data only after validation succeeds.

This ordering is implemented in the core reader APIs used by ordinary
key-holding `tzap list`, `tzap verify`, and `tzap extract`, so downstream
projects that use those APIs get the same critical-metadata-first recovery
behavior.

## Payload and metadata coverage

v0.45 protects the main archive pieces users expect:

- file payload envelopes
- IndexRoot
- index shards
- directory hint shards
- dictionary objects when present
- critical terminal metadata through CMRA
- multi-volume layouts through per-object FEC and volume discovery
- encrypted archives with keyed authentication, and plaintext archives with
  explicit no-encryption framing plus unkeyed integrity digests

That means recovery is not only for file contents. It also helps the archive
find, list, verify, and restore data after ordinary storage damage.

## Archive-native repair data

`tzap` recovery data is part of the archive package. It is not a separate
sidecar that must be kept healthy independently of the archive. Within the
chosen recovery budget, v0.45 readers repair critical metadata first, then
payload objects, then authenticate the repaired result before releasing data.

External repair schemes such as PAR2 can be useful comparison baselines, but
their recovery files are also storage objects. If those sidecar files are lost
or bit-rotted beyond the remaining usable recovery packets, the original stream
archive can lose its recovery path.

## Common commands

Create a three-volume archive that can survive one missing volume:

```sh
tzap keygen --output project.key
tzap create \
  --keyfile project.key \
  --volumes 3 \
  --volume-loss-tolerance 1 \
  -o project.tzap \
  ./project
```

Verify after copying or uploading:

```sh
tzap verify --keyfile project.key project.vol000.tzap
```

Restore one file:

```sh
tzap extract \
  --keyfile project.key \
  --directory restored \
  project.vol000.tzap \
  project/readme.txt
```

Tune bit-rot recovery:

```sh
tzap create \
  --keyfile project.key \
  --bit-rot-buffer-pct 10 \
  -o archive.tzap \
  ./archive
```

## Simple user guidance

- Use the default recovery settings for ordinary archives.
- Use `--volumes` and `--volume-loss-tolerance` when storing across drives,
  discs, or object-storage parts.
- Increase `--bit-rot-buffer-pct` for long-lived cold storage where size
  overhead is acceptable.
- Run `tzap verify` after copying, uploading, downloading, or moving archives.
- Keep at least one separate copy of the key or passphrase.

## Deeper references

- Security model: `public-docs/tzap-security-model.md`
- CLI reference: `public-docs/tzap-cli-reference.md`
- Operational boundaries: `public-docs/tzap-operational-boundaries.md`
- Format specification: `specs/tzap-format-revisedv45.md`
