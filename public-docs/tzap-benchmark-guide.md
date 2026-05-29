# tzap Benchmark Guide

This document defines the benchmark story for `tzap`. It is intentionally
reproducible: numbers should be published only with the machine, command, data
set, and tool versions that produced them.

## What to measure

`tzap` should be benchmarked on the workflows users actually care about:

- create an archive
- verify an archive after copying
- extract the full archive
- extract one file from a large archive
- archive size on disk
- memory use during create, verify, and extract
- recovery after damaged blocks
- recovery after a missing volume

The most important `tzap` story is not only "how fast does it compress?" It is:

> How fast can a user create, verify, repair, and restore encrypted archive data?

## Suggested comparison set

Use tools people already know:

- `tar + zstd`
- `tar + zstd + age`
- `7z`
- `zip`
- `tzap`

`tar + zstd` is a speed and compression baseline. `tar + zstd + age` is the
closest simple encrypted pipeline. `7z` and `zip` are familiar archive tools for
normal users.

## Data sets

Use at least three data shapes:

| Data set | Why it matters |
| --- | --- |
| Many small files | Source trees, documents, exports |
| Large media files | Photos, videos, research data |
| Mixed backup tree | Realistic home or project backup |

For public results, record:

- file count
- total uncompressed bytes
- largest file size
- operating system
- CPU and memory
- storage device type
- command versions
- exact commands

## Metrics table template

| Tool | Create | Verify/Test | Full extract | Single-file extract | Output size | Peak RSS |
| --- | --- | --- | --- | --- | --- | --- |
| tzap | TBD | TBD | TBD | TBD | TBD | TBD |
| tar + zstd | TBD | n/a | TBD | n/a | TBD | TBD |
| tar + zstd + age | TBD | n/a | TBD | n/a | TBD | TBD |
| 7z | TBD | TBD | TBD | TBD | TBD | TBD |
| zip | TBD | TBD | TBD | TBD | TBD | TBD |

Use `n/a` where a tool does not provide a comparable built-in workflow.

## Example command shape

Build `tzap` in release mode:

```sh
cargo build --release -p tzap
TZAP=target/release/tzap
```

Create and verify:

```sh
$TZAP keygen --output bench.key
/usr/bin/time -p $TZAP create --keyfile bench.key -o data.tzap ./data
/usr/bin/time -p $TZAP verify --keyfile bench.key data.tzap
```

Extract all files:

```sh
rm -rf restored
/usr/bin/time -p $TZAP extract --keyfile bench.key -C restored data.tzap
```

Extract one file:

```sh
/usr/bin/time -p $TZAP extract \
  --keyfile bench.key \
  --stdout \
  data.tzap \
  path/inside/archive.bin > /dev/null
```

Create a recoverable multi-volume archive:

```sh
/usr/bin/time -p $TZAP create \
  --keyfile bench.key \
  --volumes 4 \
  --volume-loss-tolerance 1 \
  -o data.tzap \
  ./data
```

## Publishing guidance

When benchmark numbers are added to the website or README, include the exact
benchmark document or commit that produced them. Prefer a simple table and one
sentence of interpretation over a dramatic chart.

Good phrasing:

> On this machine and data set, `tzap` restored one selected file without
> scanning unrelated payload data.

Avoid vague phrasing such as "always faster" or "best compression." `tzap` is
designed to combine encryption, verification, recovery, and random-access
restore in one format, so benchmark claims should compare complete workflows.

## Deeper references

- CLI reference: `public-docs/tzap-cli-reference.md`
- Security model: `public-docs/tzap-security-model.md`
- Recovery matrix: `public-docs/tzap-recovery-matrix.md`
