# tzap Benchmark Marketing Readout

Report date: June 2, 2026.

## Best Current Claim

Lead with this:

> `tzap` restored one 320 MiB file from a 20 GB encrypted archive in 2.08s,
> without unpacking the full archive.

Why this works:

- It is concrete.
- It highlights random-access restore, one of the strongest product advantages.
- It avoids claiming universal compression or universal speed superiority.
- It naturally sets up the broader story: one archive format for encryption,
  verification, recovery, split volumes, and selected-file restore.

## Numbers To Use

Large-archive headline, encrypted mode:

| Data set | Files | Selected file | Create | Verify | Full extract | Selected-file restore | Archive size |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 20 GB | 64 | 320 MiB | 50.11s | 95.54s | 7.59s | 2.08s | 5.84 GB |

Public/plaintext mode:

| Data set | Files | Selected file | Verify | Selected-file restore | Archive size |
| --- | ---: | ---: | ---: | ---: | ---: |
| 20 GB | 64 | 320 MiB | 45.36s | 0.545s | 5.84 GB |

1 GB comparison, last-file restore:

| Tool | Last-file restore | Recovery result |
| --- | ---: | --- |
| `tzap` | 0.010s | Recovered missing volume and rotten payload |
| `tar + zstd` | 0.182s | No repair path |
| `tar + zstd + age` | 0.371s | No repair path |
| `tar + zstd + age + PAR2` | 0.369s | External PAR2 |
| `7z` | 0.167s | No repair path |
| `zip` | 0.037s | No repair path |

The sharp comparison line:

> In the 1 GB comparison run, `tzap` restored the selected last file about 39x
> faster than the `tar + zstd + age` encrypted stream baseline, while also
> recovering the tested missing-volume and damaged-payload cases.

## Marketing Shape

Use this order on a public page:

1. Selected-file restore headline.
2. One table showing create, verify, selected-file restore, full extract,
   archive size, missing volume, and rotten payload.
3. Recovery scorecard.
4. Audit trail: machine, tool versions, command shape, and raw CSV link.

Recommended public copy:

> Backups are only useful if you can prove them and restore the one thing you
> need. On this benchmark machine, `tzap` restored a 320 MiB file from a 20 GB
> encrypted archive in 2.08s, and recovered both tested missing-volume and
> damaged-payload cases.

Short tagline candidate:

> Fast restore. Built-in verification. Recovery when storage gets ugly.

## What Not To Claim Yet

Do not say:

- "fastest archive"
- "best compression"
- "always faster"
- "beats zip/7z at everything"
- "production-final benchmark"

The better claim is narrower and stronger:

> `tzap` combines encryption, verification, recovery, split-volume handling, and
> selected-file restore in one archive workflow.

## Caveats Before A Big Launch

These are good enough for a public snapshot, but not yet a final benchmark page:

- The 20 GB headline is one run, not 30 runs.
- The 20 GB headline compares `tzap` modes, not all baseline tools.
- Peak RSS is blank because GNU `time` was not installed.
- The generated data is deterministic benchmark data, not a photo/video corpus.
- The 1 GB comparison is the complete side-by-side proof today.

## Next Benchmark To Run

For a stronger launch-grade page:

```sh
python3 scripts/tzap_benchmark.py \
  --profile standard \
  --runs 30 \
  --recovery-runs 1 \
  --file-count 64 \
  --dataset-sizes 1MB,20MB,1GB,20GB \
  --selected-file-position last \
  --benchmark-password tzap-benchmark-password \
  --recovery-volumes 3 \
  --recovery-volume-loss-tolerance 1 \
  --recovery-omit-volume-index 1 \
  --bitrot-buffer-pct 5 \
  --bitrot-small-block-size 4K \
  --bitrot-small-chunk-size 4K \
  --bitrot-large-threshold 10GB \
  --bitrot-large-block-size 64K \
  --bitrot-large-chunk-size 256K \
  --bitrot-envelope-size 1M \
  --bitrot-corruption-bytes 4096 \
  --par2-redundancy-pct 5 \
  --tools tzap,tar-zstd,tar-zstd-age,tar-zstd-age-par2,7z,zip
```

Install GNU `time` first so the report includes peak RSS.
