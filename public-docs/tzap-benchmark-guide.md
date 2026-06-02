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
- `tar + zstd + age + par2`
- `7z`
- `zip`
- `tzap`

`tar + zstd` is a speed and compression baseline. `tar + zstd + age` is the
closest simple encrypted pipeline. `tar + zstd + age + par2` adds an external
repair-data baseline with a configurable redundancy percentage. `7z` and `zip`
are familiar archive tools for normal users.

## Data sets

Use controlled data sets when publishing size comparisons. The repository
runner keeps file count the same and changes total input size, so the table
answers a clear question: "what happens as the same archive shape gets larger?"

| Data set | Why it matters |
| --- | --- |
| 1 MB | Tiny personal archive or quick sanity check |
| 20 MB | Normal document/project backup |
| 1 GB | Real media or work archive |
| 20 GB | Large home/project backup |

For public results, record:

- file count
- total uncompressed size in MB/GB for human-facing reports
- exact total uncompressed bytes in raw CSV or JSON audit files
- largest file size
- operating system
- CPU and memory
- storage device type
- command versions
- exact commands

## Public metrics table

Lead public benchmark pages with a complete-workflow table, not a compression
speed table. The headline should make the `tzap` strengths visible in one scan:
verify after copy, selected-file restore, and recovery after ordinary archive
damage.

The current measured public snapshot is
[`tzap-benchmark-results.md`](tzap-benchmark-results.md).

Copy timing, size, and memory cells from generated `results.md`; do not fill
them by hand. Use `n/a` where a tool does not provide a comparable built-in
workflow.

| Data set | Files | Input size | Tool / mode | Create | Verify/Test | Selected-file restore | Full extract | Output size | Peak RSS | Missing volume | Rotten payload |
| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| size-20gb | 64 | 20 GB | tzap encrypted archive with recovery options | TBD | TBD | TBD | TBD | TBD | TBD | Recovered | Recovered |
| size-20gb | 64 | 20 GB | tar + zstd | TBD | TBD | TBD | TBD | TBD | TBD | No repair path | No repair path |
| size-20gb | 64 | 20 GB | tar + zstd + age | TBD | TBD | TBD | TBD | TBD | TBD | No repair path | No repair path |
| size-20gb | 64 | 20 GB | tar + zstd + age + PAR2 | TBD | TBD | TBD | TBD | TBD | TBD | External PAR2 | External PAR2 |
| size-20gb | 64 | 20 GB | 7z password archive | TBD | TBD | TBD | TBD | TBD | TBD | No repair path | No repair path |
| size-20gb | 64 | 20 GB | zip password archive | TBD | TBD | TBD | TBD | TBD | TBD | No repair path | No repair path |

Use the same columns for `size-1mb`, `size-20mb`, and `size-1gb` rows in the
full report. If the public page needs one compact table, lead with `size-20gb`
and link to the generated CSV files for the complete size ladder.

## Benchmark runner

Use the repository benchmark runner to generate deterministic data sets and
result tables:

```sh
python3 scripts/tzap_benchmark.py --profile smoke --runs 10 --tools tzap
```

The smoke profile is intentionally small and is useful for checking the harness.
It writes generated data, archives, logs, and result sheets under:

```text
target/tzap-bench/
```

Useful outputs:

```text
target/tzap-bench/results/results.csv
target/tzap-bench/results/recovery.csv
target/tzap-bench/results/raw-results.csv
target/tzap-bench/results/raw-recovery.csv
target/tzap-bench/results/results.md
target/tzap-bench/results/charts/*.svg
target/tzap-bench/results/metadata.json
target/tzap-bench/logs/benchmark-progress.log
```

`results.csv` contains selected-file path/position, averages, and standard
deviations for normal archive workflows. `recovery.csv` contains the recovery
proof timings; recovery defaults to one run because it is a behavior proof, not
a speed comparison.
`raw-results.csv` and `raw-recovery.csv` keep every individual run so published
numbers can be audited. `results.md` and `metadata.json` also record the
resolved executable paths and version strings for `tzap`, `tar`, `zstd`, `age`,
`7z` or `7zz`, `zip`, and `unzip` when those tools are selected.

`results.md` is the human-facing report. It should prefer human-size columns,
short interpretation, charts, and average `+/-` standard deviation timing.
Keep exact bytes, selected-file path, and detailed per-run data in the CSV and
JSON files instead of making the marketing report hard to scan.

The recovery scorecard should be direct for non-technical readers: `tzap`
recovered the tested missing-volume and rotten-payload cases; `tar + zstd`,
`tar + zstd + age`, `7z`, and `zip` fail those recovery cases because they do
not have a repair-data path in this benchmark.

State the tool mode explicitly in the report:

| Tool | Mode used |
| --- | --- |
| `tzap` | Encrypted, authenticated archive; recovery options enabled only for recovery tests |
| `tar + zstd` | tar stream compressed with zstd, not encrypted |
| `tar + zstd + age` | tar stream compressed with zstd, then encrypted with age |
| `tar + zstd + age + par2` | tar stream compressed with zstd, encrypted with age, then protected by PAR2 recovery files |
| `7z` | LZMA2 archive with password and header encryption: `-p... -mhe=on` |
| `zip` | Zip archive with password mode: `zip -P ...` |

`age` is encryption, not parity or recovery. It is included as a simple modern
encrypted-stream baseline. The PAR2 variant keeps the same stream shape but
adds external repair data.

Run the publishable local comparison set with the benchmark shape pinned on the
command line:

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

The standard profile defaults to 64 files in every data set and targets 1 MB,
20 MB, 1 GB, and 20 GB total input sizes. Pinning `--file-count` and
`--dataset-sizes` in the public command keeps "number of files" from becoming a
hidden benchmark variable while giving normal readers sizes they understand.
The normal create/extract rows use `tzap create` defaults, including the
input-size-based payload layout. The damaged-payload recovery proof below keeps
explicit block/chunk/envelope flags so the corruption site is deterministic.
Thirty normal workflow runs is the default for this profile when `--runs` is
omitted. One recovery proof run is the default when `--recovery-runs` is
omitted.
Selected-file restore defaults to the last generated file. Keep
`--selected-file-position last` for public results so the test avoids
first-file bias. The runner also supports `first` and `middle` for diagnosis,
but first-file numbers should not be used as the headline comparison.
The 20 GB tier needs substantial free disk space because the harness creates
source data, archives, restored outputs, recovery archives, and logs.
At startup the runner prints the durable progress log path and the `tail -f`
command to watch it. `target/tzap-bench/logs/benchmark-progress.log` records
data generation, every data set, every tool/run, every subcommand start/done,
and the detail log path for each command. Use `--quiet` only to suppress the
console mirror; the progress log is still written.

For quicker local checks against one publishable tier:

```sh
python3 scripts/tzap_benchmark.py \
  --profile standard \
  --datasets size-1mb \
  --runs 5 \
  --recovery-runs 1 \
  --file-count 64 \
  --dataset-sizes 1MB,20MB,1GB,20GB \
  --selected-file-position last \
  --par2-redundancy-pct 5 \
  --tools tzap,tar-zstd,tar-zstd-age,tar-zstd-age-par2,7z,zip
```

## Command-line benchmark knobs

Use these flags to make a published result reproducible without reading the
Python source:

| Knob | Purpose |
| --- | --- |
| `--file-count` | Number of generated files in each data set |
| `--dataset-sizes` | Total input sizes for the standard profile |
| `--same-count-file-sizes` | Per-file sizes for smoke/large same-count profiles |
| `--selected-file-position` | First, middle, or last generated member used for selected-file restore |
| `--benchmark-password` | Fixed password used by the zip and 7z password-mode baselines |
| `--par2-redundancy-pct` | PAR2 redundancy percentage for the `tar-zstd-age-par2` baseline |
| `--quiet` | Suppress the console mirror while still writing `logs/benchmark-progress.log` |
| `--recovery-volumes` | Number of tzap volumes generated for missing-volume recovery |
| `--recovery-volume-loss-tolerance` | Number of volumes tzap is allowed to recover from losing |
| `--recovery-omit-volume-index` | Which generated volume is hidden during missing-volume verification |
| `--bitrot-buffer-pct` | Repair-data budget for the damaged-payload recovery case |
| `--bitrot-small-block-size`, `--bitrot-small-chunk-size` | tzap block/chunk shape below the large-data threshold |
| `--bitrot-large-threshold` | Input size where the large-data bit-rot shape starts |
| `--bitrot-large-block-size`, `--bitrot-large-chunk-size` | tzap block/chunk shape at or above the large-data threshold |
| `--bitrot-envelope-size` | tzap envelope size for the damaged-payload recovery case |
| `--bitrot-corruption-bytes` | Number of payload bytes overwritten in the damage simulation |

## Recovery benchmark input

The `tzap` recovery section currently runs two scenarios:

| Scenario | Archive input | Injected damage |
| --- | --- | --- |
| Missing volume | `--volumes 3 --volume-loss-tolerance 1` | Temporarily omit `vol001` during `tzap verify` |
| Damaged payload block | `--bit-rot-buffer-pct 5`; 1 MB, 20 MB, and 1 GB use `--block-size 4K --chunk-size 4K --envelope-size 1M`; 20 GB uses `--block-size 64K --chunk-size 256K --envelope-size 1M` | Zero the first 4096 bytes of the first payload-data BlockRecord, then run `tzap verify` |

These inputs make the recovery claim concrete: the sheet records exactly what
kind of "rotten bits" or missing media was simulated.

Missing comparison tools are recorded as skipped rows instead of failing the
whole run. Peak RSS is recorded when GNU `time` is available; on macOS, install
`gtime` if memory columns matter.

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
