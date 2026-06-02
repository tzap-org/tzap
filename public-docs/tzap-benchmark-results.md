# tzap Benchmark Results

Report date: June 2, 2026.

This is a measured benchmark snapshot for public-facing `tzap` claims. The
numbers below are from local benchmark runs on macOS 26.5 arm64 with
`tzap 0.1.2`. Timings are scoped to this machine, data shape, and command set.

## Headline

`tzap` restored one 320 MiB file from a 20 GB encrypted archive in 2.08s without
unpacking the full archive.

The same 20 GB data set created a 5.84 GB encrypted `tzap` archive. The selected
file was the middle generated member, `files/file-00032.bin`.

| Data set | Files | Selected file | Mode | Create | Verify | Full extract | Selected-file restore | Archive size |
| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 20 GB | 64 | 320 MiB | encrypted | 50.11s | 95.54s | 7.59s | 2.08s | 5.84 GB |
| 20 GB | 64 | 320 MiB | explicit plaintext | 50.78s | 45.36s | 8.56s | 0.545s | 5.84 GB |

## Public Metrics

This comparison uses the standard 1 GB benchmark data set with 64 generated
files and selects the last generated member, `files/file-00063.bin`, to avoid
first-file bias. Normal workflow timings are averages from 3 runs.

| Tool | Create | Verify/Test | Last-file restore | Full extract | Archive size | Missing volume | Rotten payload |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| `tzap` | 2.509s +/- 0.042s | 4.941s +/- 0.069s | 0.010s +/- 0.000s | 0.275s +/- 0.065s | 299.09 MB | Recovered | Recovered |
| `tar + zstd` | 0.280s +/- 0.007s | 0.128s +/- 0.000s | 0.182s +/- 0.002s | 0.578s +/- 0.010s | 256.15 MB | No repair path | No repair path |
| `tar + zstd + age` | 0.452s +/- 0.005s | 0.347s +/- 0.004s | 0.371s +/- 0.004s | 0.652s +/- 0.008s | 256.21 MB | No repair path | No repair path |
| `tar + zstd + age + PAR2` | 2.277s +/- 0.005s | 1.507s +/- 0.001s | 0.369s +/- 0.006s | 0.646s +/- 0.007s | 269.34 MB | External PAR2 | External PAR2 |
| `7z` | 1.662s +/- 0.033s | 0.174s +/- 0.009s | 0.167s +/- 0.001s | 0.265s +/- 0.030s | 256.14 MB | No repair path | No repair path |
| `zip` | 5.897s +/- 0.032s | 4.161s +/- 0.030s | 0.037s +/- 0.001s | 4.267s +/- 0.033s | 258.29 MB | No repair path | No repair path |

In this 1 GB run, `tzap` restored the selected last file about 39x faster than
the `tar + zstd + age` encrypted stream baseline, while also keeping archive
verification and recovery in one format.

## Recovery Proof

Recovery cases use one proof run per scenario. The tested `tzap` archive
recovered both damage cases.

| Data set | Recovery case | Create | Recovery verify | Output size | Result |
| --- | --- | ---: | ---: | ---: | --- |
| 1 GB | Missing volume within tolerance | 11.054s | 28.887s | 491.28 MB | Recovered |
| 1 GB | Damaged payload block within bit-rot budget | 4.053s | 6.381s | 289.10 MB | Recovered |

The comparison baselines without repair data are marked "No repair path" for
these recovery cases. The PAR2 baseline uses external recovery files rather
than archive-native recovery.

## Benchmark Scope

The 1 GB comparison run used:

- `--profile standard`
- `--runs 3`
- `--recovery-runs 1`
- `--file-count 64`
- `--dataset-sizes 1MB,20MB,1GB,20GB`
- `--datasets size-1gb`
- `--selected-file-position last`
- `--par2-redundancy-pct 5`
- `--recovery-volumes 3`
- `--recovery-volume-loss-tolerance 1`
- `--bitrot-buffer-pct 5`
- `--bitrot-corruption-bytes 4096`

The 20 GB headline rows are one-run local measurements over the same 64-file
data shape. Peak RSS is not reported because GNU `time` was not installed on
the benchmark host.

## Environment

| Field | Value |
| --- | --- |
| Benchmark host | macOS 26.5 arm64 |
| `tzap` | `tzap 0.1.2` |
| Python | `3.14.5` |
| `zstd` | `v1.5.7` |
| `age` | `v1.3.1` |
| `par2` | `par2cmdline 1.1.1` |
| `7z` | `7-Zip 26.01` |
| `zip` / `unzip` | Info-ZIP `zip 3.0`, `unzip 6.00` |

## Publishable Summary

On this machine and data set, `tzap` restored one file from a 20 GB encrypted
archive in 2.08s, and recovered both tested missing-volume and damaged-payload
cases in the 1 GB recovery benchmark.
