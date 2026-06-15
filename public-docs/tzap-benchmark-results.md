# tzap Benchmark Results

Report date: June 15, 2026.

This is a measured benchmark snapshot for public-facing `tzap` claims. The
numbers below are from a local benchmark run on macOS arm64 using `tzap 0.1.7`.
Timings are scoped to the recorded machine, data shape, and command set.

## Headline

On a 1 GB / 6000-file workflow corpus, current `tzap` created a seekable
plaintext archive with no encryption and no bit-rot recovery margin in 0.752s.
That was 2.68x faster than `tar | zstd -T0` on the same corpus, while
preserving `tzap`'s random-seekable index format.

The same no-encryption/no-bitrot `tzap` archive restored the selected last file
in 0.016s, about 12.6x faster than the `tar | zstd` stream baseline. It also
completed a full extract in 0.641s, about 3.6x faster than `tar | zstd`.

The default encrypted `tzap` row keeps archive-native recovery data and
recovered both tested damage cases. Its verification step is intentionally
heavier on this many-file corpus because it authenticates and checks the
archive-native recovery structures.

## Public Metrics

This June 15, 2026 comparison uses `tzap 0.1.7` and a 1 GB benchmark data set
with 6000 generated files. It selects the last generated member,
`files/file-05999.bin`, to avoid first-file bias. Normal workflow timings are
averages from 3 runs.

| Tool | Create | Verify/Test | Last-file restore | Full extract | Archive size | Missing volume | Rotten payload |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| `tzap` | 0.824s | 27.483s | 0.019s | 2.056s | 281.71 MB | ✅ Recovered | ✅ Recovered |
| `tzap` no encryption, no bit-rot | 0.752s | 1.954s | 0.016s | 0.641s | 262.83 MB | ❌ No repair path | ❌ No repair path |
| `tar + zstd` | 2.018s | 0.145s | 0.202s | 2.316s | 256.68 MB | ❌ No repair path | ❌ No repair path |
| `tar + zstd + age` | 2.104s | 0.279s | 0.286s | 2.973s | 256.74 MB | ❌ No repair path | ❌ No repair path |
| `tar + zstd + age + PAR2` | 3.907s | 1.467s | 0.275s | 2.597s | 269.90 MB | ✅ External PAR2 | ✅ External PAR2 |
| `7z` | 2.014s | 0.344s | 0.333s | 0.891s | 257.14 MB | ❌ No repair path | ❌ No repair path |
| `zip` | 6.172s | 4.286s | 0.004s | 5.159s | 259.82 MB | ❌ No repair path | ❌ No repair path |

Mode notes:

- `tzap` uses `tzap keygen` plus `tzap create --keyfile bench.key ...`. It is
  encrypted and authenticated, and because no `--bit-rot-buffer-pct` override
  is passed, it uses the default 5% bit-rot recovery buffer. It does not use an
  interactive password prompt in this benchmark.
- `tzap` no encryption, no bit-rot uses `tzap create --no-encryption
  --bit-rot-buffer-pct 0`. It still writes `tzap`'s seekable archive metadata,
  but does not spend work on encryption, password handling, or Reed-Solomon
  repair shards.
- `7z` and `zip` are password-encrypted archive baselines. The `7z` row uses
  header encryption (`-mhe=on`); the `zip` row uses familiar `zip -P` password
  mode.

## Recovery Proof

Recovery cases use one proof run per scenario. The tested encrypted `tzap`
archive recovered both damage cases.

| Data set | Recovery case | Create | Recovery verify | Output size | Result |
| --- | --- | ---: | ---: | ---: | --- |
| 1 GB / 6000 files | Missing volume within tolerance | 9.442s | 263.862s | 450.71 MB | ✅ Recovered |
| 1 GB / 6000 files | Damaged payload block within bit-rot budget | 9.054s | 39.682s | 289.69 MB | ✅ Recovered |

The comparison baselines without repair data are marked "❌ No repair path" for
these recovery cases. The PAR2 baseline is marked "✅ External PAR2" because it
uses external recovery files rather than archive-native recovery.

## Benchmark Scope

The 1 GB many-file comparison run used:

- `--profile standard`
- `--datasets size-1gb`
- `--runs 3`
- `--recovery-runs 1`
- `--file-count 6000`
- `--dataset-sizes 1GB`
- `--selected-file-position last`
- `--tools tzap,tzap-no-password-no-bitrot,tar-zstd,tar-zstd-age,tar-zstd-age-par2,7z,zip`
- `--par2-redundancy-pct 5`
- `--recovery-volumes 3`
- `--recovery-volume-loss-tolerance 1`
- `--bitrot-buffer-pct 5`
- `--bitrot-corruption-bytes 4096`

## Environment

| Field | Value |
| --- | --- |
| Benchmark host | macOS 26.5.1 arm64 |
| `tzap` | `tzap 0.1.7` release build |
| Python | `3.14.5` |
| `zstd` | `v1.5.7` |
| `age` | `v1.3.1` |
| `par2` | `par2cmdline 1.1.1` |
| `7z` | `7-Zip 26.01` |
| `zip` / `unzip` | Info-ZIP `zip 3.0`, `unzip 6.00` |
| Corpus | 1 GB, 6000 files |

## Publishable Summary

On the June 15 many-file workflow corpus, `tzap` created a no-encryption,
no-bitrot, random-seekable archive in 0.752s, 2.68x faster than the measured
`tar | zstd -T0` stream baseline on the same machine and data.

The same `tzap` fast-path archive restored the selected last file in 0.016s,
about 12.6x faster than `tar | zstd`, and fully extracted in 0.641s, about 3.6x
faster than `tar | zstd`. The encrypted `tzap` recovery configuration recovered
both tested missing-volume and damaged-payload cases.

## Command Shapes Used

The benchmark runner logs the concrete commands for every timed run. These are
the command shapes behind the public table:

```sh
tzap keygen --output bench.key
tzap create --keyfile bench.key -o ARCHIVE.tzap DATASET
tzap verify --keyfile bench.key ARCHIVE.tzap
tzap extract --keyfile bench.key -C RESTORE_DIR ARCHIVE.tzap
tzap extract --keyfile bench.key --stdout ARCHIVE.tzap SELECTED_FILE > /dev/null

tzap create --no-encryption --bit-rot-buffer-pct 0 -o ARCHIVE.tzap DATASET
tzap verify ARCHIVE.tzap
tzap extract -C RESTORE_DIR ARCHIVE.tzap
tzap extract --stdout ARCHIVE.tzap SELECTED_FILE > /dev/null

tar -cf - DATASET | zstd -q -T0 -o ARCHIVE.tar.zst -
zstd -q -t ARCHIVE.tar.zst
zstd -q -dc ARCHIVE.tar.zst | tar -xf - -C RESTORE_DIR

tar -cf - DATASET | zstd -q -T0 | age -r PUBLIC_KEY -o ARCHIVE.tar.zst.age
age -d -i AGE_IDENTITY ARCHIVE.tar.zst.age | zstd -q -t -
par2 create -q -q -r5 -n1 ARCHIVE.tar.zst.age.par2 ARCHIVE.tar.zst.age
par2 verify -q -q ARCHIVE.tar.zst.age.par2 ARCHIVE.tar.zst.age

7zz a -t7z -m0=lzma2 -p[BENCH_PASSWORD] -mhe=on ARCHIVE.7z DATASET
7zz t -p[BENCH_PASSWORD] ARCHIVE.7z
7zz x -y -p[BENCH_PASSWORD] -oRESTORE_DIR ARCHIVE.7z

zip -qr -P [BENCH_PASSWORD] ARCHIVE.zip DATASET
unzip -t -P [BENCH_PASSWORD] ARCHIVE.zip
unzip -q -P [BENCH_PASSWORD] ARCHIVE.zip -d RESTORE_DIR
```
