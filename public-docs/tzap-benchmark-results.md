# tzap Benchmark Results

Report date: June 16, 2026.

This is a measured benchmark snapshot for public-facing `tzap` claims. The
numbers below are from a local benchmark run on macOS arm64 using `tzap 0.1.7`.
Timings are scoped to the recorded machine, data shape, and command set.

## Headline

On a 1 GB / 6000-file workflow corpus, current `tzap` created a seekable
plaintext archive with no encryption and no bit-rot recovery margin in 0.910s.
That was 2.24x faster than `tar | zstd -T0` and 6.81x faster than `zip` on
the same corpus, while preserving `tzap`'s random-seekable index format.

The same no-encryption/no-bitrot `tzap` archive restored the selected
`files/file-04000.bin` member in 0.012s, about 15.8x faster than the
`tar | zstd` stream baseline. It also completed a full extract in 0.649s,
about 7.8x faster than `zip`.

The default encrypted `tzap` row keeps archive-native recovery data and
recovered both tested damage cases. The normal workflow now measures
`tzap verify --fast`; the fast path improved the default recoverable verify
time versus the prior snapshot, but the recoverable row remains heavier than
archive tests without archive-native repair data.

## Public Metrics

This June 16, 2026 comparison uses `tzap 0.1.7` and a 1 GB benchmark data set
with 6000 generated files. It selects generated member
`files/file-04000.bin`, avoiding both first-file and last-file edge effects.
Normal workflow timings are averages from 3 runs.

| Tool | Create | Verify/Test | Selected-file restore | Full extract | Archive size | Missing volume | Rotten payload | Repair data rot |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- | --- |
| `tzap` | 1.239s | 25.144s | 0.018s | 1.935s | 281.71 MB | ✅ Recovered | ✅ Recovered | ✅ Archive-native |
| `tzap` no encryption, no bit-rot | 0.910s | 1.451s | 0.012s | 0.649s | 262.83 MB | ❌ No repair path | ❌ No repair path | ❌ No repair data |
| `tar + zstd` | 2.039s | 0.141s | 0.195s | 2.226s | 256.67 MB | ❌ No repair path | ❌ No repair path | ❌ No repair data |
| `tar + zstd + age` | 2.007s | 0.270s | 0.276s | 2.237s | 256.73 MB | ❌ No repair path | ❌ No repair path | ❌ No repair data |
| `tar + zstd + age + PAR2` | 3.887s | 1.457s | 0.272s | 2.267s | 269.88 MB | ✅ External PAR2 | ✅ External PAR2 | ❌ Sidecar risk |
| `7z` | 2.156s | 0.355s | 0.300s | 0.862s | 257.14 MB | ❌ No repair path | ❌ No repair path | ❌ No repair data |
| `zip` | 6.195s | 4.297s | 0.006s | 5.073s | 259.82 MB | ❌ No repair path | ❌ No repair path | ❌ No repair data |

Mode notes:

- `tzap` uses `tzap keygen` plus `tzap create --keyfile bench.key ...`. It is
  encrypted and authenticated, and because no `--bit-rot-buffer-pct` override
  is passed, it uses the default 5% bit-rot recovery buffer. It does not use an
  interactive password prompt in this benchmark. The normal workflow verify
  timing uses `tzap verify --fast --keyfile bench.key ...`.
- `tzap` no encryption, no bit-rot uses `tzap create --no-encryption
  --bit-rot-buffer-pct 0`. It still writes `tzap`'s seekable archive metadata,
  but does not spend work on encryption, password handling, or Reed-Solomon
  repair shards. Its normal workflow verify timing uses `tzap verify --fast`.
- `tar + zstd + age + PAR2` reports the combined size of the encrypted stream
  archive plus the generated external PAR2 files. Those PAR2 files are part of
  the repair path: if the sidecar repair files are lost or bit-rotted beyond
  the remaining usable recovery packets, the stream archive can lose its
  recovery path.
- `7z` and `zip` are password-encrypted archive baselines. The `7z` row uses
  header encryption (`-mhe=on`); the `zip` row uses familiar `zip -P` password
  mode.

## Recovery Proof

Recovery cases use one proof run per scenario. The tested encrypted `tzap`
archive recovered both damage cases.

| Data set | Recovery case | Create | Recovery verify | Output size | Result |
| --- | --- | ---: | ---: | ---: | --- |
| 1 GB / 6000 files | Missing volume within tolerance | 9.231s | 263.130s | 450.71 MB | ✅ Recovered |
| 1 GB / 6000 files | Damaged payload block within bit-rot budget | 9.262s | 38.044s | 289.69 MB | ✅ Recovered |

The comparison baselines without repair data are marked "❌ No repair path" for
these recovery cases. The PAR2 baseline is marked "✅ External PAR2" because it
uses external recovery files rather than archive-native recovery. In contrast,
the recoverable `tzap` path stores repair data inside the archive package and
uses it across payload objects plus critical metadata such as startup headers,
terminal metadata, index roots, index shards, and directory hints, within the
chosen recovery budget. The "Repair data rot" column is a repair-path
resilience distinction, not an additional timed recovery run.

## Benchmark Scope

The 1 GB many-file comparison run used:

- `--profile standard`
- `--datasets size-1gb`
- `--runs 3`
- `--recovery-runs 1`
- `--file-count 6000`
- `--dataset-sizes 1GB`
- `--selected-file-index 4000`
- `--tzap-verify-fast`
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

On the June 16 many-file workflow corpus, `tzap` created a no-encryption,
no-bitrot, random-seekable archive in 0.910s, 2.24x faster than the measured
`tar | zstd -T0` stream baseline and 6.81x faster than `zip` on the same
machine and data.

The same `tzap` fast-path archive restored `files/file-04000.bin` in 0.012s,
about 15.8x faster than `tar | zstd`, and fully extracted in 0.649s, about
7.8x faster than `zip`. The encrypted `tzap` recovery configuration recovered
both tested missing-volume and damaged-payload cases.

## Command Shapes Used

The benchmark runner logs the concrete commands for every timed run. These are
the command shapes behind the public table:

```sh
tzap keygen --output bench.key
tzap create --keyfile bench.key -o ARCHIVE.tzap DATASET
tzap verify --fast --keyfile bench.key ARCHIVE.tzap
tzap extract --keyfile bench.key -C RESTORE_DIR ARCHIVE.tzap
tzap extract --keyfile bench.key --stdout ARCHIVE.tzap SELECTED_FILE > /dev/null

tzap create --no-encryption --bit-rot-buffer-pct 0 -o ARCHIVE.tzap DATASET
tzap verify --fast ARCHIVE.tzap
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
