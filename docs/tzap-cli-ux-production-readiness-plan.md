# tzap CLI UX Production Readiness Plan

This document is a detailed execution plan for turning the current `tzap`
command line interface into a production-ready tool. It is intentionally
specific so an implementation agent can work through the plan without needing
much background context.

Implementation target:

- CLI crate: `crates/tzap-cli`
- CLI entry point: `crates/tzap-cli/src/main.rs`
- CLI tests: `crates/tzap-cli/tests/cli_smoke.rs`
- Core crate: `crates/tzap-core`
- Format spec: `specs/tzap-format-revisedv36.md`
- Release workflow: `.github/workflows/release.yml`
- CI workflow: `.github/workflows/ci.yml`

## Current State

The CLI already supports these commands:

- `tzap create`
- `tzap extract`
- `tzap list`
- `tzap verify`

It supports raw keyfiles, passphrases read from stdin, dictionaries, bootstrap
sidecars, multi-volume archive creation, multi-volume open/verify, and safe
extraction defaults.

The CLI is still raw in these ways:

- Help text is short and does not teach users how to succeed.
- Error messages are often technically correct but not always actionable.
- There is no interactive password prompt.
- There is no key generation command for raw keyfile users.
- There is no machine-readable output mode for `list` or `verify`.
- Some multi-volume and bootstrap combinations are explicitly unsupported.
- CI tests the workspace only on Ubuntu.
- The release workflow builds Linux, macOS, and Windows artifacts, but does not
  test the CLI across all three platforms.
- Packaging is basic: no checksums, no signatures, no Homebrew/Scoop/WinGet
  support, and no installer guidance.

## Production Goal

A user should be able to install `tzap`, run `tzap --help`, and safely complete
these tasks without reading the source code:

1. Create an encrypted archive from files or directories.
2. Create an archive using either a passphrase or a raw keyfile.
3. List archive contents.
4. Verify archive integrity.
5. Extract all files or selected files safely.
6. Understand and use multi-volume recovery settings.
7. Diagnose common failures such as wrong key, missing volume, corrupt archive,
   unsafe path, unsupported feature, or invalid flag value.

## Non-Goals For This Plan

Do not implement new archive format semantics in the CLI unless the core crate
already supports them.

Do not make the CLI hide unsupported writer scope. If the core writer still
rejects large multi-index-shard or directory-hint emission, the CLI should
surface that clearly instead of pretending the operation is supported.

Do not add complex include/exclude globbing until the basic command UX, help,
and tests are solid.

Do not publish to crates.io or tag a release until the release-readiness
milestone is complete.

## Agent Operating Rules

Follow these rules while implementing this plan:

1. Keep format logic in `tzap-core`; keep `tzap-cli` focused on argument
   parsing, filesystem IO, user messages, and exit codes.
2. Every new CLI flag must have at least one test.
3. Every changed error message must have a test if it is user-facing and stable
   enough to matter.
4. Do not weaken safe extraction behavior to make tests easier.
5. Prefer adding small helper functions in `main.rs` first. Split into modules
   only when the file becomes hard to navigate.
6. Run `cargo fmt --all -- --check` and `cargo test --workspace --locked`
   before each checkpoint.
7. On platform-specific behavior, use `#[cfg(unix)]` and `#[cfg(windows)]`
   tests rather than pretending all platforms behave the same.
8. If a command cannot support a user request yet, return a clear
   `unsupported-feature` diagnostic with a useful explanation.

## Milestone 1: CLI Contract And Command Shape

Status: done.

Purpose: define the stable user-facing command contract before polishing text
or adding many tests.

Tasks:

1. Audit current command names and flags in `crates/tzap-cli/src/main.rs`.
2. Write down the intended behavior for each command in this document.

Command contract:

- `create`
  - required flags: `--output`, and exactly one key source (`--keyfile`,
    `--password-stdin`, or `--password`)
  - required positionals: one or more input paths
  - optional volume shaping flags: `--volumes`, `--volume-size`, `--volume-loss-tolerance`
  - optional dictionary/bootstrap/compression controls as currently implemented
  - behavior: archive one or more input paths into one or more output archives
- `extract`
  - required positionals: archive, optionally one or more member paths
  - required key source: exactly one of `--keyfile`, `--password-stdin`, or
    `--password`
  - optional flags: `--directory`, `--stdout`, `--overwrite`, `--bootstrap`, `--volume`
  - behavior: extract selected members (or all members) to directory, with safe defaults
- `list`
  - required positional: archive
  - required key source: exactly one of `--keyfile`, `--password-stdin`, or
    `--password`
  - optional flags: `--bootstrap`, `--volume`, `--long`
  - behavior: print archive members
- `verify`
  - required positionals: one or more archive paths (primary + optional additional volumes)
  - required key source: exactly one of `--keyfile`, `--password-stdin`, or
    `--password`
  - optional flag: `--bootstrap`
  - behavior: validate archive integrity only; no payload mutation
- `keygen`
  - required output mode: exactly one of `--output` or `--stdout`
  - optional flag: `--force` for replacing an existing keyfile output
  - behavior: generate random raw key material encoded as lowercase hex
3. Decide whether to add aliases:
   - `tzap ls` for `tzap list`
   - `tzap x` for `tzap extract`
   - `tzap c` for `tzap create`
4. Decide whether aliases should be hidden from help. Recommended: skip aliases
   for the first production release unless users ask for them.
5. Decide whether `create` should require explicit key mode. Recommended: yes;
   keep requiring either `--keyfile` or `--password-stdin` until interactive
   password input lands.
6. Decide whether `--password` should ever accept a passphrase on the command
   line. Recommended: no, because command-line arguments can leak through shell
   history and process listings.

Decision for implementation:

- We will keep the public command set at `create`, `extract`, `list`, `verify`,
  and `keygen`.
- We will not add short aliases (`tzap c`, `tzap x`, `tzap ls`) in Milestone 1.
- `create`, `extract`, `list`, and `verify` now require exactly one key source at
  parse time: one of `--keyfile`, `--password-stdin`, or `--password`.
- All key-source flags remain mutually exclusive per command.
- `create` keeps `--volumes` and `--volume-size` marked as conflicting and
  mutually exclusive.

Acceptance criteria:

- The intended command shape is written down.
- No command has two flags that mean nearly the same thing.
- Conflicting flags are explicitly marked with Clap conflicts.
- Existing smoke tests still pass.

Commands:

```bash
cargo fmt --all -- --check
cargo test -p tzap --locked
```

## Milestone 2: Help Text And Examples

Status: done.

Purpose: make `--help` useful enough that a new user can complete common tasks.

Files:

- `crates/tzap-cli/src/main.rs`
- `crates/tzap-cli/tests/cli_smoke.rs`

Tasks:

1. Improve top-level Clap metadata:
   - `name = "tzap"`
   - concise `about`
   - detailed `long_about`
   - version
   - clear subcommand descriptions
2. Add command-level `about` and `long_about` for:
   - `create`
   - `extract`
   - `list`
   - `verify`
3. Add examples to the help text. Include at least:
   - create with passphrase from stdin
   - create with raw keyfile
   - list an archive
   - verify an archive
   - extract all files
   - extract one file to stdout
   - create multiple volumes
   - verify multiple volumes
   - use bootstrap sidecar
4. Add value names and help text for every flag:
   - `--output <ARCHIVE>`
   - `--volumes <COUNT>`
   - `--volume-size <SIZE>`
   - `--volume-loss-tolerance <COUNT>`
   - `--bit-rot-buffer-pct <PERCENT>`
   - `--password`
   - `--password-stdin`
   - `--keyfile <KEYFILE>`
   - `--force`
   - `--argon2-t-cost <COUNT>`
   - `--argon2-m-cost-kib <KIB>`
   - `--argon2-parallelism <COUNT>`
   - `--dictionary <FILE>`
   - `--bootstrap-out <FILE>`
   - `--compression-level <LEVEL>`
   - `--chunk-size <SIZE>`
   - `--envelope-size <SIZE>`
   - `--block-size <SIZE>`
   - `--dry-run`
   - `--directory <DIR>`
   - `--stdout`
   - `--overwrite`
   - `--bootstrap <FILE>`
   - `--volume <FILE>`
   - `--long`
   - `keygen --output <KEYFILE>`
   - `keygen --stdout`
   - `keygen --force`
5. Explain size suffixes in help:
   - bytes with no suffix
   - `K`, `KB`, `KiB`
   - `M`, `MB`, `MiB`
   - `G`, `GB`, `GiB`
6. Explain multi-volume output naming:
   - single volume writes exactly to `--output`
   - multiple volumes write `--output.000`, `--output.001`, ...
7. Add help snapshot tests. Start with substring tests if snapshot tooling is
   not installed, then move to snapshots later.

Required tests:

- `tzap --help` includes the short tool description and command list.
- `tzap create --help` includes examples and all create flags.
- `tzap extract --help` includes examples and all extract flags.
- `tzap list --help` includes examples and all list flags.
- `tzap verify --help` includes examples and all verify flags.
- `tzap keygen --help` includes examples and all keygen flags.
- `tzap create --volumes 2 --volume-size 1M ...` fails as a usage error.
- `tzap create --password-stdin --keyfile key.hex ...` fails as a usage error.

Acceptance criteria:

- A user can infer the basic workflow from help alone.
- Help text does not imply unsupported behavior.
- Help tests pass in current CI on Linux; macOS and Windows help verification is
  deferred to Milestone 10.

Commands:

```bash
cargo test -p tzap --test cli_smoke --locked help
cargo test -p tzap --locked
```

## Milestone 3: Error Messages And Exit Codes

Status: done.

Purpose: make failures actionable and keep exit codes stable for scripts.

Current exit code labels in `main.rs`:

- usage: `2`
- IO error: `3`
- wrong key: `10`
- corrupt archive: `11`
- unsupported revision: `12`
- unsafe path: `13`
- missing bootstrap: `14`
- unsupported feature: `16`
- generic error: `1`

Tasks:

1. Keep the existing exit code values unless there is a strong reason to change
   them.
2. Add a user-facing exit-code table to top-level long help or docs.
3. Make each error message follow this shape:
   - label
   - concise cause
   - useful action if one exists
4. Improve missing-key errors:
   - current: "either --keyfile or --password-stdin is required"
   - target: "no key source provided; use --password-stdin for passphrase
     archives or --keyfile PATH for raw-key archives"
5. Improve wrong-key errors:
   - identify passphrase/raw-key mismatch when known
   - do not reveal sensitive key material
6. Improve unsafe extraction errors:
   - explain that extraction was refused before writing unsafe output
   - mention `--overwrite` only when overwrite is the issue
7. Improve unsupported feature errors:
   - explain what is unsupported in this CLI/core version
   - avoid telling users to retry with the same flags
8. Improve invalid size errors:
   - include the bad value
   - include supported suffixes
9. Add tests for exit code and stderr label for each diagnostic category.

Required tests:

- Missing key returns exit code `1` or decide to classify it as usage `2`.
- Wrong passphrase returns `10` and contains `wrong-key`.
- Raw-key archive opened with `--password-stdin` returns `10` and mentions
  `--keyfile`.
- Corrupt payload returns `11` and contains `corrupt-archive`.
- Unsupported revision returns `12`.
- Unsafe extraction returns `13`.
- Missing bootstrap returns `14` when applicable.
- Unsupported writer scope returns `16`.
- Invalid command-line conflict returns `2`.
- Missing input file returns `3` and contains `io-error`.

Acceptance criteria:

- Users can understand what to do next for common failures.
- Tests assert labels and exit codes without overfitting full backtraces.
- Error messages do not leak passphrases, raw keys, or full internal debug
  structures.

Implemented coverage for this milestone now includes the following:

- Exit-code table in top-level `--help`.
- Action-aware error diagnostics in `crates/tzap-cli/src/main.rs`.
- End-to-end tests for each required diagnostic class:
  - missing-key usage,
  - wrong passphrase/raw key,
  - wrong key mode for raw-key archives,
  - corrupt payload,
  - unsupported revision,
  - unsafe-path,
  - missing bootstrap,
  - unsupported feature,
  - invalid size suffix/helpful message,
  - and IO input failures.

Commands:

```bash
cargo test -p tzap --test cli_smoke --locked
```

## Milestone 4: Key And Password UX

Status: done.

Purpose: make encryption key handling safe and understandable.

Implemented command additions:

- `tzap keygen --output key.hex`
- `tzap keygen --stdout`
- `tzap keygen --force --output key.hex`

Implemented password additions:

- `tzap create --password`
- `tzap extract --password`
- `tzap list --password`
- `tzap verify --password`

`--password` should prompt interactively without echo. Keep
`--password-stdin` for scripts and tests.

Tasks:

1. Add a dependency for hidden terminal input, such as `rpassword`, if accepted.
2. Add `keygen` subcommand:
   - writes 32 random bytes as 64 lowercase hex characters
   - refuses to overwrite by default
   - supports `--force`
   - supports `--stdout`
3. Add interactive password prompt:
   - create prompts twice and requires match
   - open commands prompt once
   - empty passphrase policy must be explicit; recommended: reject empty
4. Keep `--password-stdin` behavior for automation:
   - read full stdin
   - strip one trailing LF or CRLF
   - do not trim other whitespace
5. Validate Argon2 parameters before doing expensive work:
   - clear error if memory is too high
   - clear error if parallelism is invalid
6. Document raw keyfile format:
   - 32 raw bytes, or
   - 64 hex characters with optional surrounding whitespace

Required tests implemented:

- `keygen --stdout` emits 64 lowercase hex chars plus newline.
- `keygen --output key.hex` creates a file with valid hex.
- `keygen --output existing` refuses overwrite.
- `keygen --force --output existing` overwrites.
- `create --password-stdin` round-trips.
- `create --password-stdin` strips one trailing LF.
- `create --password-stdin` strips CRLF.
- `create --password-stdin` preserves internal spaces.
- `create --password-stdin` rejects empty passphrase if that policy is chosen.
- `create --keyfile` accepts 32 raw bytes.
- `create --keyfile` accepts 64 hex characters.
- `create --keyfile` rejects invalid hex.
- `create --keyfile` rejects wrong length.
- `--password-stdin` conflicts with `--keyfile`.
- `create --password` prompts twice and rejects mismatches.
- `extract --password` uses interactive prompt flow (covered by prompt fallback test).

Notes:

- `keygen` uses 32-byte random key material and writes lowercase hex to avoid uppercase formatting differences.
- Raw key parsing accepts either 32 raw bytes or 64 hex characters with trimmed whitespace.
- Argon2 parameters are now validated with limits from `tzap-core` before derivation.

Acceptance criteria:

- A human can create a secure archive without manually creating a keyfile.
- A script can still use stdin passphrases or raw keyfiles.
- No key material is printed except by explicit `keygen --stdout`.

Commands:

```bash
cargo test -p tzap --test cli_smoke --locked keygen
cargo test -p tzap --test cli_smoke --locked
```

## Milestone 5: Create Command Production UX

Status: complete.

Notes: create now preflights output paths (including dotted output bases for volume-size), supports explicit `--force`/`--dry-run`, handles deterministic directory traversal, rejects symlinks and unsupported input types, and documents/guards empty-directory behavior (empty directories are omitted).

Purpose: make archive creation predictable and safe.

Tasks:

1. Add preflight validation before reading all input files:
   - input paths exist
   - output path does not already exist unless overwrite behavior is explicit
   - multi-volume output paths do not already exist
   - bootstrap output path does not already exist unless overwrite behavior is
     explicit
2. Decide whether to add `--force` to `create`. Recommended: yes, but only for
   output files created by the CLI.
3. Add `--dry-run`:
   - prints planned archive paths
   - prints number of input files
   - prints total input bytes
   - prints key mode
   - prints planned volume mode
   - does not write archive bytes
4. Improve create summary:
   - file count
   - input bytes
   - archive bytes
   - volume count
   - recovery tolerance
   - bootstrap sidecar path if written
5. Improve directory handling:
   - deterministic traversal
   - clear behavior for hidden files
   - clear behavior for empty directories
6. Decide empty directory support. If core cannot represent empty directories
   yet, document and test that empty directories are omitted or rejected.
7. Improve symlink handling:
   - current create refuses symlink inputs
   - keep this for safety unless core adds full symlink authoring support
   - error should explain that symlink inputs are refused
8. Validate and test size options:
   - `--chunk-size`
   - `--envelope-size`
   - `--block-size`
   - `--volume-size`
9. Validate compression level range if core has a supported range. If zstd
   accepts the value, still document expected values.
10. Add progress output only after the above is stable. Recommended:
    `--quiet`, `--verbose`, and progress on stderr for terminals only.

Required success tests:

- Create one-file archive with keyfile.
- Create one-file archive with passphrase.
- Create directory tree.
- Create archive with Unicode file path.
- Create archive with long path that requires PAX.
- Create archive with empty file.
- Create archive with binary file.
- Create archive with dictionary.
- Create archive with bootstrap sidecar.
- Create multi-volume archive using `--volumes`.
- Create multi-volume archive using `--volume-size`.
- Create with custom chunk/envelope/block sizes.

Required failure tests:

- Missing input path.
- Unsupported input type.
- Symlink input.
- Existing output without `--force`.
- Existing multi-volume output without `--force`.
- Existing bootstrap output without `--force`.
- Invalid size suffix.
- Size overflow.
- `--chunk-size` larger than `--envelope-size`.
- `--volumes 0`.
- `--volume-loss-tolerance` larger than writer supports.
- Unsupported large archive writer scope returns `unsupported-feature`.

Acceptance criteria:

- `create` never partially overwrites existing user files without an explicit
  force option.
- Common create workflows are covered by integration tests.
- Create output explains what was produced.

Commands:

```bash
cargo test -p tzap --test cli_smoke --locked create
```

## Milestone 6: Extract Command Production UX

Status: complete.

Purpose: make extraction safe, understandable, and useful.

Tasks:

1. Keep safe extraction as the default:
   - no path traversal
   - no absolute paths
   - no unsafe symlink traversal
   - no overwrite unless `--overwrite`
2. Add `--dry-run`:
   - prints what would be extracted
   - does not write files
   - reports missing requested archive paths
3. Add better selected-path diagnostics:
   - if a requested path is missing, print the missing archive path
   - optionally suggest close matches later
4. Improve `--stdout`:
   - exactly one archive path required
   - must be a regular file
   - writes only file bytes to stdout
   - diagnostics go to stderr
5. Decide whether extracting all files with `--stdout` should ever stream a tar
   stream. Recommended: no for now; keep it explicit and simple.
6. Improve extraction summary:
   - extracted file count
   - skipped/degraded metadata count
   - destination directory
7. Document and test overwrite behavior.
8. Investigate support for bootstrap plus multi-volume. If unsupported, keep a
   clear test for the unsupported error.

Required success tests:

- Extract all files to default current directory.
- Extract all files to `-C DIR`.
- Extract one selected file.
- Extract multiple selected files.
- Extract one file to stdout.
- Extract with overwrite enabled.
- Extract with passphrase.
- Extract with keyfile.
- Extract with bootstrap sidecar.
- Extract from multi-volume archive.
- Extract when one volume is missing but parity allows recovery.

Required failure tests:

- Extract missing archive path.
- Extract to stdout with zero paths.
- Extract to stdout with two paths.
- Extract to stdout for non-regular path if such entries exist.
- Extract wrong key.
- Extract corrupt archive.
- Extract missing unrecoverable volume.
- Extract without overwrite when destination exists.
- Extract unsafe path fixture.
- Extract with missing bootstrap file.
- Extract with unsupported bootstrap plus multi-volume if still unsupported.

Acceptance criteria:

- Extraction is safe by default and tests prove it.
- `--stdout` can be used safely in scripts.
- Users get clear output for selected-path mistakes.

Completion notes:

- `--dry-run` now summarizes requested members and exits without writing files.
- Missing path diagnostics report every unresolved path.
- `--stdout` requires exactly one requested path and rejects non-regular members.
- Extraction now prints a completion summary with file and degraded-metadata counts.
- Multi-volume + bootstrap and malformed bootstrap cases are surfaced as unsupported where appropriate.
- Missing unsafe path checks are validated before lookup.
- Selected extract paths use core path normalization before lookup.
- `--dry-run` conflicts with `--stdout` so dry-run never streams file bytes.
- Missing dictionary bootstrap metadata keeps the stable `missing-bootstrap` diagnostic.
- Overwrite behavior and recovery paths are covered by tests.

Validation:

- `cargo test -p tzap --test cli_smoke --locked`
- `cargo test -p tzap --locked`

Commands:

```bash
cargo test -p tzap --test cli_smoke --locked extract
```

## Milestone 7: List Command Production UX

Status: complete.

Purpose: make archive inspection useful for humans and scripts.

Recommended additions:

- `tzap list --json`
- `tzap list --long`

Tasks:

1. Keep default output as one path per line.
2. Define `--long` columns. Recommended:
   - size
   - kind
   - mode
   - mtime if available
   - path
3. Add `--json` with a stable schema:

```json
{
  "files": [
    {
      "path": "dir/file.txt",
      "kind": "file",
      "size": 123,
      "mode": 420,
      "mtime": 0
    }
  ]
}
```

4. Add `--format <plain|long|json>` only if it is cleaner than separate flags.
   Recommended: keep `--long` and `--json`; make them conflict.
5. Make list output deterministic.
6. Ensure diagnostics always go to stderr.

Required success tests:

- List one-file archive.
- List directory tree archive.
- List Unicode paths.
- List long path.
- List empty archive if supported.
- List with passphrase.
- List with keyfile.
- List with bootstrap sidecar.
- List multi-volume archive.
- List `--long`.
- List `--json` and parse JSON in the test.

Required failure tests:

- `--long` conflicts with `--json` if both exist.
- Wrong key.
- Corrupt archive.
- Missing archive file.
- Missing bootstrap file.

Acceptance criteria:

- Plain output remains script-friendly.
- JSON output is valid and stable.
- Long output is human-readable.

Commands:

```bash
cargo test -p tzap --test cli_smoke --locked list
```

## Milestone 8: Verify Command Production UX

Status: complete.

Purpose: make verification trustworthy for local users and CI systems.

Recommended additions:

- `tzap verify --json`
- `tzap verify --quiet`

Tasks:

1. Keep successful default output concise:
   - current style: `archive: OK`
   - improve with volume count and maybe file count if cheap
2. Add `--quiet`:
   - no stdout on success
   - nonzero exit and stderr on failure
3. Add `--json`:
   - success/failure
   - archive inputs
   - volume count
   - optional file count
   - optional repaired erasure count if core exposes it
4. Improve failure messages for:
   - wrong key
   - corrupt header
   - corrupt payload
   - missing volume
   - unsupported revision
   - unsupported feature
5. Document volume argument behavior:
   - first positional archive is primary
   - additional positionals are additional volumes
   - ordering expectations

Required success tests:

- Verify one-volume archive.
- Verify multi-volume archive.
- Verify with passphrase.
- Verify with keyfile.
- Verify with bootstrap sidecar.
- Verify with missing recoverable volume.
- Verify `--quiet`.
- Verify `--json` and parse JSON.

Required failure tests:

- Wrong key.
- Missing archive file.
- Corrupt header.
- Corrupt payload.
- Missing unrecoverable volume.
- Unsupported revision fixture.
- Missing bootstrap file.
- `--quiet` still prints failure diagnostics to stderr.

Acceptance criteria:

- `verify` is useful both interactively and in CI scripts.
- Failure output does not require reading Rust error chains to understand.

Commands:

```bash
cargo test -p tzap --test cli_smoke --locked verify
```

## Milestone 9: Output Modes And Logging

Status: complete.

Purpose: make stdout/stderr behavior predictable.

Rules:

- Archive bytes and extracted file bytes may go to stdout only when explicitly
  requested.
- Human diagnostics go to stderr.
- Machine-readable JSON goes to stdout.
- Progress goes to stderr.
- Success summaries go to stderr for `create` and `extract`, stdout for `list`
  and `verify` unless `--json` or `--quiet` changes that.

Recommended flags:

- global `--quiet`
- global `--verbose`
- command-specific `--json` where useful

Tasks:

1. Decide whether `--quiet` and `--verbose` are global or per-command.
   Recommended: global.
2. Add an output helper so commands do not call `println!` and `eprintln!`
   inconsistently.
3. Make JSON and quiet modes conflict where needed.
4. Add tests that stdout contains only the expected content.
   - implement global `--quiet` in all commands
   - prevent success summaries from leaking when `--quiet` is enabled
   - keep JSON and binary extraction paths stdout-only unless explicitly requested

Required tests:

- `extract --stdout` stdout is exactly file bytes.
- `extract --stdout` diagnostics are stderr only.
- `list --json` stdout is valid JSON.
- `verify --quiet` success emits no stdout.
- `create --quiet` suppresses success summary.
- Errors still emit stderr under `--quiet`.

Implemented in this milestone:

- global `--quiet` and `--verbose` flags were added to CLI parsing
- verify `--quiet` and `--json` are now mutually exclusive
- list/verify/create/extract/keygen output paths now flow through shared success-output helpers
- added dedicated `cli_smoke` coverage for these behaviors
- `keygen` success output is now suppressed by `--quiet` while keeping `--stdout` data output unchanged

Acceptance criteria:

- The CLI can be safely used in shell pipelines.
- Tests prevent accidental diagnostics from leaking into stdout.

## Milestone 10: Cross-Platform CI And Release Builds

Status: done.

Purpose: prove the CLI behaves on Linux, macOS, and Windows.

Implemented in this milestone:

- CI now runs `fmt`, `check`, and full workspace tests on:
  - `ubuntu-latest`
  - `macos-latest`
  - `windows-latest`
- `cargo fmt --all -- --check` runs on Linux runner only.
- Release workflow now builds each required target artifact:
  - `tzap-vX.Y.Z-linux-x86_64.tar.gz`
  - `tzap-vX.Y.Z-linux-x86_64-musl.tar.gz`
  - `tzap-vX.Y.Z-macos-x86_64.tar.gz`
  - `tzap-vX.Y.Z-macos-aarch64.tar.gz`
  - `tzap-vX.Y.Z-windows-x86_64.zip`
- Release workflow now pins baseline runner images instead of moving `*-latest`
  labels:
  - `ubuntu-22.04`
  - `macos-15-intel`
  - `macos-14`
  - `windows-2022`
- macOS release artifacts pin deployment targets to `10.12` for x86_64 and
  `11.0` for aarch64.
- Linux now publishes a static musl artifact for older distro compatibility.
- Windows release builds use static CRT flags.
- Release packaging now emits per-platform SHA-256 checksum files and merges them into a `SHA256SUMS` manifest.
- Release packaging now runs post-build smoke tests (`tzap --version`, `tzap --help`) before upload.

Completed notes:

- Existing OS-gated tests are preserved and now exercised in CI matrix runs.
- Release artifacts are uploaded with matching checksum sidecar files.

Acceptance criteria:

- A tag produces useful release artifacts for common platforms.
- The same CLI smoke tests run on all supported OSes.

## Milestone 11: Documentation And README

Status: done.

Purpose: make the public docs match the polished CLI.

Files:

- `README.md`
- `docs/tzap-cli-reference.md` if created
- `crates/tzap-cli/Cargo.toml`

Tasks:

1. Add README quickstart:
   - install from GitHub release
   - create archive with passphrase
   - list archive
   - verify archive
   - extract archive
2. Add raw keyfile workflow:
   - `tzap keygen`
   - `tzap create --keyfile`
   - `tzap extract --keyfile`
3. Add multi-volume workflow:
   - create with `--volumes`
   - verify all volumes
   - recover with missing volume if supported
4. Add safety notes:
   - no overwrite by default
   - safe path handling
   - passphrase stdin vs interactive prompt
   - published archive format revision
5. Add an exit-code table.
6. Add supported platform table.
7. Add known limitations:
   - unsupported large writer shapes if still true
   - bootstrap plus multi-volume limitation if still true
8. Ensure examples are tested or manually verified.

Acceptance criteria:

- README examples work when copied into a shell.
- Known limitations are honest and current.
- The docs do not promise features the CLI rejects.

## Milestone 12: Crates.io Readiness

Status: done.

Purpose: prepare source publishing after the CLI is polished.

Completion notes:

- `tzap-core` package metadata and README are publish-ready and `tzap-core`
  0.1.0 has been published before the CLI crate.
- `tzap` uses a versioned `tzap-core` dependency for crates.io while keeping
  the workspace path dependency for local development.
- Package contents were inspected for both crates and kept focused on
  manifests, READMEs, source, and tests.
- Final release checks pass with locked dependencies.

Tasks:

1. Update package metadata:
   - `repository`
   - `readme`
   - package-specific `description`
   - `keywords`
   - `categories`
2. Update `crates/tzap-cli/Cargo.toml` dependency:

```toml
tzap-core = { path = "../tzap-core", version = "0.1.0" }
```

3. Confirm `tzap-core` publishes before `tzap`.
4. Inspect packaged files:

```bash
cargo package -p tzap-core --list
cargo package -p tzap --list
```

5. Run dry-runs:

```bash
cargo publish -p tzap-core --dry-run
cargo publish -p tzap --dry-run
```

6. Confirm package size is reasonable.
7. Confirm docs.rs build is likely to pass:

```bash
cargo doc --workspace --no-deps
```

Acceptance criteria:

- Both packages pass `cargo publish --dry-run`.
- Package contents do not include large or irrelevant local artifacts.
- README and manifest metadata render well on crates.io.

## Suggested Implementation Order

Use this exact order unless there is a strong reason to change it:

1. Help text and examples.
2. Error messages and exit-code tests.
3. Key/password UX, including `keygen`.
4. Create command preflight and dry-run.
5. Extract command dry-run and stdout polish.
6. List JSON/long output.
7. Verify quiet/JSON output.
8. Output mode consistency.
9. Cross-platform CI.
10. README and CLI reference docs.
11. Crates.io dry-run readiness.

## Minimum Test Matrix

Every major command must have tests for all of these dimensions where
applicable:

| Dimension | Cases |
| --- | --- |
| Key mode | raw keyfile, passphrase stdin, interactive password when added |
| Archive shape | one file, directory tree, empty file, binary file, Unicode path, long path |
| Volume mode | single volume, fixed volume count, target volume size, missing recoverable volume, missing unrecoverable volume |
| Bootstrap | no bootstrap, bootstrap sidecar written, bootstrap sidecar used, missing bootstrap |
| Output mode | human default, quiet, JSON, stdout bytes |
| Safety | no overwrite, overwrite allowed, unsafe path rejected, symlink behavior |
| Corruption | wrong key, header mutation, payload mutation, bad revision |
| Platform | Linux, macOS, Windows |

## Flag Coverage Checklist

Before adding or changing a flag, update this checklist.

Create command:

- [x] `-o, --output <ARCHIVE>`
- [x] `--volumes <COUNT>`
- [x] `--volume-size <SIZE>`
- [x] `--volume-loss-tolerance <COUNT>`
- [x] `--bit-rot-buffer-pct <PERCENT>`
- [x] `--password-stdin`
- [x] `--password` if added
- [x] `--keyfile <KEYFILE>`
- [x] `--argon2-t-cost <COUNT>`
- [x] `--argon2-m-cost-kib <KIB>`
- [x] `--argon2-parallelism <COUNT>`
- [x] `--dictionary <FILE>`
- [x] `--bootstrap-out <FILE>`
- [x] `--compression-level <LEVEL>`
- [x] `--chunk-size <SIZE>`
- [x] `--envelope-size <SIZE>`
- [x] `--block-size <SIZE>`
- [x] `--dry-run`
- [x] `--force`

Extract command:

- [x] positional archive path
- [x] optional archive member paths
- [x] `-C, --directory <DIR>`
- [x] `--stdout`
- [x] `--overwrite`
- [x] `--password-stdin`
- [x] `--password` if added
- [x] `--keyfile <KEYFILE>`
- [x] `--bootstrap <FILE>`
- [x] `--volume <FILE>`
- [x] `--dry-run` if added

List command:

- [x] positional archive path
- [x] `--password-stdin`
- [x] `--password` if added
- [x] `--keyfile <KEYFILE>`
- [x] `--bootstrap <FILE>`
- [x] `--volume <FILE>`
- [x] `--long`
- [x] `--json` if added

Verify command:

- [x] positional archive paths
- [x] `--password-stdin`
- [x] `--password` if added
- [x] `--keyfile <KEYFILE>`
- [x] `--bootstrap <FILE>`
- [x] `--quiet` if added
- [x] `--json` if added

Keygen command if added:

- [x] `--output <KEYFILE>`
- [x] `--stdout`
- [x] `--force`

Global flags if added:

- [ ] `--quiet`
- [ ] `--verbose`
- [ ] `--color <auto|always|never>` if added

## Definition Of Done

The CLI is production-ready when all of these are true:

1. `tzap --help` teaches the common workflow.
2. Each subcommand has useful examples in help.
3. Every flag has at least one test.
4. Error labels and exit codes are documented and tested.
5. Create/list/extract/verify each have success, edge, and failure tests.
6. Password and keyfile flows are safe and documented.
7. `extract` is safe by default and has tests proving that.
8. JSON or quiet modes exist for automation where needed.
9. CI passes on Linux, macOS, and Windows.
10. Release artifacts are named by OS and architecture.
11. README examples have been manually or automatically verified.
12. `cargo publish --dry-run` passes for `tzap-core` and `tzap`.

## Checkpoint Commands

Run these commands before merging each milestone:

```bash
cargo fmt --all -- --check
cargo test --workspace --locked
cargo check --workspace --all-targets --locked
```

Run these before release readiness:

```bash
cargo package -p tzap-core --list
cargo package -p tzap --list
cargo publish -p tzap-core --dry-run
cargo publish -p tzap --dry-run
cargo doc --workspace --no-deps
```
