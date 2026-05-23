use std::ffi::OsStr;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgGroup, Parser, Subcommand};
use rand::RngCore;
use serde_json::json;
use tzap_core::format::{
    FormatError, CRYPTO_HEADER_FIXED_LEN, READER_MAX_ARGON2ID_M_COST_KIB,
    READER_MAX_ARGON2ID_PARALLELISM, READER_MAX_ARGON2ID_T_COST, VOLUME_HEADER_LEN,
};
use tzap_core::metadata::normalize_lookup_file_path;
use tzap_core::reader::ArchiveEntry;
use tzap_core::wire::{CryptoHeader, CryptoHeaderFixed, VolumeHeader};
use tzap_core::{
    open_archive, open_archive_volumes, open_archive_with_bootstrap_sidecar, write_archive,
    write_archive_with_dictionary, write_archive_with_dictionary_and_kdf, write_archive_with_kdf,
    KdfParams, MasterKey, MetadataDiagnostic, OpenedArchive, RegularFile, SafeExtractionOptions,
    TarEntryKind, WriterOptions,
};

const EXIT_USAGE: u8 = 2;
const EXIT_IO: u8 = 3;
const EXIT_WRONG_KEY: u8 = 10;
const EXIT_CORRUPT_ARCHIVE: u8 = 11;
const EXIT_UNSUPPORTED_REVISION: u8 = 12;
const EXIT_UNSAFE_PATH: u8 = 13;
const EXIT_MISSING_BOOTSTRAP: u8 = 14;
const EXIT_UNSUPPORTED_FEATURE: u8 = 16;
const EXIT_GENERIC: u8 = 1;

const DEFAULT_ARGON2_T_COST: u32 = 3;
const DEFAULT_ARGON2_M_COST_KIB: u32 = 262_144;
const DEFAULT_ARGON2_PARALLELISM: u32 = 4;
const DEFAULT_ARGON2_SALT_LEN: usize = 16;

#[derive(Debug, Parser)]
#[command(name = "tzap")]
#[command(version)]
#[command(about = "Create, list, verify, and extract v36 archives")]
#[command(
    long_about = "Create, list, verify, and extract v36 archives.\n\nUsage is centered on an explicit key source per command: either `--keyfile` for raw-key archives, `--password` for interactive prompt, or `--password-stdin` for scripted passphrase input.\n\nSize suffixes accepted by size flags:\n  0-9 (bytes), K/KB/KiB, M/MB/MiB, G/GB/GiB.\n\nMulti-volume output naming for this CLI:\n  - one volume: --output writes exactly that path\n  - multiple volumes: --output writes --output.000, --output.001, ...\n\nExit codes:\n  2  usage / argument error\n  3  I/O failure (missing file, permission denied, etc.)\n  10 wrong key\n  11 archive corruption or integrity mismatch\n  12 unsupported archive revision / format version\n  13 unsafe extraction attempt\n  14 missing required bootstrap metadata\n  16 unsupported feature in this CLI/core version\n  1  generic failure\n\nSubcommands:\n  create   Build a new archive\n  extract  Extract files from an archive\n  list     List archive contents\n  verify   Validate archive integrity\n  keygen   Generate a random raw keyfile"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[arg(long = "quiet", global = true, help = "Suppress success summaries.")]
    quiet: bool,

    #[arg(long = "verbose", global = true, help = "Enable verbose diagnostics.")]
    verbose: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(
        about = "Create a new archive",
        long_about = "Create a new archive from files and directories.\n\nThe command writes one output path for single-volume archives, or a base path plus `.000`, `.001`, ... suffixes for multi-volume archives.",
        after_help = "Examples:\n  tzap create --keyfile key.hex -o backup.tzap file.txt\n  tzap create --password -o backup.tzap file.txt\n  tzap create --password-stdin --argon2-t-cost 1 --argon2-m-cost-kib 8192 -o backup.tzap file.txt\n  tzap create --keyfile key.hex -o backup.tzap --volumes 3 dir/\n  tzap create --keyfile key.hex --volume-size 64M --volume-loss-tolerance 1 -o backup.tzap dir/\n  tzap create --keyfile key.hex --bootstrap-out backup.tzap.bootstrap file.txt",
        group(
            ArgGroup::new("create-key-source")
                .required(true)
                .args(["password_stdin", "password", "keyfile"])
        )
    )]
    Create {
        #[arg(
            short = 'o',
            long = "output",
            value_name = "ARCHIVE",
            help = "Write output to ARCHIVE (single volume) or base path for multi-volume output."
        )]
        output: String,

        #[arg(
            long = "volumes",
            value_name = "COUNT",
            conflicts_with = "volume_size",
            help = "Create exactly COUNT output volumes."
        )]
        volumes: Option<u32>,

        #[arg(
            long = "volume-size",
            value_name = "SIZE",
            conflicts_with = "volumes",
            help = "Create as many fixed-size output volumes as needed."
        )]
        volume_size: Option<String>,

        #[arg(
            long = "volume-loss-tolerance",
            value_name = "COUNT",
            help = "Allowed missing-volume recovery tolerance for multi-volume archives.",
            default_value_t = 0
        )]
        volume_loss_tolerance: u8,

        #[arg(
            long = "bit-rot-buffer-pct",
            value_name = "PERCENT",
            default_value_t = 5,
            help = "Percent of archive reserved for bit-rot recovery structures."
        )]
        bit_rot_buffer_pct: u8,

        #[arg(
            long = "password-stdin",
            conflicts_with = "keyfile",
            conflicts_with = "password",
            value_name = "STDIN",
            help = "Read passphrase from stdin; one trailing LF or CRLF is stripped."
        )]
        password_stdin: bool,

        #[arg(
            long = "password",
            conflicts_with = "keyfile",
            conflicts_with = "password_stdin",
            help = "Read passphrase from an interactive prompt."
        )]
        password: bool,

        #[arg(
            long = "keyfile",
            value_name = "KEYFILE",
            help = "Use a raw key from KEYFILE."
        )]
        keyfile: Option<String>,

        #[arg(
            long = "force",
            help = "Overwrite existing output files and bootstrap sidecar."
        )]
        force: bool,

        #[arg(
            long = "argon2-t-cost",
            value_name = "COUNT",
            default_value_t = DEFAULT_ARGON2_T_COST,
            help = "Argon2 iterations when deriving from passphrase."
        )]
        argon2_t_cost: u32,

        #[arg(
            long = "argon2-m-cost-kib",
            value_name = "KIB",
            default_value_t = DEFAULT_ARGON2_M_COST_KIB,
            help = "Argon2 memory cost (KiB) when deriving from passphrase."
        )]
        argon2_m_cost_kib: u32,

        #[arg(
            long = "argon2-parallelism",
            value_name = "COUNT",
            default_value_t = DEFAULT_ARGON2_PARALLELISM,
            help = "Argon2 parallelism when deriving from passphrase."
        )]
        argon2_parallelism: u32,

        #[arg(
            long = "dictionary",
            value_name = "FILE",
            help = "Read compression dictionary from FILE."
        )]
        dictionary: Option<String>,

        #[arg(
            long = "bootstrap-out",
            value_name = "FILE",
            help = "Write bootstrap recovery sidecar to FILE."
        )]
        bootstrap_out: Option<String>,

        #[arg(
            long = "compression-level",
            value_name = "LEVEL",
            default_value_t = 3,
            help = "zstd compression level."
        )]
        compression_level: i32,

        #[arg(
            long = "chunk-size",
            value_name = "SIZE",
            default_value = "256K",
            help = "Compression chunk size."
        )]
        chunk_size: String,

        #[arg(
            long = "envelope-size",
            value_name = "SIZE",
            default_value = "1M",
            help = "Archive envelope size."
        )]
        envelope_size: String,

        #[arg(
            long = "block-size",
            value_name = "SIZE",
            default_value = "64K",
            help = "Block size for archive payload layout."
        )]
        block_size: String,

        #[arg(
            long = "dry-run",
            help = "Print a create plan and file summary without writing archive bytes."
        )]
        dry_run: bool,

        #[arg(
            required = true,
            value_name = "PATH",
            help = "One or more input files or directories."
        )]
        paths: Vec<String>,
    },
    #[command(
        about = "Extract files from an archive",
        long_about = "Extract one or many archive members into a directory, with safe-path protections enabled by default.",
        after_help = "Examples:\n  tzap extract --keyfile key.hex -C out/ backup.tzap\n  tzap extract --keyfile key.hex backup.tzap file.txt\n  tzap extract --keyfile key.hex --stdout backup.tzap hello.txt > out.bin\n  tzap extract --password-stdin --overwrite backup.tzap target/\n  tzap extract --dry-run -C out backup.tzap file.txt\n  tzap extract --bootstrap backup.tzap.bootstrap -C out backup.tzap",
        group(
            ArgGroup::new("open-key-source")
                .required(true)
                .args(["password_stdin", "password", "keyfile"])
        )
    )]
    Extract {
        #[arg(
            value_name = "ARCHIVE",
            help = "Primary archive input. Use additional --volume for extra volumes."
        )]
        archive: String,

        #[arg(
            value_name = "PATH",
            help = "Optional archive member paths to extract."
        )]
        paths: Vec<String>,

        #[arg(
            short = 'C',
            long = "directory",
            value_name = "DIR",
            default_value = ".",
            help = "Destination directory for extracted files."
        )]
        directory: String,

        #[arg(
            long = "stdout",
            conflicts_with = "dry_run",
            help = "Write a single selected member to stdout."
        )]
        stdout: bool,

        #[arg(
            long = "dry-run",
            help = "Show what would be extracted without writing files."
        )]
        dry_run: bool,

        #[arg(long = "overwrite", help = "Allow overwriting existing output files.")]
        overwrite: bool,

        #[arg(
            long = "password-stdin",
            conflicts_with = "keyfile",
            conflicts_with = "password",
            value_name = "STDIN",
            help = "Read passphrase from stdin; one trailing LF or CRLF is stripped."
        )]
        password_stdin: bool,

        #[arg(
            long = "password",
            conflicts_with = "keyfile",
            conflicts_with = "password_stdin",
            help = "Read passphrase from an interactive prompt."
        )]
        password: bool,

        #[arg(
            long = "keyfile",
            value_name = "KEYFILE",
            help = "Use a raw key from KEYFILE."
        )]
        keyfile: Option<String>,

        #[arg(
            long = "bootstrap",
            value_name = "FILE",
            help = "Use bootstrap sidecar FILE."
        )]
        bootstrap: Option<String>,

        #[arg(long = "volume", value_name = "FILE", help = "Additional volume path.")]
        volumes: Vec<String>,
    },
    #[command(
        about = "List archive contents",
        long_about = "List archive members in plain format by default.",
        after_help = "Examples:\n  tzap list --keyfile key.hex backup.tzap\n  tzap list --keyfile key.hex --long backup.tzap\n  tzap list --keyfile key.hex --json backup.tzap\n  tzap list --password-stdin --bootstrap backup.tzap.bootstrap backup.tzap",
        group(
            ArgGroup::new("open-key-source")
                .required(true)
                .args(["password_stdin", "password", "keyfile"])
        )
    )]
    List {
        #[arg(value_name = "ARCHIVE", help = "Archive to inspect.")]
        archive: String,

        #[arg(
            long = "password-stdin",
            conflicts_with = "keyfile",
            conflicts_with = "password",
            value_name = "STDIN",
            help = "Read passphrase from stdin; one trailing LF or CRLF is stripped."
        )]
        password_stdin: bool,

        #[arg(
            long = "password",
            conflicts_with = "keyfile",
            conflicts_with = "password_stdin",
            help = "Read passphrase from an interactive prompt."
        )]
        password: bool,

        #[arg(
            long = "keyfile",
            value_name = "KEYFILE",
            help = "Use a raw key from KEYFILE."
        )]
        keyfile: Option<String>,

        #[arg(
            long = "bootstrap",
            value_name = "FILE",
            help = "Use bootstrap sidecar FILE."
        )]
        bootstrap: Option<String>,

        #[arg(long = "volume", value_name = "FILE", help = "Additional volume path.")]
        volumes: Vec<String>,

        #[arg(
            long = "long",
            conflicts_with = "json",
            help = "Use verbose listing output."
        )]
        long: bool,

        #[arg(
            long = "json",
            conflicts_with = "long",
            help = "Emit stable machine-readable JSON output."
        )]
        json: bool,
    },
    #[command(
        about = "Verify archive integrity",
        long_about = "Verify archive signatures and checksum integrity. No payload changes are made.",
        after_help = "Examples:\n  tzap verify --keyfile key.hex backup.tzap\n  tzap verify --keyfile key.hex backup.tzap backup.tzap.001\n  tzap verify --password-stdin backup.tzap\n  tzap verify --json --keyfile key.hex backup.tzap\n  tzap verify --quiet --keyfile key.hex backup.tzap\n\nFor multi-volume archives, the first positional argument is the primary archive.\nAdditional positionals are optional extra volumes.",
        group(
            ArgGroup::new("open-key-source")
                .required(true)
                .args(["password_stdin", "password", "keyfile"])
        )
    )]
    Verify {
        #[arg(
            required = true,
            value_name = "ARCHIVE",
            help = "Primary archive followed by optional additional volumes."
        )]
        archives: Vec<String>,

        #[arg(
            long = "password-stdin",
            conflicts_with = "keyfile",
            conflicts_with = "password",
            value_name = "STDIN",
            help = "Read passphrase from stdin; one trailing LF or CRLF is stripped."
        )]
        password_stdin: bool,

        #[arg(
            long = "password",
            conflicts_with = "keyfile",
            conflicts_with = "password_stdin",
            help = "Read passphrase from an interactive prompt."
        )]
        password: bool,

        #[arg(
            long = "keyfile",
            value_name = "KEYFILE",
            help = "Use a raw key from KEYFILE."
        )]
        keyfile: Option<String>,

        #[arg(
            long = "bootstrap",
            value_name = "FILE",
            help = "Use bootstrap sidecar FILE."
        )]
        bootstrap: Option<String>,

        #[arg(
            long = "json",
            conflicts_with = "quiet",
            help = "Emit stable machine-readable JSON output."
        )]
        json: bool,
    },
    #[command(
        about = "Generate a random raw key",
        long_about = "Generate a random 32-byte raw key and write it as 64 lowercase hex characters.\n\nBy default, --output refuses to overwrite an existing file.\nUse --force if you want to replace it.\n\nUse --stdout to print the key to stdout instead.",
        group(
            ArgGroup::new("keygen-output")
                .required(true)
                .args(["output", "stdout"])
        )
    )]
    Keygen {
        #[arg(
            short = 'o',
            long = "output",
            value_name = "KEYFILE",
            conflicts_with = "stdout",
            help = "Write the generated key to KEYFILE."
        )]
        output: Option<String>,

        #[arg(long = "stdout", help = "Write the generated key to stdout.")]
        stdout: bool,

        #[arg(long = "force", help = "Overwrite an existing output keyfile.")]
        force: bool,
    },
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let code = if err.use_stderr() { EXIT_USAGE } else { 0 };
            let _ = err.print();
            return ExitCode::from(code);
        }
    };
    if cli.quiet && matches!(&cli.command, Command::Verify { json: true, .. }) {
        eprintln!("error: --quiet cannot be used with --json for verify");
        return ExitCode::from(EXIT_USAGE);
    }
    let is_verify_json = matches!(&cli.command, Command::Verify { json: true, .. });

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let diagnostic = classify_error(&err);
            if !is_verify_json {
                if diagnostic.action.is_empty() {
                    eprintln!("tzap: {}: {err:#}", diagnostic.label);
                } else {
                    eprintln!("tzap: {}: {err:#}: {}", diagnostic.label, diagnostic.action);
                }
            }
            ExitCode::from(diagnostic.exit_code)
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let quiet = cli.quiet;
    match cli.command {
        Command::Create {
            output,
            volumes,
            volume_size,
            volume_loss_tolerance,
            bit_rot_buffer_pct,
            password_stdin,
            password,
            keyfile,
            force,
            dry_run,
            argon2_t_cost,
            argon2_m_cost_kib,
            argon2_parallelism,
            dictionary,
            bootstrap_out,
            compression_level,
            chunk_size,
            envelope_size,
            block_size,
            paths,
        } => {
            let mut options = WriterOptions::default();
            options.stripe_width = volumes.unwrap_or(1);
            options.target_volume_size = volume_size
                .as_deref()
                .map(|value| {
                    parse_size(value).with_context(|| format!("invalid volume-size: {value}"))
                })
                .transpose()?;
            options.volume_loss_tolerance = volume_loss_tolerance;
            options.bit_rot_buffer_pct = bit_rot_buffer_pct;
            options.zstd_level = compression_level;
            options.chunk_size = parse_size_u32(&chunk_size, "chunk-size")?;
            options.envelope_target_size = parse_size_u32(&envelope_size, "envelope-size")?;
            options.block_size = parse_size_u32(&block_size, "block-size")?;
            if bootstrap_out.is_some() && (volumes.unwrap_or(1) > 1 || volume_size.is_some()) {
                return Err(FormatError::WriterUnsupported(
                    "--bootstrap-out is currently supported only for single-volume output",
                )
                .into());
            }
            reject_create_stdout_sentinels(&output, bootstrap_out.as_deref())?;

            ensure_create_output_paths_can_be_written(
                &output,
                volumes,
                volume_size.is_some(),
                bootstrap_out.as_deref(),
                force,
            )?;
            validate_create_writer_options(&options)?;
            let input_specs = collect_input_specs(&paths)?;
            let bootstrap_output = bootstrap_out.clone();

            if dry_run {
                eprintln!("create dry-run summary:");
                eprintln!("  files: {}", input_specs.len());
                eprintln!(
                    "  input bytes: {}",
                    input_specs.iter().map(|entry| entry.size).sum::<u64>()
                );
                eprintln!(
                    "  key mode: {}",
                    create_key_mode_label(keyfile.as_deref(), password_stdin, password)
                );
                eprintln!(
                    "  volume mode: {}",
                    describe_planned_volume_mode(volumes, volume_size.as_deref())
                );
                eprintln!("  planned archive paths:");
                for path in create_dry_run_output_paths(&output, volumes, volume_size.is_some()) {
                    eprintln!("    {path}");
                }
                if let Some(bootstrap_path) = bootstrap_output {
                    eprintln!("  bootstrap: {}", bootstrap_path);
                }
                return Ok(());
            }

            let key = load_create_key(
                keyfile.as_deref(),
                password_stdin,
                password,
                argon2_t_cost,
                argon2_m_cost_kib,
                argon2_parallelism,
            )?;
            let inputs = collect_inputs_from_specs(&input_specs)?;
            let regular_files = inputs
                .iter()
                .map(|file| RegularFile {
                    path: file.archive_path.as_str(),
                    contents: &file.contents,
                    mode: file.mode,
                    mtime: file.mtime,
                })
                .collect::<Vec<_>>();
            let dictionary_bytes = dictionary
                .as_deref()
                .map(|path| {
                    fs::read(path).with_context(|| format!("failed to read dictionary {path}"))
                })
                .transpose()?;
            let archive = match (&dictionary_bytes, &key.kdf_params) {
                (Some(dictionary), KdfParams::Raw) => write_archive_with_dictionary(
                    &regular_files,
                    &key.master_key,
                    options,
                    dictionary,
                ),
                (Some(dictionary), kdf_params) => write_archive_with_dictionary_and_kdf(
                    &regular_files,
                    &key.master_key,
                    options,
                    dictionary,
                    kdf_params,
                ),
                (None, KdfParams::Raw) => write_archive(&regular_files, &key.master_key, options),
                (None, kdf_params) => {
                    write_archive_with_kdf(&regular_files, &key.master_key, options, kdf_params)
                }
            }
            .context("failed to create archive")?;

            let output_paths = create_output_paths(&output, archive.volumes.len());
            if !force {
                check_archive_paths_free_for_write(&output_paths)?;
            }
            if let Some(bootstrap_path) = &bootstrap_output {
                if !force {
                    check_output_path_free("bootstrap", Path::new(bootstrap_path))?;
                }
            }

            write_archive_outputs(&output, &archive.volumes)?;
            if let Some(path) = bootstrap_out {
                if archive.bootstrap_sidecar.is_empty() {
                    return Err(FormatError::WriterUnsupported(
                        "bootstrap output is unavailable for this archive shape",
                    )
                    .into());
                }
                fs::write(&path, &archive.bootstrap_sidecar)
                    .with_context(|| format!("failed to write bootstrap sidecar {path}"))?;
            }
            let summary = format!(
                "created {} file(s), {} bytes in, {} archive bytes, {} volume(s), volume-loss tolerance {}, bit-rot buffer {}%",
                regular_files.len(),
                input_specs.iter().map(|entry| entry.size).sum::<u64>(),
                archive.volumes.iter().map(|volume| volume.len() as u64).sum::<u64>(),
                archive.volumes.len(),
                volume_loss_tolerance,
                bit_rot_buffer_pct
            );
            emit_success_summary(quiet, &summary)?;
            if let Some(path) = bootstrap_output {
                emit_success_summary(quiet, &format!("  bootstrap output: {}", path))?;
            }
            Ok(())
        }
        Command::Extract {
            archive,
            paths,
            directory,
            stdout,
            dry_run,
            overwrite,
            password_stdin,
            password,
            keyfile,
            bootstrap,
            volumes,
        } => {
            let volume_bytes = read_volume_inputs(&archive, &volumes)?;
            let master_key = load_open_key(
                keyfile.as_deref(),
                password_stdin,
                password,
                &volume_bytes[0],
            )?;
            let opened =
                open_inputs_maybe_bootstrap(&volume_bytes, &master_key, bootstrap.as_deref())
                    .with_context(|| format!("failed to open archive {archive}"))?;
            let all_entries = opened.list_files()?;
            let (requested_paths, missing_paths) =
                resolve_extract_paths(&all_entries, &paths, opened.crypto_header.max_path_length)?;
            if !missing_paths.is_empty() {
                for missing in missing_paths {
                    eprintln!("missing archive path: {missing}");
                }
                return Err(anyhow!("missing requested archive paths"));
            }
            if stdout {
                if paths.is_empty() || requested_paths.len() != 1 {
                    bail!("--stdout requires exactly one archive path");
                }
                let path = requested_paths[0].as_str();
                let member = opened
                    .extract_member(path)?
                    .ok_or_else(|| anyhow!("path not found in archive: {path}"))?;
                if member.kind != TarEntryKind::Regular {
                    bail!("--stdout supports regular file members only");
                }
                emit_member_metadata_diagnostics(path, &member.diagnostics)?;
                io::stdout().write_all(&member.data)?;
                return Ok(());
            }

            if dry_run {
                emit_entry_metadata_diagnostics_for_paths(&all_entries, &requested_paths)?;
                eprintln!("extract dry-run summary:");
                eprintln!("  destination: {}", directory);
                eprintln!("  archive members:");
                for path in &requested_paths {
                    if let Some(size) = all_entries
                        .iter()
                        .find(|entry| entry.path == *path)
                        .map(|entry| entry.file_data_size)
                    {
                        eprintln!("    {path} ({size} bytes)");
                    } else {
                        eprintln!("    {path}");
                    }
                }
                return Ok(());
            }

            let root = PathBuf::from(directory);
            fs::create_dir_all(&root).with_context(|| {
                format!("failed to create extraction directory {}", root.display())
            })?;
            let mut extracted_count = 0u64;
            let mut degraded_metadata_count = 0u64;
            let options = SafeExtractionOptions {
                overwrite_existing: overwrite,
            };
            for path in requested_paths {
                let diagnostics = opened
                    .extract_file_to(&path, &root, options)?
                    .ok_or_else(|| anyhow!("path not found in archive: {path}"))?;
                extracted_count = extracted_count
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("extracted path count overflow"))?;
                degraded_metadata_count = degraded_metadata_count
                    .checked_add(diagnostics.len() as u64)
                    .ok_or_else(|| anyhow!("degraded metadata count overflow"))?;
                emit_member_metadata_diagnostics(&path, &diagnostics)?;
            }
            emit_success_summary(
                quiet,
                &format!(
                    "extracted {extracted_count} file(s), {degraded_metadata_count} degraded metadata items to {}",
                    root.display()
                ),
            )?;
            Ok(())
        }
        Command::List {
            archive,
            password_stdin,
            password,
            keyfile,
            bootstrap,
            volumes,
            long,
            json,
        } => {
            let volume_bytes = read_volume_inputs(&archive, &volumes)?;
            let master_key = load_open_key(
                keyfile.as_deref(),
                password_stdin,
                password,
                &volume_bytes[0],
            )?;
            let opened =
                open_inputs_maybe_bootstrap(&volume_bytes, &master_key, bootstrap.as_deref())
                    .with_context(|| format!("failed to open archive {archive}"))?;
            let entries = opened.list_files()?;
            emit_entry_metadata_diagnostics(&entries)?;
            if json {
                let files = entries
                    .iter()
                    .map(|entry| {
                        let kind = match entry.kind {
                            TarEntryKind::Regular => "file",
                            TarEntryKind::Directory => "directory",
                            TarEntryKind::Symlink => "symlink",
                            TarEntryKind::Hardlink => "hardlink",
                        };
                        json!({
                            "path": &entry.path,
                            "kind": kind,
                            "size": entry.file_data_size,
                            "mode": entry.mode,
                            "mtime": entry.mtime,
                        })
                    })
                    .collect::<Vec<_>>();
                println!(
                    "{}",
                    serde_json::to_string(&json!({ "files": files }))
                        .context("failed to encode list output as JSON")?
                );
                Ok(())
            } else {
                for entry in entries {
                    if long {
                        let kind = match entry.kind {
                            TarEntryKind::Regular => "file",
                            TarEntryKind::Directory => "directory",
                            TarEntryKind::Symlink => "symlink",
                            TarEntryKind::Hardlink => "hardlink",
                        };
                        println!(
                            "{}\t{}\t{}\t{}\t{}",
                            entry.file_data_size, kind, entry.mode, entry.mtime, entry.path
                        );
                    } else {
                        println!("{}", entry.path);
                    }
                }
                Ok(())
            }
        }
        Command::Verify {
            archives,
            password_stdin,
            password,
            keyfile,
            bootstrap,
            json,
        } => {
            let first = archives
                .first()
                .ok_or_else(|| anyhow!("at least one archive volume is required"))?;
            let archive_paths = archives.to_vec();
            let volume_bytes = match read_volume_inputs(first, &archives[1..]) {
                Ok(volume_bytes) => volume_bytes,
                Err(err) => {
                    if json {
                        emit_verify_json_error(&archive_paths, None, None, &err)?;
                    }
                    return Err(err);
                }
            };
            let master_key = match load_open_key(
                keyfile.as_deref(),
                password_stdin,
                password,
                &volume_bytes[0],
            ) {
                Ok(master_key) => master_key,
                Err(err) => {
                    if json {
                        emit_verify_json_error(&archive_paths, None, None, &err)?;
                    }
                    return Err(err);
                }
            };
            let opened =
                match open_inputs_maybe_bootstrap(&volume_bytes, &master_key, bootstrap.as_deref())
                    .with_context(|| format!("failed to open archive {first}"))
                {
                    Ok(opened) => opened,
                    Err(err) => {
                        if json {
                            emit_verify_json_error(&archive_paths, None, None, &err)?;
                        }
                        return Err(err);
                    }
                };
            let result = opened
                .verify()
                .with_context(|| format!("failed to verify archive {first}"));
            let volume_count = opened.manifest_footer.total_volumes;
            let file_count = opened.index_root.header.file_count;
            match result {
                Ok(()) => {
                    let entries = opened.list_files()?;
                    emit_entry_metadata_diagnostics(&entries)?;
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string(&json!({
                                "ok": true,
                                "archives": archive_paths,
                                "volume_count": volume_count,
                                "file_count": file_count,
                            }))
                            .context("failed to encode verify output as JSON")?
                        );
                        return Ok(());
                    }
                    emit_success_stdout(
                        quiet,
                        &format!(
                            "{}: OK ({} volume(s), {} file(s))",
                            first, volume_count, file_count
                        ),
                    )?;
                    Ok(())
                }
                Err(err) => {
                    if json {
                        emit_verify_json_error(
                            &archive_paths,
                            Some(volume_count as u64),
                            Some(file_count),
                            &err,
                        )?;
                    }
                    Err(err)
                }
            }
        }
        Command::Keygen {
            output,
            stdout,
            force,
        } => {
            let bytes = generate_random_key_material()?;
            let key_hex = format!("{}\n", encode_hex(&bytes));
            if stdout {
                print!("{}", key_hex);
                io::stdout().flush()?;
                return Ok(());
            }
            let output = output.expect("--output required by clap");
            write_keyfile(&output, &key_hex, force).context("failed to write keyfile")?;
            emit_success_summary(quiet, &format!("wrote keyfile to {}", output))?;
            Ok(())
        }
    }
}

fn emit_success_summary(quiet: bool, message: &str) -> io::Result<()> {
    if quiet {
        return Ok(());
    }
    eprintln!("{message}");
    Ok(())
}

fn emit_success_stdout(quiet: bool, message: &str) -> io::Result<()> {
    if quiet {
        return Ok(());
    }
    println!("{message}");
    Ok(())
}

fn metadata_diagnostic_line(path: &str, diagnostic: &MetadataDiagnostic) -> String {
    format!(
        "tzap: degraded-metadata: {}: {}: {}",
        path, diagnostic.profile, diagnostic.message
    )
}

fn emit_member_metadata_diagnostics(
    path: &str,
    diagnostics: &[MetadataDiagnostic],
) -> io::Result<()> {
    for diagnostic in diagnostics {
        eprintln!("{}", metadata_diagnostic_line(path, diagnostic));
    }
    Ok(())
}

fn metadata_diagnostic_lines_for_entries(entries: &[ArchiveEntry]) -> Vec<String> {
    entries
        .iter()
        .flat_map(|entry| {
            entry
                .diagnostics
                .iter()
                .map(|diagnostic| metadata_diagnostic_line(&entry.path, diagnostic))
        })
        .collect()
}

fn metadata_diagnostic_lines_for_paths(entries: &[ArchiveEntry], paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .filter_map(|path| entries.iter().find(|entry| entry.path == *path))
        .flat_map(|entry| {
            entry
                .diagnostics
                .iter()
                .map(|diagnostic| metadata_diagnostic_line(&entry.path, diagnostic))
        })
        .collect()
}

fn emit_entry_metadata_diagnostics(entries: &[ArchiveEntry]) -> io::Result<()> {
    for line in metadata_diagnostic_lines_for_entries(entries) {
        eprintln!("{line}");
    }
    Ok(())
}

fn emit_entry_metadata_diagnostics_for_paths(
    entries: &[ArchiveEntry],
    paths: &[String],
) -> io::Result<()> {
    for line in metadata_diagnostic_lines_for_paths(entries, paths) {
        eprintln!("{line}");
    }
    Ok(())
}

fn emit_verify_json_error(
    archives: &[String],
    volume_count: Option<u64>,
    file_count: Option<u64>,
    err: &anyhow::Error,
) -> Result<()> {
    let diagnostic = classify_error(err);
    let mut payload = json!({
        "ok": false,
        "archives": archives,
        "error": {
            "label": diagnostic.label,
            "action": diagnostic.action,
            "message": err.to_string(),
        },
    });
    if let Some(volume_count) = volume_count {
        payload["volume_count"] = json!(volume_count);
    }
    if let Some(file_count) = file_count {
        payload["file_count"] = json!(file_count);
    }
    println!(
        "{}",
        serde_json::to_string(&payload).context("failed to encode verify error output as JSON")?
    );
    Ok(())
}

#[derive(Debug)]
struct InputFile {
    archive_path: String,
    contents: Vec<u8>,
    mode: u32,
    mtime: u64,
}

#[derive(Debug)]
struct InputSpec {
    source: PathBuf,
    archive_path: String,
    mode: u32,
    mtime: u64,
    size: u64,
}

#[derive(Debug)]
struct CreateKey {
    master_key: MasterKey,
    kdf_params: KdfParams,
}

#[derive(Debug, Clone, Copy)]
struct Diagnostic {
    label: &'static str,
    exit_code: u8,
    action: &'static str,
}

fn collect_input_specs(paths: &[String]) -> Result<Vec<InputSpec>> {
    let mut out = Vec::new();
    for path in paths {
        let input = PathBuf::from(path);
        let base = input
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| anyhow!("input path has no valid UTF-8 file name: {path}"))?
            .to_owned();
        collect_one_input_spec(&input, Path::new(&base), &mut out)
            .with_context(|| format!("failed to collect input {path}"))?;
    }
    out.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    Ok(out)
}

fn collect_input_files(specs: &[InputSpec]) -> Result<Vec<InputFile>> {
    let mut out = Vec::new();
    for spec in specs {
        let contents = fs::read(&spec.source)
            .with_context(|| format!("failed to read input {}", spec.source.display()))?;
        out.push(InputFile {
            archive_path: spec.archive_path.clone(),
            contents,
            mode: spec.mode,
            mtime: spec.mtime,
        });
    }
    Ok(out)
}

fn collect_inputs_from_specs(specs: &[InputSpec]) -> Result<Vec<InputFile>> {
    collect_input_files(specs)
}

fn collect_one_input_spec(
    input: &Path,
    archive_path: &Path,
    out: &mut Vec<InputSpec>,
) -> Result<()> {
    let metadata = fs::symlink_metadata(input)
        .with_context(|| format!("failed to inspect input {}", input.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("refusing to archive symlink input {}", input.display());
    }
    if metadata.is_dir() {
        let mut entries = fs::read_dir(input)
            .with_context(|| format!("failed to read directory {}", input.display()))?
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let child_name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow!("input path is not valid UTF-8"))?;
            collect_one_input_spec(&entry.path(), &archive_path.join(child_name), out)?;
        }
        return Ok(());
    }
    if !metadata.is_file() {
        bail!("unsupported input type {}", input.display());
    }
    let archive_path = archive_path_to_string(archive_path)?;
    out.push(InputSpec {
        source: input.to_owned(),
        archive_path,
        mode: readonly_mode(&metadata),
        mtime: 0,
        size: metadata.len(),
    });
    Ok(())
}

fn resolve_extract_paths(
    all_entries: &[ArchiveEntry],
    requested: &[String],
    max_path_length: u32,
) -> Result<(Vec<String>, Vec<String>)> {
    if requested.is_empty() {
        return Ok((
            all_entries.iter().map(|entry| entry.path.clone()).collect(),
            Vec::new(),
        ));
    }

    let available = all_entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut resolved = Vec::with_capacity(requested.len());
    let mut missing = Vec::new();
    for path in requested {
        let normalized = normalize_lookup_file_path(path, max_path_length)?;
        let normalized =
            String::from_utf8(normalized).map_err(|_| anyhow!(FormatError::UnsafeArchivePath))?;
        if available.contains(normalized.as_str()) {
            resolved.push(normalized);
        } else {
            missing.push(path.clone());
        }
    }
    Ok((resolved, missing))
}

fn archive_path_to_string(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        let std::path::Component::Normal(part) = component else {
            bail!("unsafe archive path component in {}", path.display());
        };
        parts.push(
            part.to_str()
                .ok_or_else(|| anyhow!("archive path is not valid UTF-8"))?
                .to_owned(),
        );
    }
    if parts.is_empty() {
        bail!("empty archive path");
    }
    Ok(parts.join("/"))
}

#[cfg(unix)]
fn readonly_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn readonly_mode(_metadata: &fs::Metadata) -> u32 {
    0o644
}

fn write_archive_outputs(output: &str, volumes: &[Vec<u8>]) -> Result<()> {
    if volumes.is_empty() {
        bail!("writer returned no volumes");
    }
    if volumes.len() == 1 {
        fs::write(output, &volumes[0])
            .with_context(|| format!("failed to write archive {output}"))?;
        return Ok(());
    }
    for (index, volume) in volumes.iter().enumerate() {
        let path = format!("{output}.{index:03}");
        fs::write(&path, volume)
            .with_context(|| format!("failed to write archive volume {path}"))?;
    }
    Ok(())
}

fn reject_create_stdout_sentinels(output: &str, bootstrap_out: Option<&str>) -> Result<()> {
    if output == "-" {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--output - is not archive stdout; create output must be a file path",
        )));
    }
    if matches!(bootstrap_out, Some("-")) {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--bootstrap-out - is not sidecar stdout; sidecar output must be a file path",
        )));
    }
    Ok(())
}

fn ensure_create_output_paths_can_be_written(
    output: &str,
    volumes: Option<u32>,
    has_volume_size: bool,
    bootstrap_out: Option<&str>,
    force: bool,
) -> Result<()> {
    if let Some(volumes) = volumes {
        if volumes == 0 {
            bail!("--volumes must be at least 1");
        }
        if !force && volumes == 1 {
            check_output_path_free("archive output", Path::new(output))?;
        }
        if !force && volumes > 1 {
            let paths = create_output_paths(output, volumes as usize);
            check_archive_paths_free_for_write(&paths)?;
        }
        if let Some(path) = bootstrap_out {
            if !force {
                check_output_path_free("bootstrap output", Path::new(path))?;
            }
        }
        return Ok(());
    }
    if has_volume_size {
        if !force {
            check_output_path_collisions_for_volume_size_output(output)?;
            if let Some(path) = bootstrap_out {
                check_output_path_free("bootstrap output", Path::new(path))?;
            }
        }
        return Ok(());
    }
    if !force {
        check_output_path_free("archive output", Path::new(output))?;
        if let Some(path) = bootstrap_out {
            check_output_path_free("bootstrap output", Path::new(path))?;
        }
    }
    Ok(())
}

fn check_output_path_collisions_for_volume_size_output(output: &str) -> Result<()> {
    check_output_path_free("archive output", Path::new(output))?;
    let output_path = Path::new(output);
    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
    let base = output_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("output path has invalid UTF-8: {output}"))?;
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err).with_context(|| {
                format!("failed to inspect output directory {}", parent.display())
            })
        }
    };
    for entry in entries.filter_map(|entry| entry.ok()) {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if looks_like_numbered_volume(&name, base) {
            bail!("output path collision: {output}.* already exists; use --force to overwrite");
        }
    }
    Ok(())
}

fn looks_like_numbered_volume(path_name: &str, base: &str) -> bool {
    let Some(suffix) = path_name.strip_prefix(base) else {
        return false;
    };
    if !suffix.starts_with('.') {
        return false;
    }
    let suffix = &suffix[1..];
    if suffix.len() != 3 {
        return false;
    }
    suffix.bytes().all(|byte| matches!(byte, b'0'..=b'9'))
}

fn check_archive_paths_free_for_write(paths: &[PathBuf]) -> Result<()> {
    for path in paths {
        check_output_path_free("archive output", path)?;
    }
    Ok(())
}

fn validate_create_writer_options(options: &WriterOptions) -> Result<()> {
    if options.block_size < 4096 || options.block_size % 2 != 0 {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "M6 writer requires an even block size of at least 4096",
        )));
    }
    if options.stripe_width == 0 {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "stripe_width must be non-zero",
        )));
    }
    let effective_stripe_width = if options.target_volume_size.is_some() {
        options
            .stripe_width
            .max(options.volume_loss_tolerance as u32 + 1)
    } else {
        options.stripe_width
    };
    if options.volume_loss_tolerance as u32 >= effective_stripe_width {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "volume_loss_tolerance must be less than stripe_width",
        )));
    }
    if effective_stripe_width == 1 && options.volume_loss_tolerance != 0 {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "single-volume archives cannot tolerate volume loss",
        )));
    }
    if matches!(options.target_volume_size, Some(0)) {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "target_volume_size must be non-zero",
        )));
    }
    if options.bit_rot_buffer_pct > 100 {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "bit_rot_buffer_pct must be at most 100",
        )));
    }
    if options.chunk_size == 0 || options.chunk_size > options.envelope_target_size {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "chunk_size must be non-zero and no larger than envelope_target_size",
        )));
    }
    Ok(())
}

fn check_output_path_free(label: &str, path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    if path.exists() {
        bail!(
            "{label} already exists: {}; use --force to overwrite",
            path.display()
        );
    }
    Ok(())
}

fn create_output_paths(output: &str, volume_count: usize) -> Vec<PathBuf> {
    if volume_count == 1 {
        vec![PathBuf::from(output)]
    } else {
        (0..volume_count)
            .map(|index| PathBuf::from(format!("{output}.{index:03}")))
            .collect()
    }
}

fn create_dry_run_output_paths(
    output: &str,
    volumes: Option<u32>,
    has_volume_size: bool,
) -> Vec<String> {
    if let Some(volumes) = volumes {
        return create_output_paths(output, volumes as usize)
            .into_iter()
            .map(|path| path.display().to_string())
            .collect();
    }
    if has_volume_size {
        return vec![
            format!("{output} (if one volume is emitted)"),
            format!("{output}.000, {output}.001, ... (if split)"),
        ];
    }
    vec![output.to_owned()]
}

fn describe_planned_volume_mode(volumes: Option<u32>, volume_size: Option<&str>) -> String {
    if let Some(volumes) = volumes {
        return format!("{volumes} explicit volume(s) requested");
    }
    if let Some(size) = volume_size {
        return format!("volume-size mode, target size {size}");
    }
    format!("single volume")
}

fn create_key_mode_label(keyfile: Option<&str>, password_stdin: bool, password: bool) -> String {
    if password_stdin {
        return "password-stdin".to_string();
    }
    if password {
        return "password".to_string();
    }
    if keyfile.is_some() {
        return "keyfile".to_string();
    }
    "unknown".to_string()
}

fn read_volume_inputs(primary: &str, additional: &[String]) -> Result<Vec<Vec<u8>>> {
    let mut paths = Vec::with_capacity(additional.len() + 1);
    paths.push(primary.to_owned());
    paths.extend(additional.iter().cloned());
    paths
        .into_iter()
        .map(|path| fs::read(&path).with_context(|| format!("failed to read archive {path}")))
        .collect()
}

fn open_inputs_maybe_bootstrap(
    volume_bytes: &[Vec<u8>],
    master_key: &MasterKey,
    bootstrap: Option<&str>,
) -> Result<OpenedArchive> {
    if volume_bytes.len() > 1 {
        if bootstrap.is_some() {
            return Err(anyhow!(FormatError::ReaderUnsupported(
                "bootstrap is not supported with multi-volume extraction",
            ))
            .into());
        }
        let borrowed = volume_bytes.iter().map(Vec::as_slice).collect::<Vec<_>>();
        return open_archive_volumes(&borrowed, master_key).map_err(Into::into);
    }
    if let Some(path) = bootstrap {
        let sidecar =
            fs::read(path).with_context(|| format!("failed to read bootstrap sidecar {path}"))?;
        open_archive_with_bootstrap_sidecar(&volume_bytes[0], &sidecar, master_key)
            .map_err(Into::into)
    } else {
        open_archive(&volume_bytes[0], master_key).map_err(Into::into)
    }
}

fn generate_random_key_material() -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    Ok(bytes)
}

fn write_keyfile(path: &str, key_hex: &str, force: bool) -> Result<()> {
    if !force && Path::new(path).exists() {
        bail!("keyfile already exists: {path}; use --force to overwrite");
    }
    if force {
        fs::write(path, key_hex).with_context(|| format!("failed to write keyfile {path}"))?;
        return Ok(());
    }
    fs::write(path, key_hex)
        .map(|_| ())
        .with_context(|| format!("failed to write keyfile {path}"))
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = std::fmt::Write::write_fmt(&mut output, format_args!("{:02x}", byte));
    }
    output
}

fn load_create_key(
    keyfile: Option<&str>,
    password_stdin: bool,
    password: bool,
    t_cost: u32,
    m_cost_kib: u32,
    parallelism: u32,
) -> Result<CreateKey> {
    if password_stdin {
        let passphrase = read_passphrase_stdin()?;
        validate_argon2_params(t_cost, m_cost_kib, parallelism)?;
        let mut salt = vec![0u8; DEFAULT_ARGON2_SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let kdf_params = KdfParams::Argon2id {
            t_cost,
            m_cost_kib,
            parallelism,
            salt,
        };
        let master_key = MasterKey::derive_from_passphrase(&kdf_params, &passphrase)?;
        return Ok(CreateKey {
            master_key,
            kdf_params,
        });
    }
    if password {
        let passphrase = read_passphrase_interactive_create()?;
        validate_argon2_params(t_cost, m_cost_kib, parallelism)?;
        let mut salt = vec![0u8; DEFAULT_ARGON2_SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let kdf_params = KdfParams::Argon2id {
            t_cost,
            m_cost_kib,
            parallelism,
            salt,
        };
        let master_key = MasterKey::derive_from_passphrase(&kdf_params, &passphrase)?;
        return Ok(CreateKey {
            master_key,
            kdf_params,
        });
    }
    Ok(CreateKey {
        master_key: load_raw_master_key(keyfile)?,
        kdf_params: KdfParams::Raw,
    })
}

fn load_open_key(
    keyfile: Option<&str>,
    password_stdin: bool,
    password: bool,
    first_volume: &[u8],
) -> Result<MasterKey> {
    if password_stdin {
        let passphrase = read_passphrase_stdin()?;
        let kdf_params = read_kdf_params_from_volume(first_volume)?;
        return derive_key_from_passphrase(&kdf_params, &passphrase);
    }
    if password {
        let passphrase = read_passphrase_interactive_open()?;
        let kdf_params = read_kdf_params_from_volume(first_volume)?;
        return derive_key_from_passphrase(&kdf_params, &passphrase);
    }
    load_raw_master_key(keyfile)
}

fn derive_key_from_passphrase(kdf_params: &KdfParams, passphrase: &str) -> Result<MasterKey> {
    match kdf_params {
        KdfParams::Argon2id { .. } => {
            MasterKey::derive_from_passphrase(kdf_params, passphrase).map_err(Into::into)
        }
        KdfParams::Raw => Err(anyhow!(FormatError::KeyMaterialMismatch)
            .context("raw-key archives require --keyfile, not passphrase input")),
    }
}

fn validate_argon2_params(t_cost: u32, m_cost_kib: u32, parallelism: u32) -> Result<()> {
    if t_cost == 0 {
        return Err(anyhow!(FormatError::InvalidKdfParams(
            "argon2 t_cost must be at least 1",
        )));
    }
    if t_cost > READER_MAX_ARGON2ID_T_COST {
        return Err(anyhow!(FormatError::InvalidKdfParams(
            "argon2 t_cost exceeds reader maximum",
        )));
    }
    if parallelism == 0 {
        return Err(anyhow!(FormatError::InvalidKdfParams(
            "argon2 parallelism must be at least 1",
        )));
    }
    if parallelism > READER_MAX_ARGON2ID_PARALLELISM {
        return Err(anyhow!(FormatError::InvalidKdfParams(
            "argon2 parallelism exceeds reader maximum",
        )));
    }
    if m_cost_kib > READER_MAX_ARGON2ID_M_COST_KIB {
        return Err(anyhow!(FormatError::InvalidKdfParams(
            "argon2 memory cost exceeds reader maximum",
        )));
    }
    let min_memory = parallelism.checked_mul(8).ok_or_else(|| {
        anyhow!(FormatError::InvalidKdfParams(
            "argon2 memory per lane computation overflows",
        ))
    })?;
    if m_cost_kib < min_memory {
        return Err(anyhow!(FormatError::InvalidKdfParams(
            "argon2 memory must be at least 8 KiB per lane",
        )));
    }
    Ok(())
}

fn load_raw_master_key(keyfile: Option<&str>) -> Result<MasterKey> {
    let keyfile = keyfile.ok_or_else(|| {
        anyhow!("no key source provided; use --password-stdin, --password, or --keyfile PATH")
    })?;
    let bytes = fs::read(keyfile).with_context(|| format!("failed to read keyfile {keyfile}"))?;
    if bytes.len() == 32 {
        return MasterKey::from_raw_key(&bytes).map_err(Into::into);
    }

    let hex = std::str::from_utf8(&bytes)
        .context("keyfile must contain either 32 raw bytes or 64 hex characters")?
        .trim();
    if hex.len() != 64 {
        bail!("keyfile must contain either 32 raw bytes or 64 hex characters");
    }
    let mut raw = [0u8; 32];
    for (idx, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        raw[idx] = decode_hex_byte(chunk)?;
    }
    MasterKey::from_raw_key(&raw).map_err(Into::into)
}

fn read_passphrase_stdin() -> Result<String> {
    let mut passphrase = String::new();
    io::stdin()
        .read_to_string(&mut passphrase)
        .context("failed to read passphrase from stdin")?;
    if passphrase.ends_with('\n') {
        passphrase.pop();
        if passphrase.ends_with('\r') {
            passphrase.pop();
        }
    }
    if passphrase.is_empty() {
        bail!("passphrase must not be empty");
    }
    Ok(passphrase)
}

fn read_passphrase_interactive_create() -> Result<String> {
    loop {
        let first = read_passphrase_interactive("Passphrase: ")?;
        let second = read_passphrase_interactive("Confirm passphrase: ")?;
        if first == second {
            return Ok(first);
        }
        eprintln!("Passphrases do not match; try again.");
    }
}

fn read_passphrase_interactive_open() -> Result<String> {
    read_passphrase_interactive("Passphrase: ")
}

fn read_passphrase_interactive(prompt: &str) -> Result<String> {
    if !io::stdin().is_terminal() {
        eprint!("{prompt}");
        io::stderr().flush()?;
        return read_non_empty_passphrase(read_passphrase_stdin_fallback()?);
    }

    let passphrase = match read_passphrase_hidden(prompt) {
        Ok(passphrase) => passphrase,
        Err(err) => {
            let _ = err;
            eprint!("{prompt}");
            io::stderr().flush()?;
            read_passphrase_stdin_fallback()?
        }
    };
    read_non_empty_passphrase(passphrase)
}

fn read_non_empty_passphrase(passphrase: String) -> Result<String> {
    if passphrase.is_empty() {
        bail!("passphrase must not be empty");
    }
    Ok(passphrase)
}

fn read_passphrase_hidden(prompt: &str) -> Result<String> {
    Ok(rpassword::prompt_password(prompt)?)
}

fn read_passphrase_stdin_fallback() -> Result<String> {
    let mut passphrase = String::new();
    io::stdin()
        .read_line(&mut passphrase)
        .context("failed to read passphrase from stdin")?;
    if passphrase.ends_with('\n') {
        passphrase.pop();
        if passphrase.ends_with('\r') {
            passphrase.pop();
        }
    }
    Ok(passphrase)
}

fn read_kdf_params_from_volume(bytes: &[u8]) -> Result<KdfParams> {
    let header_bytes = bytes.get(..VOLUME_HEADER_LEN).ok_or_else(|| {
        anyhow!(FormatError::InvalidArchive(
            "volume is too short for VolumeHeader"
        ))
    })?;
    let volume_header = VolumeHeader::parse(header_bytes)?;
    let offset = volume_header.crypto_header_offset as usize;
    let length = volume_header.crypto_header_length as usize;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| anyhow!(FormatError::InvalidArchive("CryptoHeader range overflow")))?;
    let crypto_header_bytes = bytes.get(offset..end).ok_or_else(|| {
        anyhow!(FormatError::InvalidArchive(
            "volume is too short for CryptoHeader"
        ))
    })?;
    let fixed_bytes = crypto_header_bytes
        .get(..CRYPTO_HEADER_FIXED_LEN)
        .ok_or_else(|| {
            anyhow!(FormatError::InvalidLength {
                structure: "CryptoHeaderFixed",
                expected: CRYPTO_HEADER_FIXED_LEN,
                actual: crypto_header_bytes.len(),
            })
        })?;
    let fixed = CryptoHeaderFixed::parse(fixed_bytes, volume_header.crypto_header_length)?;
    if fixed.stripe_width != volume_header.stripe_width {
        return Err(anyhow!(FormatError::InvalidArchive(
            "VolumeHeader and CryptoHeader stripe_width differ"
        )));
    }
    let crypto_header =
        CryptoHeader::parse(crypto_header_bytes, volume_header.crypto_header_length)?;
    Ok(crypto_header.kdf_params)
}

fn parse_size_u32(value: &str, name: &'static str) -> Result<u32> {
    let size = parse_size(value).with_context(|| format!("invalid {name}: {value}"))?;
    u32::try_from(size).with_context(|| format!("{name} exceeds u32"))
}

fn parse_size(value: &str) -> Result<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("size is empty");
    }
    let split_at = trimmed
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let (digits, suffix) = trimmed.split_at(split_at);
    if digits.is_empty() {
        bail!("invalid size '{value}': missing size digits");
    }
    let number = digits
        .parse::<u64>()
        .with_context(|| format!("invalid size '{trimmed}': bad digit sequence"))?;
    let multiplier = match suffix.to_ascii_lowercase().as_str() {
        "" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        _ => bail!(
            "invalid size '{trimmed}': unsupported suffix '{suffix}'; supported: K/KB/KiB, M/MB/MiB, G/GB/GiB"
        ),
    };
    number
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow!("size overflow"))
}

fn decode_hex_byte(bytes: &[u8]) -> Result<u8> {
    Ok((decode_hex_nibble(bytes[0])? << 4) | decode_hex_nibble(bytes[1])?)
}

fn decode_hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("keyfile contains non-hex characters"),
    }
}

fn classify_error(err: &anyhow::Error) -> Diagnostic {
    for cause in err.chain() {
        if let Some(format) = cause.downcast_ref::<FormatError>() {
            return classify_format_error(format);
        }
        if let Some(io_error) = cause.downcast_ref::<io::Error>() {
            return match io_error.kind() {
                io::ErrorKind::PermissionDenied
                | io::ErrorKind::NotFound
                | io::ErrorKind::AlreadyExists => Diagnostic {
                    label: "io-error",
                    exit_code: EXIT_IO,
                    action: "check file paths and permissions",
                },
                _ => Diagnostic {
                    label: "io-error",
                    exit_code: EXIT_IO,
                    action: "check filesystem state",
                },
            };
        }
    }
    Diagnostic {
        label: "error",
        exit_code: EXIT_GENERIC,
        action: "",
    }
}

fn classify_format_error(err: &FormatError) -> Diagnostic {
    match err {
        FormatError::UnsupportedFormatVersion(_)
        | FormatError::UnsupportedVolumeFormatRevision(_)
        | FormatError::UnknownCompressionAlgo(_)
        | FormatError::UnknownAeadAlgo(_)
        | FormatError::UnknownFecAlgo(_)
        | FormatError::UnknownKdfAlgo(_)
        | FormatError::UnsupportedCompressionForV36(_)
        | FormatError::UnsupportedFecForV36(_)
        | FormatError::UnsupportedBootstrapSidecarVersion(_) => Diagnostic {
            label: "unsupported-revision",
            exit_code: EXIT_UNSUPPORTED_REVISION,
            action: "use the matching tzap version for this archive",
        },
        FormatError::BadMagic { structure: "VolumeHeader" }
        | FormatError::BadMagic { structure: "VolumeTrailer" }
        | FormatError::BadMagic { structure: "ManifestFooter" } => Diagnostic {
            label: "corrupt-header",
            exit_code: EXIT_CORRUPT_ARCHIVE,
            action: "verify the archive header/trailer bytes and source file path",
        },
        FormatError::HmacMismatch {
            structure: "CryptoHeader",
        }
        | FormatError::KeyMaterialMismatch
        | FormatError::InvalidRawMasterKeyLength => Diagnostic {
            label: "wrong-key",
            exit_code: EXIT_WRONG_KEY,
            action: "confirm the archive key source (passphrase/raw key)",
        },
        FormatError::FecTooFewAvailableShards => Diagnostic {
            label: "missing-volume",
            exit_code: EXIT_CORRUPT_ARCHIVE,
            action: "add the missing archive volume(s) or confirm volume-loss tolerance",
        },
        FormatError::InvalidArchive(message)
            if *message == "complete volume set has missing global blocks" =>
        {
            Diagnostic {
                label: "missing-volume",
                exit_code: EXIT_CORRUPT_ARCHIVE,
                action: "add the missing archive volume(s) or confirm volume-loss tolerance",
            }
        }
        FormatError::HmacMismatch { .. } | FormatError::AeadFailure => Diagnostic {
            label: "corrupt-payload",
            exit_code: EXIT_CORRUPT_ARCHIVE,
            action: "verify archive payload integrity",
        },
        FormatError::BadCrc { structure: "VolumeHeader" }
        | FormatError::BadCrc { structure: "VolumeTrailer" }
        | FormatError::BadCrc { structure: "ManifestFooter" }
        | FormatError::InvalidMetadata { structure: "ManifestFooter", .. }
        | FormatError::InvalidMetadata { structure: "VolumeHeader", .. } => Diagnostic {
            label: "corrupt-header",
            exit_code: EXIT_CORRUPT_ARCHIVE,
            action: "inspect archive metadata and source file path",
        },
        FormatError::BadCrc { structure: _ } => Diagnostic {
            label: "corrupt-payload",
            exit_code: EXIT_CORRUPT_ARCHIVE,
            action: "verify payload integrity",
        },
        FormatError::InvalidKdfParams(message) => Diagnostic {
            label: "invalid-arguments",
            exit_code: EXIT_USAGE,
            action: message,
        },
        FormatError::InvalidMetadata { structure, .. } => Diagnostic {
            label: if *structure == "IndexRoot" || *structure == "FrameEntry" || *structure == "EnvelopeEntry"
            {
                "corrupt-payload"
            } else {
                "corrupt-header"
            },
            exit_code: EXIT_CORRUPT_ARCHIVE,
            action: if *structure == "IndexRoot" || *structure == "FrameEntry" || *structure == "EnvelopeEntry"
            {
                "inspect archive metadata tables and payload"
            } else {
                "inspect archive header metadata"
            },
        },
        FormatError::ReaderResourceLimitExceeded { field, .. } => Diagnostic {
            label: "invalid-arguments",
            exit_code: EXIT_USAGE,
            action: match field {
                _ => "check argon2 flags (--argon2-t-cost, --argon2-m-cost-kib, --argon2-parallelism)",
            },
        },
        FormatError::UnsafeArchivePath => Diagnostic {
            label: "unsafe-path",
            exit_code: EXIT_UNSAFE_PATH,
            action: "archive contains unsafe paths; extract paths should be reviewed first",
        },
        FormatError::UnsafeOverwrite => Diagnostic {
            label: "unsafe-path",
            exit_code: EXIT_UNSAFE_PATH,
            action: "add --overwrite if overwriting existing files is intended",
        },
        FormatError::ReaderUnsupported(message) | FormatError::WriterUnsupported(message)
            if message.contains("bootstrap sidecar")
                || message.contains("dictionary bootstrap required") =>
        {
            Diagnostic {
                label: "missing-bootstrap",
                exit_code: EXIT_MISSING_BOOTSTRAP,
                action: "use --bootstrap with a matching sidecar",
            }
        }
        FormatError::ReaderUnsupported(_) | FormatError::WriterUnsupported(_) => Diagnostic {
            label: "unsupported-feature",
            exit_code: EXIT_UNSUPPORTED_FEATURE,
            action: "use a supported archive shape or upgrade tzap",
        },
        _ => Diagnostic {
            label: "corrupt-archive",
            exit_code: EXIT_CORRUPT_ARCHIVE,
            action: "verify archive integrity and source",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tzap_core::format::MASTER_KEY_LEN;

    fn test_master_key() -> MasterKey {
        MasterKey::from_raw_key(&[0x42; MASTER_KEY_LEN]).unwrap()
    }

    #[test]
    fn read_kdf_params_rejects_stripe_width_mismatch_before_returning_kdf() {
        let archive = write_archive_with_kdf(
            &[RegularFile::new("file.txt", b"contents")],
            &test_master_key(),
            WriterOptions {
                archive_uuid: Some([0x11; 16]),
                session_id: Some([0x22; 16]),
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            &KdfParams::Argon2id {
                t_cost: 1,
                m_cost_kib: 8,
                parallelism: 1,
                salt: vec![0x33; 8],
            },
        )
        .unwrap();
        let mut bytes = archive.bytes;
        let mut volume_header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
        volume_header.stripe_width += 1;
        bytes[..VOLUME_HEADER_LEN].copy_from_slice(&volume_header.to_bytes());

        let err = read_kdf_params_from_volume(&bytes).unwrap_err();

        assert_eq!(
            err.downcast_ref::<FormatError>(),
            Some(&FormatError::InvalidArchive(
                "VolumeHeader and CryptoHeader stripe_width differ"
            ))
        );
    }

    #[test]
    fn bootstrap_required_errors_keep_missing_bootstrap_diagnostic() {
        for err in [
            FormatError::ReaderUnsupported("dictionary bootstrap required"),
            FormatError::ReaderUnsupported(
                "dictionary bootstrap required for non-seekable sequential extraction",
            ),
            FormatError::ReaderUnsupported(
                "non-seekable random access requires a bootstrap sidecar",
            ),
            FormatError::WriterUnsupported("bootstrap sidecar required"),
        ] {
            let diagnostic = classify_format_error(&err);

            assert_eq!(diagnostic.label, "missing-bootstrap");
            assert_eq!(diagnostic.exit_code, EXIT_MISSING_BOOTSTRAP);
            assert_eq!(diagnostic.action, "use --bootstrap with a matching sidecar");
        }
    }

    #[test]
    fn metadata_diagnostic_lines_use_stable_cli_warning_prefix() {
        let line = metadata_diagnostic_line(
            "path/in/archive",
            &MetadataDiagnostic {
                profile: "gnu-sparse",
                message: "unsupported sparse-file PAX metadata was ignored",
            },
        );

        assert_eq!(
            line,
            "tzap: degraded-metadata: path/in/archive: gnu-sparse: unsupported sparse-file PAX metadata was ignored"
        );
    }

    #[test]
    fn selected_metadata_diagnostic_lines_filter_to_requested_paths() {
        let entries = vec![
            ArchiveEntry {
                path: "selected.txt".to_string(),
                file_data_size: 1,
                kind: TarEntryKind::Regular,
                mode: 0o644,
                mtime: 0,
                diagnostics: vec![MetadataDiagnostic {
                    profile: "pax-posix-2001",
                    message: "unsupported PAX key was ignored",
                }],
            },
            ArchiveEntry {
                path: "other.txt".to_string(),
                file_data_size: 1,
                kind: TarEntryKind::Regular,
                mode: 0o644,
                mtime: 0,
                diagnostics: vec![MetadataDiagnostic {
                    profile: "gnu-sparse",
                    message: "unsupported sparse-file PAX metadata was ignored",
                }],
            },
        ];

        assert_eq!(
            metadata_diagnostic_lines_for_paths(&entries, &["selected.txt".to_string()]),
            vec![
                "tzap: degraded-metadata: selected.txt: pax-posix-2001: unsupported PAX key was ignored"
                    .to_string()
            ]
        );
        assert_eq!(metadata_diagnostic_lines_for_entries(&entries).len(), 2);
    }
}
