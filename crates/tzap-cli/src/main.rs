use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use rand::RngCore;
use tzap_core::format::{FormatError, VOLUME_HEADER_LEN};
use tzap_core::wire::{CryptoHeader, VolumeHeader};
use tzap_core::{
    open_archive, open_archive_volumes, open_archive_with_bootstrap_sidecar, write_archive,
    write_archive_with_dictionary, write_archive_with_dictionary_and_kdf, write_archive_with_kdf,
    KdfParams, MasterKey, OpenedArchive, RegularFile, SafeExtractionOptions, WriterOptions,
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
#[command(about = "tzap archive tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Create {
        #[arg(short = 'o', long = "output")]
        output: String,

        #[arg(long = "volumes", default_value_t = 1)]
        volumes: u32,

        #[arg(long = "volume-loss-tolerance", default_value_t = 0)]
        volume_loss_tolerance: u8,

        #[arg(long = "bit-rot-buffer-pct", default_value_t = 5)]
        bit_rot_buffer_pct: u8,

        #[arg(
            long = "password-stdin",
            conflicts_with = "keyfile",
            help = "Read passphrase from stdin; one trailing LF or CRLF is stripped before NFC normalization"
        )]
        password_stdin: bool,

        #[arg(long = "keyfile")]
        keyfile: Option<String>,

        #[arg(long = "argon2-t-cost", default_value_t = DEFAULT_ARGON2_T_COST)]
        argon2_t_cost: u32,

        #[arg(long = "argon2-m-cost-kib", default_value_t = DEFAULT_ARGON2_M_COST_KIB)]
        argon2_m_cost_kib: u32,

        #[arg(long = "argon2-parallelism", default_value_t = DEFAULT_ARGON2_PARALLELISM)]
        argon2_parallelism: u32,

        #[arg(long = "dictionary")]
        dictionary: Option<String>,

        #[arg(long = "bootstrap-out")]
        bootstrap_out: Option<String>,

        #[arg(long = "compression-level", default_value_t = 3)]
        compression_level: i32,

        #[arg(long = "chunk-size", default_value = "256K")]
        chunk_size: String,

        #[arg(long = "envelope-size", default_value = "1M")]
        envelope_size: String,

        #[arg(long = "block-size", default_value = "64K")]
        block_size: String,

        #[arg(required = true)]
        paths: Vec<String>,
    },
    Extract {
        archive: String,

        #[arg(value_name = "PATH")]
        paths: Vec<String>,

        #[arg(short = 'C', long = "directory", default_value = ".")]
        directory: String,

        #[arg(long = "stdout")]
        stdout: bool,

        #[arg(long = "overwrite")]
        overwrite: bool,

        #[arg(
            long = "password-stdin",
            conflicts_with = "keyfile",
            help = "Read passphrase from stdin; one trailing LF or CRLF is stripped before NFC normalization"
        )]
        password_stdin: bool,

        #[arg(long = "keyfile")]
        keyfile: Option<String>,

        #[arg(long = "bootstrap")]
        bootstrap: Option<String>,

        #[arg(long = "volume")]
        volumes: Vec<String>,
    },
    List {
        archive: String,

        #[arg(
            long = "password-stdin",
            conflicts_with = "keyfile",
            help = "Read passphrase from stdin; one trailing LF or CRLF is stripped before NFC normalization"
        )]
        password_stdin: bool,

        #[arg(long = "keyfile")]
        keyfile: Option<String>,

        #[arg(long = "bootstrap")]
        bootstrap: Option<String>,

        #[arg(long = "volume")]
        volumes: Vec<String>,

        #[arg(long = "long")]
        long: bool,
    },
    Verify {
        #[arg(required = true)]
        archives: Vec<String>,

        #[arg(
            long = "password-stdin",
            conflicts_with = "keyfile",
            help = "Read passphrase from stdin; one trailing LF or CRLF is stripped before NFC normalization"
        )]
        password_stdin: bool,

        #[arg(long = "keyfile")]
        keyfile: Option<String>,

        #[arg(long = "bootstrap")]
        bootstrap: Option<String>,
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

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let diagnostic = classify_error(&err);
            eprintln!("tzap: {}: {err:#}", diagnostic.label);
            ExitCode::from(diagnostic.exit_code)
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Create {
            output,
            volumes,
            volume_loss_tolerance,
            bit_rot_buffer_pct,
            password_stdin,
            keyfile,
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
            options.stripe_width = volumes;
            options.volume_loss_tolerance = volume_loss_tolerance;
            options.bit_rot_buffer_pct = bit_rot_buffer_pct;
            options.zstd_level = compression_level;
            options.chunk_size = parse_size_u32(&chunk_size, "chunk-size")?;
            options.envelope_target_size = parse_size_u32(&envelope_size, "envelope-size")?;
            options.block_size = parse_size_u32(&block_size, "block-size")?;

            let key = load_create_key(
                keyfile.as_deref(),
                password_stdin,
                argon2_t_cost,
                argon2_m_cost_kib,
                argon2_parallelism,
            )?;
            let inputs = collect_inputs(&paths)?;
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

            write_archive_outputs(&output, &archive.volumes)?;
            if let Some(path) = bootstrap_out {
                fs::write(&path, &archive.bootstrap_sidecar)
                    .with_context(|| format!("failed to write bootstrap sidecar {path}"))?;
            }
            eprintln!(
                "created {} file(s), {} volume(s), volume-loss tolerance {}, bit-rot buffer {}%",
                regular_files.len(),
                archive.volumes.len(),
                volume_loss_tolerance,
                bit_rot_buffer_pct
            );
            Ok(())
        }
        Command::Extract {
            archive,
            paths,
            directory,
            stdout,
            overwrite,
            password_stdin,
            keyfile,
            bootstrap,
            volumes,
        } => {
            let volume_bytes = read_volume_inputs(&archive, &volumes)?;
            let master_key = load_open_key(keyfile.as_deref(), password_stdin, &volume_bytes[0])?;
            let opened =
                open_inputs_maybe_bootstrap(&volume_bytes, &master_key, bootstrap.as_deref())
                    .with_context(|| format!("failed to open archive {archive}"))?;
            let paths = if paths.is_empty() {
                opened
                    .list_files()?
                    .into_iter()
                    .map(|entry| entry.path)
                    .collect::<Vec<_>>()
            } else {
                paths
            };
            if stdout {
                if paths.len() != 1 {
                    bail!("--stdout requires exactly one archive path");
                }
                let contents = opened
                    .extract_file(&paths[0])?
                    .ok_or_else(|| anyhow!("path not found in archive: {}", paths[0]))?;
                io::stdout().write_all(&contents)?;
                return Ok(());
            }
            let root = PathBuf::from(directory);
            fs::create_dir_all(&root).with_context(|| {
                format!("failed to create extraction directory {}", root.display())
            })?;
            let options = SafeExtractionOptions {
                overwrite_existing: overwrite,
            };
            for path in paths {
                let diagnostics = opened
                    .extract_file_to(&path, &root, options)?
                    .ok_or_else(|| anyhow!("path not found in archive: {path}"))?;
                for diagnostic in diagnostics {
                    eprintln!(
                        "tzap: degraded-metadata: {}: {}: {}",
                        path, diagnostic.profile, diagnostic.message
                    );
                }
            }
            Ok(())
        }
        Command::List {
            archive,
            password_stdin,
            keyfile,
            bootstrap,
            volumes,
            long,
        } => {
            let volume_bytes = read_volume_inputs(&archive, &volumes)?;
            let master_key = load_open_key(keyfile.as_deref(), password_stdin, &volume_bytes[0])?;
            let opened =
                open_inputs_maybe_bootstrap(&volume_bytes, &master_key, bootstrap.as_deref())
                    .with_context(|| format!("failed to open archive {archive}"))?;
            for entry in opened.list_files()? {
                if long {
                    println!("{}\t{}", entry.file_data_size, entry.path);
                } else {
                    println!("{}", entry.path);
                }
            }
            Ok(())
        }
        Command::Verify {
            archives,
            password_stdin,
            keyfile,
            bootstrap,
        } => {
            let first = archives
                .first()
                .ok_or_else(|| anyhow!("at least one archive volume is required"))?;
            let volume_bytes = read_volume_inputs(first, &archives[1..])?;
            let master_key = load_open_key(keyfile.as_deref(), password_stdin, &volume_bytes[0])?;
            let opened =
                open_inputs_maybe_bootstrap(&volume_bytes, &master_key, bootstrap.as_deref())
                    .with_context(|| format!("failed to open archive {first}"))?;
            opened
                .verify()
                .with_context(|| format!("failed to verify archive {first}"))?;
            println!("{}: OK", archives.join(" "));
            Ok(())
        }
    }
}

#[derive(Debug)]
struct InputFile {
    archive_path: String,
    contents: Vec<u8>,
    mode: u32,
    mtime: u64,
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
}

fn collect_inputs(paths: &[String]) -> Result<Vec<InputFile>> {
    let mut out = Vec::new();
    for path in paths {
        let input = PathBuf::from(path);
        let base = input
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| anyhow!("input path has no valid UTF-8 file name: {path}"))?
            .to_owned();
        collect_one_input(&input, Path::new(&base), &mut out)
            .with_context(|| format!("failed to collect input {path}"))?;
    }
    out.sort_by(|left, right| left.archive_path.cmp(&right.archive_path));
    Ok(out)
}

fn collect_one_input(input: &Path, archive_path: &Path, out: &mut Vec<InputFile>) -> Result<()> {
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
            collect_one_input(&entry.path(), &archive_path.join(child_name), out)?;
        }
        return Ok(());
    }
    if !metadata.is_file() {
        bail!("unsupported input type {}", input.display());
    }
    let archive_path = archive_path_to_string(archive_path)?;
    let contents =
        fs::read(input).with_context(|| format!("failed to read input {}", input.display()))?;
    out.push(InputFile {
        archive_path,
        contents,
        mode: readonly_mode(&metadata),
        mtime: 0,
    });
    Ok(())
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
            bail!("--bootstrap is only supported with a single archive input in this CLI pass");
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

fn load_create_key(
    keyfile: Option<&str>,
    password_stdin: bool,
    t_cost: u32,
    m_cost_kib: u32,
    parallelism: u32,
) -> Result<CreateKey> {
    if password_stdin {
        let passphrase = read_passphrase_stdin()?;
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
    first_volume: &[u8],
) -> Result<MasterKey> {
    if password_stdin {
        let passphrase = read_passphrase_stdin()?;
        let kdf_params = read_kdf_params_from_volume(first_volume)?;
        return match kdf_params {
            KdfParams::Argon2id { .. } => {
                MasterKey::derive_from_passphrase(&kdf_params, &passphrase).map_err(Into::into)
            }
            KdfParams::Raw => Err(anyhow!(FormatError::KeyMaterialMismatch)
                .context("raw-key archives require --keyfile, not --password-stdin")),
        };
    }
    load_raw_master_key(keyfile)
}

fn load_raw_master_key(keyfile: Option<&str>) -> Result<MasterKey> {
    let keyfile =
        keyfile.ok_or_else(|| anyhow!("either --keyfile or --password-stdin is required"))?;
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
        bail!("size is missing digits");
    }
    let number = digits.parse::<u64>()?;
    let multiplier = match suffix.to_ascii_lowercase().as_str() {
        "" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        _ => bail!("unsupported size suffix {suffix}"),
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
                },
                _ => Diagnostic {
                    label: "io-error",
                    exit_code: EXIT_IO,
                },
            };
        }
    }
    Diagnostic {
        label: "error",
        exit_code: EXIT_GENERIC,
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
        },
        FormatError::HmacMismatch {
            structure: "CryptoHeader",
        }
        | FormatError::KeyMaterialMismatch
        | FormatError::InvalidRawMasterKeyLength => Diagnostic {
            label: "wrong-key",
            exit_code: EXIT_WRONG_KEY,
        },
        FormatError::HmacMismatch { .. } | FormatError::AeadFailure => Diagnostic {
            label: "corrupt-archive",
            exit_code: EXIT_CORRUPT_ARCHIVE,
        },
        FormatError::UnsafeArchivePath | FormatError::UnsafeOverwrite => Diagnostic {
            label: "unsafe-path",
            exit_code: EXIT_UNSAFE_PATH,
        },
        FormatError::ReaderUnsupported(message) | FormatError::WriterUnsupported(message)
            if message.contains("bootstrap") =>
        {
            Diagnostic {
                label: "missing-bootstrap",
                exit_code: EXIT_MISSING_BOOTSTRAP,
            }
        }
        FormatError::ReaderUnsupported(_) | FormatError::WriterUnsupported(_) => Diagnostic {
            label: "unsupported-feature",
            exit_code: EXIT_UNSUPPORTED_FEATURE,
        },
        _ => Diagnostic {
            label: "corrupt-archive",
            exit_code: EXIT_CORRUPT_ARCHIVE,
        },
    }
}
