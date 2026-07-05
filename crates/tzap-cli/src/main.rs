use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgGroup, Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use memmap2::Mmap;
use openssl::pkey::PKey;
use openssl::x509::X509;
use rand::RngCore;
use serde_json::json;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tzap_core::format::{
    FormatError, CRYPTO_HEADER_FIXED_LEN, FORMAT_VERSION, READER_MAX_ARGON2ID_M_COST_KIB,
    READER_MAX_ARGON2ID_PARALLELISM, READER_MAX_ARGON2ID_T_COST,
    READER_MAX_SUPPORTED_VOLUME_FORMAT_REV, VOLUME_FORMAT_REV_44, VOLUME_HEADER_LEN,
};
use tzap_core::reader::{ArchiveEntry, ArchiveIndexEntry, RecipientWrapRecordContext};
use tzap_core::wire::{CryptoHeader, CryptoHeaderFixed, VolumeHeader};
use tzap_core::{
    extract_non_seekable_stream_to_dir, extract_non_seekable_stream_to_dir_with_bootstrap_sidecar,
    extract_non_seekable_stream_to_dir_with_recipient_wrap_resolver,
    extract_non_seekable_stream_to_dir_with_recipient_wrap_resolver_and_bootstrap_sidecar,
    extract_unencrypted_non_seekable_stream_to_dir,
    extract_unencrypted_non_seekable_stream_to_dir_with_bootstrap_sidecar,
    list_non_seekable_stream, list_non_seekable_stream_with_bootstrap_sidecar,
    list_non_seekable_stream_with_recipient_wrap_resolver,
    list_non_seekable_stream_with_recipient_wrap_resolver_and_bootstrap_sidecar,
    list_unencrypted_non_seekable_stream,
    list_unencrypted_non_seekable_stream_with_bootstrap_sidecar, open_seekable_archive,
    open_seekable_archive_volumes_with_recipient_wrap_resolver_options,
    open_seekable_archive_with_bootstrap_sidecar_options,
    public_no_key_verify_volumes_with_options, verify_non_seekable_stream_with_bootstrap_sidecar,
    verify_non_seekable_stream_with_options,
    verify_non_seekable_stream_with_recipient_wrap_resolver_and_bootstrap_sidecar,
    verify_non_seekable_stream_with_recipient_wrap_resolver_options,
    verify_unencrypted_non_seekable_stream_with_bootstrap_sidecar,
    verify_unencrypted_non_seekable_stream_with_options, write_archive,
    write_archive_sources_to_sink_ordered_parallel,
    write_archive_sources_to_sink_ordered_parallel_with_recipient_wrap_records,
    write_archive_with_dictionary, write_archive_with_dictionary_and_kdf,
    write_archive_with_dictionary_and_root_auth, write_archive_with_dictionary_kdf_and_root_auth,
    write_archive_with_kdf, write_archive_with_root_auth, write_archive_with_root_auth_and_kdf,
    write_sized_raw_member_archive_to_sink_with_kdf_and_root_auth,
    write_tar_stream_archive_to_sink_with_kdf_and_root_auth, AeadAlgo, ArchiveContentVerification,
    ArchiveRepairPatch, ArchiveWriteError, ArchiveWriteSink, ExtractError, KdfAlgo, KdfParams,
    MasterKey, MemoryArchiveSink, MetadataDiagnostic, NonSeekableReaderOptions, OpenedArchive,
    PublicNoKeyVerification, ReaderOptions, RegularFile, RegularFileSource, RootAuthSigningRequest,
    RootAuthVerification, RootAuthWriterConfig, SafeExtractionOptions, SequentialRootAuthStatus,
    StreamingRawWriterSummary, StreamingTarWriterSummary, TarEntryKind, WriterOptions,
    WriterTimings, WrittenArchiveSummary,
};
use tzap_plugin_keywrap::{
    dispatch_key_wrap_record, wrap_master_key_for_recipient,
    ArchiveIdentity as KeyWrapArchiveIdentity, KeyWrapOutcome, KeyWrapSuite, PrivateKeyLookup,
    RecipientRecordInput, RecipientRecordMetadata,
};
use tzap_plugin_signing::ed25519_raw::{
    self, Ed25519RootAuthOutcome, Ed25519VerificationMode, ED25519_AUTHENTICATOR_ID,
    ED25519_AUTHENTICATOR_VALUE_LEN,
};
use tzap_plugin_signing::x509_chain::{
    self, X509RootAuthReport, X509RootAuthSigner, X509SignatureScheme, X509_AUTHENTICATOR_ID,
};

mod plaintext_spool;
use plaintext_spool::{spool_unknown_size_raw_stdin, ExplicitPlaintextSpool};

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
const INSECURE_ZERO_KEY: [u8; 32] = [0; 32];
const LARGE_CREATE_LAYOUT_THRESHOLD: u64 = 100 * 1024 * 1024 * 1024;
const OFFICIAL_TZAP_ROOT_CERT_SHA256: &str =
    "sha256:d80d318f6cd6096dc791e314ec6f41434caa47feb75e85ad6f87d5bf72bbd53d";
const OFFICIAL_TZAP_ROOT_CERT_PEM: &[u8] = include_bytes!("trust/tzap-production-root-ca-2026.pem");

type CliRootAuthAuthenticator<'a> =
    dyn FnMut(&RootAuthSigningRequest) -> std::result::Result<Vec<u8>, FormatError> + 'a;

#[derive(Debug, Parser)]
#[command(name = "tzap")]
#[command(version)]
#[command(about = "Create, list, verify, and extract v44 archives")]
#[command(
    long_about = "Create, list, verify, and extract v44 archives.\n\nCreate selects one protection mode: `--keyfile` for encrypted raw-key archives, `--password` or `--password-stdin` for encrypted passphrase archives, `--recipient-cert` for encrypted v44 RecipientWrap archives, or `--no-encryption` for explicit plaintext archives. Plaintext archives can be listed, verified, and extracted without a password or keyfile. RecipientWrap archives are opened with `--recipient-key`. The `verify --public-no-key` mode verifies signed public RootAuth commitments without the archive key.\n\nSize suffixes accepted by size flags:\n  0-9 (bytes), K/KB/KiB, M/MB/MiB, G/GB/GiB.\n\nMulti-volume output naming for this CLI:\n  - one volume: --output writes exactly that path\n  - multiple volumes: --output backup.tzap writes backup.vol000.tzap, backup.vol001.tzap, ...\n\nExit codes:\n  2  usage / argument error\n  3  I/O failure (missing file, permission denied, etc.)\n  10 wrong key\n  11 archive corruption or integrity mismatch\n  12 unsupported archive revision / format version\n  13 unsafe extraction attempt\n  14 missing required bootstrap metadata\n  16 unsupported feature in this CLI/core version\n  1  generic failure\n\nSubcommands:\n  create   Build a new archive\n  extract  Extract files from an archive\n  list     List archive contents\n  verify   Validate archive integrity\n  keygen   Generate a random raw keyfile\n  signing-keygen Generate an Ed25519 RootAuth signing keypair"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[arg(long = "quiet", global = true, help = "Suppress success summaries.")]
    quiet: bool,

    #[arg(long = "verbose", global = true, help = "Enable verbose diagnostics.")]
    verbose: bool,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum Command {
    #[command(
        about = "Create a new archive",
        long_about = "Create a new archive from files and directories.\n\nThe command writes one output path for single-volume archives, or `.vol000.tzap`, `.vol001.tzap`, ... files for multi-volume archives.",
        after_help = "Examples:\n  tzap create --keyfile key.hex -o backup.tzap file.txt\n  tzap create --recipient-cert recipient.pem -o backup.tzap file.txt\n  tzap create --password -o backup.tzap file.txt\n  tzap create --password-stdin --argon2-t-cost 1 --argon2-m-cost-kib 8192 -o backup.tzap file.txt\n  tar cf - ./dir | tzap create --tar-stdin --keyfile key.hex -o backup.tzap -\n  tzap create --keyfile key.hex --signing-key root.signing.hex -o backup.tzap file.txt\n  tzap create --keyfile key.hex --signing-cert signer.pem --signing-private-key signer.key -o backup.tzap file.txt\n  tzap create --keyfile key.hex -o backup.tzap --volumes 3 dir/\n  tzap create --keyfile key.hex --volume-size 64M --volume-loss-tolerance 1 -o backup.tzap dir/\n  tzap create --keyfile key.hex --bootstrap-out backup.tzap.bootstrap file.txt",
        group(ArgGroup::new("create-key-source").args([
            "password_stdin",
            "password",
            "keyfile",
            "recipient_cert",
            "no_encryption",
        ]))
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
            help = "Allowed missing-volume recovery tolerance for multi-volume archives."
        )]
        volume_loss_tolerance: Option<u8>,

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
            conflicts_with = "no_encryption",
            value_name = "STDIN",
            help = "Read passphrase from stdin; one trailing LF or CRLF is stripped."
        )]
        password_stdin: bool,

        #[arg(
            long = "password",
            conflicts_with = "keyfile",
            conflicts_with = "password_stdin",
            conflicts_with = "no_encryption",
            help = "Read passphrase from an interactive prompt."
        )]
        password: bool,

        #[arg(
            long = "keyfile",
            value_name = "KEYFILE",
            conflicts_with = "no_encryption",
            conflicts_with = "recipient_cert",
            help = "Use a raw key from KEYFILE."
        )]
        keyfile: Option<String>,

        #[arg(
            long = "recipient-cert",
            value_name = "FILE",
            conflicts_with = "keyfile",
            conflicts_with = "password",
            conflicts_with = "password_stdin",
            conflicts_with = "no_encryption",
            help = "Encrypt a v44 RecipientWrap archive to one X.509 recipient certificate."
        )]
        recipient_cert: Option<String>,

        #[arg(
            long = "no-encryption",
            conflicts_with = "recipient_cert",
            help = "Create an explicit plaintext v44 archive with no password or keyfile."
        )]
        no_encryption: bool,

        #[arg(
            long = "insecure-zero-key",
            hide = true,
            help = "Removed in v43; use --no-encryption for plaintext archives."
        )]
        insecure_zero_key: bool,

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
            long = "signing-key",
            value_name = "FILE",
            conflicts_with = "signing_cert",
            help = "Sign RootAuth with an Ed25519 signing key seed from FILE."
        )]
        signing_key: Option<String>,

        #[arg(
            long = "signing-cert",
            value_name = "FILE",
            conflicts_with = "signing_key",
            requires = "signing_private_key",
            help = "Sign RootAuth with an X.509 leaf certificate from FILE."
        )]
        signing_cert: Option<String>,

        #[arg(
            long = "signing-private-key",
            value_name = "FILE",
            conflicts_with = "signing_key",
            requires = "signing_cert",
            help = "Private key for --signing-cert."
        )]
        signing_private_key: Option<String>,

        #[arg(
            long = "signing-chain",
            value_name = "FILE",
            requires = "signing_cert",
            help = "PEM or DER intermediate certificate chain for --signing-cert."
        )]
        signing_chain: Vec<String>,

        #[arg(
            long = "x509-signature-scheme",
            value_name = "SCHEME",
            value_enum,
            requires = "signing_cert",
            help = "X.509 RootAuth signature scheme: rsa-pkcs1-sha256, ecdsa-sha256-der, or rsa-pss-sha256."
        )]
        x509_signature_scheme: Option<CliX509SignatureScheme>,

        #[arg(
            long = "bootstrap-out",
            value_name = "FILE",
            help = "Write bootstrap recovery sidecar to FILE (single-volume output only)."
        )]
        bootstrap_out: Option<String>,

        #[arg(
            long = "tar-stdin",
            help = "Treat PATH '-' as a tar stream read from stdin."
        )]
        tar_stdin: bool,

        #[arg(
            long = "raw-stdin",
            help = "Treat PATH '-' as one raw stdin member named by --stdin-name."
        )]
        raw_stdin: bool,

        #[arg(
            long = "stdin-name",
            value_name = "PATH",
            help = "Archive member path for --raw-stdin."
        )]
        stdin_name: Option<String>,

        #[arg(
            long = "stdin-size",
            value_name = "SIZE",
            help = "Expected byte size for known-size --raw-stdin."
        )]
        stdin_size: Option<String>,

        #[arg(
            long = "spool-stdin",
            help = "Spool unknown-size raw stdin to a restrictive temporary file before archiving."
        )]
        spool_stdin: bool,

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
            help = "Compression chunk size (default: auto by input size)."
        )]
        chunk_size: Option<String>,

        #[arg(
            long = "envelope-size",
            value_name = "SIZE",
            help = "Archive envelope size (default: auto by input size)."
        )]
        envelope_size: Option<String>,

        #[arg(
            long = "block-size",
            value_name = "SIZE",
            help = "Block size for archive payload layout (default: auto by input size)."
        )]
        block_size: Option<String>,

        #[arg(
            long = "jobs",
            value_name = "N",
            help = "Worker jobs for reader/writer CPU work (default: logical CPU count)."
        )]
        jobs: Option<usize>,

        #[arg(
            long = "timings",
            help = "Print create-stage timing breakdown to stderr."
        )]
        timings: bool,

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
        after_help = "Examples:\n  tzap extract --keyfile key.hex -C out/ backup.tzap\n  tzap extract --recipient-key recipient.key -C out/ backup.tzap\n  tzap extract --keyfile key.hex backup.tzap file.txt\n  tzap extract --keyfile key.hex --stdout backup.tzap hello.txt > out.bin\n  tzap extract --password-stdin --overwrite backup.tzap target/\n  tzap extract --dry-run -C out backup.tzap file.txt\n  tzap extract --bootstrap backup.tzap.bootstrap -C out backup.tzap",
        group(
            ArgGroup::new("open-key-source")
                .args(["password_stdin", "password", "keyfile", "recipient_key", "insecure_zero_key"])
        )
    )]
    Extract {
        #[arg(
            value_name = "ARCHIVE",
            help = "Archive input. A .volNNN.tzap path discovers sibling volumes unless --volume is used."
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
            conflicts_with = "insecure_zero_key",
            value_name = "STDIN",
            help = "Read passphrase from stdin; one trailing LF or CRLF is stripped."
        )]
        password_stdin: bool,

        #[arg(
            long = "password",
            conflicts_with = "keyfile",
            conflicts_with = "password_stdin",
            conflicts_with = "insecure_zero_key",
            help = "Read passphrase from an interactive prompt."
        )]
        password: bool,

        #[arg(
            long = "keyfile",
            value_name = "KEYFILE",
            conflicts_with = "insecure_zero_key",
            conflicts_with = "recipient_key",
            help = "Use a raw key from KEYFILE."
        )]
        keyfile: Option<String>,

        #[arg(
            long = "recipient-key",
            value_name = "FILE",
            conflicts_with = "keyfile",
            conflicts_with = "password",
            conflicts_with = "password_stdin",
            conflicts_with = "insecure_zero_key",
            help = "Use a local recipient private key to open a v44 RecipientWrap archive."
        )]
        recipient_key: Option<String>,

        #[arg(
            long = "insecure-zero-key",
            hide = true,
            help = "Removed in v43; plaintext archives need no key source."
        )]
        insecure_zero_key: bool,

        #[arg(
            long = "bootstrap",
            value_name = "FILE",
            help = "Use bootstrap sidecar FILE for single-volume archive input."
        )]
        bootstrap: Option<String>,

        #[arg(
            long = "volume",
            value_name = "FILE",
            help = "Explicit additional volume path."
        )]
        volumes: Vec<String>,

        #[arg(
            long = "jobs",
            value_name = "N",
            help = "Worker jobs for reader CPU work (default: logical CPU count)."
        )]
        jobs: Option<usize>,
    },
    #[command(
        about = "List archive contents",
        long_about = "List archive members in plain format by default.",
        after_help = "Examples:\n  tzap list --keyfile key.hex backup.tzap\n  tzap list --recipient-key recipient.key backup.tzap\n  tzap list --keyfile key.hex --long backup.tzap\n  tzap list --keyfile key.hex --json backup.tzap\n  tzap list --password-stdin --bootstrap backup.tzap.bootstrap backup.tzap",
        group(
            ArgGroup::new("open-key-source")
                .args(["password_stdin", "password", "keyfile", "recipient_key", "insecure_zero_key"])
        )
    )]
    List {
        #[arg(
            value_name = "ARCHIVE",
            help = "Archive to inspect. A .volNNN.tzap path discovers sibling volumes unless --volume is used."
        )]
        archive: String,

        #[arg(
            long = "password-stdin",
            conflicts_with = "keyfile",
            conflicts_with = "password",
            conflicts_with = "insecure_zero_key",
            value_name = "STDIN",
            help = "Read passphrase from stdin; one trailing LF or CRLF is stripped."
        )]
        password_stdin: bool,

        #[arg(
            long = "password",
            conflicts_with = "keyfile",
            conflicts_with = "password_stdin",
            conflicts_with = "insecure_zero_key",
            help = "Read passphrase from an interactive prompt."
        )]
        password: bool,

        #[arg(
            long = "keyfile",
            value_name = "KEYFILE",
            conflicts_with = "insecure_zero_key",
            conflicts_with = "recipient_key",
            help = "Use a raw key from KEYFILE."
        )]
        keyfile: Option<String>,

        #[arg(
            long = "recipient-key",
            value_name = "FILE",
            conflicts_with = "keyfile",
            conflicts_with = "password",
            conflicts_with = "password_stdin",
            conflicts_with = "insecure_zero_key",
            help = "Use a local recipient private key to open a v44 RecipientWrap archive."
        )]
        recipient_key: Option<String>,

        #[arg(
            long = "insecure-zero-key",
            hide = true,
            help = "Removed in v43; plaintext archives need no key source."
        )]
        insecure_zero_key: bool,

        #[arg(
            long = "bootstrap",
            value_name = "FILE",
            help = "Use bootstrap sidecar FILE for single-volume archive input."
        )]
        bootstrap: Option<String>,

        #[arg(
            long = "volume",
            value_name = "FILE",
            help = "Explicit additional volume path."
        )]
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

        #[arg(
            long = "jobs",
            value_name = "N",
            help = "Worker jobs for reader CPU work (default: logical CPU count)."
        )]
        jobs: Option<usize>,
    },
    #[command(
        about = "Verify archive integrity",
        long_about = "Verify archive signatures and checksum integrity. No payload changes are made unless --write-repaired is set; original archive files are never modified.\n\nEncrypted archives need --keyfile, --password, --password-stdin, or --recipient-key for v44 RecipientWrap archives. Unencrypted archives need no key source. Official TZAP X.509 RootAuth uses the embedded TZAP root by default. With --public-no-key, verify uses the public RootAuth profile and does not require the archive key.",
        after_help = "Examples:\n  tzap verify --keyfile key.hex backup.tzap\n  tzap verify --recipient-key recipient.key backup.tzap\n  tzap verify --keyfile key.hex --write-repaired backup.tzap\n  tzap verify --keyfile key.hex --trusted-public-key root.public.hex backup.tzap\n  tzap verify --keyfile key.hex --trusted-ca-cert root-ca.pem backup.tzap\n  tzap verify --public-no-key backup.tzap\n  tzap verify --public-no-key --trusted-public-key root.public.hex backup.tzap\n  tzap verify --public-no-key --trusted-ca-cert root-ca.pem backup.tzap\n  tzap verify --keyfile key.hex backup.vol000.tzap backup.vol001.tzap\n  tzap verify --password-stdin backup.tzap\n  tzap verify --json --keyfile key.hex backup.tzap\n  tzap verify --quiet --keyfile key.hex backup.tzap\n\nFor multi-volume archives named `.volNNN.tzap`, passing any one volume discovers matching siblings in the same directory. Additional positionals are explicit extra volumes."
    )]
    Verify {
        #[arg(
            required = true,
            value_name = "ARCHIVE",
            help = "Archive path. A .volNNN.tzap path discovers sibling volumes unless extra archive paths are supplied."
        )]
        archives: Vec<String>,

        #[arg(
            long = "password-stdin",
            conflicts_with = "keyfile",
            conflicts_with = "password",
            conflicts_with = "insecure_zero_key",
            value_name = "STDIN",
            help = "Read passphrase from stdin; one trailing LF or CRLF is stripped."
        )]
        password_stdin: bool,

        #[arg(
            long = "password",
            conflicts_with = "keyfile",
            conflicts_with = "password_stdin",
            conflicts_with = "insecure_zero_key",
            help = "Read passphrase from an interactive prompt."
        )]
        password: bool,

        #[arg(
            long = "keyfile",
            value_name = "KEYFILE",
            conflicts_with = "insecure_zero_key",
            conflicts_with = "recipient_key",
            help = "Use a raw key from KEYFILE."
        )]
        keyfile: Option<String>,

        #[arg(
            long = "recipient-key",
            value_name = "FILE",
            conflicts_with = "keyfile",
            conflicts_with = "password",
            conflicts_with = "password_stdin",
            conflicts_with = "insecure_zero_key",
            help = "Use a local recipient private key to verify a v44 RecipientWrap archive."
        )]
        recipient_key: Option<String>,

        #[arg(
            long = "insecure-zero-key",
            hide = true,
            help = "Removed in v43; plaintext archives need no key source."
        )]
        insecure_zero_key: bool,

        #[arg(
            long = "trusted-public-key",
            value_name = "FILE",
            help = "Verify Ed25519 RootAuth with trusted public key FILE."
        )]
        trusted_public_key: Option<String>,

        #[arg(
            long = "trusted-ca-cert",
            value_name = "FILE",
            help = "Verify X.509 RootAuth with trusted CA certificate FILE."
        )]
        trusted_ca_cert: Vec<String>,

        #[arg(
            long = "trusted-system-roots",
            help = "Allow X.509 RootAuth verification with OpenSSL default trust roots."
        )]
        trusted_system_roots: bool,

        #[arg(
            long = "public-no-key",
            help = "Verify public RootAuth commitments without the archive key."
        )]
        public_no_key: bool,

        #[arg(
            long = "fast",
            help = "Verify readable archive content with repair-on-demand parity reads, but skip RootAuth and recovery-margin checks."
        )]
        fast: bool,

        #[arg(
            long = "bootstrap",
            value_name = "FILE",
            help = "Use bootstrap sidecar FILE for single-volume archive input."
        )]
        bootstrap: Option<String>,

        #[arg(
            long = "json",
            conflicts_with = "quiet",
            help = "Emit stable machine-readable JSON output."
        )]
        json: bool,

        #[arg(
            long = "write-repaired",
            help = "After successful key-holding verification, write repaired copies for volumes that had recoverable block damage."
        )]
        write_repaired: bool,

        #[arg(
            long = "jobs",
            value_name = "N",
            help = "Worker jobs for reader CPU work (default: logical CPU count)."
        )]
        jobs: Option<usize>,
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
    #[command(
        name = "signing-keygen",
        about = "Generate an Ed25519 RootAuth signing keypair",
        long_about = "Generate an Ed25519 RootAuth signing keypair. The secret output is a 32-byte signing seed encoded as 64 lowercase hex characters; the public output is a 32-byte Ed25519 verifying key encoded the same way."
    )]
    SigningKeygen {
        #[arg(
            long = "secret-output",
            value_name = "FILE",
            help = "Write the generated Ed25519 signing seed to FILE."
        )]
        secret_output: String,

        #[arg(
            long = "public-output",
            value_name = "FILE",
            help = "Write the generated Ed25519 public key to FILE."
        )]
        public_output: String,

        #[arg(long = "force", help = "Overwrite existing keypair output files.")]
        force: bool,
    },
    #[command(
        name = "trust-info",
        about = "Show embedded official TZAP trust and build identity",
        long_about = "Show the embedded official TZAP root certificate fingerprint and build identity used by this tzap binary."
    )]
    TrustInfo {
        #[arg(long = "json", help = "Emit stable machine-readable JSON output.")]
        json: bool,
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
            recipient_cert,
            no_encryption,
            insecure_zero_key,
            force,
            dry_run,
            argon2_t_cost,
            argon2_m_cost_kib,
            argon2_parallelism,
            dictionary,
            signing_key,
            signing_cert,
            signing_private_key,
            signing_chain,
            x509_signature_scheme,
            bootstrap_out,
            tar_stdin,
            raw_stdin,
            stdin_name,
            stdin_size,
            spool_stdin,
            compression_level,
            chunk_size,
            envelope_size,
            block_size,
            jobs,
            timings,
            paths,
        } => {
            let create_total_started = Instant::now();
            let jobs = resolve_jobs(jobs)?;
            let resolved_volume_loss_tolerance = resolve_create_volume_loss_tolerance(
                volume_loss_tolerance,
                volumes,
                volume_size.as_deref(),
                tar_stdin || raw_stdin || spool_stdin,
            );
            let layout_overrides = CreateLayoutOverrides {
                chunk_size: chunk_size.as_deref(),
                envelope_size: envelope_size.as_deref(),
                block_size: block_size.as_deref(),
            };
            let build_writer_options = |total_input_size: Option<u64>| -> Result<WriterOptions> {
                let mut options = create_writer_options(CreateWriterOptionsArgs {
                    volumes,
                    volume_size: volume_size.as_deref(),
                    volume_loss_tolerance: resolved_volume_loss_tolerance,
                    bit_rot_buffer_pct,
                    compression_level,
                    jobs,
                    layout_overrides,
                    total_input_size,
                })?;
                if no_encryption {
                    options.aead_algo = AeadAlgo::None;
                }
                Ok(options)
            };
            validate_create_key_source(
                keyfile.as_deref(),
                recipient_cert.as_deref(),
                password_stdin,
                password,
                no_encryption,
                insecure_zero_key,
            )?;
            if bootstrap_out.is_some() && (volumes.unwrap_or(1) > 1 || volume_size.is_some()) {
                return Err(FormatError::WriterUnsupported(
                    "--bootstrap-out is currently supported only for single-volume output",
                )
                .into());
            }
            reject_create_stdout_sentinels(&output, bootstrap_out.as_deref())?;
            let stdin_mode = validate_create_stdin_mode(CreateStdinArgs {
                tar_stdin,
                raw_stdin,
                stdin_name: stdin_name.as_deref(),
                stdin_size: stdin_size.as_deref(),
                spool_stdin,
                paths: &paths,
                password_stdin,
                password,
                has_dictionary: dictionary.is_some(),
                volumes,
                volume_size: volume_size.as_deref(),
                volume_loss_tolerance,
            })?;
            validate_create_recipient_wrap_scope(
                recipient_cert.as_deref(),
                stdin_mode,
                dictionary.is_some(),
                signing_key.is_some() || signing_cert.is_some(),
                volumes,
                volume_size.as_deref(),
            )?;

            ensure_create_output_paths_can_be_written(
                &output,
                volumes,
                volume_size.is_some(),
                bootstrap_out.as_deref(),
                force,
            )?;
            if let Some(stdin_mode) = stdin_mode {
                if dry_run {
                    let dry_run_input_size = match stdin_mode {
                        CreateStdinMode::RawKnownSize => Some(parse_size(
                            stdin_size.as_deref().expect("validated stdin-size"),
                        )?),
                        CreateStdinMode::Tar
                        | CreateStdinMode::RawSpool
                        | CreateStdinMode::RawUnknownSize => None,
                    };
                    let options = build_writer_options(dry_run_input_size)?;
                    validate_create_writer_options(&options)?;
                }
                if dry_run {
                    eprintln!("create dry-run summary:");
                    eprintln!("  files: streaming stdin");
                    eprintln!("  input bytes: unknown until stdin is consumed");
                    eprintln!(
                        "  key mode: {}",
                        create_key_mode_label(
                            keyfile.as_deref(),
                            recipient_cert.as_deref(),
                            password_stdin,
                            password,
                            no_encryption,
                            insecure_zero_key
                        )
                    );
                    eprintln!(
                        "  root auth: {}",
                        create_root_auth_mode_label(
                            signing_key.as_deref(),
                            signing_cert.as_deref()
                        )
                    );
                    eprintln!(
                        "  volume mode: {}",
                        describe_planned_volume_mode(volumes, volume_size.as_deref())
                    );
                    eprintln!("  planned archive paths:");
                    for path in create_dry_run_output_paths(&output, volumes, volume_size.is_some())
                    {
                        eprintln!("    {path}");
                    }
                    if let Some(bootstrap_path) = bootstrap_out.as_ref() {
                        eprintln!("  bootstrap: {}", bootstrap_path);
                    }
                    return Ok(());
                }

                if matches!(stdin_mode, CreateStdinMode::RawUnknownSize) {
                    return Err(FormatError::WriterUnsupported(
                        "unknown-size raw stdin without --spool-stdin requires the future raw_stream_v1 profile",
                    )
                    .into());
                }

                let key = load_create_key(
                    keyfile.as_deref(),
                    password_stdin,
                    password,
                    no_encryption,
                    insecure_zero_key,
                    argon2_t_cost,
                    argon2_m_cost_kib,
                    argon2_parallelism,
                )?;
                let root_auth_profile = load_create_root_auth_profile(
                    signing_key.as_deref(),
                    signing_cert.as_deref(),
                    signing_private_key.as_deref(),
                    &signing_chain,
                    x509_signature_scheme,
                )?;
                let root_auth = root_auth_profile
                    .as_ref()
                    .map(CreateRootAuthProfile::root_auth_writer_config)
                    .transpose()?;
                let core_writer_started = Instant::now();
                let (bootstrap_sidecar, summary_text, writer_timings) = match stdin_mode {
                    CreateStdinMode::Tar => {
                        let options = build_writer_options(None)?;
                        validate_create_writer_options(&options)?;
                        let (summary, bootstrap_sidecar) = write_tar_stdin_archive_output(
                            &output,
                            &key,
                            options,
                            root_auth,
                            root_auth_profile.as_ref(),
                            force,
                        )?;
                        let summary_text = format!(
                            "created {} file(s), {} tar bytes in, {} archive bytes, {} volume(s), volume-loss tolerance {}, bit-rot buffer {}%",
                            summary.input_member_count,
                            summary.input_tar_bytes,
                            summary.archive.archive_bytes,
                            summary.archive.volume_count,
                            resolved_volume_loss_tolerance,
                            bit_rot_buffer_pct
                        );
                        (bootstrap_sidecar, summary_text, summary.archive.timings)
                    }
                    CreateStdinMode::RawKnownSize => {
                        let stdin_size =
                            parse_size(stdin_size.as_deref().expect("validated stdin-size"))?;
                        let options = build_writer_options(Some(stdin_size))?;
                        validate_create_writer_options(&options)?;
                        let (summary, bootstrap_sidecar) = write_raw_stdin_archive_output(
                            &output,
                            io::stdin().lock(),
                            stdin_name.as_deref().expect("validated stdin-name"),
                            stdin_size,
                            &key,
                            options,
                            root_auth,
                            root_auth_profile.as_ref(),
                            force,
                        )?;
                        let summary_text = format!(
                            "created 1 file(s), {} raw bytes in, {} archive bytes, {} volume(s), volume-loss tolerance {}, bit-rot buffer {}%",
                            summary.input_bytes,
                            summary.archive.archive_bytes,
                            summary.archive.volume_count,
                            resolved_volume_loss_tolerance,
                            bit_rot_buffer_pct
                        );
                        (bootstrap_sidecar, summary_text, summary.archive.timings)
                    }
                    CreateStdinMode::RawSpool => {
                        let stdin = io::stdin();
                        let mut stdin_lock = stdin.lock();
                        let spool = spool_unknown_size_raw_stdin(
                            &mut stdin_lock,
                            u64::MAX,
                            ExplicitPlaintextSpool::acknowledge_plaintext_spool(),
                        )?;
                        let known_size_source = spool.known_size_source();
                        let spool_reader = spool.reopen()?;
                        let options = build_writer_options(Some(known_size_source.size()))?;
                        validate_create_writer_options(&options)?;
                        let (summary, bootstrap_sidecar) = write_raw_stdin_archive_output(
                            &output,
                            spool_reader,
                            stdin_name.as_deref().expect("validated stdin-name"),
                            known_size_source.size(),
                            &key,
                            options,
                            root_auth,
                            root_auth_profile.as_ref(),
                            force,
                        )?;
                        let summary_text = format!(
                            "created 1 file(s), {} spooled raw bytes in, {} archive bytes, {} volume(s), volume-loss tolerance {}, bit-rot buffer {}%",
                            summary.input_bytes,
                            summary.archive.archive_bytes,
                            summary.archive.volume_count,
                            resolved_volume_loss_tolerance,
                            bit_rot_buffer_pct
                        );
                        (bootstrap_sidecar, summary_text, summary.archive.timings)
                    }
                    CreateStdinMode::RawUnknownSize => unreachable!("rejected before key loading"),
                };
                let core_writer = core_writer_started.elapsed();
                let write_outputs_started = Instant::now();
                if let Some(path) = bootstrap_out.as_deref() {
                    if bootstrap_sidecar.is_empty() {
                        return Err(FormatError::WriterUnsupported(
                            "bootstrap output is unavailable for this archive shape",
                        )
                        .into());
                    }
                    write_bootstrap_output(path, &bootstrap_sidecar, force)?;
                }
                let write_outputs = write_outputs_started.elapsed();
                emit_success_summary(quiet, &summary_text)?;
                if let Some(profile) = root_auth_profile.as_ref() {
                    emit_success_summary(
                        quiet,
                        &format!("  root auth: {} signed", profile.label()),
                    )?;
                }
                if let Some(path) = bootstrap_out.as_ref() {
                    emit_success_summary(quiet, &format!("  bootstrap output: {}", path))?;
                }
                if timings {
                    emit_create_timing_report(
                        Duration::default(),
                        Duration::default(),
                        core_writer,
                        write_outputs,
                        create_total_started.elapsed(),
                        writer_timings,
                    )?;
                }
                return Ok(());
            }
            let scan_inputs_started = Instant::now();
            let input_specs = collect_input_specs(&paths)?;
            let scan_inputs = scan_inputs_started.elapsed();
            let bootstrap_output = bootstrap_out.clone();
            let input_bytes = input_specs_total_size(&input_specs)?;
            let options = build_writer_options(Some(input_bytes))?;
            validate_create_writer_options(&options)?;

            if dry_run {
                eprintln!("create dry-run summary:");
                eprintln!("  files: {}", input_specs.len());
                eprintln!("  input bytes: {}", input_bytes);
                eprintln!(
                    "  key mode: {}",
                    create_key_mode_label(
                        keyfile.as_deref(),
                        recipient_cert.as_deref(),
                        password_stdin,
                        password,
                        no_encryption,
                        insecure_zero_key
                    )
                );
                eprintln!(
                    "  root auth: {}",
                    create_root_auth_mode_label(signing_key.as_deref(), signing_cert.as_deref())
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

            if let Some(recipient_cert_path) = recipient_cert.as_deref() {
                let mut recipient_options = options;
                let master_key = generate_random_master_key()?;
                let recipient_record = build_recipient_wrap_record(
                    recipient_cert_path,
                    &master_key,
                    &mut recipient_options,
                )?;
                let core_writer_started = Instant::now();
                let (archive, sink) = write_file_inputs_ordered_parallel_recipient_wrap_to_memory(
                    &input_specs,
                    &master_key,
                    recipient_options,
                    recipient_record,
                )
                .context("failed to create recipient-wrap archive")?;
                let core_writer = core_writer_started.elapsed();

                let write_outputs_started = Instant::now();
                write_archive_outputs(&output, &sink.volumes, force)?;
                if let Some(path) = bootstrap_out {
                    if sink.bootstrap_sidecar.is_empty() {
                        return Err(FormatError::WriterUnsupported(
                            "bootstrap output is unavailable for this archive shape",
                        )
                        .into());
                    }
                    write_bootstrap_output(&path, &sink.bootstrap_sidecar, force)?;
                }
                let write_outputs = write_outputs_started.elapsed();
                let summary = format!(
                    "created {} file(s), {} bytes in, {} archive bytes, {} volume(s), volume-loss tolerance {}, bit-rot buffer {}%",
                    input_specs.len(),
                    input_bytes,
                    archive.archive_bytes,
                    archive.volume_count,
                    resolved_volume_loss_tolerance,
                    bit_rot_buffer_pct
                );
                emit_success_summary(quiet, &summary)?;
                emit_success_summary(quiet, "  key wrap: recipient certificate")?;
                if let Some(path) = bootstrap_output {
                    emit_success_summary(quiet, &format!("  bootstrap output: {}", path))?;
                }
                if timings {
                    emit_create_timing_report(
                        scan_inputs,
                        Duration::default(),
                        core_writer,
                        write_outputs,
                        create_total_started.elapsed(),
                        archive.timings,
                    )?;
                }
                return Ok(());
            }

            let key = load_create_key(
                keyfile.as_deref(),
                password_stdin,
                password,
                no_encryption,
                insecure_zero_key,
                argon2_t_cost,
                argon2_m_cost_kib,
                argon2_parallelism,
            )?;
            let dictionary_bytes = dictionary
                .as_deref()
                .map(|path| {
                    fs::read(path).with_context(|| format!("failed to read dictionary {path}"))
                })
                .transpose()?;
            let root_auth_profile = load_create_root_auth_profile(
                signing_key.as_deref(),
                signing_cert.as_deref(),
                signing_private_key.as_deref(),
                &signing_chain,
                x509_signature_scheme,
            )?;
            let root_auth = root_auth_profile
                .as_ref()
                .map(CreateRootAuthProfile::root_auth_writer_config)
                .transpose()?;

            if dictionary_bytes.is_none()
                && options.target_volume_size.is_none()
                && options.volume_loss_tolerance == 0
            {
                let core_writer_started = Instant::now();
                let (archive, sink) = write_file_inputs_ordered_parallel_to_memory(
                    &input_specs,
                    &key,
                    options,
                    root_auth,
                    root_auth_profile.as_ref(),
                )
                .context("failed to create archive")?;
                let core_writer = core_writer_started.elapsed();

                let write_outputs_started = Instant::now();
                write_archive_outputs(&output, &sink.volumes, force)?;
                if let Some(path) = bootstrap_out.as_deref() {
                    if sink.bootstrap_sidecar.is_empty() {
                        return Err(FormatError::WriterUnsupported(
                            "bootstrap output is unavailable for this archive shape",
                        )
                        .into());
                    }
                    write_bootstrap_output(path, &sink.bootstrap_sidecar, force)?;
                }
                let write_outputs = write_outputs_started.elapsed();
                let summary = format!(
                    "created {} file(s), {} bytes in, {} archive bytes, {} volume(s), volume-loss tolerance {}, bit-rot buffer {}%",
                    input_specs.len(),
                    input_bytes,
                    archive.archive_bytes,
                    archive.volume_count,
                    resolved_volume_loss_tolerance,
                    bit_rot_buffer_pct
                );
                emit_success_summary(quiet, &summary)?;
                if let Some(profile) = root_auth_profile.as_ref() {
                    emit_success_summary(
                        quiet,
                        &format!("  root auth: {} signed", profile.label()),
                    )?;
                }
                if let Some(path) = bootstrap_output {
                    emit_success_summary(quiet, &format!("  bootstrap output: {}", path))?;
                }
                if timings {
                    emit_create_timing_report(
                        scan_inputs,
                        Duration::default(),
                        core_writer,
                        write_outputs,
                        create_total_started.elapsed(),
                        archive.timings,
                    )?;
                }
                return Ok(());
            }

            let read_inputs_started = Instant::now();
            let inputs = collect_input_files(&input_specs)?;
            let read_inputs = read_inputs_started.elapsed();
            let regular_files = inputs
                .iter()
                .map(|file| RegularFile {
                    path: file.archive_path.as_str(),
                    contents: &file.contents,
                    mode: file.mode,
                    mtime: file.mtime,
                })
                .collect::<Vec<_>>();
            let core_writer_started = Instant::now();
            let archive = match (
                &dictionary_bytes,
                &key.kdf_params,
                root_auth,
                root_auth_profile.as_ref(),
            ) {
                (Some(dictionary), KdfParams::Raw, Some(root_auth), Some(profile)) => {
                    write_archive_with_dictionary_and_root_auth(
                        &regular_files,
                        &key.master_key,
                        options,
                        dictionary,
                        root_auth,
                        |request| root_auth_authenticator_value(profile, request),
                    )
                }
                (Some(dictionary), kdf_params, Some(root_auth), Some(profile)) => {
                    write_archive_with_dictionary_kdf_and_root_auth(
                        &regular_files,
                        &key.master_key,
                        options,
                        dictionary,
                        kdf_params,
                        root_auth,
                        |request| root_auth_authenticator_value(profile, request),
                    )
                }
                (None, KdfParams::Raw, Some(root_auth), Some(profile)) => {
                    write_archive_with_root_auth(
                        &regular_files,
                        &key.master_key,
                        options,
                        root_auth,
                        |request| root_auth_authenticator_value(profile, request),
                    )
                }
                (None, kdf_params, Some(root_auth), Some(profile)) => {
                    write_archive_with_root_auth_and_kdf(
                        &regular_files,
                        &key.master_key,
                        options,
                        kdf_params,
                        root_auth,
                        |request| root_auth_authenticator_value(profile, request),
                    )
                }
                (Some(dictionary), KdfParams::Raw, None, _) => write_archive_with_dictionary(
                    &regular_files,
                    &key.master_key,
                    options,
                    dictionary,
                ),
                (Some(dictionary), kdf_params, None, _) => write_archive_with_dictionary_and_kdf(
                    &regular_files,
                    &key.master_key,
                    options,
                    dictionary,
                    kdf_params,
                ),
                (None, KdfParams::Raw, None, _) => {
                    write_archive(&regular_files, &key.master_key, options)
                }
                (None, kdf_params, None, _) => {
                    write_archive_with_kdf(&regular_files, &key.master_key, options, kdf_params)
                }
                (_, _, Some(_), None) => unreachable!("root auth requires signing profile"),
            }
            .context("failed to create archive")?;
            let core_writer = core_writer_started.elapsed();

            let output_paths = create_output_paths(&output, archive.volumes.len());
            if !force {
                check_archive_paths_free_for_write(&output_paths)?;
            }
            if let Some(bootstrap_path) = &bootstrap_output {
                if !force {
                    check_output_path_free("bootstrap", Path::new(bootstrap_path))?;
                }
            }

            let write_outputs_started = Instant::now();
            write_archive_outputs(&output, &archive.volumes, force)?;
            if let Some(path) = bootstrap_out {
                if archive.bootstrap_sidecar.is_empty() {
                    return Err(FormatError::WriterUnsupported(
                        "bootstrap output is unavailable for this archive shape",
                    )
                    .into());
                }
                write_bootstrap_output(&path, &archive.bootstrap_sidecar, force)?;
            }
            let write_outputs = write_outputs_started.elapsed();
            let summary = format!(
                "created {} file(s), {} bytes in, {} archive bytes, {} volume(s), volume-loss tolerance {}, bit-rot buffer {}%",
                regular_files.len(),
                input_bytes,
                archive.volumes.iter().map(|volume| volume.len() as u64).sum::<u64>(),
                archive.volumes.len(),
                resolved_volume_loss_tolerance,
                bit_rot_buffer_pct
            );
            emit_success_summary(quiet, &summary)?;
            if let Some(profile) = root_auth_profile.as_ref() {
                emit_success_summary(quiet, &format!("  root auth: {} signed", profile.label()))?;
            }
            if let Some(path) = bootstrap_output {
                emit_success_summary(quiet, &format!("  bootstrap output: {}", path))?;
            }
            if timings {
                emit_create_timing_report(
                    scan_inputs,
                    read_inputs,
                    core_writer,
                    write_outputs,
                    create_total_started.elapsed(),
                    archive.timings,
                )?;
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
            recipient_key,
            insecure_zero_key,
            bootstrap,
            volumes,
            jobs,
        } => {
            let reader_options = reader_options(resolve_jobs(jobs)?);
            reject_multi_volume_bootstrap(1 + volumes.len(), bootstrap.as_deref())?;
            reject_stdout_extract_shape(stdout, paths.len())?;
            if archive == "-" {
                reject_archive_stdin_open_options(ArchiveStdinOpenOptions {
                    paths: &paths,
                    stdout,
                    volumes: &volumes,
                    password_stdin,
                    password,
                    keyfile: keyfile.as_deref(),
                    recipient_key: recipient_key.as_deref(),
                    insecure_zero_key,
                })?;
                if dry_run {
                    eprintln!("extract dry-run summary:");
                    eprintln!("  input: archive stdin");
                    eprintln!("  destination: {}", directory);
                    eprintln!("  mode: staged non-seekable extract-all");
                    return Ok(());
                }
                let options = SafeExtractionOptions {
                    overwrite_existing: overwrite,
                };
                let bootstrap_bytes = read_optional_bootstrap_sidecar(bootstrap.as_deref())?;
                let stdin = io::stdin();
                let report = if let Some(keyfile) = keyfile.as_deref() {
                    let master_key = load_archive_stdin_key(
                        Some(keyfile),
                        password_stdin,
                        password,
                        insecure_zero_key,
                    )?;
                    if let Some(bootstrap_bytes) = bootstrap_bytes.as_deref() {
                        extract_non_seekable_stream_to_dir_with_bootstrap_sidecar(
                            stdin.lock(),
                            bootstrap_bytes,
                            &master_key,
                            Path::new(&directory),
                            non_seekable_reader_options(reader_options),
                            options,
                        )
                    } else {
                        extract_non_seekable_stream_to_dir(
                            stdin.lock(),
                            &master_key,
                            Path::new(&directory),
                            non_seekable_reader_options(reader_options),
                            options,
                        )
                    }
                } else if let Some(recipient_key) = recipient_key.as_deref() {
                    let lookup = load_recipient_private_key_lookup(recipient_key)?;
                    let mut stats = RecipientWrapOpenStats::default();
                    if let Some(bootstrap_bytes) = bootstrap_bytes.as_deref() {
                        extract_non_seekable_stream_to_dir_with_recipient_wrap_resolver_and_bootstrap_sidecar(
                            stdin.lock(),
                            bootstrap_bytes,
                            |context| recipient_wrap_candidates_for_record(context, &lookup, &mut stats),
                            Path::new(&directory),
                            non_seekable_reader_options(reader_options),
                            options,
                        )
                    } else {
                        extract_non_seekable_stream_to_dir_with_recipient_wrap_resolver(
                            stdin.lock(),
                            |context| recipient_wrap_candidates_for_record(context, &lookup, &mut stats),
                            Path::new(&directory),
                            non_seekable_reader_options(reader_options),
                            options,
                        )
                    }
                } else {
                    if let Some(bootstrap_bytes) = bootstrap_bytes.as_deref() {
                        extract_unencrypted_non_seekable_stream_to_dir_with_bootstrap_sidecar(
                            stdin.lock(),
                            bootstrap_bytes,
                            Path::new(&directory),
                            non_seekable_reader_options(reader_options),
                            options,
                        )
                    } else {
                        extract_unencrypted_non_seekable_stream_to_dir(
                            stdin.lock(),
                            Path::new(&directory),
                            non_seekable_reader_options(reader_options),
                            options,
                        )
                    }
                }
                .context("failed to extract non-seekable archive stream")?;
                emit_success_summary(
                    quiet,
                    &format!(
                        "extracted {} member(s), {} degraded metadata items to {} using staged non-seekable stream extraction",
                        report.extracted_member_count,
                        report.degraded_metadata_count,
                        directory
                    ),
                )?;
                return Ok(());
            }
            let selection = resolve_archive_input_paths(&archive, &volumes, bootstrap.is_none())?;
            let opened = if let Some(recipient_key) = recipient_key.as_deref() {
                open_selection_with_recipient_key(
                    &selection,
                    recipient_key,
                    bootstrap.as_deref(),
                    reader_options,
                )
                .map(|opened_selection| opened_selection.opened)
            } else {
                let master_key = load_open_key_from_paths(
                    keyfile.as_deref(),
                    password_stdin,
                    password,
                    insecure_zero_key,
                    &selection.paths,
                )?;
                open_selection_maybe_bootstrap(
                    &selection,
                    &master_key,
                    bootstrap.as_deref(),
                    reader_options,
                )
            }
            .with_context(|| format!("failed to open archive {archive}"))?;
            let (requested_entries, missing_paths) = if stdout || dry_run || !paths.is_empty() {
                resolve_extract_index_entries(&opened, &paths)?
            } else {
                (Vec::new(), Vec::new())
            };
            if !missing_paths.is_empty() {
                for missing in missing_paths {
                    eprintln!("missing archive path: {missing}");
                }
                return Err(anyhow!("missing requested archive paths"));
            }
            if stdout {
                let path = requested_entries[0].path.as_str();
                let mut stdout = io::stdout().lock();
                let diagnostics = match opened.extract_file_to_writer(path, &mut stdout) {
                    Ok(Some(diagnostics)) => diagnostics,
                    Ok(None) => bail!("path not found in archive: {path}"),
                    Err(ExtractError::Format(FormatError::ReaderUnsupported(message)))
                        if message.contains("regular file") =>
                    {
                        bail!("--stdout supports regular file members only");
                    }
                    Err(err) => return Err(err.into()),
                };
                stdout.flush()?;
                emit_member_metadata_diagnostics(quiet, path, &diagnostics)?;
                return Ok(());
            }

            if dry_run {
                eprintln!("extract dry-run summary:");
                eprintln!("  destination: {}", directory);
                eprintln!("  archive members:");
                for entry in &requested_entries {
                    eprintln!("    {} ({} bytes)", entry.path, entry.file_data_size);
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
            let diagnostics = if paths.is_empty() {
                opened.extract_indexed_files_to(&root, options, reader_options.jobs)?
            } else {
                extract_entries_to_dir_parallel(
                    &opened,
                    requested_entries,
                    &root,
                    options,
                    reader_options.jobs,
                )?
            };
            for (path, diagnostics) in diagnostics {
                extracted_count = extracted_count
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("extracted path count overflow"))?;
                degraded_metadata_count = degraded_metadata_count
                    .checked_add(diagnostics.len() as u64)
                    .ok_or_else(|| anyhow!("degraded metadata count overflow"))?;
                emit_member_metadata_diagnostics(quiet, &path, &diagnostics)?;
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
            recipient_key,
            insecure_zero_key,
            bootstrap,
            volumes,
            long,
            json,
            jobs,
        } => {
            let reader_options = reader_options(resolve_jobs(jobs)?);
            reject_multi_volume_bootstrap(1 + volumes.len(), bootstrap.as_deref())?;
            if archive == "-" {
                reject_archive_stdin_list_options(
                    &volumes,
                    password_stdin,
                    password,
                    keyfile.as_deref(),
                    recipient_key.as_deref(),
                    insecure_zero_key,
                )?;
                let bootstrap_bytes = read_optional_bootstrap_sidecar(bootstrap.as_deref())?;
                let stdin = io::stdin();
                let report = if let Some(keyfile) = keyfile.as_deref() {
                    let master_key = load_archive_stdin_key(
                        Some(keyfile),
                        password_stdin,
                        password,
                        insecure_zero_key,
                    )?;
                    if let Some(bootstrap_bytes) = bootstrap_bytes.as_deref() {
                        list_non_seekable_stream_with_bootstrap_sidecar(
                            stdin.lock(),
                            bootstrap_bytes,
                            &master_key,
                            non_seekable_reader_options(reader_options),
                        )
                    } else {
                        list_non_seekable_stream(
                            stdin.lock(),
                            &master_key,
                            non_seekable_reader_options(reader_options),
                        )
                    }
                } else if let Some(recipient_key) = recipient_key.as_deref() {
                    let lookup = load_recipient_private_key_lookup(recipient_key)?;
                    let mut stats = RecipientWrapOpenStats::default();
                    if let Some(bootstrap_bytes) = bootstrap_bytes.as_deref() {
                        list_non_seekable_stream_with_recipient_wrap_resolver_and_bootstrap_sidecar(
                            stdin.lock(),
                            bootstrap_bytes,
                            |context| {
                                recipient_wrap_candidates_for_record(context, &lookup, &mut stats)
                            },
                            non_seekable_reader_options(reader_options),
                        )
                    } else {
                        list_non_seekable_stream_with_recipient_wrap_resolver(
                            stdin.lock(),
                            |context| {
                                recipient_wrap_candidates_for_record(context, &lookup, &mut stats)
                            },
                            non_seekable_reader_options(reader_options),
                        )
                    }
                } else {
                    if let Some(bootstrap_bytes) = bootstrap_bytes.as_deref() {
                        list_unencrypted_non_seekable_stream_with_bootstrap_sidecar(
                            stdin.lock(),
                            bootstrap_bytes,
                            non_seekable_reader_options(reader_options),
                        )
                    } else {
                        list_unencrypted_non_seekable_stream(
                            stdin.lock(),
                            non_seekable_reader_options(reader_options),
                        )
                    }
                }
                .context("failed to list non-seekable archive stream")?;
                emit_entry_metadata_diagnostics(quiet, &report.entries)?;
                if json {
                    let files = report
                        .entries
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
                        serde_json::to_string(&json!({
                            "streaming_mode": "non-seekable",
                            "verification": {
                                "file_count": report.verification.file_count,
                                "tar_total_size": report.verification.tar_total_size,
                            },
                            "files": files,
                        }))
                        .context("failed to encode list output as JSON")?
                    );
                    return Ok(());
                }
                if long {
                    for entry in report.entries {
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
                    }
                    return Ok(());
                }
                for entry in report.entries {
                    println!("{}", entry.path);
                }
                return Ok(());
            }
            let selection = resolve_archive_input_paths(&archive, &volumes, bootstrap.is_none())?;
            let opened = if let Some(recipient_key) = recipient_key.as_deref() {
                open_selection_with_recipient_key(
                    &selection,
                    recipient_key,
                    bootstrap.as_deref(),
                    reader_options,
                )
                .map(|opened_selection| opened_selection.opened)
            } else {
                let master_key = load_open_key_from_paths(
                    keyfile.as_deref(),
                    password_stdin,
                    password,
                    insecure_zero_key,
                    &selection.paths,
                )?;
                open_selection_maybe_bootstrap(
                    &selection,
                    &master_key,
                    bootstrap.as_deref(),
                    reader_options,
                )
            }
            .with_context(|| format!("failed to open archive {archive}"))?;
            if json || long {
                let entries = opened.list_files()?;
                emit_entry_metadata_diagnostics(quiet, &entries)?;
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
                    }
                    Ok(())
                }
            } else {
                for entry in opened.list_index_entries()? {
                    println!("{}", entry.path);
                }
                Ok(())
            }
        }
        Command::Verify {
            archives,
            password_stdin,
            password,
            keyfile,
            recipient_key,
            insecure_zero_key,
            trusted_public_key,
            trusted_ca_cert,
            trusted_system_roots,
            public_no_key,
            fast,
            bootstrap,
            json,
            write_repaired,
            jobs,
        } => {
            let reader_options = reader_options(resolve_jobs(jobs)?);
            let first = archives
                .first()
                .ok_or_else(|| anyhow!("at least one archive volume is required"))?;
            let archive_paths = archives.to_vec();
            if let Err(err) = validate_fast_verify_options(
                fast,
                public_no_key,
                trusted_public_key.is_some(),
                !trusted_ca_cert.is_empty(),
                trusted_system_roots,
                write_repaired,
            ) {
                if json {
                    emit_verify_json_error(&archive_paths, None, None, &err)?;
                }
                return Err(err);
            }
            if archives.iter().any(|path| path == "-") {
                if write_repaired {
                    let err = anyhow!(FormatError::ReaderUnsupported(
                        "--write-repaired is not supported for archive stdin",
                    ));
                    if json {
                        emit_verify_json_error(&archive_paths, None, None, &err)?;
                    }
                    return Err(err);
                }
                if fast {
                    let err = anyhow!(UsageError(
                        "--fast requires seekable archive paths; archive stdin uses full non-seekable verification",
                    ));
                    if json {
                        emit_verify_json_error(&archive_paths, None, None, &err)?;
                    }
                    return Err(err);
                }
                if json && archives.len() != 1 {
                    let err = anyhow!(FormatError::ReaderUnsupported(
                        "archive stdin must be the only archive input",
                    ));
                    emit_verify_json_error(&archive_paths, None, None, &err)?;
                    return Err(err);
                }
                if first != "-" || archives.len() != 1 {
                    return Err(anyhow!(FormatError::ReaderUnsupported(
                        "archive stdin must be the only archive input",
                    )));
                }
                if public_no_key {
                    let err = anyhow!(FormatError::ReaderUnsupported(
                        "public no-key verification is not supported for archive stdin",
                    ));
                    if json {
                        emit_verify_json_error(&archive_paths, None, None, &err)?;
                    }
                    return Err(err);
                }
                if trusted_public_key.is_some()
                    || !trusted_ca_cert.is_empty()
                    || trusted_system_roots
                {
                    let err = anyhow!(FormatError::ReaderUnsupported(
                        "RootAuth external verification is not supported for archive stdin",
                    ));
                    if json {
                        emit_verify_json_error(&archive_paths, None, None, &err)?;
                    }
                    return Err(err);
                }
                let bootstrap_bytes = match read_optional_bootstrap_sidecar(bootstrap.as_deref()) {
                    Ok(bootstrap_bytes) => bootstrap_bytes,
                    Err(err) => {
                        if json {
                            emit_verify_json_error(&archive_paths, None, None, &err)?;
                        }
                        return Err(err);
                    }
                };
                let stdin = io::stdin();
                let result = if let Some(keyfile) = keyfile.as_deref() {
                    let master_key = match load_archive_stdin_key(
                        Some(keyfile),
                        password_stdin,
                        password,
                        insecure_zero_key,
                    ) {
                        Ok(master_key) => master_key,
                        Err(err) => {
                            if json {
                                emit_verify_json_error(&archive_paths, None, None, &err)?;
                            }
                            return Err(err);
                        }
                    };
                    if let Some(bootstrap_bytes) = bootstrap_bytes.as_deref() {
                        verify_non_seekable_stream_with_bootstrap_sidecar(
                            stdin.lock(),
                            bootstrap_bytes,
                            &master_key,
                            non_seekable_reader_options(reader_options),
                        )
                    } else {
                        verify_non_seekable_stream_with_options(
                            stdin.lock(),
                            &master_key,
                            non_seekable_reader_options(reader_options),
                        )
                    }
                } else if let Some(recipient_key) = recipient_key.as_deref() {
                    let lookup = match load_recipient_private_key_lookup(recipient_key) {
                        Ok(lookup) => lookup,
                        Err(err) => {
                            if json {
                                emit_verify_json_error(&archive_paths, None, None, &err)?;
                            }
                            return Err(err);
                        }
                    };
                    let mut stats = RecipientWrapOpenStats::default();
                    if let Some(bootstrap_bytes) = bootstrap_bytes.as_deref() {
                        verify_non_seekable_stream_with_recipient_wrap_resolver_and_bootstrap_sidecar(
                            stdin.lock(),
                            bootstrap_bytes,
                            |context| recipient_wrap_candidates_for_record(context, &lookup, &mut stats),
                            non_seekable_reader_options(reader_options),
                        )
                    } else {
                        verify_non_seekable_stream_with_recipient_wrap_resolver_options(
                            stdin.lock(),
                            |context| recipient_wrap_candidates_for_record(context, &lookup, &mut stats),
                            non_seekable_reader_options(reader_options),
                        )
                    }
                } else {
                    if let Some(bootstrap_bytes) = bootstrap_bytes.as_deref() {
                        verify_unencrypted_non_seekable_stream_with_bootstrap_sidecar(
                            stdin.lock(),
                            bootstrap_bytes,
                            non_seekable_reader_options(reader_options),
                        )
                    } else {
                        verify_unencrypted_non_seekable_stream_with_options(
                            stdin.lock(),
                            non_seekable_reader_options(reader_options),
                        )
                    }
                }
                .context("failed to verify non-seekable archive stream");
                let report = match result {
                    Ok(report) => report,
                    Err(err) => {
                        if json {
                            emit_verify_json_error(&archive_paths, None, None, &err)?;
                        }
                        return Err(err);
                    }
                };
                if json {
                    println!(
                        "{}",
                        serde_json::to_string(&json!({
                            "ok": true,
                            "archives": &archive_paths,
                            "verification_mode": "key-holding-non-seekable-stream",
                            "status": {
                                "revision_mode": revision_mode_label(report.volume_format_rev),
                                "format_version": FORMAT_VERSION,
                                "volume_format_rev": report.volume_format_rev,
                                "header_base_integrity": "verified",
                                "decryption_keywrap": if recipient_key.is_some() {
                                    "recipientwrap_opened"
                                } else if keyfile.is_some() {
                                    "key_holding_decrypted"
                                } else {
                                    "plaintext_opened"
                                },
                                "root_auth_signer": match report.root_auth {
                                    SequentialRootAuthStatus::Absent => "absent",
                                    SequentialRootAuthStatus::WireValidOnly => "wire_valid_only",
                                },
                                "trust_policy": "not_requested",
                                "public_no_key_metadata_only": "not_requested",
                            },
                            "volume_count": report.total_volumes,
                            "file_count": report.file_count,
                            "tar_total_size": report.tar_total_size,
                        }))
                        .context("failed to encode verify output as JSON")?
                    );
                    return Ok(());
                }
                emit_success_stdout(
                    quiet,
                    &format!(
                        "{} {} ({} volume(s), {} file(s))",
                        "-: OK non-seekable stream",
                        revision_mode_label(report.volume_format_rev),
                        report.total_volumes,
                        report.file_count
                    ),
                )?;
                if report.root_auth == SequentialRootAuthStatus::WireValidOnly {
                    emit_success_stdout(
                        quiet,
                        "root-auth: wire-valid-only (signer trust not checked)",
                    )?;
                }
                return Ok(());
            }
            if public_no_key {
                if write_repaired {
                    let err = anyhow!(FormatError::ReaderUnsupported(
                        "--write-repaired requires key-holding verification",
                    ));
                    if json {
                        emit_verify_json_error(&archive_paths, None, None, &err)?;
                    }
                    return Err(err);
                }
                return run_public_no_key_verify(PublicNoKeyVerifyRequest {
                    archive_paths: &archive_paths,
                    trusted_public_key: trusted_public_key.as_deref(),
                    trusted_ca_cert: &trusted_ca_cert,
                    trusted_system_roots,
                    password_stdin,
                    password,
                    keyfile: keyfile.as_deref(),
                    recipient_key: recipient_key.as_deref(),
                    insecure_zero_key,
                    bootstrap: bootstrap.as_deref(),
                    reader_options,
                    quiet,
                    json,
                });
            }
            if let Err(err) = validate_verify_key_holding_key_source(
                keyfile.as_deref(),
                recipient_key.as_deref(),
                password_stdin,
                password,
                insecure_zero_key,
            ) {
                if json {
                    emit_verify_json_error(&archive_paths, None, None, &err)?;
                }
                return Err(err);
            }
            if let Err(err) = reject_multi_volume_bootstrap(archives.len(), bootstrap.as_deref()) {
                if json {
                    emit_verify_json_error(&archive_paths, None, None, &err)?;
                }
                return Err(err);
            }
            if write_repaired && bootstrap.is_some() {
                let err = anyhow!(FormatError::ReaderUnsupported(
                    "--write-repaired is not supported with --bootstrap",
                ));
                if json {
                    emit_verify_json_error(&archive_paths, None, None, &err)?;
                }
                return Err(err);
            }
            let selection =
                match resolve_archive_input_paths(first, &archives[1..], bootstrap.is_none()) {
                    Ok(selection) => selection,
                    Err(err) => {
                        if json {
                            emit_verify_json_error(&archive_paths, None, None, &err)?;
                        }
                        return Err(err);
                    }
                };
            let archive_paths = selection.paths.clone();
            let opened_selection_result = if let Some(recipient_key) = recipient_key.as_deref() {
                open_selection_with_recipient_key(
                    &selection,
                    recipient_key,
                    bootstrap.as_deref(),
                    reader_options,
                )
            } else {
                let master_key = match load_open_key_from_paths(
                    keyfile.as_deref(),
                    password_stdin,
                    password,
                    insecure_zero_key,
                    &selection.paths,
                ) {
                    Ok(master_key) => master_key,
                    Err(err) => {
                        if json {
                            emit_verify_json_error(&archive_paths, None, None, &err)?;
                        }
                        return Err(err);
                    }
                };
                open_selection_maybe_bootstrap_resolved(
                    &selection,
                    &master_key,
                    bootstrap.as_deref(),
                    reader_options,
                )
            };
            let opened_selection = match opened_selection_result
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
            let archive_paths = opened_selection.paths;
            let opened = opened_selection.opened;
            let result = if fast {
                opened
                    .verify_content_fast()
                    .with_context(|| format!("failed to fast-verify archive {first}"))
            } else {
                opened
                    .verify_content()
                    .with_context(|| format!("failed to verify archive {first}"))
            };
            let volume_count = opened.manifest_footer.total_volumes;
            let file_count = opened.index_root.header.file_count;
            match result {
                Ok(content_verification) => {
                    let root_auth = if fast {
                        None
                    } else {
                        match verify_opened_root_auth(
                            &opened,
                            &content_verification,
                            trusted_public_key.as_deref(),
                            &trusted_ca_cert,
                            trusted_system_roots,
                        )
                        .with_context(|| format!("failed to verify RootAuth for {first}"))
                        {
                            Ok(root_auth) => root_auth,
                            Err(err) => {
                                if json {
                                    emit_verify_json_error(
                                        &archive_paths,
                                        Some(volume_count as u64),
                                        Some(file_count),
                                        &err,
                                    )?;
                                }
                                return Err(err);
                            }
                        }
                    };
                    let entries = opened.list_files()?;
                    emit_entry_metadata_diagnostics(quiet, &entries)?;
                    let repaired_outputs = if write_repaired {
                        match write_repaired_archive_copies(&archive_paths, &opened) {
                            Ok(outputs) => outputs,
                            Err(err) => {
                                if json {
                                    emit_verify_json_error(
                                        &archive_paths,
                                        Some(volume_count as u64),
                                        Some(file_count),
                                        &err,
                                    )?;
                                }
                                return Err(err);
                            }
                        }
                    } else {
                        Vec::new()
                    };
                    if json {
                        let mut payload = json!({
                            "ok": true,
                            "archives": &archive_paths,
                            "verification_mode": if fast { "fast" } else { "key-holding" },
                            "status": key_holding_status_json(
                                &opened,
                                root_auth.as_ref(),
                                fast,
                                recipient_key.is_some(),
                                trusted_public_key.is_some()
                                    || !trusted_ca_cert.is_empty()
                                    || trusted_system_roots,
                            ),
                            "volume_count": volume_count,
                            "file_count": file_count,
                        });
                        if let Some(root_auth) = &root_auth {
                            payload["root_auth"] = root_auth_json(root_auth);
                        } else if fast {
                            let diagnostics = fast_verify_diagnostic_labels(&opened);
                            payload["diagnostics"] = json!(diagnostics);
                            if opened.root_auth_footer.is_some() {
                                payload["root_auth"] = json!({
                                    "status": "root_auth_deferred_full_archive_scan_required",
                                    "diagnostics": ["root_auth_deferred_full_archive_scan_required"],
                                });
                            }
                        }
                        if write_repaired {
                            payload["repaired_outputs"] = json!(repaired_outputs
                                .iter()
                                .map(|output| json!({
                                    "path": output.path.clone(),
                                    "volume_index": output.volume_index,
                                    "repaired_block_count": output.repaired_block_count,
                                }))
                                .collect::<Vec<_>>());
                        }
                        println!(
                            "{}",
                            serde_json::to_string(&payload)
                                .context("failed to encode verify output as JSON")?
                        );
                        return Ok(());
                    }
                    emit_success_stdout(
                        quiet,
                        &format!(
                            "{}: OK{} {} {} ({} volume(s), {} file(s))",
                            first,
                            if fast { " fast" } else { "" },
                            revision_mode_label(opened.volume_header.volume_format_rev),
                            key_access_status(&opened, recipient_key.is_some()),
                            volume_count,
                            file_count
                        ),
                    )?;
                    if fast {
                        emit_fast_verify_diagnostics_stdout(quiet, &opened)?;
                    } else if let Some(root_auth) = &root_auth {
                        emit_root_auth_stdout(quiet, root_auth)?;
                    }
                    if write_repaired {
                        if repaired_outputs.is_empty() {
                            emit_success_stdout(
                                quiet,
                                "no repaired output written; no recoverable block damage found",
                            )?;
                        } else {
                            for output in repaired_outputs {
                                emit_success_stdout(
                                    quiet,
                                    &format!(
                                        "wrote repaired volume copy {} ({} block(s))",
                                        output.path, output.repaired_block_count
                                    ),
                                )?;
                            }
                        }
                    }
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
        Command::SigningKeygen {
            secret_output,
            public_output,
            force,
        } => {
            if Path::new(&secret_output) == Path::new(&public_output) {
                return Err(UsageError(
                    "--secret-output and --public-output must be different paths",
                )
                .into());
            }
            if !force {
                check_output_path_free("signing secret output", Path::new(&secret_output))?;
                check_output_path_free("signing public output", Path::new(&public_output))?;
            }
            let signing_key = generate_ed25519_signing_key();
            let secret_hex = format!("{}\n", encode_hex(&signing_key.to_bytes()));
            let public_hex = format!("{}\n", encode_hex(&signing_key.verifying_key().to_bytes()));
            write_atomic_output_file(
                "signing secret",
                Path::new(&secret_output),
                secret_hex.as_bytes(),
                force,
            )?;
            write_atomic_output_file(
                "signing public key",
                Path::new(&public_output),
                public_hex.as_bytes(),
                force,
            )?;
            emit_success_summary(
                quiet,
                &format!("wrote signing keypair to {secret_output} and {public_output}"),
            )?;
            Ok(())
        }
        Command::TrustInfo { json } => emit_trust_info(json).map_err(Into::into),
    }
}

fn emit_trust_info(json_output: bool) -> io::Result<()> {
    let build_profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "official_tzap_root_certificate_sha256": OFFICIAL_TZAP_ROOT_CERT_SHA256,
                "official_tzap_root_source": "embedded",
                "package": env!("CARGO_PKG_NAME"),
                "version": env!("CARGO_PKG_VERSION"),
                "repository": env!("CARGO_PKG_REPOSITORY"),
                "build_profile": build_profile,
                "target_os": std::env::consts::OS,
                "target_arch": std::env::consts::ARCH,
            }))
            .expect("trust-info JSON is serializable")
        );
        return Ok(());
    }
    println!("tzap {}", env!("CARGO_PKG_VERSION"));
    println!("repository: {}", env!("CARGO_PKG_REPOSITORY"));
    println!("build-profile: {build_profile}");
    println!(
        "target: {}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!("official-tzap-root-source: embedded");
    println!("official-tzap-root-sha256: {OFFICIAL_TZAP_ROOT_CERT_SHA256}");
    Ok(())
}

fn emit_success_summary(quiet: bool, message: &str) -> io::Result<()> {
    if quiet {
        return Ok(());
    }
    eprintln!("{message}");
    Ok(())
}

fn emit_create_timing_report(
    scan_inputs: Duration,
    read_inputs: Duration,
    core_writer: Duration,
    write_outputs: Duration,
    total: Duration,
    writer: WriterTimings,
) -> io::Result<()> {
    let accounted = scan_inputs + read_inputs + core_writer + write_outputs;
    let other_cli = total.saturating_sub(accounted);
    eprintln!("create timings:");
    eprintln!("  scan inputs: {}", format_duration(scan_inputs));
    eprintln!("  read inputs: {}", format_duration(read_inputs));
    eprintln!("  core writer: {}", format_duration(core_writer));
    eprintln!("  write outputs: {}", format_duration(write_outputs));
    eprintln!("  other CLI: {}", format_duration(other_cli));
    eprintln!("  total: {}", format_duration(total));
    eprintln!("writer timings:");
    eprintln!("  plan payload: {}", format_duration(writer.plan_payload));
    eprintln!("  plan metadata: {}", format_duration(writer.plan_metadata));
    eprintln!("  emit payload: {}", format_duration(writer.emit_payload));
    eprintln!("  emit metadata: {}", format_duration(writer.emit_metadata));
    eprintln!("  total: {}", format_duration(writer.total));
    Ok(())
}

fn format_duration(duration: Duration) -> String {
    format!("{:.3}s", duration.as_secs_f64())
}

fn emit_success_stdout(quiet: bool, message: &str) -> io::Result<()> {
    if quiet {
        return Ok(());
    }
    println!("{message}");
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct CreateLayoutOverrides<'a> {
    chunk_size: Option<&'a str>,
    envelope_size: Option<&'a str>,
    block_size: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CreateLayout {
    block_size: u32,
    chunk_size: u32,
    envelope_target_size: u32,
}

#[derive(Debug, Clone, Copy)]
struct CreateWriterOptionsArgs<'a> {
    volumes: Option<u32>,
    volume_size: Option<&'a str>,
    volume_loss_tolerance: u8,
    bit_rot_buffer_pct: u8,
    compression_level: i32,
    jobs: usize,
    layout_overrides: CreateLayoutOverrides<'a>,
    total_input_size: Option<u64>,
}

fn create_writer_options(args: CreateWriterOptionsArgs<'_>) -> Result<WriterOptions> {
    let layout = resolve_create_layout(args.layout_overrides, args.total_input_size)?;
    Ok(WriterOptions {
        stripe_width: args.volumes.unwrap_or(1),
        target_volume_size: args
            .volume_size
            .map(|value| parse_size(value).with_context(|| format!("invalid volume-size: {value}")))
            .transpose()?,
        volume_loss_tolerance: args.volume_loss_tolerance,
        bit_rot_buffer_pct: args.bit_rot_buffer_pct,
        zstd_level: args.compression_level,
        jobs: args.jobs,
        chunk_size: layout.chunk_size,
        envelope_target_size: layout.envelope_target_size,
        block_size: layout.block_size,
        ..WriterOptions::default()
    })
}

fn resolve_create_layout(
    overrides: CreateLayoutOverrides<'_>,
    total_input_size: Option<u64>,
) -> Result<CreateLayout> {
    let mut layout = default_create_layout(total_input_size);
    if let Some(value) = overrides.block_size {
        layout.block_size = parse_size_u32(value, "block-size")?;
    }
    if let Some(value) = overrides.envelope_size {
        layout.envelope_target_size = parse_size_u32(value, "envelope-size")?;
    }
    if let Some(value) = overrides.chunk_size {
        layout.chunk_size = parse_size_u32(value, "chunk-size")?;
        if overrides.envelope_size.is_none() && layout.chunk_size > layout.envelope_target_size {
            layout.envelope_target_size = layout.chunk_size;
        }
    }
    Ok(layout)
}

fn default_create_layout(total_input_size: Option<u64>) -> CreateLayout {
    match total_input_size {
        Some(size) if size <= LARGE_CREATE_LAYOUT_THRESHOLD => CreateLayout {
            block_size: 64 * 1024,
            chunk_size: 256 * 1024,
            envelope_target_size: 1024 * 1024,
        },
        Some(_) | None => CreateLayout {
            block_size: 1024 * 1024,
            chunk_size: 32 * 1024 * 1024,
            envelope_target_size: 64 * 1024 * 1024,
        },
    }
}

fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map(|jobs| jobs.get())
        .unwrap_or(1)
}

fn resolve_jobs(jobs: Option<usize>) -> Result<usize> {
    let jobs = jobs.unwrap_or_else(default_jobs);
    if jobs == 0 {
        return Err(UsageError("--jobs must be at least 1").into());
    }
    Ok(jobs)
}

fn validate_fast_verify_options(
    fast: bool,
    public_no_key: bool,
    has_trusted_public_key: bool,
    has_trusted_ca_cert: bool,
    trusted_system_roots: bool,
    write_repaired: bool,
) -> Result<()> {
    if !fast {
        return Ok(());
    }
    if public_no_key {
        return Err(UsageError("--fast cannot be combined with --public-no-key").into());
    }
    if has_trusted_public_key || has_trusted_ca_cert || trusted_system_roots {
        return Err(UsageError(
            "--fast cannot be combined with RootAuth trust options; omit --fast for full RootAuth verification",
        )
        .into());
    }
    if write_repaired {
        return Err(UsageError("--fast cannot be combined with --write-repaired").into());
    }
    Ok(())
}

fn reader_options(jobs: usize) -> ReaderOptions {
    ReaderOptions {
        jobs,
        ..ReaderOptions::default()
    }
}

fn non_seekable_reader_options(reader: ReaderOptions) -> NonSeekableReaderOptions {
    NonSeekableReaderOptions {
        reader,
        ..NonSeekableReaderOptions::default()
    }
}

fn metadata_diagnostic_line(path: &str, diagnostic: &MetadataDiagnostic) -> String {
    format!(
        "tzap: degraded-metadata: {}: {}: {}",
        path, diagnostic.profile, diagnostic.message
    )
}

fn emit_member_metadata_diagnostics(
    quiet: bool,
    path: &str,
    diagnostics: &[MetadataDiagnostic],
) -> io::Result<()> {
    if quiet {
        return Ok(());
    }
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

#[cfg(test)]
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

fn emit_entry_metadata_diagnostics(quiet: bool, entries: &[ArchiveEntry]) -> io::Result<()> {
    if quiet {
        return Ok(());
    }
    for line in metadata_diagnostic_lines_for_entries(entries) {
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
    if diagnostic.label == "unsupported-revision" {
        let payload = json!({
            "ok": false,
            "archives": archives,
            "error": unsupported_revision_error_json(err, diagnostic.action),
        });
        println!(
            "{}",
            serde_json::to_string(&payload)
                .context("failed to encode verify error output as JSON")?
        );
        return Ok(());
    }
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

fn unsupported_revision_error_json(err: &anyhow::Error, action: &'static str) -> serde_json::Value {
    for cause in err.chain() {
        if let Some(format) = cause.downcast_ref::<FormatError>() {
            match format {
                FormatError::UnsupportedFormatVersion(observed_format_version) => {
                    return json!({
                    "label": "unsupported-revision",
                    "observed": {
                        "format_version": observed_format_version,
                    },
                    "supported": {
                        "format_version": FORMAT_VERSION,
                        "max_volume_format_rev": READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
                    },
                    "action": action,
                    });
                }
                FormatError::UnsupportedVolumeFormatRevision {
                    format_version,
                    volume_format_rev,
                    reader_max_supported_revision,
                } => {
                    return json!({
                    "label": "unsupported-revision",
                    "observed": {
                        "format_version": format_version,
                        "volume_format_rev": volume_format_rev,
                    },
                    "supported": {
                        "format_version": FORMAT_VERSION,
                        "max_volume_format_rev": reader_max_supported_revision,
                    },
                    "action": action,
                    });
                }
                _ => {}
            }
        }
    }
    json!({
        "label": "unsupported-revision",
        "observed": null,
        "supported": {
            "format_version": FORMAT_VERSION,
            "max_volume_format_rev": READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
        },
        "action": action,
    })
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

impl RegularFileSource for InputSpec {
    fn archive_path(&self) -> &str {
        &self.archive_path
    }

    fn file_data_size(&self) -> u64 {
        self.size
    }

    fn mode(&self) -> u32 {
        self.mode
    }

    fn mtime(&self) -> u64 {
        self.mtime
    }

    fn open(&self) -> std::result::Result<Box<dyn Read + '_>, ArchiveWriteError> {
        File::open(&self.source)
            .map(|file| Box::new(file) as Box<dyn Read + '_>)
            .map_err(ArchiveWriteError::Io)
    }
}

#[derive(Debug)]
struct CreateKey {
    master_key: MasterKey,
    kdf_params: KdfParams,
}

#[derive(Debug)]
enum CreateRootAuthProfile {
    Ed25519 {
        signing_key: SigningKey,
        signer_identity: [u8; 32],
    },
    X509(X509RootAuthSigner),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliX509SignatureScheme {
    #[value(name = "rsa-pkcs1-sha256")]
    RsaPkcs1Sha256,
    #[value(name = "ecdsa-sha256-der")]
    EcdsaSha256Der,
    #[value(name = "rsa-pss-sha256")]
    RsaPssSha256,
}

impl CliX509SignatureScheme {
    fn to_plugin_scheme(self) -> X509SignatureScheme {
        match self {
            Self::RsaPkcs1Sha256 => X509SignatureScheme::RsaPkcs1Sha256,
            Self::EcdsaSha256Der => X509SignatureScheme::EcdsaSha256Der,
            Self::RsaPssSha256 => X509SignatureScheme::RsaPssSha256,
        }
    }
}

#[derive(Debug)]
enum VerifiedRootAuth {
    Ed25519(RootAuthVerification),
    X509 {
        verification: RootAuthVerification,
        report: Box<X509RootAuthReport>,
    },
}

#[derive(Debug)]
enum PublicNoKeyTrust {
    Ed25519 {
        public_key: [u8; 32],
    },
    X509 {
        trusted_roots_der: Vec<Vec<u8>>,
        trusted_system_roots: bool,
    },
}

#[derive(Debug)]
enum VerifiedPublicNoKeyRootAuth {
    Ed25519(PublicNoKeyVerification),
    X509 {
        verification: PublicNoKeyVerification,
        report: Box<X509RootAuthReport>,
    },
}

#[derive(Debug, Clone, Copy)]
enum CreateStdinMode {
    Tar,
    RawUnknownSize,
    RawKnownSize,
    RawSpool,
}

#[derive(Debug)]
struct CreateStdinArgs<'a> {
    tar_stdin: bool,
    raw_stdin: bool,
    stdin_name: Option<&'a str>,
    stdin_size: Option<&'a str>,
    spool_stdin: bool,
    paths: &'a [String],
    password_stdin: bool,
    password: bool,
    has_dictionary: bool,
    volumes: Option<u32>,
    volume_size: Option<&'a str>,
    volume_loss_tolerance: Option<u8>,
}

#[derive(Debug, Clone, Copy)]
struct Diagnostic {
    label: &'static str,
    exit_code: u8,
    action: &'static str,
}

#[derive(Debug)]
struct UsageError(&'static str);

impl std::fmt::Display for UsageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for UsageError {}

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

fn input_specs_total_size(specs: &[InputSpec]) -> Result<u64> {
    specs.iter().try_fold(0u64, |sum, entry| {
        sum.checked_add(entry.size)
            .ok_or_else(|| anyhow!("input byte count overflow"))
    })
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

fn resolve_extract_index_entries(
    opened: &OpenedArchive,
    requested: &[String],
) -> Result<(Vec<ArchiveIndexEntry>, Vec<String>)> {
    if requested.is_empty() {
        return Ok((opened.list_index_entries()?, Vec::new()));
    }

    let mut resolved = Vec::with_capacity(requested.len());
    let mut missing = Vec::new();
    for path in requested {
        match opened.lookup_index_entry(path)? {
            Some(entry) => resolved.push(entry),
            None => missing.push(path.clone()),
        }
    }
    Ok((resolved, missing))
}

fn extract_entries_to_dir_parallel(
    opened: &OpenedArchive,
    entries: Vec<ArchiveIndexEntry>,
    root: &Path,
    options: SafeExtractionOptions,
    jobs: usize,
) -> Result<Vec<(String, Vec<MetadataDiagnostic>)>> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    if jobs <= 1 || entries.len() <= 1 {
        return entries
            .into_iter()
            .map(|entry| {
                let path = entry.path;
                let diagnostics = opened
                    .extract_file_to(&path, root, options)?
                    .ok_or_else(|| anyhow!("path not found in archive: {path}"))?;
                Ok((path, diagnostics))
            })
            .collect();
    }

    let worker_count = jobs.min(entries.len());
    let chunk_size = entries.len().div_ceil(worker_count);
    std::thread::scope(|scope| {
        let handles = entries
            .chunks(chunk_size)
            .map(|chunk| {
                let chunk = chunk.to_vec();
                scope.spawn(move || {
                    chunk
                        .into_iter()
                        .map(|entry| {
                            let path = entry.path;
                            let diagnostics = opened
                                .extract_file_to(&path, root, options)?
                                .ok_or_else(|| anyhow!("path not found in archive: {path}"))?;
                            Ok((path, diagnostics))
                        })
                        .collect::<Result<Vec<_>>>()
                })
            })
            .collect::<Vec<_>>();
        let mut out = Vec::new();
        for handle in handles {
            let mut chunk = handle
                .join()
                .map_err(|_| anyhow!("extract worker panicked"))??;
            out.append(&mut chunk);
        }
        Ok(out)
    })
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

fn write_archive_outputs(output: &str, volumes: &[Vec<u8>], force: bool) -> Result<()> {
    if volumes.is_empty() {
        bail!("writer returned no volumes");
    }
    let output_paths = create_output_paths(output, volumes.len());
    let mut temps = create_archive_output_temps(&output_paths)?;
    for ((temp, output_path), volume) in temps.iter_mut().zip(&output_paths).zip(volumes) {
        temp.as_file_mut().write_all(volume).with_context(|| {
            format!(
                "failed to write temporary archive volume for {}",
                output_path.display()
            )
        })?;
    }
    flush_archive_output_temps(&mut temps, &output_paths)?;
    publish_archive_output_temps(temps, &output_paths, force)?;
    Ok(())
}

struct PathBackedArchiveSink<'a> {
    temps: &'a mut [tempfile::NamedTempFile],
    bootstrap_sidecar: Vec<u8>,
}

impl ArchiveWriteSink for PathBackedArchiveSink<'_> {
    fn begin_archive(&mut self, volume_count: usize) -> std::result::Result<(), ArchiveWriteError> {
        if volume_count != self.temps.len() {
            return Err(FormatError::WriterInvariant(
                "stdin file sink volume count does not match output paths",
            )
            .into());
        }
        for temp in self.temps.iter_mut() {
            let file = temp.as_file_mut();
            file.set_len(0).map_err(ArchiveWriteError::Io)?;
            file.seek(SeekFrom::Start(0))
                .map_err(ArchiveWriteError::Io)?;
        }
        self.bootstrap_sidecar.clear();
        Ok(())
    }

    fn write_volume(
        &mut self,
        volume_index: usize,
        bytes: &[u8],
    ) -> std::result::Result<(), ArchiveWriteError> {
        let temp = self
            .temps
            .get_mut(volume_index)
            .ok_or(FormatError::WriterInvariant(
                "stdin file sink volume index is out of bounds",
            ))?;
        temp.as_file_mut()
            .write_all(bytes)
            .map_err(ArchiveWriteError::Io)
    }

    fn write_bootstrap_sidecar(
        &mut self,
        bytes: &[u8],
    ) -> std::result::Result<(), ArchiveWriteError> {
        self.bootstrap_sidecar.extend_from_slice(bytes);
        Ok(())
    }
}

fn write_tar_stdin_archive_output(
    output: &str,
    key: &CreateKey,
    options: WriterOptions,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    root_auth_profile: Option<&CreateRootAuthProfile>,
    force: bool,
) -> Result<(StreamingTarWriterSummary, Vec<u8>)> {
    let stdin = io::stdin();
    let mut stdin_lock = stdin.lock();
    if let (Some(profile), Some(root_auth)) = (root_auth_profile, root_auth) {
        let mut authenticator =
            |request: &RootAuthSigningRequest| root_auth_authenticator_value(profile, request);
        return write_tar_stdin_archive_output_from_reader(
            output,
            &mut stdin_lock,
            key,
            options,
            Some(root_auth),
            Some(&mut authenticator),
            force,
        );
    }
    write_tar_stdin_archive_output_from_reader(
        output,
        &mut stdin_lock,
        key,
        options,
        None,
        None,
        force,
    )
}

fn write_tar_stdin_archive_output_from_reader<R: Read>(
    output: &str,
    reader: &mut R,
    key: &CreateKey,
    options: WriterOptions,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut CliRootAuthAuthenticator<'_>>,
    force: bool,
) -> Result<(StreamingTarWriterSummary, Vec<u8>)> {
    let volume_count = options.stripe_width as usize;
    write_stdin_archive_output_with_sink(output, volume_count, force, |sink| {
        write_tar_stream_archive_to_sink_with_kdf_and_root_auth(
            reader,
            &key.master_key,
            options,
            &key.kdf_params,
            root_auth,
            authenticator,
            sink,
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn write_raw_stdin_archive_output<R: Read>(
    output: &str,
    mut reader: R,
    archive_path: &str,
    input_size: u64,
    key: &CreateKey,
    options: WriterOptions,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    root_auth_profile: Option<&CreateRootAuthProfile>,
    force: bool,
) -> Result<(StreamingRawWriterSummary, Vec<u8>)> {
    if let (Some(profile), Some(root_auth)) = (root_auth_profile, root_auth) {
        let mut authenticator =
            |request: &RootAuthSigningRequest| root_auth_authenticator_value(profile, request);
        return write_raw_stdin_archive_output_from_reader(
            output,
            &mut reader,
            archive_path,
            input_size,
            key,
            options,
            Some(root_auth),
            Some(&mut authenticator),
            force,
        );
    }
    write_raw_stdin_archive_output_from_reader(
        output,
        &mut reader,
        archive_path,
        input_size,
        key,
        options,
        None,
        None,
        force,
    )
}

fn write_file_inputs_ordered_parallel_to_memory(
    input_specs: &[InputSpec],
    key: &CreateKey,
    options: WriterOptions,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    root_auth_profile: Option<&CreateRootAuthProfile>,
) -> Result<(WrittenArchiveSummary, MemoryArchiveSink)> {
    if let (Some(profile), Some(root_auth)) = (root_auth_profile, root_auth) {
        let mut authenticator =
            |request: &RootAuthSigningRequest| root_auth_authenticator_value(profile, request);
        return write_file_inputs_ordered_parallel_to_memory_with_authenticator(
            input_specs,
            key,
            options,
            Some(root_auth),
            Some(&mut authenticator),
        );
    }
    write_file_inputs_ordered_parallel_to_memory_with_authenticator(
        input_specs,
        key,
        options,
        None,
        None,
    )
}

fn write_file_inputs_ordered_parallel_to_memory_with_authenticator(
    input_specs: &[InputSpec],
    key: &CreateKey,
    options: WriterOptions,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut CliRootAuthAuthenticator<'_>>,
) -> Result<(WrittenArchiveSummary, MemoryArchiveSink)> {
    let mut sink = MemoryArchiveSink::default();
    let summary = write_archive_sources_to_sink_ordered_parallel(
        input_specs,
        &key.master_key,
        options,
        &key.kdf_params,
        root_auth,
        authenticator,
        &mut sink,
    )?;
    Ok((summary, sink))
}

fn write_file_inputs_ordered_parallel_recipient_wrap_to_memory(
    input_specs: &[InputSpec],
    master_key: &MasterKey,
    options: WriterOptions,
    recipient_record: tzap_core::wire::RecipientRecordV1,
) -> Result<(WrittenArchiveSummary, MemoryArchiveSink)> {
    let mut sink = MemoryArchiveSink::default();
    let summary = write_archive_sources_to_sink_ordered_parallel_with_recipient_wrap_records(
        input_specs,
        master_key,
        options,
        vec![recipient_record],
        None,
        None,
        &mut sink,
    )?;
    Ok((summary, sink))
}

#[allow(clippy::too_many_arguments)]
fn write_raw_stdin_archive_output_from_reader<R: Read>(
    output: &str,
    reader: &mut R,
    archive_path: &str,
    input_size: u64,
    key: &CreateKey,
    options: WriterOptions,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut CliRootAuthAuthenticator<'_>>,
    force: bool,
) -> Result<(StreamingRawWriterSummary, Vec<u8>)> {
    let volume_count = options.stripe_width as usize;
    write_stdin_archive_output_with_sink(output, volume_count, force, |sink| {
        write_sized_raw_member_archive_to_sink_with_kdf_and_root_auth(
            reader,
            archive_path,
            input_size,
            &key.master_key,
            options,
            &key.kdf_params,
            root_auth,
            authenticator,
            sink,
        )
    })
}

fn write_stdin_archive_output_with_sink<T>(
    output: &str,
    volume_count: usize,
    force: bool,
    write_archive: impl FnOnce(
        &mut PathBackedArchiveSink<'_>,
    ) -> std::result::Result<T, ArchiveWriteError>,
) -> Result<(T, Vec<u8>)> {
    if volume_count == 0 {
        bail!("writer returned no volumes");
    }
    let output_paths = create_output_paths(output, volume_count);
    let mut temps = create_archive_output_temps(&output_paths)?;
    let (summary, bootstrap_sidecar) = {
        let mut sink = PathBackedArchiveSink {
            temps: temps.as_mut_slice(),
            bootstrap_sidecar: Vec::new(),
        };
        let summary = write_archive(&mut sink)?;
        (summary, sink.bootstrap_sidecar)
    };
    flush_archive_output_temps(&mut temps, &output_paths)?;
    publish_archive_output_temps(temps, &output_paths, force)?;
    Ok((summary, bootstrap_sidecar))
}

fn create_archive_output_temps(output_paths: &[PathBuf]) -> Result<Vec<tempfile::NamedTempFile>> {
    output_paths
        .iter()
        .map(|output_path| {
            let parent = output_path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            tempfile::Builder::new()
                .prefix(".tzap-create-")
                .suffix(".partial")
                .tempfile_in(parent)
                .with_context(|| {
                    format!(
                        "failed to create temporary archive output in {}",
                        parent.display()
                    )
                })
        })
        .collect()
}

fn flush_archive_output_temps(
    temps: &mut [tempfile::NamedTempFile],
    output_paths: &[PathBuf],
) -> Result<()> {
    for (temp, output_path) in temps.iter_mut().zip(output_paths) {
        temp.as_file_mut().flush().with_context(|| {
            format!(
                "failed to flush temporary archive for {}",
                output_path.display()
            )
        })?;
        temp.as_file_mut().sync_all().with_context(|| {
            format!(
                "failed to sync temporary archive for {}",
                output_path.display()
            )
        })?;
    }
    Ok(())
}

fn publish_archive_output_temps(
    temps: Vec<tempfile::NamedTempFile>,
    output_paths: &[PathBuf],
    force: bool,
) -> Result<()> {
    let volume_count = output_paths.len();
    let publish_order = if volume_count == 1 {
        vec![0]
    } else {
        (1..volume_count).chain(std::iter::once(0)).collect()
    };
    let mut temp_slots = temps.into_iter().map(Some).collect::<Vec<_>>();
    let mut persisted_paths = Vec::new();
    for volume_index in publish_order {
        let temp = temp_slots[volume_index]
            .take()
            .ok_or_else(|| anyhow!("missing temporary archive volume {volume_index}"))?;
        let output_path = &output_paths[volume_index];
        let publish_result = if force {
            temp.persist(output_path)
        } else {
            temp.persist_noclobber(output_path)
        };
        if let Err(error) = publish_result {
            for path in &persisted_paths {
                let _ = fs::remove_file(path);
            }
            return Err(error.error)
                .with_context(|| format!("failed to publish archive {}", output_path.display()));
        }
        persisted_paths.push(output_path.clone());
    }
    Ok(())
}

fn write_bootstrap_output(path: &str, bytes: &[u8], force: bool) -> Result<()> {
    write_atomic_output_file("bootstrap output", Path::new(path), bytes, force)
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

fn validate_create_stdin_mode(args: CreateStdinArgs<'_>) -> Result<Option<CreateStdinMode>> {
    if args.tar_stdin && args.raw_stdin {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--tar-stdin and --raw-stdin cannot be used together",
        )));
    }
    if args.spool_stdin && !args.raw_stdin {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--spool-stdin requires --raw-stdin",
        )));
    }
    if args.stdin_name.is_some() && !args.raw_stdin {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--stdin-name requires --raw-stdin",
        )));
    }
    if args.stdin_size.is_some() && !args.raw_stdin {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--stdin-size requires --raw-stdin",
        )));
    }

    let Some(mode) = (if args.tar_stdin {
        Some(CreateStdinMode::Tar)
    } else if args.raw_stdin && args.spool_stdin {
        Some(CreateStdinMode::RawSpool)
    } else if args.raw_stdin && args.stdin_size.is_some() {
        Some(CreateStdinMode::RawKnownSize)
    } else if args.raw_stdin {
        Some(CreateStdinMode::RawUnknownSize)
    } else {
        None
    }) else {
        return Ok(None);
    };

    if args.paths != ["-"] {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "stdin create modes require exactly one archive input path: -",
        )));
    }
    if args.password_stdin {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--password-stdin cannot be used when stdin carries archive payload bytes",
        )));
    }
    if args.password {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--password cannot be used when stdin carries archive payload bytes",
        )));
    }
    if args.has_dictionary {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--dictionary is not supported with stdin create modes",
        )));
    }
    if args.volume_size.is_some() {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--volume-size is not supported with stdin create modes",
        )));
    }
    if args.volume_loss_tolerance.unwrap_or(0) != 0 {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--volume-loss-tolerance > 0 is not supported with stdin create modes",
        )));
    }
    if matches!(args.volumes, Some(volumes) if volumes > 1)
        && !matches!(
            mode,
            CreateStdinMode::Tar | CreateStdinMode::RawKnownSize | CreateStdinMode::RawSpool
        )
    {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--volumes > 1 is supported only with --tar-stdin, known-size --raw-stdin, or --raw-stdin --spool-stdin",
        )));
    }

    match mode {
        CreateStdinMode::Tar => {
            if args.stdin_name.is_some() || args.stdin_size.is_some() || args.spool_stdin {
                return Err(anyhow!(FormatError::WriterUnsupported(
                    "--stdin-name, --stdin-size, and --spool-stdin require --raw-stdin",
                )));
            }
        }
        CreateStdinMode::RawUnknownSize => {
            if args.stdin_name.is_none() {
                return Err(anyhow!(FormatError::WriterUnsupported(
                    "--raw-stdin requires --stdin-name PATH",
                )));
            }
        }
        CreateStdinMode::RawKnownSize => {
            if args.stdin_name.is_none() {
                return Err(anyhow!(FormatError::WriterUnsupported(
                    "--raw-stdin requires --stdin-name PATH",
                )));
            }
            parse_size(args.stdin_size.expect("checked raw known-size stdin"))
                .with_context(|| UsageError("invalid stdin-size"))?;
        }
        CreateStdinMode::RawSpool => {
            if args.stdin_name.is_none() {
                return Err(anyhow!(FormatError::WriterUnsupported(
                    "--raw-stdin requires --stdin-name PATH",
                )));
            }
            if args.stdin_size.is_some() {
                return Err(anyhow!(FormatError::WriterUnsupported(
                    "--spool-stdin is for unknown-size raw stdin; omit --stdin-size",
                )));
            }
        }
    }

    Ok(Some(mode))
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
    let base = multi_volume_base_name(output)?;
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
        if looks_like_tzap_volume(&name, &base) {
            bail!(
                "output path collision: {base}.volNNN.tzap already exists; use --force to overwrite"
            );
        }
    }
    Ok(())
}

fn looks_like_tzap_volume(path_name: &str, base: &str) -> bool {
    let Some(rest) = path_name.strip_prefix(base) else {
        return false;
    };
    let Some(digits) = rest
        .strip_prefix(".vol")
        .and_then(|rest| rest.strip_suffix(".tzap"))
    else {
        return false;
    };
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}

fn check_archive_paths_free_for_write(paths: &[PathBuf]) -> Result<()> {
    for path in paths {
        check_output_path_free("archive output", path)?;
    }
    Ok(())
}

fn resolve_create_volume_loss_tolerance(
    explicit: Option<u8>,
    volumes: Option<u32>,
    volume_size: Option<&str>,
    stdin_payload_mode_requested: bool,
) -> u8 {
    explicit.unwrap_or_else(|| {
        if stdin_payload_mode_requested || (volumes.unwrap_or(1) <= 1 && volume_size.is_none()) {
            0
        } else {
            1
        }
    })
}

fn validate_create_writer_options(options: &WriterOptions) -> Result<()> {
    if options.block_size < 4096 || options.block_size % 2 != 0 {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "writer requires an even block size of at least 4096",
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
            .map(|index| create_volume_output_path(output, index))
            .collect()
    }
}

fn create_volume_output_path(output: &str, index: usize) -> PathBuf {
    let output_path = Path::new(output);
    let base = multi_volume_base_name(output).unwrap_or_else(|_| output.to_owned());
    let file_name = format!("{base}.vol{index:03}.tzap");
    match output_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(file_name),
        _ => PathBuf::from(file_name),
    }
}

fn multi_volume_base_name(output: &str) -> Result<String> {
    let file_name = Path::new(output)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("output path has invalid UTF-8: {output}"))?;
    Ok(file_name
        .strip_suffix(".tzap")
        .unwrap_or(file_name)
        .to_owned())
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
        let first = create_volume_output_path(output, 0);
        let second = create_volume_output_path(output, 1);
        return vec![
            format!("{output} (if one volume is emitted)"),
            format!("{}, {}, ... (if split)", first.display(), second.display()),
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
    "single volume".to_string()
}

fn create_key_mode_label(
    keyfile: Option<&str>,
    recipient_cert: Option<&str>,
    password_stdin: bool,
    password: bool,
    no_encryption: bool,
    insecure_zero_key: bool,
) -> String {
    if password_stdin {
        return "password-stdin".to_string();
    }
    if password {
        return "password".to_string();
    }
    if keyfile.is_some() {
        return "keyfile".to_string();
    }
    if recipient_cert.is_some() {
        return "recipient-cert".to_string();
    }
    if no_encryption {
        return "no-encryption".to_string();
    }
    if insecure_zero_key {
        return "insecure-zero-key".to_string();
    }
    "unknown".to_string()
}

fn removed_insecure_zero_key_error() -> UsageError {
    UsageError("--insecure-zero-key was removed in v43; use --no-encryption for plaintext archives")
}

fn validate_create_key_source(
    keyfile: Option<&str>,
    recipient_cert: Option<&str>,
    password_stdin: bool,
    password: bool,
    no_encryption: bool,
    insecure_zero_key: bool,
) -> Result<()> {
    if insecure_zero_key {
        return Err(removed_insecure_zero_key_error().into());
    }
    let count = usize::from(keyfile.is_some())
        + usize::from(recipient_cert.is_some())
        + usize::from(password_stdin)
        + usize::from(password)
        + usize::from(no_encryption);
    if count == 0 {
        return Err(UsageError(
            "no key source provided; use --password-stdin, --password, --keyfile PATH, --recipient-cert FILE, or --no-encryption",
        )
        .into());
    }
    if count > 1 {
        return Err(UsageError(
            "create accepts exactly one protection mode: --keyfile, --password, --password-stdin, --recipient-cert, or --no-encryption",
        )
        .into());
    }
    Ok(())
}

fn validate_create_recipient_wrap_scope(
    recipient_cert: Option<&str>,
    stdin_mode: Option<CreateStdinMode>,
    has_dictionary: bool,
    has_root_auth: bool,
    volumes: Option<u32>,
    volume_size: Option<&str>,
) -> Result<()> {
    if recipient_cert.is_none() {
        return Ok(());
    }
    if stdin_mode.is_some() {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--recipient-cert is currently supported only for file-backed create inputs",
        )));
    }
    if has_dictionary {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--recipient-cert is not yet supported with --dictionary",
        )));
    }
    if has_root_auth {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--recipient-cert is not yet supported with RootAuth signing flags",
        )));
    }
    if volumes.unwrap_or(1) != 1 || volume_size.is_some() {
        return Err(anyhow!(FormatError::WriterUnsupported(
            "--recipient-cert is currently supported only for single-volume create",
        )));
    }
    Ok(())
}

fn create_root_auth_mode_label(signing_key: Option<&str>, signing_cert: Option<&str>) -> String {
    if signing_key.is_some() {
        return "ed25519".to_string();
    }
    if signing_cert.is_some() {
        return "x509".to_string();
    }
    "unsigned".to_string()
}

impl CreateRootAuthProfile {
    fn label(&self) -> &'static str {
        match self {
            Self::Ed25519 { .. } => "ed25519",
            Self::X509(_) => "x509",
        }
    }

    fn root_auth_writer_config(&self) -> Result<RootAuthWriterConfig<'_>> {
        match self {
            Self::Ed25519 {
                signer_identity, ..
            } => Ok(RootAuthWriterConfig {
                authenticator_id: ED25519_AUTHENTICATOR_ID,
                signer_identity_type: 1,
                signer_identity,
                authenticator_value_length: ED25519_AUTHENTICATOR_VALUE_LEN,
            }),
            Self::X509(signer) => signer.root_auth_writer_config().map_err(Into::into),
        }
    }
}

fn root_auth_authenticator_value(
    profile: &CreateRootAuthProfile,
    request: &RootAuthSigningRequest,
) -> Result<Vec<u8>, FormatError> {
    match profile {
        CreateRootAuthProfile::Ed25519 { signing_key, .. } => {
            Ok(ed25519_raw::authenticator_value_for_request(signing_key, request).to_vec())
        }
        CreateRootAuthProfile::X509(signer) => signer
            .authenticator_value_for_request(request)
            .map_err(|_| FormatError::WriterUnsupported("X.509 RootAuth signing failed")),
    }
}

#[derive(Debug, Clone)]
struct ArchiveInputSelection {
    paths: Vec<String>,
    autodiscovered: bool,
}

struct OpenedArchiveSelection {
    paths: Vec<String>,
    opened: OpenedArchive,
}

#[derive(Debug)]
struct CliRecipientPrivateKeyLookup {
    private_key_bytes: Vec<u8>,
    private_key_spki_der: Option<Vec<u8>>,
}

impl PrivateKeyLookup for CliRecipientPrivateKeyLookup {
    fn lookup_private_key(
        &self,
        _archive_identity: &KeyWrapArchiveIdentity,
        _metadata: &RecipientRecordMetadata,
        recipient_identity_bytes: &[u8],
    ) -> Option<Vec<u8>> {
        if let Some(private_key_spki_der) = self.private_key_spki_der.as_ref() {
            let certificate = X509::from_der(recipient_identity_bytes).ok()?;
            let certificate_spki_der = certificate.public_key().ok()?.public_key_to_der().ok()?;
            if certificate_spki_der != *private_key_spki_der {
                return None;
            }
        }
        Some(self.private_key_bytes.clone())
    }
}

#[derive(Debug, Default)]
struct RecipientWrapOpenStats {
    records_seen: usize,
    no_matching_private_key: usize,
    invalid_record_or_unwrap: usize,
    unsupported_record: usize,
    candidate_count: usize,
}

struct RepairedArchiveOutput {
    path: String,
    volume_index: u32,
    repaired_block_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VolumePathPattern {
    base: String,
    volume_index: u32,
}

fn resolve_archive_input_paths(
    primary: &str,
    additional: &[String],
    allow_autodiscovery: bool,
) -> Result<ArchiveInputSelection> {
    let mut paths = Vec::with_capacity(additional.len() + 1);
    paths.push(primary.to_owned());
    paths.extend(additional.iter().cloned());
    if !allow_autodiscovery || !additional.is_empty() || primary == "-" {
        return Ok(ArchiveInputSelection {
            paths,
            autodiscovered: false,
        });
    }

    let Some(pattern) = parse_volume_path_pattern(Path::new(primary)) else {
        return Ok(ArchiveInputSelection {
            paths,
            autodiscovered: false,
        });
    };
    let discovered = discover_volume_siblings(Path::new(primary), &pattern)?;
    if discovered.is_empty() {
        return Ok(ArchiveInputSelection {
            paths,
            autodiscovered: false,
        });
    }
    Ok(ArchiveInputSelection {
        paths: discovered,
        autodiscovered: true,
    })
}

enum MappedVolumeInput {
    Empty(Vec<u8>),
    Mapped(Mmap),
}

impl MappedVolumeInput {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Empty(bytes) => bytes,
            Self::Mapped(map) => map.as_ref(),
        }
    }
}

fn map_volume_inputs_from_paths(paths: &[String]) -> Result<Vec<MappedVolumeInput>> {
    paths
        .iter()
        .map(|path| {
            let file =
                File::open(path).with_context(|| format!("failed to read archive {path}"))?;
            if file
                .metadata()
                .with_context(|| format!("failed to inspect archive {path}"))?
                .len()
                == 0
            {
                return Ok(MappedVolumeInput::Empty(Vec::new()));
            }
            // SAFETY: the mapping is read-only and retained while verifier slices are in use.
            let map = unsafe { Mmap::map(&file) }
                .with_context(|| format!("failed to map archive {path}"))?;
            Ok(MappedVolumeInput::Mapped(map))
        })
        .collect()
}

fn open_volume_inputs_from_paths(paths: &[String]) -> Result<Vec<File>> {
    paths
        .iter()
        .map(|path| File::open(path).with_context(|| format!("failed to read archive {path}")))
        .collect()
}

fn write_repaired_archive_copies(
    paths: &[String],
    opened: &OpenedArchive,
) -> Result<Vec<RepairedArchiveOutput>> {
    let patches = opened
        .repair_patches()
        .context("failed to prepare repaired archive output")?;
    if patches.is_empty() {
        return Ok(Vec::new());
    }

    let mut path_by_volume = BTreeMap::<u32, String>::new();
    for path in paths {
        let volume_index = read_volume_index_from_path(path)?;
        if path_by_volume.insert(volume_index, path.clone()).is_some() {
            bail!("duplicate archive input for volume index {volume_index}");
        }
    }

    let mut patches_by_volume = BTreeMap::<u32, Vec<&ArchiveRepairPatch>>::new();
    for patch in &patches {
        patches_by_volume
            .entry(patch.volume_index)
            .or_default()
            .push(patch);
    }

    let mut outputs = Vec::new();
    for (volume_index, volume_patches) in patches_by_volume {
        let input_path = path_by_volume.get(&volume_index).ok_or_else(|| {
            anyhow!("repair output references unavailable volume index {volume_index}")
        })?;
        let output_path = repaired_archive_output_path(input_path)?;
        if output_path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("repaired output already exists: {}", output_path.display()),
            )
            .into());
        }
        fs::copy(input_path, &output_path).with_context(|| {
            format!(
                "failed to copy archive volume {} to {}",
                input_path,
                output_path.display()
            )
        })?;

        let mut output = OpenOptions::new()
            .write(true)
            .open(&output_path)
            .with_context(|| format!("failed to open repaired output {}", output_path.display()))?;
        for patch in &volume_patches {
            output
                .seek(SeekFrom::Start(patch.record_offset))
                .with_context(|| {
                    format!(
                        "failed to seek repaired output {} to offset {}",
                        output_path.display(),
                        patch.record_offset
                    )
                })?;
            output.write_all(&patch.record_bytes).with_context(|| {
                format!(
                    "failed to write repaired block {} to {}",
                    patch.block_index,
                    output_path.display()
                )
            })?;
        }
        output.flush().with_context(|| {
            format!("failed to flush repaired output {}", output_path.display())
        })?;
        outputs.push(RepairedArchiveOutput {
            path: output_path.to_string_lossy().into_owned(),
            volume_index,
            repaired_block_count: volume_patches.len(),
        });
    }

    Ok(outputs)
}

fn read_volume_index_from_path(path: &str) -> Result<u32> {
    let mut file = File::open(path).with_context(|| format!("failed to read archive {path}"))?;
    let mut header = [0u8; VOLUME_HEADER_LEN];
    file.read_exact(&mut header)
        .with_context(|| format!("failed to read archive header {path}"))?;
    Ok(VolumeHeader::parse(&header)
        .with_context(|| format!("failed to parse archive header {path}"))?
        .volume_index)
}

fn repaired_archive_output_path(input: &str) -> Result<PathBuf> {
    let path = Path::new(input);
    let file_name = path
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .ok_or_else(|| anyhow!("archive path has no UTF-8 file name: {input}"))?;
    let repaired_name = if let Some(pattern) = parse_volume_file_name(file_name) {
        format!(
            "{}.repaired.vol{:03}.tzap",
            pattern.base, pattern.volume_index
        )
    } else if let Some(stem) = file_name.strip_suffix(".tzap") {
        format!("{stem}.repaired.tzap")
    } else {
        format!("{file_name}.repaired")
    };
    Ok(path.with_file_name(repaired_name))
}

fn parse_volume_path_pattern(path: &Path) -> Option<VolumePathPattern> {
    let file_name = path.file_name()?.to_str()?;
    parse_volume_file_name(file_name)
}

fn parse_volume_file_name(file_name: &str) -> Option<VolumePathPattern> {
    let stem = file_name.strip_suffix(".tzap")?;
    let (base, digits) = stem.rsplit_once(".vol")?;
    if base.is_empty() || digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(VolumePathPattern {
        base: base.to_owned(),
        volume_index: digits.parse().ok()?,
    })
}

fn discover_volume_siblings(primary: &Path, pattern: &VolumePathPattern) -> Result<Vec<String>> {
    let parent = primary.parent().unwrap_or_else(|| Path::new("."));
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err).with_context(|| {
                format!("failed to inspect archive directory {}", parent.display())
            })
        }
    };
    let mut discovered = Vec::new();
    for entry in entries.filter_map(|entry| entry.ok()) {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Some(candidate) = parse_volume_file_name(file_name) else {
            continue;
        };
        if candidate.base != pattern.base {
            continue;
        }
        discovered.push((candidate.volume_index, entry.path()));
    }
    discovered.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    Ok(discovered
        .into_iter()
        .map(|(_, path)| path.to_string_lossy().into_owned())
        .collect())
}

fn reject_multi_volume_bootstrap(volume_count: usize, bootstrap: Option<&str>) -> Result<()> {
    if volume_count > 1 && bootstrap.is_some() {
        return Err(anyhow!(FormatError::ReaderUnsupported(
            "multi-volume inputs with --bootstrap are not supported; pass volume files without --bootstrap",
        )));
    }
    Ok(())
}

fn reject_stdout_extract_shape(stdout: bool, path_count: usize) -> Result<()> {
    if stdout && path_count != 1 {
        return Err(anyhow!(FormatError::ReaderUnsupported(
            "--stdout requires exactly one archive path",
        )));
    }
    Ok(())
}

struct ArchiveStdinOpenOptions<'a> {
    paths: &'a [String],
    stdout: bool,
    volumes: &'a [String],
    password_stdin: bool,
    password: bool,
    keyfile: Option<&'a str>,
    recipient_key: Option<&'a str>,
    insecure_zero_key: bool,
}

fn reject_archive_stdin_open_options(options: ArchiveStdinOpenOptions<'_>) -> Result<()> {
    if !options.volumes.is_empty() {
        return Err(anyhow!(FormatError::ReaderUnsupported(
            "archive stdin must be the only archive input",
        )));
    }
    if options.stdout {
        return Err(anyhow!(FormatError::ReaderUnsupported(
            "--stdout is not supported for archive stdin extraction",
        )));
    }
    if !options.paths.is_empty() {
        return Err(anyhow!(FormatError::ReaderUnsupported(
            "selected-path extraction is not supported for archive stdin",
        )));
    }
    reject_archive_stdin_key_options(
        options.password_stdin,
        options.password,
        options.keyfile,
        options.recipient_key,
        options.insecure_zero_key,
    )
}

fn reject_archive_stdin_list_options(
    volumes: &[String],
    password_stdin: bool,
    password: bool,
    keyfile: Option<&str>,
    recipient_key: Option<&str>,
    insecure_zero_key: bool,
) -> Result<()> {
    if !volumes.is_empty() {
        return Err(anyhow!(FormatError::ReaderUnsupported(
            "archive stdin must be the only archive input",
        )));
    }
    reject_archive_stdin_key_options(
        password_stdin,
        password,
        keyfile,
        recipient_key,
        insecure_zero_key,
    )
}

fn reject_archive_stdin_key_options(
    password_stdin: bool,
    password: bool,
    _keyfile: Option<&str>,
    _recipient_key: Option<&str>,
    insecure_zero_key: bool,
) -> Result<()> {
    if insecure_zero_key {
        return Err(removed_insecure_zero_key_error().into());
    }
    if password_stdin || password {
        return Err(anyhow!(FormatError::ReaderUnsupported(
            "archive stdin currently supports raw --keyfile, --recipient-key, or no-key unencrypted archives only",
        )));
    }
    Ok(())
}

fn load_archive_stdin_key(
    keyfile: Option<&str>,
    password_stdin: bool,
    password: bool,
    insecure_zero_key: bool,
) -> Result<MasterKey> {
    reject_archive_stdin_key_options(password_stdin, password, keyfile, None, insecure_zero_key)?;
    if keyfile.is_some() {
        return load_raw_master_key(keyfile);
    }
    Err(anyhow!(FormatError::KeyMaterialMismatch).context(
        "encrypted archive stdin requires --keyfile; unencrypted archive stdin uses no key source",
    ))
}

fn read_optional_bootstrap_sidecar(path: Option<&str>) -> Result<Option<Vec<u8>>> {
    path.map(|path| {
        fs::read(path).with_context(|| format!("failed to read bootstrap sidecar {path}"))
    })
    .transpose()
}

fn open_inputs_maybe_bootstrap(
    volume_files: Vec<File>,
    master_key: &MasterKey,
    bootstrap: Option<&str>,
    options: ReaderOptions,
) -> Result<OpenedArchive> {
    if volume_files.len() > 1 {
        reject_multi_volume_bootstrap(volume_files.len(), bootstrap)?;
        return OpenedArchive::open_seekable_volumes_with_options(
            volume_files,
            master_key,
            options,
        )
        .map_err(Into::into);
    }
    let volume_file = volume_files
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("at least one archive volume is required"))?;
    if let Some(path) = bootstrap {
        let sidecar =
            fs::read(path).with_context(|| format!("failed to read bootstrap sidecar {path}"))?;
        open_seekable_archive_with_bootstrap_sidecar_options(
            volume_file,
            &sidecar,
            master_key,
            options,
        )
        .map_err(Into::into)
    } else {
        OpenedArchive::open_seekable_volumes_with_options(vec![volume_file], master_key, options)
            .map_err(Into::into)
    }
}

fn open_selection_maybe_bootstrap(
    selection: &ArchiveInputSelection,
    master_key: &MasterKey,
    bootstrap: Option<&str>,
    options: ReaderOptions,
) -> Result<OpenedArchive> {
    Ok(open_selection_maybe_bootstrap_resolved(selection, master_key, bootstrap, options)?.opened)
}

fn open_selection_maybe_bootstrap_resolved(
    selection: &ArchiveInputSelection,
    master_key: &MasterKey,
    bootstrap: Option<&str>,
    options: ReaderOptions,
) -> Result<OpenedArchiveSelection> {
    let volume_files = open_volume_inputs_from_paths(&selection.paths)?;
    match open_inputs_maybe_bootstrap(volume_files, master_key, bootstrap, options) {
        Ok(opened) => Ok(OpenedArchiveSelection {
            paths: selection.paths.clone(),
            opened,
        }),
        Err(err)
            if selection.autodiscovered && bootstrap.is_none() && selection.paths.len() > 1 =>
        {
            let usable_paths =
                filter_usable_autodiscovered_volume_paths(&selection.paths, master_key)
                    .with_context(|| "failed to filter autodiscovered archive volumes")?;
            if usable_paths == selection.paths {
                return Err(err);
            }
            let volume_files = open_volume_inputs_from_paths(&usable_paths)?;
            let opened = open_inputs_maybe_bootstrap(volume_files, master_key, bootstrap, options)?;
            Ok(OpenedArchiveSelection {
                paths: usable_paths,
                opened,
            })
        }
        Err(err) => Err(err),
    }
}

fn open_selection_with_recipient_key(
    selection: &ArchiveInputSelection,
    recipient_key: &str,
    bootstrap: Option<&str>,
    options: ReaderOptions,
) -> Result<OpenedArchiveSelection> {
    if bootstrap.is_some() {
        return Err(anyhow!(FormatError::ReaderUnsupported(
            "--recipient-key is not currently supported with --bootstrap",
        )));
    }
    let volume_files = open_volume_inputs_from_paths(&selection.paths)?;
    let lookup = load_recipient_private_key_lookup(recipient_key)?;
    let mut stats = RecipientWrapOpenStats::default();
    let opened = open_seekable_archive_volumes_with_recipient_wrap_resolver_options(
        volume_files,
        |context| recipient_wrap_candidates_for_record(context, &lookup, &mut stats),
        options,
    )
    .map_err(|err| recipient_wrap_open_error(err, &stats))
    .with_context(|| "failed to open RecipientWrap archive")?;
    Ok(OpenedArchiveSelection {
        paths: selection.paths.clone(),
        opened,
    })
}

fn recipient_wrap_candidates_for_record(
    context: RecipientWrapRecordContext<'_>,
    lookup: &CliRecipientPrivateKeyLookup,
    stats: &mut RecipientWrapOpenStats,
) -> std::result::Result<Vec<[u8; 32]>, FormatError> {
    stats.records_seen += 1;
    let input = RecipientRecordInput {
        archive_identity: KeyWrapArchiveIdentity {
            archive_uuid: context.archive_identity.archive_uuid,
            session_id: context.archive_identity.session_id,
            format_version: context.archive_identity.format_version,
            volume_format_rev: context.archive_identity.volume_format_rev,
        },
        metadata: RecipientRecordMetadata {
            profile_id: context.record.profile_id,
            recipient_identity_type: context.record.recipient_identity_type,
            recipient_identity_digest: context.record.recipient_identity_digest,
        },
        recipient_identity_bytes: context.record.recipient_identity_bytes.clone(),
        profile_payload_bytes: context.record.profile_payload_bytes.clone(),
    };
    match dispatch_key_wrap_record(input, lookup) {
        KeyWrapOutcome::UnwrappedCandidateMasterKey { master_key, .. } => {
            stats.candidate_count += 1;
            Ok(vec![master_key])
        }
        KeyWrapOutcome::NoMatchingPrivateKey => {
            stats.no_matching_private_key += 1;
            Ok(Vec::new())
        }
        KeyWrapOutcome::InvalidRecord | KeyWrapOutcome::CertificatePolicyRejected => {
            stats.invalid_record_or_unwrap += 1;
            Ok(Vec::new())
        }
        KeyWrapOutcome::UnsupportedProfileId
        | KeyWrapOutcome::UnsupportedArchiveIdentity
        | KeyWrapOutcome::UnsupportedRecipientIdentity
        | KeyWrapOutcome::UnsupportedSuite => {
            stats.unsupported_record += 1;
            Ok(Vec::new())
        }
    }
}

fn recipient_wrap_open_error(err: FormatError, stats: &RecipientWrapOpenStats) -> anyhow::Error {
    if !matches!(err, FormatError::KeyMaterialMismatch) {
        return anyhow!(err);
    }
    if stats.candidate_count > 0 {
        return anyhow!(err).context(
            "recipient private key unwrapped a candidate, but archive header_hmac did not verify",
        );
    }
    if stats.records_seen == 0 {
        return anyhow!(err).context("recipient-wrap archive has no recipient records");
    }
    if stats.no_matching_private_key > 0 && stats.invalid_record_or_unwrap == 0 {
        return anyhow!(err).context("no matching recipient private key for archive");
    }
    anyhow!(err).context(
        "recipient private key did not match any recipient record or failed recipient unwrap",
    )
}

fn filter_usable_autodiscovered_volume_paths(
    paths: &[String],
    master_key: &MasterKey,
) -> Result<Vec<String>> {
    let mut usable = Vec::new();
    let mut first_error = None;
    for path in paths {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(err) => {
                if first_error.is_none() {
                    first_error =
                        Some(anyhow!(err).context(format!("failed to read archive {path}")));
                }
                continue;
            }
        };
        match open_seekable_archive(file, master_key) {
            Ok(_) => usable.push(path.clone()),
            Err(err) if is_single_volume_candidate_usable_error(&err) => usable.push(path.clone()),
            Err(err) => {
                if first_error.is_none() {
                    first_error =
                        Some(anyhow!(err).context(format!("failed to open archive {path}")));
                }
            }
        }
    }
    if usable.is_empty() {
        return Err(
            first_error.unwrap_or_else(|| anyhow!("no autodiscovered archive volumes found"))
        );
    }
    Ok(usable)
}

fn is_single_volume_candidate_usable_error(err: &FormatError) -> bool {
    matches!(err, FormatError::FecTooFewAvailableShards)
        || matches!(
            err,
            FormatError::InvalidArchive(message)
                if *message == "missing volume count exceeds volume_loss_tolerance"
        )
}

fn validate_verify_key_holding_key_source(
    keyfile: Option<&str>,
    recipient_key: Option<&str>,
    password_stdin: bool,
    password: bool,
    insecure_zero_key: bool,
) -> Result<()> {
    if insecure_zero_key {
        return Err(removed_insecure_zero_key_error().into());
    }
    let count = usize::from(keyfile.is_some())
        + usize::from(recipient_key.is_some())
        + usize::from(password_stdin)
        + usize::from(password);
    if count > 1 {
        return Err(UsageError(
            "verify accepts at most one key source: --keyfile, --recipient-key, --password, or --password-stdin",
        )
        .into());
    }
    Ok(())
}

struct PublicNoKeyVerifyRequest<'a> {
    archive_paths: &'a [String],
    trusted_public_key: Option<&'a str>,
    trusted_ca_cert: &'a [String],
    trusted_system_roots: bool,
    password_stdin: bool,
    password: bool,
    keyfile: Option<&'a str>,
    recipient_key: Option<&'a str>,
    insecure_zero_key: bool,
    bootstrap: Option<&'a str>,
    reader_options: ReaderOptions,
    quiet: bool,
    json: bool,
}

fn run_public_no_key_verify(request: PublicNoKeyVerifyRequest<'_>) -> Result<()> {
    let trust = match load_public_no_key_trust(&request) {
        Ok(trust) => trust,
        Err(err) => {
            if request.json {
                emit_verify_json_error(request.archive_paths, None, None, &err)?;
            }
            return Err(err);
        }
    };
    let first = request
        .archive_paths
        .first()
        .ok_or(UsageError("at least one archive volume is required"))?;
    let selection = match resolve_archive_input_paths(first, &request.archive_paths[1..], true) {
        Ok(selection) => selection,
        Err(err) => {
            if request.json {
                emit_verify_json_error(request.archive_paths, None, None, &err)?;
            }
            return Err(err);
        }
    };
    let archive_paths = selection.paths;
    let volume_inputs = match map_volume_inputs_from_paths(&archive_paths) {
        Ok(volume_inputs) => volume_inputs,
        Err(err) => {
            if request.json {
                emit_verify_json_error(&archive_paths, None, None, &err)?;
            }
            return Err(err);
        }
    };
    let borrowed = volume_inputs
        .iter()
        .map(MappedVolumeInput::as_slice)
        .collect::<Vec<_>>();
    let mut x509_report = None;
    let mut x509_error = None;
    let verification = match public_no_key_verify_volumes_with_options(
        &borrowed,
        |footer, archive_root| match &trust {
            PublicNoKeyTrust::Ed25519 { public_key } => {
                if footer.authenticator_id != ED25519_AUTHENTICATOR_ID {
                    return Err(FormatError::ReaderUnsupported(
                        "trusted public key can only verify Ed25519 RootAuth",
                    ));
                }
                Ok(matches!(
                    ed25519_raw::verify_root_auth_footer(
                        footer,
                        archive_root,
                        Some(*public_key),
                        Ed25519VerificationMode::PublicNoKey,
                    ),
                    Ed25519RootAuthOutcome::PublicDataBlockCommitmentVerified { .. }
                ))
            }
            PublicNoKeyTrust::X509 {
                trusted_roots_der,
                trusted_system_roots,
            } => {
                if footer.authenticator_id != X509_AUTHENTICATOR_ID {
                    return Err(FormatError::ReaderUnsupported(
                        "X.509 trust can only verify X.509 RootAuth",
                    ));
                }
                match x509_chain::verify_root_auth_footer(
                    footer,
                    archive_root,
                    trusted_roots_der,
                    *trusted_system_roots,
                ) {
                    Ok(report) => {
                        x509_report = Some(report);
                        Ok(true)
                    }
                    Err(err) => {
                        x509_error = Some(err.to_string());
                        Ok(false)
                    }
                }
            }
        },
        request.reader_options,
    )
    .map_err(|err| {
        if let Some(detail) = x509_error.take() {
            anyhow!("{err}: {detail}")
        } else {
            anyhow!(err)
        }
    })
    .with_context(|| format!("failed to verify public RootAuth for {first}"))
    {
        Ok(verification) => verification,
        Err(err) => {
            if request.json {
                emit_verify_json_error(&archive_paths, None, None, &err)?;
            }
            return Err(err);
        }
    };
    let root_auth = match trust {
        PublicNoKeyTrust::Ed25519 { .. } => VerifiedPublicNoKeyRootAuth::Ed25519(verification),
        PublicNoKeyTrust::X509 { .. } => {
            let report = x509_report.ok_or(FormatError::InvalidArchive(
                "missing X.509 public no-key verification report",
            ))?;
            VerifiedPublicNoKeyRootAuth::X509 {
                verification,
                report: Box::new(report),
            }
        }
    };
    if request.json {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "ok": true,
                "archives": &archive_paths,
                "verification_mode": "public-no-key",
                "status": public_no_key_status_json(&root_auth),
                "volume_count": archive_paths.len(),
                "root_auth": public_no_key_root_auth_json(&root_auth),
                "public_diagnostics": public_no_key_diagnostic_labels_for_root_auth(&root_auth),
            }))
            .context("failed to encode verify output as JSON")?
        );
        return Ok(());
    }
    emit_success_stdout(
        request.quiet,
        &format!(
            "{}: OK public-no-key metadata-only ({} volume(s), {} data block(s))",
            first,
            archive_paths.len(),
            public_no_key_total_data_block_count(&root_auth)
        ),
    )?;
    emit_public_no_key_root_auth_stdout(request.quiet, &root_auth)?;
    for diagnostic in public_no_key_diagnostic_labels_for_root_auth(&root_auth) {
        emit_success_stdout(request.quiet, &format!("public-no-key: {diagnostic}"))?;
    }
    Ok(())
}

fn load_public_no_key_trust(request: &PublicNoKeyVerifyRequest<'_>) -> Result<PublicNoKeyTrust> {
    let wants_ed25519 = request.trusted_public_key.is_some();
    let wants_x509 = !request.trusted_ca_cert.is_empty() || request.trusted_system_roots;
    if wants_ed25519 && wants_x509 {
        return Err(UsageError(
            "use either --trusted-public-key or X.509 trust options with --public-no-key, not both",
        )
        .into());
    }
    if request.insecure_zero_key {
        return Err(removed_insecure_zero_key_error().into());
    }
    if request.password_stdin
        || request.password
        || request.keyfile.is_some()
        || request.recipient_key.is_some()
    {
        return Err(UsageError(
            "--public-no-key cannot be combined with --keyfile, --recipient-key, --password, or --password-stdin",
        )
        .into());
    }
    if request.bootstrap.is_some() {
        return Err(UsageError("--public-no-key does not use --bootstrap sidecars").into());
    }
    if let Some(path) = request.trusted_public_key {
        return Ok(PublicNoKeyTrust::Ed25519 {
            public_key: load_ed25519_public_key(path)?,
        });
    }
    Ok(PublicNoKeyTrust::X509 {
        trusted_roots_der: load_x509_trusted_roots(request.trusted_ca_cert, !wants_x509)?,
        trusted_system_roots: request.trusted_system_roots,
    })
}

fn verify_opened_root_auth_ed25519(
    opened: &OpenedArchive,
    content_verification: &ArchiveContentVerification<'_>,
    trusted_public_key: &str,
) -> Result<RootAuthVerification> {
    let public_key = load_ed25519_public_key(trusted_public_key)?;
    opened
        .verify_root_auth_with_verified_content(content_verification, |footer, archive_root| {
            Ok(matches!(
                ed25519_raw::verify_root_auth_footer(
                    footer,
                    archive_root,
                    Some(public_key),
                    Ed25519VerificationMode::KeyHoldingRootAuth,
                ),
                Ed25519RootAuthOutcome::RootAuthContentVerified { .. }
            ))
        })
        .map_err(Into::into)
}

fn verify_opened_root_auth(
    opened: &OpenedArchive,
    content_verification: &ArchiveContentVerification<'_>,
    trusted_public_key: Option<&str>,
    trusted_ca_cert: &[String],
    trusted_system_roots: bool,
) -> Result<Option<VerifiedRootAuth>> {
    let wants_ed25519 = trusted_public_key.is_some();
    let wants_explicit_x509 = !trusted_ca_cert.is_empty() || trusted_system_roots;
    if wants_ed25519 && wants_explicit_x509 {
        return Err(
            UsageError("use either --trusted-public-key or X.509 trust options, not both").into(),
        );
    }
    let Some(footer) = opened.root_auth_footer.as_ref() else {
        if wants_ed25519 || wants_explicit_x509 {
            return Err(FormatError::InvalidArchive("missing RootAuthFooter").into());
        }
        return Ok(None);
    };
    let wants_official_x509 =
        !wants_ed25519 && !wants_explicit_x509 && footer.authenticator_id == X509_AUTHENTICATOR_ID;
    if !wants_ed25519 && !wants_explicit_x509 && !wants_official_x509 {
        return Ok(None);
    }
    match footer.authenticator_id {
        ED25519_AUTHENTICATOR_ID if wants_ed25519 => {
            let public_key = trusted_public_key.expect("checked Ed25519 trust request");
            Ok(Some(VerifiedRootAuth::Ed25519(
                verify_opened_root_auth_ed25519(opened, content_verification, public_key)?,
            )))
        }
        X509_AUTHENTICATOR_ID if wants_explicit_x509 || wants_official_x509 => {
            let trusted_roots_der = load_x509_trusted_roots(trusted_ca_cert, wants_official_x509)?;
            Ok(Some(verify_opened_root_auth_x509(
                opened,
                content_verification,
                &trusted_roots_der,
                trusted_system_roots,
            )?))
        }
        ED25519_AUTHENTICATOR_ID => {
            Err(UsageError("Ed25519 RootAuth requires --trusted-public-key FILE").into())
        }
        X509_AUTHENTICATOR_ID => Err(UsageError(
            "X.509 RootAuth requires --trusted-ca-cert FILE or --trusted-system-roots",
        )
        .into()),
        _ => Err(FormatError::ReaderUnsupported("unsupported RootAuth authenticator id").into()),
    }
}

fn verify_opened_root_auth_x509(
    opened: &OpenedArchive,
    content_verification: &ArchiveContentVerification<'_>,
    trusted_roots_der: &[Vec<u8>],
    trusted_system_roots: bool,
) -> Result<VerifiedRootAuth> {
    let mut report = None;
    let mut x509_error = None;
    let verification = opened
        .verify_root_auth_with_verified_content(content_verification, |footer, archive_root| {
            match x509_chain::verify_root_auth_footer(
                footer,
                archive_root,
                trusted_roots_der,
                trusted_system_roots,
            ) {
                Ok(value) => {
                    report = Some(value);
                    Ok(true)
                }
                Err(err) => {
                    x509_error = Some(err.to_string());
                    Ok(false)
                }
            }
        })
        .map_err(|err| {
            if let Some(detail) = x509_error {
                anyhow!("{err}: {detail}")
            } else {
                anyhow!(err)
            }
        })?;
    let report = report.ok_or(FormatError::InvalidArchive(
        "missing X.509 RootAuth verification report",
    ))?;
    Ok(VerifiedRootAuth::X509 {
        verification,
        report: Box::new(report),
    })
}

fn revision_mode_label(volume_format_rev: u16) -> &'static str {
    match volume_format_rev {
        VOLUME_FORMAT_REV_44 => "v44",
        _ => "unsupported",
    }
}

fn key_access_status(opened: &OpenedArchive, used_recipient_key: bool) -> &'static str {
    if opened.crypto_header.aead_algo == AeadAlgo::None {
        "plaintext_opened"
    } else if used_recipient_key || opened.crypto_header.kdf_algo == KdfAlgo::RecipientWrap {
        "recipientwrap_opened"
    } else {
        "key_holding_decrypted"
    }
}

fn key_holding_status_json(
    opened: &OpenedArchive,
    root_auth: Option<&VerifiedRootAuth>,
    fast: bool,
    used_recipient_key: bool,
    trust_requested: bool,
) -> serde_json::Value {
    json!({
        "revision_mode": revision_mode_label(opened.volume_header.volume_format_rev),
        "format_version": opened.volume_header.format_version,
        "volume_format_rev": opened.volume_header.volume_format_rev,
        "header_base_integrity": if fast { "fast_verified" } else { "verified" },
        "decryption_keywrap": key_access_status(opened, used_recipient_key),
        "root_auth_signer": key_holding_root_auth_status(opened, root_auth, fast),
        "trust_policy": key_holding_trust_policy_status(root_auth, trust_requested),
        "public_no_key_metadata_only": "not_requested",
    })
}

fn key_holding_root_auth_status(
    opened: &OpenedArchive,
    root_auth: Option<&VerifiedRootAuth>,
    fast: bool,
) -> &'static str {
    if let Some(root_auth) = root_auth {
        return verified_root_auth_status(root_auth);
    }
    if fast && opened.root_auth_footer.is_some() {
        "deferred_full_archive_scan_required"
    } else if opened.root_auth_footer.is_some() {
        "not_requested"
    } else {
        "absent"
    }
}

fn key_holding_trust_policy_status(
    root_auth: Option<&VerifiedRootAuth>,
    trust_requested: bool,
) -> &'static str {
    if root_auth.is_some() {
        "trusted"
    } else if trust_requested {
        "unverified"
    } else {
        "not_requested"
    }
}

fn verified_root_auth_status(root_auth: &VerifiedRootAuth) -> &'static str {
    match root_auth {
        VerifiedRootAuth::Ed25519(verification) => root_auth_status(verification),
        VerifiedRootAuth::X509 { verification, .. } => root_auth_status(verification),
    }
}

fn public_no_key_status_json(root_auth: &VerifiedPublicNoKeyRootAuth) -> serde_json::Value {
    let verification = public_no_key_verification(root_auth);
    json!({
        "revision_mode": revision_mode_label(verification.volume_format_rev),
        "format_version": verification.format_version,
        "volume_format_rev": verification.volume_format_rev,
        "header_base_integrity": "public_metadata_verified",
        "decryption_keywrap": "not_used",
        "root_auth_signer": public_no_key_status(verification),
        "trust_policy": "public_trust_matched",
        "public_no_key_metadata_only": "metadata_commitments_verified",
    })
}

fn public_no_key_verification(root_auth: &VerifiedPublicNoKeyRootAuth) -> &PublicNoKeyVerification {
    match root_auth {
        VerifiedPublicNoKeyRootAuth::Ed25519(verification) => verification,
        VerifiedPublicNoKeyRootAuth::X509 { verification, .. } => verification,
    }
}

fn root_auth_json(root_auth: &VerifiedRootAuth) -> serde_json::Value {
    match root_auth {
        VerifiedRootAuth::Ed25519(root_auth) => {
            let mut payload = json!({
                "status": root_auth_status(root_auth),
                "diagnostics": root_auth_diagnostic_labels(root_auth),
                "revision_mode": revision_mode_label(root_auth.volume_format_rev),
                "format_version": root_auth.format_version,
                "volume_format_rev": root_auth.volume_format_rev,
                "authenticator": "ed25519",
                "archive_root": encode_hex(&root_auth.archive_root),
                "authenticator_id": root_auth.authenticator_id,
                "signer_identity_type": root_auth.signer_identity_type,
                "signer_identity": encode_hex(&root_auth.signer_identity_bytes),
                "total_data_block_count": root_auth.total_data_block_count,
            });
            if root_auth.signer_identity_type == 1 && root_auth.signer_identity_bytes.len() == 32 {
                payload["key_id"] = json!(encode_hex(&root_auth.signer_identity_bytes));
            }
            payload
        }
        VerifiedRootAuth::X509 {
            verification,
            report,
        } => json!({
            "status": root_auth_status(verification),
            "diagnostics": root_auth_diagnostic_labels(verification),
            "revision_mode": revision_mode_label(verification.volume_format_rev),
            "format_version": verification.format_version,
            "volume_format_rev": verification.volume_format_rev,
            "authenticator": "x509",
            "archive_root": encode_hex(&verification.archive_root),
            "authenticator_id": verification.authenticator_id,
            "signer_identity_type": verification.signer_identity_type,
            "signer_identity": encode_hex(&verification.signer_identity_bytes),
            "total_data_block_count": verification.total_data_block_count,
            "subject": &report.subject,
            "issuer": &report.issuer,
            "serial_number": &report.serial_number_hex,
            "certificate_sha256": encode_hex(&report.certificate_sha256),
            "signed_at_unix_seconds": report.signed_at_unix_seconds,
            "signed_at": format_unix_timestamp(report.signed_at_unix_seconds),
            "time_source": "signer_claimed",
            "signature_scheme": report.signature_scheme,
            "chain_validation_time_unix_seconds": report.chain_validation_time_unix_seconds,
            "chain_validation_time": format_unix_timestamp(report.chain_validation_time_unix_seconds),
            "x509_time_policy": report.x509_time_policy,
            "chain_time_basis": report.chain_time_basis,
            "trusted_timestamp": report.trusted_timestamp,
            "revocation_checked": report.revocation_checked,
            "trust_store_policy": report.trust_store_policy,
            "key_usage_policy": report.key_usage_policy,
            "eku_policy": report.eku_policy,
            "verified_chain_subjects": &report.verified_chain_subjects,
            "trust_anchor_subject": &report.trust_anchor_subject,
        }),
    }
}

fn root_auth_status(root_auth: &RootAuthVerification) -> &'static str {
    root_auth
        .diagnostics
        .first()
        .map(|diagnostic| diagnostic.label())
        .unwrap_or("root_auth_content_verified")
}

fn root_auth_diagnostic_labels(root_auth: &RootAuthVerification) -> Vec<&'static str> {
    root_auth
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.label())
        .collect()
}

fn emit_root_auth_stdout(quiet: bool, root_auth: &VerifiedRootAuth) -> io::Result<()> {
    match root_auth {
        VerifiedRootAuth::Ed25519(verification) => {
            emit_success_stdout(
                quiet,
                &format!(
                    "root-auth: OK ed25519 {}",
                    encode_hex(&verification.archive_root)
                ),
            )?;
            emit_root_auth_diagnostics_stdout(quiet, verification)
        }
        VerifiedRootAuth::X509 {
            verification,
            report,
        } => {
            emit_success_stdout(
                quiet,
                &format!(
                    "root-auth: OK x509 {}",
                    encode_hex(&verification.archive_root)
                ),
            )?;
            emit_success_stdout(quiet, &format!("root-auth signer: {}", report.subject))?;
            emit_success_stdout(quiet, &format!("root-auth issuer: {}", report.issuer))?;
            if let Some(trust_anchor) = &report.trust_anchor_subject {
                emit_success_stdout(quiet, &format!("root-auth trust-anchor: {trust_anchor}"))?;
            }
            emit_success_stdout(
                quiet,
                &format!(
                    "root-auth signed-at: {} (signer-claimed)",
                    format_unix_timestamp(report.signed_at_unix_seconds)
                ),
            )?;
            emit_success_stdout(
                quiet,
                &format!(
                    "root-auth chain-validation-time: {} ({})",
                    format_unix_timestamp(report.chain_validation_time_unix_seconds),
                    report.chain_time_basis
                ),
            )?;
            emit_success_stdout(
                quiet,
                &format!(
                    "root-auth x509-policy: signature-scheme={} trust-store={} key-usage={} eku={} revocation-checked={} trusted-timestamp={}",
                    report.signature_scheme,
                    report.trust_store_policy,
                    report.key_usage_policy,
                    report.eku_policy,
                    report.revocation_checked,
                    report.trusted_timestamp
                ),
            )?;
            emit_success_stdout(
                quiet,
                &format!(
                    "root-auth certificate-sha256: {}",
                    encode_hex(&report.certificate_sha256)
                ),
            )?;
            emit_root_auth_diagnostics_stdout(quiet, verification)
        }
    }
}

fn emit_root_auth_diagnostics_stdout(
    quiet: bool,
    verification: &RootAuthVerification,
) -> io::Result<()> {
    for diagnostic in &verification.diagnostics {
        emit_success_stdout(quiet, &format!("root-auth: {}", diagnostic.label()))?;
    }
    Ok(())
}

fn fast_verify_diagnostic_labels(opened: &OpenedArchive) -> Vec<&'static str> {
    let mut diagnostics = Vec::new();
    if opened.fast_verify_defers_payload_semantics() {
        diagnostics.push("payload_semantics_deferred");
    }
    if opened.root_auth_footer.is_some() {
        diagnostics.push("root_auth_deferred_full_archive_scan_required");
    }
    if opened.crypto_header.fec_parity_shards > 0
        || opened.crypto_header.index_fec_parity_shards > 0
        || opened.crypto_header.index_root_fec_parity_shards > 0
        || opened.manifest_footer.index_root_parity_block_count > 0
    {
        diagnostics.push("recovery_margin_unchecked");
    }
    diagnostics
}

fn emit_fast_verify_diagnostics_stdout(quiet: bool, opened: &OpenedArchive) -> io::Result<()> {
    for diagnostic in fast_verify_diagnostic_labels(opened) {
        emit_success_stdout(quiet, &format!("fast-verify: {diagnostic}"))?;
    }
    Ok(())
}

fn public_no_key_root_auth_json(root_auth: &VerifiedPublicNoKeyRootAuth) -> serde_json::Value {
    match root_auth {
        VerifiedPublicNoKeyRootAuth::Ed25519(verification) => {
            let mut payload = json!({
                "status": public_no_key_status(verification),
                "diagnostics": public_no_key_diagnostic_labels(verification),
                "revision_mode": revision_mode_label(verification.volume_format_rev),
                "format_version": verification.format_version,
                "volume_format_rev": verification.volume_format_rev,
                "authenticator": "ed25519",
                "archive_root": encode_hex(&verification.archive_root),
                "authenticator_id": verification.authenticator_id,
                "signer_identity_type": verification.signer_identity_type,
                "signer_identity": encode_hex(&verification.signer_identity_bytes),
                "total_data_block_count": verification.total_data_block_count,
            });
            if verification.signer_identity_type == 1
                && verification.signer_identity_bytes.len() == 32
            {
                payload["key_id"] = json!(encode_hex(&verification.signer_identity_bytes));
            }
            payload
        }
        VerifiedPublicNoKeyRootAuth::X509 {
            verification,
            report,
        } => json!({
            "status": public_no_key_status(verification),
            "diagnostics": public_no_key_diagnostic_labels(verification),
            "revision_mode": revision_mode_label(verification.volume_format_rev),
            "format_version": verification.format_version,
            "volume_format_rev": verification.volume_format_rev,
            "authenticator": "x509",
            "archive_root": encode_hex(&verification.archive_root),
            "authenticator_id": verification.authenticator_id,
            "signer_identity_type": verification.signer_identity_type,
            "signer_identity": encode_hex(&verification.signer_identity_bytes),
            "total_data_block_count": verification.total_data_block_count,
            "subject": &report.subject,
            "issuer": &report.issuer,
            "serial_number": &report.serial_number_hex,
            "certificate_sha256": encode_hex(&report.certificate_sha256),
            "signed_at_unix_seconds": report.signed_at_unix_seconds,
            "signed_at": format_unix_timestamp(report.signed_at_unix_seconds),
            "time_source": "signer_claimed",
            "signature_scheme": report.signature_scheme,
            "chain_validation_time_unix_seconds": report.chain_validation_time_unix_seconds,
            "chain_validation_time": format_unix_timestamp(report.chain_validation_time_unix_seconds),
            "x509_time_policy": report.x509_time_policy,
            "chain_time_basis": report.chain_time_basis,
            "trusted_timestamp": report.trusted_timestamp,
            "revocation_checked": report.revocation_checked,
            "trust_store_policy": report.trust_store_policy,
            "key_usage_policy": report.key_usage_policy,
            "eku_policy": report.eku_policy,
            "verified_chain_subjects": &report.verified_chain_subjects,
            "trust_anchor_subject": &report.trust_anchor_subject,
        }),
    }
}

fn public_no_key_status(verification: &PublicNoKeyVerification) -> &'static str {
    verification
        .diagnostics
        .first()
        .map(|diagnostic| diagnostic.label())
        .unwrap_or("public_data_block_commitment_verified")
}

fn public_no_key_diagnostic_labels(verification: &PublicNoKeyVerification) -> Vec<&'static str> {
    verification
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.label())
        .collect()
}

fn public_no_key_diagnostic_labels_for_root_auth(
    root_auth: &VerifiedPublicNoKeyRootAuth,
) -> Vec<&'static str> {
    match root_auth {
        VerifiedPublicNoKeyRootAuth::Ed25519(verification) => {
            public_no_key_diagnostic_labels(verification)
        }
        VerifiedPublicNoKeyRootAuth::X509 { verification, .. } => {
            public_no_key_diagnostic_labels(verification)
        }
    }
}

fn emit_public_no_key_root_auth_stdout(
    quiet: bool,
    root_auth: &VerifiedPublicNoKeyRootAuth,
) -> io::Result<()> {
    match root_auth {
        VerifiedPublicNoKeyRootAuth::Ed25519(verification) => emit_success_stdout(
            quiet,
            &format!(
                "root-auth: OK public-no-key ed25519 {}",
                encode_hex(&verification.archive_root)
            ),
        ),
        VerifiedPublicNoKeyRootAuth::X509 {
            verification,
            report,
        } => {
            emit_success_stdout(
                quiet,
                &format!(
                    "root-auth: OK public-no-key x509 {}",
                    encode_hex(&verification.archive_root)
                ),
            )?;
            emit_success_stdout(quiet, &format!("root-auth signer: {}", report.subject))?;
            emit_success_stdout(quiet, &format!("root-auth issuer: {}", report.issuer))?;
            if let Some(trust_anchor) = &report.trust_anchor_subject {
                emit_success_stdout(quiet, &format!("root-auth trust-anchor: {trust_anchor}"))?;
            }
            emit_success_stdout(
                quiet,
                &format!(
                    "root-auth signed-at: {} (signer-claimed)",
                    format_unix_timestamp(report.signed_at_unix_seconds)
                ),
            )?;
            emit_success_stdout(
                quiet,
                &format!(
                    "root-auth chain-validation-time: {} ({})",
                    format_unix_timestamp(report.chain_validation_time_unix_seconds),
                    report.chain_time_basis
                ),
            )?;
            emit_success_stdout(
                quiet,
                &format!(
                    "root-auth x509-policy: signature-scheme={} trust-store={} key-usage={} eku={} revocation-checked={} trusted-timestamp={}",
                    report.signature_scheme,
                    report.trust_store_policy,
                    report.key_usage_policy,
                    report.eku_policy,
                    report.revocation_checked,
                    report.trusted_timestamp
                ),
            )
        }
    }
}

fn public_no_key_total_data_block_count(root_auth: &VerifiedPublicNoKeyRootAuth) -> u64 {
    match root_auth {
        VerifiedPublicNoKeyRootAuth::Ed25519(verification) => verification.total_data_block_count,
        VerifiedPublicNoKeyRootAuth::X509 { verification, .. } => {
            verification.total_data_block_count
        }
    }
}

fn format_unix_timestamp(unix_seconds: i64) -> String {
    match OffsetDateTime::from_unix_timestamp(unix_seconds) {
        Ok(date_time) => date_time
            .format(&Rfc3339)
            .unwrap_or_else(|_| unix_seconds.to_string()),
        Err(_) => unix_seconds.to_string(),
    }
}

fn generate_random_key_material() -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    Ok(bytes)
}

fn generate_ed25519_signing_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

fn write_keyfile(path: &str, key_hex: &str, force: bool) -> Result<()> {
    write_atomic_output_file("keyfile", Path::new(path), key_hex.as_bytes(), force)
}

fn write_atomic_output_file(label: &str, path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    if !force && path.exists() {
        bail!(
            "{label} already exists: {}; use --force to overwrite",
            path.display()
        );
    }
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::Builder::new()
        .prefix(".tzap-write-")
        .suffix(".partial")
        .tempfile_in(parent)
        .with_context(|| format!("failed to create temporary {label} in {}", parent.display()))?;
    temp.as_file_mut()
        .write_all(bytes)
        .with_context(|| format!("failed to write temporary {label} {}", path.display()))?;
    temp.as_file_mut()
        .flush()
        .with_context(|| format!("failed to flush temporary {label} {}", path.display()))?;
    temp.as_file_mut()
        .sync_all()
        .with_context(|| format!("failed to sync temporary {label} {}", path.display()))?;

    let publish_result = if force {
        temp.persist(path)
    } else {
        temp.persist_noclobber(path)
    };
    match publish_result {
        Ok(_) => Ok(()),
        Err(error) if !force && error.error.kind() == io::ErrorKind::AlreadyExists => bail!(
            "{label} already exists: {}; use --force to overwrite",
            path.display()
        ),
        Err(error) => Err(error.error)
            .with_context(|| format!("failed to publish {label} {}", path.display())),
    }
}

fn load_ed25519_signing_key(path: &str) -> Result<SigningKey> {
    let seed = load_32_byte_key_file("Ed25519 signing key seed", path)?;
    Ok(SigningKey::from_bytes(&seed))
}

fn load_create_root_auth_profile(
    signing_key: Option<&str>,
    signing_cert: Option<&str>,
    signing_private_key: Option<&str>,
    signing_chain: &[String],
    x509_signature_scheme: Option<CliX509SignatureScheme>,
) -> Result<Option<CreateRootAuthProfile>> {
    match (signing_key, signing_cert, signing_private_key) {
        (Some(path), None, None) => {
            if x509_signature_scheme.is_some() {
                return Err(UsageError("--x509-signature-scheme requires --signing-cert").into());
            }
            let signing_key = load_ed25519_signing_key(path)?;
            let signer_identity = signing_key.verifying_key().to_bytes();
            Ok(Some(CreateRootAuthProfile::Ed25519 {
                signing_key,
                signer_identity,
            }))
        }
        (None, Some(cert_path), Some(private_key_path)) => {
            let cert = fs::read(cert_path)
                .with_context(|| format!("failed to read signing certificate {cert_path}"))?;
            let private_key = fs::read(private_key_path).with_context(|| {
                format!("failed to read signing private key {private_key_path}")
            })?;
            let chain_der = load_x509_certificate_files(signing_chain)?;
            let signed_at = current_unix_seconds()?;
            let signer = if let Some(scheme) = x509_signature_scheme {
                X509RootAuthSigner::from_pem_or_der_with_signature_scheme(
                    &cert,
                    &private_key,
                    chain_der,
                    signed_at,
                    scheme.to_plugin_scheme(),
                )
            } else {
                X509RootAuthSigner::from_pem_or_der(&cert, &private_key, chain_der, signed_at)
            }
            .with_context(|| format!("failed to load X.509 signing profile from {cert_path}"))?;
            Ok(Some(CreateRootAuthProfile::X509(signer)))
        }
        (None, None, None) => {
            if !signing_chain.is_empty() {
                return Err(UsageError("--signing-chain requires --signing-cert").into());
            }
            if x509_signature_scheme.is_some() {
                return Err(UsageError("--x509-signature-scheme requires --signing-cert").into());
            }
            Ok(None)
        }
        _ => Err(UsageError(
            "create requires either --signing-key or --signing-cert with --signing-private-key",
        )
        .into()),
    }
}

fn load_ed25519_public_key(path: &str) -> Result<[u8; 32]> {
    load_32_byte_key_file("Ed25519 public key", path)
}

fn load_x509_certificate_files(paths: &[String]) -> Result<Vec<Vec<u8>>> {
    let mut certificates = Vec::new();
    for path in paths {
        let bytes = fs::read(path).with_context(|| format!("failed to read certificate {path}"))?;
        certificates.extend(
            x509_chain::certificates_der_from_pem_or_der(&bytes)
                .with_context(|| format!("failed to parse certificate {path}"))?,
        );
    }
    Ok(certificates)
}

fn load_x509_trusted_roots(
    paths: &[String],
    include_official_tzap_root: bool,
) -> Result<Vec<Vec<u8>>> {
    let mut certificates = Vec::new();
    if include_official_tzap_root {
        certificates.push(
            x509_chain::certificate_der_from_pem_or_der(OFFICIAL_TZAP_ROOT_CERT_PEM)
                .with_context(|| {
                    format!(
                        "failed to parse embedded TZAP root certificate {OFFICIAL_TZAP_ROOT_CERT_SHA256}"
                    )
                })?,
        );
    }
    certificates.extend(load_x509_certificate_files(paths)?);
    Ok(certificates)
}

fn load_single_x509_certificate_file(label: &'static str, path: &str) -> Result<Vec<u8>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {label} {path}"))?;
    let certificates = x509_chain::certificates_der_from_pem_or_der(&bytes)
        .with_context(|| format!("failed to parse {label} {path}"))?;
    match certificates.as_slice() {
        [certificate] => Ok(certificate.clone()),
        [] => bail!("{label} must contain exactly one X.509 certificate"),
        _ => bail!("{label} must contain exactly one X.509 certificate"),
    }
}

fn load_recipient_private_key_lookup(path: &str) -> Result<CliRecipientPrivateKeyLookup> {
    let bytes = fs::read(path).with_context(|| format!("failed to read recipient key {path}"))?;
    if bytes.len() == 32 {
        return Ok(CliRecipientPrivateKeyLookup {
            private_key_bytes: bytes,
            private_key_spki_der: None,
        });
    }
    let private_key = if bytes.starts_with(b"-----BEGIN") {
        PKey::private_key_from_pem(&bytes)
            .with_context(|| format!("failed to parse recipient private key {path}"))?
    } else {
        PKey::private_key_from_der(&bytes)
            .with_context(|| format!("failed to parse recipient private key {path}"))?
    };
    let private_key_bytes = private_key
        .private_key_to_der()
        .with_context(|| format!("failed to normalize recipient private key {path}"))?;
    let private_key_spki_der = private_key.public_key_to_der().ok();
    Ok(CliRecipientPrivateKeyLookup {
        private_key_bytes,
        private_key_spki_der,
    })
}

fn generate_random_master_key() -> Result<MasterKey> {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    MasterKey::from_raw_key(&bytes).map_err(Into::into)
}

fn build_recipient_wrap_record(
    recipient_cert_path: &str,
    master_key: &MasterKey,
    options: &mut WriterOptions,
) -> Result<tzap_core::wire::RecipientRecordV1> {
    let recipient_certificate =
        load_single_x509_certificate_file("recipient certificate", recipient_cert_path)?;
    let archive_identity = recipient_wrap_archive_identity_for_writer(options);
    let master_key_bytes = master_key.0;
    for suite in [
        KeyWrapSuite::X25519HkdfSha256ChaCha20Poly1305,
        KeyWrapSuite::P256HkdfSha256Aes256Gcm,
    ] {
        match wrap_master_key_for_recipient(
            archive_identity.clone(),
            &recipient_certificate,
            &master_key_bytes,
            suite,
        ) {
            Ok(record) => return Ok(record),
            Err(KeyWrapOutcome::InvalidRecord) | Err(KeyWrapOutcome::UnsupportedSuite) => {}
            Err(outcome) => return Err(key_wrap_outcome_error(outcome)),
        }
    }
    Err(anyhow!(FormatError::WriterUnsupported(
        "recipient certificate is not supported by keywrap-v1 suites",
    )))
}

fn recipient_wrap_archive_identity_for_writer(
    options: &mut WriterOptions,
) -> KeyWrapArchiveIdentity {
    let archive_uuid = *options.archive_uuid.get_or_insert_with(random_16_bytes);
    let session_id = *options.session_id.get_or_insert_with(random_16_bytes);
    KeyWrapArchiveIdentity {
        archive_uuid,
        session_id,
        format_version: FORMAT_VERSION,
        volume_format_rev: VOLUME_FORMAT_REV_44,
    }
}

fn random_16_bytes() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn key_wrap_outcome_error(outcome: KeyWrapOutcome) -> anyhow::Error {
    match outcome {
        KeyWrapOutcome::UnsupportedProfileId => anyhow!(FormatError::ReaderUnsupported(
            "unsupported keywrap recipient profile",
        )),
        KeyWrapOutcome::UnsupportedArchiveIdentity => anyhow!(FormatError::ReaderUnsupported(
            "unsupported keywrap archive identity",
        )),
        KeyWrapOutcome::UnsupportedRecipientIdentity => anyhow!(FormatError::ReaderUnsupported(
            "unsupported keywrap recipient identity",
        )),
        KeyWrapOutcome::UnsupportedSuite => anyhow!(FormatError::ReaderUnsupported(
            "unsupported keywrap recipient suite",
        )),
        KeyWrapOutcome::CertificatePolicyRejected => anyhow!(FormatError::ReaderUnsupported(
            "recipient certificate policy rejected",
        )),
        KeyWrapOutcome::InvalidRecord => anyhow!(FormatError::InvalidArchive(
            "invalid keywrap recipient record",
        )),
        KeyWrapOutcome::NoMatchingPrivateKey => anyhow!(FormatError::KeyMaterialMismatch)
            .context("no matching recipient private key for archive"),
        KeyWrapOutcome::UnwrappedCandidateMasterKey { .. } => anyhow!(
            FormatError::WriterInvariant("keywrap success outcome cannot be converted to error",)
        ),
    }
}

fn current_unix_seconds() -> Result<i64> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    i64::try_from(seconds).context("current Unix timestamp exceeds i64")
}

fn load_32_byte_key_file(label: &'static str, path: &str) -> Result<[u8; 32]> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {label} {path}"))?;
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }

    let hex = std::str::from_utf8(&bytes)
        .with_context(|| format!("{label} must contain either 32 raw bytes or 64 hex characters"))?
        .trim();
    if hex.len() != 64 {
        bail!("{label} must contain either 32 raw bytes or 64 hex characters");
    }
    let mut out = [0u8; 32];
    for (idx, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        out[idx] = decode_hex_byte(chunk)?;
    }
    Ok(out)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = std::fmt::Write::write_fmt(&mut output, format_args!("{:02x}", byte));
    }
    output
}

#[allow(clippy::too_many_arguments)]
fn load_create_key(
    keyfile: Option<&str>,
    password_stdin: bool,
    password: bool,
    no_encryption: bool,
    insecure_zero_key: bool,
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
    if no_encryption {
        return Ok(CreateKey {
            master_key: insecure_zero_master_key()?,
            kdf_params: KdfParams::None,
        });
    }
    if insecure_zero_key {
        return Err(removed_insecure_zero_key_error().into());
    }
    Ok(CreateKey {
        master_key: load_raw_master_key(keyfile)?,
        kdf_params: KdfParams::Raw,
    })
}

fn load_open_key_from_paths(
    keyfile: Option<&str>,
    password_stdin: bool,
    password: bool,
    insecure_zero_key: bool,
    volume_paths: &[String],
) -> Result<MasterKey> {
    if password_stdin {
        let passphrase = read_passphrase_stdin()?;
        let kdf_params = read_kdf_params_from_any_volume_path(volume_paths)?;
        return derive_key_from_passphrase(&kdf_params, &passphrase);
    }
    if password {
        let passphrase = read_passphrase_interactive_open()?;
        let kdf_params = read_kdf_params_from_any_volume_path(volume_paths)?;
        return derive_key_from_passphrase(&kdf_params, &passphrase);
    }
    if insecure_zero_key {
        return Err(removed_insecure_zero_key_error().into());
    }
    if keyfile.is_some() {
        return load_raw_master_key(keyfile);
    }
    let protection = read_archive_protection_from_any_volume_path(volume_paths)?;
    if protection.aead_algo == AeadAlgo::None && protection.kdf_algo == KdfAlgo::None {
        return insecure_zero_master_key();
    }
    Err(anyhow!(FormatError::KeyMaterialMismatch)
        .context("encrypted archives require --keyfile, --password, or --password-stdin"))
}

fn insecure_zero_master_key() -> Result<MasterKey> {
    MasterKey::from_raw_key(&INSECURE_ZERO_KEY).map_err(Into::into)
}

fn derive_key_from_passphrase(kdf_params: &KdfParams, passphrase: &str) -> Result<MasterKey> {
    match kdf_params {
        KdfParams::Argon2id { .. } => {
            MasterKey::derive_from_passphrase(kdf_params, passphrase).map_err(Into::into)
        }
        KdfParams::Raw => Err(anyhow!(FormatError::KeyMaterialMismatch)
            .context("raw-key archives require --keyfile, not passphrase input")),
        KdfParams::RecipientWrap { .. } => Err(anyhow!(FormatError::KeyMaterialMismatch)
            .context("recipient-wrap archives require recipient key unwrap, not passphrase input")),
        KdfParams::None => Err(anyhow!(FormatError::KeyMaterialMismatch)
            .context("unencrypted archives do not use passphrase input")),
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
        anyhow!(
            "no key source provided; use --password-stdin, --password, --keyfile PATH, --recipient-cert FILE, or --no-encryption for create"
        )
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

#[cfg(test)]
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
    Ok(read_archive_protection_from_headers(header_bytes, crypto_header_bytes)?.kdf_params)
}

fn read_kdf_params_from_volume_path(path: &str) -> Result<KdfParams> {
    Ok(read_archive_protection_from_volume_path(path)?.kdf_params)
}

#[derive(Debug)]
struct ArchiveProtection {
    aead_algo: AeadAlgo,
    kdf_algo: KdfAlgo,
    kdf_params: KdfParams,
}

fn read_archive_protection_from_volume_path(path: &str) -> Result<ArchiveProtection> {
    let mut file = File::open(path).with_context(|| format!("failed to open archive {path}"))?;
    let mut header_bytes = vec![0u8; VOLUME_HEADER_LEN];
    file.read_exact(&mut header_bytes)
        .with_context(|| format!("failed to read VolumeHeader from {path}"))?;
    let volume_header = VolumeHeader::parse(&header_bytes)?;
    let offset = volume_header.crypto_header_offset as u64;
    let length = volume_header.crypto_header_length as usize;
    file.seek(SeekFrom::Start(offset))
        .with_context(|| format!("failed to seek to CryptoHeader in {path}"))?;
    let mut crypto_header_bytes = vec![0u8; length];
    file.read_exact(&mut crypto_header_bytes)
        .with_context(|| format!("failed to read CryptoHeader from {path}"))?;
    read_archive_protection_from_headers(&header_bytes, &crypto_header_bytes)
}

fn read_kdf_params_from_any_volume_path(paths: &[String]) -> Result<KdfParams> {
    let mut first_error = None;
    for path in paths {
        match read_kdf_params_from_volume_path(path) {
            Ok(params) => return Ok(params),
            Err(err) => {
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
        }
    }
    Err(first_error.unwrap_or_else(|| anyhow!("at least one archive volume is required")))
        .context("failed to read KDF parameters from any archive volume")
}

fn read_archive_protection_from_any_volume_path(paths: &[String]) -> Result<ArchiveProtection> {
    let mut first_error = None;
    for path in paths {
        match read_archive_protection_from_volume_path(path) {
            Ok(protection) => return Ok(protection),
            Err(err) => {
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
        }
    }
    Err(first_error.unwrap_or_else(|| anyhow!("at least one archive volume is required")))
        .context("failed to read protection mode from any archive volume")
}

fn read_archive_protection_from_headers(
    header_bytes: &[u8],
    crypto_header_bytes: &[u8],
) -> Result<ArchiveProtection> {
    let volume_header = VolumeHeader::parse(header_bytes)?;
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
    Ok(ArchiveProtection {
        aead_algo: fixed.aead_algo,
        kdf_algo: fixed.kdf_algo,
        kdf_params: crypto_header.kdf_params,
    })
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
    if err.downcast_ref::<UsageError>().is_some() {
        return Diagnostic {
            label: "invalid-arguments",
            exit_code: EXIT_USAGE,
            action: "check command arguments",
        };
    }
    for cause in err.chain() {
        if let Some(usage) = cause.downcast_ref::<UsageError>() {
            let _ = usage;
            return Diagnostic {
                label: "invalid-arguments",
                exit_code: EXIT_USAGE,
                action: "check command arguments",
            };
        }
        if let Some(write_error) = cause.downcast_ref::<ArchiveWriteError>() {
            return match write_error {
                ArchiveWriteError::Format(format) => classify_format_error(format),
                ArchiveWriteError::Io(io_error) => classify_io_error(io_error),
            };
        }
        if let Some(extract_error) = cause.downcast_ref::<ExtractError>() {
            return match extract_error {
                ExtractError::Format(format) => classify_format_error(format),
                ExtractError::Output(io_error) => classify_io_error(io_error),
            };
        }
        if let Some(format) = cause.downcast_ref::<FormatError>() {
            return classify_format_error(format);
        }
        if let Some(io_error) = cause.downcast_ref::<io::Error>() {
            return classify_io_error(io_error);
        }
    }
    Diagnostic {
        label: "error",
        exit_code: EXIT_GENERIC,
        action: "",
    }
}

fn classify_io_error(err: &io::Error) -> Diagnostic {
    match err.kind() {
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
    }
}

fn classify_format_error(err: &FormatError) -> Diagnostic {
    match err {
        FormatError::UnsupportedFormatVersion(_)
        | FormatError::UnsupportedVolumeFormatRevision { .. }
        | FormatError::UnknownCompressionAlgo(_)
        | FormatError::UnknownAeadAlgo(_)
        | FormatError::UnknownFecAlgo(_)
        | FormatError::UnknownKdfAlgo(_)
        | FormatError::UnsupportedCompression(_)
        | FormatError::UnsupportedFec(_)
        | FormatError::UnsupportedBootstrapSidecarVersion(_) => Diagnostic {
            label: "unsupported-revision",
            exit_code: EXIT_UNSUPPORTED_REVISION,
            action: "upgrade tzap or use a reader that supports this archive revision",
        },
        FormatError::BadMagic {
            structure: "VolumeHeader",
        }
        | FormatError::BadMagic {
            structure: "VolumeTrailer",
        }
        | FormatError::BadMagic {
            structure: "ManifestFooter",
        } => Diagnostic {
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
            action: "confirm the archive key source (passphrase/raw key/recipient key)",
        },
        FormatError::IntegrityDigestMismatch { .. } => Diagnostic {
            label: "corrupt-archive",
            exit_code: EXIT_CORRUPT_ARCHIVE,
            action: "verify the archive bytes and source file path",
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
        FormatError::InvalidArchive(message)
            if *message == "missing volume count exceeds volume_loss_tolerance" =>
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
        FormatError::BadCrc {
            structure: "VolumeHeader",
        }
        | FormatError::BadCrc {
            structure: "VolumeTrailer",
        }
        | FormatError::BadCrc {
            structure: "ManifestFooter",
        }
        | FormatError::InvalidMetadata {
            structure: "ManifestFooter",
            ..
        }
        | FormatError::InvalidMetadata {
            structure: "VolumeHeader",
            ..
        } => Diagnostic {
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
            label: if *structure == "IndexRoot"
                || *structure == "FrameEntry"
                || *structure == "EnvelopeEntry"
            {
                "corrupt-payload"
            } else {
                "corrupt-header"
            },
            exit_code: EXIT_CORRUPT_ARCHIVE,
            action: if *structure == "IndexRoot"
                || *structure == "FrameEntry"
                || *structure == "EnvelopeEntry"
            {
                "inspect archive metadata tables and payload"
            } else {
                "inspect archive header metadata"
            },
        },
        FormatError::ReaderResourceLimitExceeded { .. } => Diagnostic {
            label: "invalid-arguments",
            exit_code: EXIT_USAGE,
            action:
                "check argon2 flags (--argon2-t-cost, --argon2-m-cost-kib, --argon2-parallelism)",
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

    use std::io::Cursor;

    use tzap_core::format::MASTER_KEY_LEN;

    fn test_master_key() -> MasterKey {
        MasterKey::from_raw_key(&[0x42; MASTER_KEY_LEN]).unwrap()
    }

    fn test_tar_stream(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (path, data) in entries {
            out.extend_from_slice(&test_tar_header(path.as_bytes(), b'0', data.len() as u64));
            out.extend_from_slice(data);
            out.resize(out.len() + test_tar_padding(data.len()), 0);
        }
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    fn test_tar_header(path: &[u8], kind: u8, size: u64) -> [u8; 512] {
        let mut header = [0u8; 512];
        header[..path.len()].copy_from_slice(path);
        test_tar_octal(&mut header[100..108], 0o644);
        test_tar_octal(&mut header[108..116], 0);
        test_tar_octal(&mut header[116..124], 0);
        test_tar_octal(&mut header[124..136], size);
        test_tar_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = kind;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
        test_tar_checksum(&mut header[148..156], checksum);
        header
    }

    fn test_tar_octal(field: &mut [u8], value: u64) {
        let digits = format!("{value:o}");
        field.fill(0);
        let start = field.len() - 1 - digits.len();
        field[..start].fill(b'0');
        field[start..start + digits.len()].copy_from_slice(digits.as_bytes());
    }

    fn test_tar_checksum(field: &mut [u8], value: u64) {
        let digits = format!("{value:06o}");
        field[0..6].copy_from_slice(digits.as_bytes());
        field[6] = 0;
        field[7] = b' ';
    }

    fn test_tar_padding(len: usize) -> usize {
        let remainder = len % 512;
        if remainder == 0 {
            0
        } else {
            512 - remainder
        }
    }

    #[test]
    fn create_layout_defaults_scale_by_input_size() {
        assert_eq!(
            default_create_layout(Some(LARGE_CREATE_LAYOUT_THRESHOLD)),
            CreateLayout {
                block_size: 64 * 1024,
                chunk_size: 256 * 1024,
                envelope_target_size: 1024 * 1024,
            }
        );
        assert_eq!(
            default_create_layout(Some(LARGE_CREATE_LAYOUT_THRESHOLD + 1)),
            CreateLayout {
                block_size: 1024 * 1024,
                chunk_size: 32 * 1024 * 1024,
                envelope_target_size: 64 * 1024 * 1024,
            }
        );
        assert_eq!(
            default_create_layout(None),
            default_create_layout(Some(LARGE_CREATE_LAYOUT_THRESHOLD + 1))
        );
    }

    #[test]
    fn create_layout_chunk_override_grows_implicit_envelope() {
        let layout = resolve_create_layout(
            CreateLayoutOverrides {
                chunk_size: Some("4M"),
                envelope_size: None,
                block_size: None,
            },
            Some(1024),
        )
        .unwrap();

        assert_eq!(layout.chunk_size, 4 * 1024 * 1024);
        assert_eq!(layout.envelope_target_size, 4 * 1024 * 1024);
        assert_eq!(layout.block_size, 64 * 1024);
    }

    #[test]
    fn tar_stdin_signer_failure_removes_temporary_archive_output() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("failed.tzap");
        let key = CreateKey {
            master_key: test_master_key(),
            kdf_params: KdfParams::Raw,
        };
        let root_auth = RootAuthWriterConfig {
            authenticator_id: 0x9001,
            signer_identity_type: 0x9002,
            signer_identity: b"test signer",
            authenticator_value_length: 64,
        };
        let mut authenticator = |_request: &RootAuthSigningRequest| {
            Err(FormatError::WriterUnsupported("test signer failed"))
        };
        let mut input = Cursor::new(test_tar_stream(&[("signed.txt", b"signed")]));

        let error = write_tar_stdin_archive_output_from_reader(
            output.to_str().unwrap(),
            &mut input,
            &key,
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
            Some(root_auth),
            Some(&mut authenticator),
            false,
        )
        .unwrap_err();

        assert!(error.to_string().contains("test signer failed"));
        assert!(!output.exists());
    }

    #[test]
    fn raw_spool_multi_volume_signer_failure_removes_temporary_archive_outputs_and_spool() {
        let temp = tempfile::tempdir().unwrap();
        let output = temp.path().join("failed-raw-spool.tzap");
        let volume_0 = create_output_paths(output.to_str().unwrap(), 3)[0].clone();
        let volume_1 = create_output_paths(output.to_str().unwrap(), 3)[1].clone();
        let volume_2 = create_output_paths(output.to_str().unwrap(), 3)[2].clone();
        let key = CreateKey {
            master_key: test_master_key(),
            kdf_params: KdfParams::Raw,
        };
        let root_auth = RootAuthWriterConfig {
            authenticator_id: 0x9001,
            signer_identity_type: 0x9002,
            signer_identity: b"test signer",
            authenticator_value_length: 64,
        };
        let mut authenticator = |_request: &RootAuthSigningRequest| {
            Err(FormatError::WriterUnsupported("test signer failed"))
        };
        let payload = (0..150_000)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let spool_path;

        {
            let spool = crate::plaintext_spool::spool_unknown_size_raw_stdin_in(
                Cursor::new(payload),
                temp.path(),
                u64::MAX,
                ExplicitPlaintextSpool::acknowledge_plaintext_spool(),
            )
            .unwrap();
            let known_size_source = spool.known_size_source();
            spool_path = spool.path().to_path_buf();
            let mut spool_reader = spool.reopen().unwrap();

            let error = write_raw_stdin_archive_output_from_reader(
                output.to_str().unwrap(),
                &mut spool_reader,
                "raw/spooled.bin",
                known_size_source.size(),
                &key,
                WriterOptions {
                    stripe_width: 3,
                    volume_loss_tolerance: 0,
                    bit_rot_buffer_pct: 0,
                    ..WriterOptions::default()
                },
                Some(root_auth),
                Some(&mut authenticator),
                false,
            )
            .unwrap_err();

            assert!(error.to_string().contains("test signer failed"));
            assert!(spool_path.exists());
        }

        assert!(!spool_path.exists());
        assert!(!output.exists());
        assert!(!volume_0.exists());
        assert!(!volume_1.exists());
        assert!(!volume_2.exists());
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
    fn unsupported_revision_errors_suggest_reader_upgrade() {
        for err in [
            FormatError::UnsupportedFormatVersion(2),
            FormatError::UnsupportedVolumeFormatRevision {
                format_version: 1,
                volume_format_rev: 44,
                reader_max_supported_revision: READER_MAX_SUPPORTED_VOLUME_FORMAT_REV,
            },
        ] {
            let diagnostic = classify_format_error(&err);

            assert_eq!(diagnostic.label, "unsupported-revision");
            assert_eq!(diagnostic.exit_code, EXIT_UNSUPPORTED_REVISION);
            assert_eq!(
                diagnostic.action,
                "upgrade tzap or use a reader that supports this archive revision"
            );
        }
    }

    #[test]
    fn reporting_unsupported_revision_json_has_observed_supported_action_only() {
        let err = anyhow!(FormatError::UnsupportedVolumeFormatRevision {
            format_version: 1,
            volume_format_rev: VOLUME_FORMAT_REV_44 + 1,
            reader_max_supported_revision: VOLUME_FORMAT_REV_44,
        });

        let payload = unsupported_revision_error_json(
            &err,
            "upgrade tzap or use a reader that supports this archive revision",
        );

        assert_eq!(payload["label"], "unsupported-revision");
        assert_eq!(
            payload["observed"]["format_version"],
            serde_json::json!(FORMAT_VERSION)
        );
        assert_eq!(
            payload["observed"]["volume_format_rev"],
            serde_json::json!(VOLUME_FORMAT_REV_44 + 1)
        );
        assert_eq!(
            payload["supported"]["max_volume_format_rev"],
            serde_json::json!(VOLUME_FORMAT_REV_44)
        );
        assert!(payload.get("root_auth").is_none());
        assert!(payload.get("decryption_keywrap").is_none());
    }

    #[test]
    fn reporting_public_no_key_status_is_metadata_only() {
        let root_auth = VerifiedPublicNoKeyRootAuth::Ed25519(PublicNoKeyVerification {
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV_44,
            archive_root: [1; 32],
            authenticator_id: ED25519_AUTHENTICATOR_ID,
            signer_identity_type: 1,
            signer_identity_bytes: [2; 32].to_vec(),
            total_data_block_count: 7,
            diagnostics: vec![
                tzap_core::reader::PublicNoKeyDiagnostic::PublicDataBlockCommitmentVerified,
                tzap_core::reader::PublicNoKeyDiagnostic::PublicPhysicalCompletenessUnverified,
            ],
        });

        let status = public_no_key_status_json(&root_auth);

        assert_eq!(status["revision_mode"], serde_json::json!("v44"));
        assert_eq!(status["decryption_keywrap"], serde_json::json!("not_used"));
        assert_eq!(
            status["trust_policy"],
            serde_json::json!("public_trust_matched")
        );
        assert_eq!(
            status["public_no_key_metadata_only"],
            serde_json::json!("metadata_commitments_verified")
        );
    }

    #[test]
    fn embedded_official_root_fingerprint_matches_certificate() {
        let der = x509_chain::certificate_der_from_pem_or_der(OFFICIAL_TZAP_ROOT_CERT_PEM).unwrap();
        let cert = X509::from_der(&der).unwrap();
        let digest = cert.digest(openssl::hash::MessageDigest::sha256()).unwrap();

        assert_eq!(
            OFFICIAL_TZAP_ROOT_CERT_SHA256,
            format!("sha256:{}", encode_hex(&digest))
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
    fn missing_volume_errors_keep_stable_diagnostic() {
        let diagnostic = classify_format_error(&FormatError::InvalidArchive(
            "missing volume count exceeds volume_loss_tolerance",
        ));

        assert_eq!(diagnostic.label, "missing-volume");
        assert_eq!(diagnostic.exit_code, EXIT_CORRUPT_ARCHIVE);
        assert_eq!(
            diagnostic.action,
            "add the missing archive volume(s) or confirm volume-loss tolerance"
        );
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
