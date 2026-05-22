use std::fs;
use std::io::{self, Write};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use tzap_core::{open_archive, MasterKey};

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

        #[arg(long = "password-stdin")]
        password_stdin: bool,

        #[arg(long = "keyfile")]
        keyfile: Option<String>,

        #[arg(long = "dictionary")]
        dictionary: Option<String>,

        #[arg(required = true)]
        paths: Vec<String>,
    },
    Extract {
        archive: String,

        path: String,

        #[arg(long = "password-stdin")]
        password_stdin: bool,

        #[arg(long = "keyfile")]
        keyfile: Option<String>,

        #[arg(long = "bootstrap")]
        bootstrap: Option<String>,
    },
    List {
        archive: String,

        #[arg(long = "password-stdin")]
        password_stdin: bool,

        #[arg(long = "keyfile")]
        keyfile: Option<String>,

        #[arg(long = "bootstrap")]
        bootstrap: Option<String>,

        #[arg(long = "long")]
        long: bool,
    },
    Verify {
        #[arg(required = true)]
        archives: Vec<String>,

        #[arg(long = "password-stdin")]
        password_stdin: bool,

        #[arg(long = "keyfile")]
        keyfile: Option<String>,

        #[arg(long = "bootstrap")]
        bootstrap: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Create { .. } => {
            bail!("create is implemented in milestone 12, not milestone 7")
        }
        Command::Extract {
            archive,
            path,
            password_stdin,
            keyfile,
            bootstrap,
        } => {
            reject_bootstrap(&bootstrap)?;
            let master_key = load_master_key(keyfile.as_deref(), password_stdin)?;
            let archive_bytes =
                fs::read(&archive).with_context(|| format!("failed to read archive {archive}"))?;
            let opened = open_archive(&archive_bytes, &master_key)
                .with_context(|| format!("failed to open archive {archive}"))?;
            let contents = opened
                .extract_file(&path)?
                .ok_or_else(|| anyhow!("path not found in archive: {path}"))?;
            io::stdout().write_all(&contents)?;
            Ok(())
        }
        Command::List {
            archive,
            password_stdin,
            keyfile,
            bootstrap,
            long,
        } => {
            reject_bootstrap(&bootstrap)?;
            let master_key = load_master_key(keyfile.as_deref(), password_stdin)?;
            let archive_bytes =
                fs::read(&archive).with_context(|| format!("failed to read archive {archive}"))?;
            let opened = open_archive(&archive_bytes, &master_key)
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
            reject_bootstrap(&bootstrap)?;
            let master_key = load_master_key(keyfile.as_deref(), password_stdin)?;
            for archive in archives {
                let archive_bytes = fs::read(&archive)
                    .with_context(|| format!("failed to read archive {archive}"))?;
                let opened = open_archive(&archive_bytes, &master_key)
                    .with_context(|| format!("failed to open archive {archive}"))?;
                opened
                    .verify()
                    .with_context(|| format!("failed to verify archive {archive}"))?;
                println!("{archive}: OK");
            }
            Ok(())
        }
    }
}

fn reject_bootstrap(bootstrap: &Option<String>) -> Result<()> {
    if bootstrap.is_some() {
        bail!("bootstrap sidecars are implemented in milestone 9, not milestone 7");
    }
    Ok(())
}

fn load_master_key(keyfile: Option<&str>, password_stdin: bool) -> Result<MasterKey> {
    if password_stdin {
        bail!("password-based key derivation is implemented in milestone 12; use --keyfile for M7");
    }
    let keyfile = keyfile.ok_or_else(|| anyhow!("--keyfile is required for the M7 raw-key CLI"))?;
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
