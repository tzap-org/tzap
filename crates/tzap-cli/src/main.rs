use anyhow::Result;
use clap::{Parser, Subcommand};

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
        Command::Create { .. } => todo!("create implementation"),
        Command::Extract { .. } => todo!("extract implementation"),
        Command::List { .. } => todo!("list implementation"),
        Command::Verify { .. } => todo!("verify implementation"),
    }
}
