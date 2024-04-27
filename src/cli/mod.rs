mod baes64_opts;
mod csv_opts;
mod genpass_opts;
mod text_opts;

use std::path::{Path, PathBuf};

pub use baes64_opts::{Base64Format, Base64SubCommand};
use clap::Parser;
pub use csv_opts::{CsvOpts, OutputFormat};
pub use genpass_opts::GenPassOpts;
pub use text_opts::{TextSignFormat, TextSignOpt, TextSubCommand, TextVerifyOpt};

#[derive(Debug, Parser)]
#[command(name = "rcil", version, author)]
pub struct Opts {
    #[command(subcommand)]
    pub cmd: SubCommand,
}

#[derive(Debug, Parser)]
pub enum SubCommand {
    #[command(name = "csv", about = "Show Csv ,or convert Csv to other type")]
    Csv(CsvOpts),
    #[command(name = "genpass", about = "Generate a random password")]
    GenPass(GenPassOpts),
    #[command(subcommand)]
    Base64(Base64SubCommand),
    #[command(subcommand)]
    Text(TextSubCommand),
}

fn verify_file(filename: &str) -> Result<String, &'static str> {
    if filename == "-" || Path::new(filename).exists() {
        Ok(filename.into())
    } else {
        Err("File does not exist")
    }
}

fn verify_path(path: &str) -> Result<PathBuf, &'static str> {
    let p = Path::new(path);
    if p.exists() && p.is_dir() {
        Ok(path.into())
    } else {
        Err("path does not exist or is not a directory")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_verify_file() {
        assert_eq!(verify_file("-"), Ok("-".into()));
        assert_eq!(verify_file("*"), Err("File does not exist"));
        assert_eq!(verify_file("Cargo.toml"), Ok("Cargo.toml".into()));
        assert_eq!(verify_file("not-exist"), Err("File does not exist"));
    }
}
