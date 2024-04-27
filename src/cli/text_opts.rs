use core::fmt;
use std::{path::PathBuf, str::FromStr};

use clap::{arg, Parser};

use super::{verify_file, verify_key, verify_path};

#[derive(Debug, Parser)]
pub enum TextSubCommand {
    #[command(about = "Sign a text with a private/session key and return")]
    Sign(TextSignOpt),
    #[command(about = "Verify a text with a public/session key")]
    Verify(TextVerifyOpt),
    #[command(about = "Generate a randow blake3 or ed25519 key")]
    Generate(KeyGenerateOpt),
    #[command(about = "encrypt text")]
    Encrypt(TextEncryptOpt),
    #[command(about = "decrypt text")]
    Decrypt(TextDecryptOpt),
}

#[derive(Debug, Parser)]
pub struct TextSignOpt {
    #[arg(short,long,value_parser=verify_file,default_value="-")]
    pub input: String,
    #[arg(short,long,value_parser=verify_file)]
    pub key: String,
    #[arg(long,default_value="blake3",value_parser=parse_text_sign_format)]
    pub format: TextSignFormat,
}

#[derive(Debug, Parser)]
pub struct TextVerifyOpt {
    #[arg(short,long,value_parser=verify_file,default_value="-")]
    pub input: String,
    #[arg(short,long,value_parser=verify_file)]
    pub key: String,
    #[arg(long)]
    pub sig: String,
    #[arg(long,default_value="blake3",value_parser=parse_text_sign_format)]
    pub format: TextSignFormat,
}

#[derive(Debug, Parser)]
pub struct KeyGenerateOpt {
    #[arg(long,default_value="blake3",value_parser=parse_text_sign_format)]
    pub format: TextSignFormat,
    #[arg(short, long,value_parser=verify_path)]
    pub output_path: PathBuf,
}

#[derive(Debug, Parser)]
pub struct TextEncryptOpt {
    #[arg(short,long,value_parser=verify_file,default_value="-")]
    pub input: String,
    #[arg(short, long,value_parser=verify_key)]
    pub key: String,
}

#[derive(Debug, Parser)]
pub struct TextDecryptOpt {
    #[arg(short,long,value_parser=verify_file,default_value="-")]
    pub input: String,
    #[arg(short, long,value_parser=verify_key)]
    pub key: String,
}

#[derive(Debug, Clone, Copy)]
pub enum TextSignFormat {
    Blake3,
    Ed25519,
}

fn parse_text_sign_format(format: &str) -> Result<TextSignFormat, anyhow::Error> {
    format.parse()
}

impl FromStr for TextSignFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "blake3" => Ok(TextSignFormat::Blake3),
            "ed25519" => Ok(TextSignFormat::Ed25519),
            _ => Err(anyhow::anyhow!("Invalid format")),
        }
    }
}

impl From<TextSignFormat> for &'static str {
    fn from(format: TextSignFormat) -> Self {
        match format {
            TextSignFormat::Blake3 => "blake3",
            TextSignFormat::Ed25519 => "ed25519",
        }
    }
}

impl fmt::Display for TextSignFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Into::<&str>::into(*self))
    }
}
