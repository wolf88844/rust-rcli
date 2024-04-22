use clap::Parser;

#[derive(Debug, Parser)]
pub struct GenPassOpts {
    #[arg(short, long, default_value_t = 16)]
    pub length: u8,

    #[arg(short = 'u', long, default_value_t = false)]
    pub has_uppercase: bool,

    #[arg(long, default_value_t = false)]
    pub has_lowercase: bool,

    #[arg(short = 'n', long, default_value_t = false)]
    pub has_number: bool,

    #[arg(short = 's', long, default_value_t = false)]
    pub has_symbol: bool,
}
