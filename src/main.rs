use std::fs;

#[warn(unused_imports)]
use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use rcli::{
    get_content, get_reader, process_csv, process_decode, process_encode, process_genpass,
    process_text_decrypt, process_text_encrypt, process_text_key_generate,
    process_text_nonce_generate, process_text_sign, process_text_verify, Base64SubCommand, Opts,
    SubCommand, TextSubCommand,
};
use zxcvbn::zxcvbn;

fn main() -> Result<()> {
    let opts = Opts::parse();
    match opts.cmd {
        SubCommand::Csv(opts) => {
            let output = if let Some(output) = opts.output {
                output.clone()
            } else {
                format!("output.{}", opts.format)
            };
            process_csv(&opts.input, output, opts.format)?;
        }
        SubCommand::GenPass(opts) => {
            let password = process_genpass(
                opts.length,
                opts.has_uppercase,
                opts.has_lowercase,
                opts.has_number,
                opts.has_symbol,
            )?;
            println!("{}", password);

            let estimate = zxcvbn(&password, &[])?;
            eprintln!("Password strength: {}", estimate.score());
        }
        SubCommand::Base64(subcmd) => match subcmd {
            Base64SubCommand::Encode(opts) => {
                let mut reader = get_reader(&opts.input)?;
                let encode = process_encode(&mut reader, opts.format)?;
                println!("encode:{}", encode);
            }
            Base64SubCommand::Decode(opts) => {
                let mut reader = get_reader(&opts.input)?;
                let decoded = process_decode(&mut reader, opts.format)?;
                println!("decoded:{}", decoded);
            }
        },
        SubCommand::Text(subcmd) => match subcmd {
            TextSubCommand::Sign(opts) => {
                let mut reader = get_reader(&opts.input)?;
                let key = get_content(&opts.key)?;
                let sig = process_text_sign(&mut reader, &key, opts.format)?;
                let encoded = URL_SAFE_NO_PAD.encode(sig);
                println!("sig:{}", encoded);
            }
            TextSubCommand::Generate(opts) => {
                let map = process_text_key_generate(opts.format)?;
                for (k, v) in map {
                    fs::write(opts.output_path.join(k), v)?;
                }
            }
            TextSubCommand::Verify(opts) => {
                let mut reader = get_reader(&opts.input)?;
                let key = get_content(&opts.key)?;
                let decoded = URL_SAFE_NO_PAD.decode(&opts.sig)?;
                let verified = process_text_verify(&mut reader, &key, &decoded, opts.format)?;
                if verified {
                    println!("verified");
                } else {
                    println!("not verified");
                }
            }
            TextSubCommand::GenerateNonce(opts) => {
                let nonce = process_text_nonce_generate()?;
                for (k, v) in nonce {
                    fs::write(opts.output_path.join(k), v)?;
                }
            }
            TextSubCommand::Encrypt(opts) => {
                let mut reader = get_reader(&opts.input)?;
                let key = opts.key.into_bytes();
                let encrypt = process_text_encrypt(&mut reader, &key, &opts.nonce)?;
                let encrypt = URL_SAFE_NO_PAD.encode(encrypt);
                println!("encrypt:{}", encrypt);
            }
            TextSubCommand::Decrypt(opts) => {
                let reader = get_content(&opts.input)?;
                let mut reader = URL_SAFE_NO_PAD.decode(reader)?;
                let key = opts.key.into_bytes();
                let decrypt = process_text_decrypt(&mut reader, &key, &opts.nonce)?;
                println!("decrypt:{}", String::from_utf8(decrypt)?);
            }
        },
    }
    Ok(())
}
