use anyhow::{Ok, Result};
use std::{fs::File, io::Read};

pub fn get_reader(input: &str) -> Result<Box<dyn Read>> {
    let reader: Box<dyn Read> = if input == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(File::open(input)?)
    };
    Ok(reader)
}

pub fn get_content(input: &str) -> Result<Vec<u8>> {
    let mut reader = get_reader(input)?;
    let mut content = Vec::new();
    reader.read_to_end(&mut content)?;
    Ok(content)
}
