use anyhow::Ok;
use rand::seq::SliceRandom;

const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefjhijkmnopqrstuvwxyz";
const NUMBER: &[u8] = b"123456789";
const SYMBOL: &[u8] = b"!@#$%^&*_";

pub fn process_genpass(
    length: u8,
    uppercase: bool,
    lowercase: bool,
    number: bool,
    symbol: bool,
) -> anyhow::Result<String> {
    let mut rng = rand::thread_rng();
    let mut password = Vec::new();
    let mut chars = Vec::new();

    if uppercase {
        chars.extend_from_slice(UPPER);
        password.push(*UPPER.choose(&mut rng).expect("UPPER wont't be empty"));
    }

    if lowercase {
        chars.extend_from_slice(LOWER);
        password.push(*LOWER.choose(&mut rng).expect("LOWER wont't be empty"));
    }

    if number {
        chars.extend_from_slice(NUMBER);
        password.push(*NUMBER.choose(&mut rng).expect("NUMBER wont't be empty"));
    }

    if symbol {
        chars.extend_from_slice(SYMBOL);
        password.push(*SYMBOL.choose(&mut rng).expect("SYMBOL wont't be empty"));
    }

    for _ in 0..(length - password.len() as u8) {
        let c = chars
            .choose(&mut rng)
            .expect("chars won't empty in this context");
        password.push(*c);
    }

    password.shuffle(&mut rng);

    let password = String::from_utf8(password)?;

    Ok(password)
}
