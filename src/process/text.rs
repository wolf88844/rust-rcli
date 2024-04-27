use anyhow::{Ok, Result};
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit, OsRng},
    ChaCha20Poly1305,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::{collections::HashMap, io::Read};

use crate::{process_genpass, TextSignFormat};

pub trait TextSigner {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextVerifier {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool>;
}

pub trait TextEncrypt {
    fn text_encrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextDecrypt {
    fn text_decrypt(&self, reader: &mut Vec<u8>) -> Result<Vec<u8>>;
}

pub struct Chacha2 {
    key: [u8; 32],
}

pub struct Blake3 {
    key: [u8; 32],
}

pub struct Ed25519Signer {
    key: SigningKey,
}

pub struct Ed25519Verifier {
    key: VerifyingKey,
}

impl TextSigner for Blake3 {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ret = blake3::keyed_hash(&self.key, &buf);
        Ok(ret.as_bytes().to_vec())
    }
}

impl TextVerifier for Blake3 {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ret = blake3::keyed_hash(&self.key, &buf);
        Ok(ret.as_bytes() == sig)
    }
}

impl TextSigner for Ed25519Signer {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ret = self.key.sign(&buf);
        Ok(ret.to_bytes().to_vec())
    }
}

impl TextVerifier for Ed25519Verifier {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let sig = (&sig[..64]).try_into()?;
        let ret = Signature::from_bytes(sig);
        Ok(self.key.verify(&buf, &ret).is_ok())
    }
}

impl TextEncrypt for Chacha2 {
    fn text_encrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ci = ChaCha20Poly1305::new_from_slice(&self.key);
        let cipher = match ci {
            std::result::Result::Ok(cipher) => cipher,
            Err(e) => return Err(anyhow::anyhow!("encrypt error: {}", e)),
        };
        let ve = vec![249, 115, 113, 158, 149, 52, 117, 46, 246, 119, 228, 36];
        let nonce = GenericArray::from_slice(&ve);
        //let nonce = ChaCha20Poly1305::generate_nonce(&mut os_rng); // 96-bits; unique per message
        let ciphertext = cipher.encrypt(nonce, buf.as_ref());
        let text = match ciphertext {
            std::result::Result::Ok(ciphertext) => Ok(ciphertext),
            Err(e) => Err(anyhow::anyhow!("encrypt error: {}", e)),
        }?;
        Ok(text)
    }
}

impl TextDecrypt for Chacha2 {
    fn text_decrypt(&self, reader: &mut Vec<u8>) -> Result<Vec<u8>> {
        let ci = ChaCha20Poly1305::new_from_slice(&self.key);
        let cipher = match ci {
            std::result::Result::Ok(cipher) => cipher,
            Err(e) => return Err(anyhow::anyhow!("encrypt error: {}", e)),
        };
        let ve = vec![249, 115, 113, 158, 149, 52, 117, 46, 246, 119, 228, 36];
        let nonce = GenericArray::from_slice(&ve); // 96-bits; unique per message
        let ciphertext = cipher.decrypt(nonce, reader.as_ref());
        let decrypt = match ciphertext {
            std::result::Result::Ok(ciphertext) => Ok(ciphertext),
            Err(e) => Err(anyhow::anyhow!("decrypt error: {}", e)),
        }?;
        Ok(decrypt)
    }
}

impl Blake3 {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        if key.len() != 32 {
            return Err(anyhow::anyhow!("key length must be 32 bytes"));
        }
        let key = (&key[..32]).try_into()?;
        let ret = Blake3::new(key);
        Ok(ret)
    }

    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let key = process_genpass(32, true, true, true, true)?;
        let mut map = HashMap::new();
        map.insert("blake3.txt", key.as_bytes().to_vec());
        Ok(map)
    }
}

impl Ed25519Signer {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        if key.len() != 32 {
            return Err(anyhow::anyhow!("key length must be 32 bytes"));
        }
        let key = (&key[..32]).try_into()?;
        let ret = Ed25519Signer::new(key);
        Ok(ret)
    }

    pub fn new(key: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(key);
        Self { key }
    }

    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let pk = sk.verifying_key();
        let mut map = HashMap::new();
        map.insert("ed25519.sk", sk.as_bytes().to_vec());
        map.insert("ed25519.pk", pk.as_bytes().to_vec());
        Ok(map)
    }
}

impl Chacha2 {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        if key.len() != 32 {
            return Err(anyhow::anyhow!("key length must be 32 bytes"));
        }
        let key = (&key[..32]).try_into()?;
        let ret = Chacha2::new(key);
        Ok(ret)
    }
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
}

impl Ed25519Verifier {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        if key.len() != 32 {
            return Err(anyhow::anyhow!("key length must be 32 bytes"));
        }
        let key = (&key[..32]).try_into()?;
        let key = VerifyingKey::from_bytes(key)?;
        Ok(Self { key })
    }
}

pub fn process_text_sign(
    reader: &mut dyn Read,
    key: &[u8],
    format: TextSignFormat,
) -> Result<Vec<u8>> {
    let signer: Box<dyn TextSigner> = match format {
        TextSignFormat::Blake3 => Box::new(Blake3::try_new(key)?),
        TextSignFormat::Ed25519 => Box::new(Ed25519Signer::try_new(key)?),
    };
    signer.sign(reader)
}

pub fn process_text_verify(
    reader: &mut dyn Read,
    key: &[u8],
    sig: &[u8],
    format: TextSignFormat,
) -> Result<bool> {
    let verifier: Box<dyn TextVerifier> = match format {
        TextSignFormat::Blake3 => Box::new(Blake3::try_new(key)?),
        TextSignFormat::Ed25519 => Box::new(Ed25519Verifier::try_new(key)?),
    };
    verifier.verify(reader, sig)
}

pub fn process_text_key_generate(format: TextSignFormat) -> Result<HashMap<&'static str, Vec<u8>>> {
    match format {
        TextSignFormat::Blake3 => Blake3::generate(),
        TextSignFormat::Ed25519 => Ed25519Signer::generate(),
    }
}

pub fn process_text_encrypt(reader: &mut dyn Read, key: &[u8]) -> Result<Vec<u8>> {
    let chacha2 = Chacha2::try_new(key)?;
    let encrypt = chacha2.text_encrypt(reader)?;
    Ok(encrypt)
}

pub fn process_text_decrypt(reader: &mut Vec<u8>, key: &[u8]) -> Result<Vec<u8>> {
    let chacha2 = Chacha2::try_new(key)?;
    let decrypt = chacha2.text_decrypt(reader)?;
    Ok(decrypt)
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    use super::*;

    const KEY: &[u8] = b"iCfTwZ7jtMV*@FXZzEE&KCB#SXn7eGCE";

    #[test]
    fn test_process_text_sign() -> Result<()> {
        let mut reader = std::io::Cursor::new("hello world");
        let mut reader1 = std::io::Cursor::new("hello world");

        let format = TextSignFormat::Blake3;

        let sig = process_text_sign(&mut reader, KEY, format)?;
        let ret = process_text_verify(&mut reader1, KEY, &sig, format)?;
        assert!(ret);
        Ok(())
    }

    #[test]
    fn test_process_text_verify() -> Result<()> {
        let mut reader = std::io::Cursor::new("hello world");
        let mut reader1 = std::io::Cursor::new("hello world");

        let format = TextSignFormat::Blake3;

        let sig = process_text_sign(&mut reader1, KEY, format)?;
        let ret = process_text_verify(&mut reader, KEY, &sig, format)?;
        assert!(ret);
        Ok(())
    }

    #[test]
    fn test_process_encrypt() -> Result<()> {
        let mut content = std::io::Cursor::new("hello world");
        println!("key: {}", String::from_utf8(KEY.to_vec())?);
        let ret = process_text_encrypt(&mut content, KEY)?;
        let ret = URL_SAFE_NO_PAD.encode(ret);
        println!("encrypt:{:?}", ret);
        Ok(())
    }

    #[test]
    fn test_process_decrypt() -> Result<()> {
        let encrypt = "1IWwtO0MRNLgCzkujDhmbiihVd9D6WnKWbGl".to_string();
        let mut content = URL_SAFE_NO_PAD.decode(encrypt)?;
        //let mut content = std::io::Cursor::new(content);
        let ret = process_text_decrypt(&mut content, KEY)?;
        let ret = String::from_utf8(ret)?;
        println!("{}", ret);
        Ok(())
    }
}
