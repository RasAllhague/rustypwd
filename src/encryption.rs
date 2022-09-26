use anyhow::anyhow;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::{
    aead::{stream, NewAead},
    XChaCha20Poly1305,
};
use rand::{rngs::OsRng, RngCore};
use secstr::SecStr;
use std::{
    fs::File,
    io::{Read, Write},
};
use zeroize::Zeroize;

const BUFFER_LEN: usize = 500;

pub trait CryptoProvider {
    fn encrypt_string(
        &self,
        data_to_encrypt: SecStr,
        password: &SecStr,
    ) -> Result<SecStr, anyhow::Error>;
    fn decrypt_string_from_file(
        &self,
        source_file: &str,
        password: &SecStr,
    ) -> Result<SecStr, anyhow::Error>;
}

pub struct Chacha20poly1305Provider;

impl CryptoProvider for Chacha20poly1305Provider {
    fn encrypt_string(
        &self,
        mut data_to_encrypt: SecStr,
        password: &SecStr,
    ) -> Result<SecStr, anyhow::Error> {
        let argon2_config = argon2_config();

        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);

        let mut key = argon2::hash_raw(password.unsecure(), &salt, &argon2_config)?;

        let cipher = chacha20poly1305::ChaCha20Poly1305::new(key[..32].as_ref().into());

        let mut encrypted_data: Vec<u8> = Vec::new();

        encrypted_data.extend_from_slice(&salt);
        encrypted_data.extend_from_slice(&nonce);

        let mut ciphertext = cipher
            .encrypt(nonce.as_ref().into(), data_to_encrypt.unsecure().as_ref())
            .map_err(|err| anyhow!("Encrypting password: {}", err))?;
        encrypted_data.extend_from_slice(&ciphertext);

        ciphertext.zeroize();
        salt.zeroize();
        nonce.zeroize();
        key.zeroize();
        data_to_encrypt.zero_out();

        Ok(SecStr::from(encrypted_data))
    }

    fn decrypt_string_from_file(
        &self,
        source_file: &str,
        password: &SecStr,
    ) -> Result<SecStr, anyhow::Error> {
        let mut salt = [0u8; 32];
        let mut nonce = [0u8; 12];

        let mut encrypted_file = File::open(source_file)?;

        let mut read_count = encrypted_file.read(&mut salt)?;
        if read_count != salt.len() {
            return Err(anyhow!("Error reading salt."));
        }

        read_count = encrypted_file.read(&mut nonce)?;
        if read_count != nonce.len() {
            return Err(anyhow!("Error reading nonce."));
        }

        let metadata = std::fs::metadata(&source_file)?;
        let mut buffer = vec![0; (metadata.len() - 44) as usize];
        read_count = encrypted_file.read(&mut buffer)?;

        if read_count != buffer.len() {
            return Err(anyhow!("Error reading buffer."));
        }

        let argon2_config = argon2_config();
        let mut key = argon2::hash_raw(password.unsecure(), &salt, &argon2_config)?;

        let cipher = ChaCha20Poly1305::new(key[..32].as_ref().into());

        let plaintext = cipher
            .decrypt(nonce.as_ref().into(), buffer.as_ref())
            .map_err(|err| anyhow!("Decrypting password: {}", err))?;

        salt.zeroize();
        nonce.zeroize();
        key.zeroize();

        Ok(SecStr::from(plaintext))
    }
}

pub fn argon2_config<'a>() -> argon2::Config<'a> {
    argon2::Config {
        variant: argon2::Variant::Argon2id,
        hash_length: 32,
        lanes: 8,
        mem_cost: 16 * 1024,
        time_cost: 8,
        ..Default::default()
    }
}

pub fn encrypt_file(
    source_file_path: &str,
    dist_file_path: &str,
    password: &SecStr,
) -> Result<(), anyhow::Error> {
    let argon2_config = argon2_config();

    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = argon2::hash_raw(password.unsecure(), &salt, &argon2_config)?;

    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut buffer = [0u8; BUFFER_LEN];

    let mut source_file = File::open(source_file_path)?;
    let mut dist_file = File::create(dist_file_path)?;

    dist_file.write(&salt)?;
    dist_file.write(&nonce)?;

    loop {
        let read_count = source_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            dist_file.write(&ciphertext)?;
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            dist_file.write(&ciphertext)?;
            break;
        }
    }

    salt.zeroize();
    nonce.zeroize();
    key.zeroize();

    Ok(())
}

pub fn decrypt_file(
    encrypted_file_path: &str,
    dist: &str,
    password: &SecStr,
) -> Result<(), anyhow::Error> {
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];

    let mut encrypted_file = File::open(encrypted_file_path)?;
    let mut dist_file = File::create(dist)?;

    let mut read_count = encrypted_file.read(&mut salt)?;
    if read_count != salt.len() {
        return Err(anyhow!("Error reading salt."));
    }

    read_count = encrypted_file.read(&mut nonce)?;
    if read_count != nonce.len() {
        return Err(anyhow!("Error reading nonce."));
    }

    let argon2_config = argon2_config();

    let mut key = argon2::hash_raw(password.unsecure(), &salt, &argon2_config)?;

    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut buffer = [0u8; BUFFER_LEN];

    loop {
        let read_count = encrypted_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            dist_file.write(&plaintext)?;
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            dist_file.write(&plaintext)?;
            break;
        }
    }

    salt.zeroize();
    nonce.zeroize();
    key.zeroize();

    Ok(())
}

pub fn encrypt_file_to_string(
    source_file_path: &str,
    password: &SecStr,
) -> Result<String, anyhow::Error> {
    let argon2_config = argon2_config();

    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = argon2::hash_raw(password.unsecure(), &salt, &argon2_config)?;

    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut buffer = [0u8; BUFFER_LEN];

    let mut source_file = File::open(source_file_path)?;
    let mut encrypted_string = String::new();

    encrypted_string.push_str(std::str::from_utf8(&salt)?);
    encrypted_string.push_str(std::str::from_utf8(&nonce)?);

    loop {
        let read_count = source_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            encrypted_string.push_str(std::str::from_utf8(&ciphertext)?);
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Encrypting large file: {}", err))?;
            encrypted_string.push_str(std::str::from_utf8(&ciphertext)?);
            break;
        }
    }

    salt.zeroize();
    nonce.zeroize();
    key.zeroize();

    Ok(encrypted_string)
}

pub fn decrypt_file_to_string(
    encrypted_file_path: &str,
    password: &SecStr,
) -> Result<String, anyhow::Error> {
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 19];

    let mut encrypted_file = File::open(encrypted_file_path)?;
    let mut decrypted_data = String::new();

    let mut read_count = encrypted_file.read(&mut salt)?;
    if read_count != salt.len() {
        return Err(anyhow!("Error reading salt."));
    }

    read_count = encrypted_file.read(&mut nonce)?;
    if read_count != nonce.len() {
        return Err(anyhow!("Error reading nonce."));
    }

    let argon2_config = argon2_config();

    let mut key = argon2::hash_raw(password.unsecure(), &salt, &argon2_config)?;

    let aead = XChaCha20Poly1305::new(key[..32].as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut buffer = [0u8; BUFFER_LEN];

    loop {
        let read_count = encrypted_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            decrypted_data.push_str(std::str::from_utf8(&plaintext)?);
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Decrypting large file: {}", err))?;
            decrypted_data.push_str(std::str::from_utf8(&plaintext)?);
            break;
        }
    }

    salt.zeroize();
    nonce.zeroize();
    key.zeroize();

    Ok(decrypted_data)
}
