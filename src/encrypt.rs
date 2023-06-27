use openssl::envelope::{Open, Seal};
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::symm::Cipher;
use serde::{Deserialize, Serialize};

/// Ciphertext from a PKE.
#[derive(Serialize, Deserialize, Debug)]
pub struct CT {
    pub encrypted: Vec<u8>,
    pub iv: [u8; 16],
    pub encrypted_key: Vec<u8>,
}

/// Generate a PK/SK pair for encrypted messaging.
pub fn kgen() -> (PKey<Private>, PKey<Public>) {
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = PKey::from_rsa(rsa).unwrap();

    let public_key_pem = private_key.public_key_to_pem().unwrap();
    let public_key = PKey::public_key_from_pem(&public_key_pem).unwrap();

    (private_key, public_key)
}

/// Returns a vector of bytes with a ciphertext encrypted against the public key.
pub fn encrypt(pk: &PKey<Public>, message: &[u8]) -> CT {
    let cipher = Cipher::aes_256_cbc();
    let mut seal = Seal::new(cipher, &[pk.clone()]).unwrap();

    // Create an output buffer
    let mut encrypted = vec![0; message.len() + cipher.block_size()];

    let mut enc_len = seal.update(message, &mut encrypted).unwrap();
    enc_len += seal.finalize(&mut encrypted[enc_len..]).unwrap();
    encrypted.truncate(enc_len);

    let mut seal_iv = [0u8; 16];
    seal_iv[..16].clone_from_slice(seal.iv().unwrap());

    CT {
        encrypted: encrypted,
        iv: seal_iv,
        encrypted_key: seal.encrypted_keys()[0].clone(),
    }
}

/// Returns a vector of bytes by decrypting the ciphertext with the private key.
pub fn decrypt(sk: &PKey<Private>, ct: &CT) -> Vec<u8> {
    // Decrypt the data
    let cipher = Cipher::aes_256_cbc();
    let mut open = Open::new(cipher, sk, Some(&ct.iv), &ct.encrypted_key).unwrap();

    // Create an output buffer
    let buffer_len = ct.encrypted.len() + cipher.block_size();
    let mut decrypted = vec![0; buffer_len];

    // Decrypt and truncate the buffer
    let mut decrypted_len = open
        .update(&ct.encrypted[..ct.encrypted.len()], &mut decrypted)
        .unwrap();
    decrypted_len += open.finalize(&mut decrypted[decrypted_len..]).unwrap();
    decrypted.truncate(decrypted_len);

    decrypted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_not_equal_to_original() {
        let (_, public) = kgen();
        let data = [0u8; 16];

        let encrypted = encrypt(&public, &data);

        assert_eq!(encrypted.encrypted.len(), 32);
        assert_ne!(encrypted.encrypted, Vec::from(data));
    }

    #[test]
    fn encrypt_decrypt_equals_original() {
        let (private, public) = kgen();
        let data = [0u8; 16];

        let encrypted = encrypt(&public, &data);
        let decrypted = decrypt(&private, &encrypted);

        assert_eq!(decrypted, Vec::from(data));
        assert_eq!(decrypted.len(), 16);
    }
}
