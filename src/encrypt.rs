use openssl::encrypt::{Decrypter, Encrypter};
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::{Padding, Rsa};

/// Generate a PK/SK pair for encrypted messaging.
pub fn kgen() -> (PKey<Private>, PKey<Public>) {
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = PKey::from_rsa(rsa).unwrap();

    let public_key_pem = private_key.public_key_to_pem().unwrap();
    let public_key = PKey::public_key_from_pem(&public_key_pem).unwrap();

    (private_key, public_key)
}

/// Returns a vector of bytes with a ciphertext encrypted against the public key.
pub fn encrypt(pk: &PKey<Public>, message: &[u8]) -> Vec<u8> {
    let mut encrypter = Encrypter::new(pk).unwrap();
    encrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();

    // Create an output buffer
    let buffer_len = encrypter.encrypt_len(message).unwrap();
    let mut encrypted = vec![0; buffer_len];

    // Encrypt and truncate the buffer
    let encrypted_len = encrypter.encrypt(message, &mut encrypted).unwrap();
    encrypted.truncate(encrypted_len);

    encrypted
}

/// Returns a vector of bytes by decrypting the ciphertext with the private key.
pub fn decrypt(sk: &PKey<Private>, ct: &Vec<u8>) -> Vec<u8> {
    // Decrypt the data
    let mut decrypter = Decrypter::new(sk).unwrap();
    decrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();

    // Create an output buffer
    let buffer_len = decrypter.decrypt_len(ct).unwrap();
    let mut decrypted = vec![0; buffer_len];

    // Encrypt and truncate the buffer
    let decrypted_len = decrypter.decrypt(ct, &mut decrypted).unwrap();
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

        assert_ne!(encrypted, Vec::from(data));
    }

    #[test]
    fn encrypt_decrypt_equals_original() {
        let (private, public) = kgen();
        let data = [0u8; 16];

        let encrypted = encrypt(&public, &data);
        let decrypted = decrypt(&private, &encrypted);

        assert_eq!(decrypted, Vec::from(data));
    }
}
