// We use HMAC to MAC statements of exponentiations.

use hmac::{digest::MacError, Hmac, Mac};
use sha2_10::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct BackendMAC {
    /// 256-bit key for a MAC.
    key: [u8; 32],
}

impl BackendMAC {
    pub fn new(key: [u8; 32]) -> BackendMAC {
        BackendMAC { key: key }
    }

    fn hmac(&self) -> HmacSha256 {
        HmacSha256::new_from_slice(&self.key).expect("HMAC can take key of any size")
    }

    /// Returns a 256-bit tag from an HMAC sign() invocation.
    pub fn sign(&self, message: &[u8]) -> [u8; 32] {
        let mut mac = self.hmac();

        mac.update(message);

        let mut output = [0; 32];
        output[0..32].clone_from_slice(&mac.finalize().into_bytes()[0..32]);
        output
    }

    /// Returns the result of verifying the provided message and tag.
    pub fn verify(&self, message: &[u8], tag: &[u8]) -> Result<(), MacError> {
        let mut mac = self.hmac();

        mac.update(message);

        mac.verify_slice(&tag[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verifies() -> Result<(), MacError> {
        let ones = [255u8; 32];
        let message = [35u8; 16];

        let mac = BackendMAC::new(ones);

        let tag = mac.sign(&message);
        mac.verify(&message, &tag)
    }

    #[test]
    fn sign_returns_bytes() {
        let ones = [255u8; 32];
        let message = [35u8; 16];

        let mac = BackendMAC::new(ones);
        let tag = mac.sign(&message);

        assert_eq!(
            tag,
            [
                48, 160, 158, 223, 237, 184, 33, 60, 161, 0, 55, 128, 246, 9, 213, 70, 173, 157,
                111, 23, 180, 179, 1, 62, 198, 90, 13, 216, 104, 74, 127, 209
            ]
        );
    }

    #[test]
    fn sign_with_different_keys_differs() {
        let zeros = [0u8; 32];
        let ones = [255u8; 32];
        let message = [35u8; 16];

        let mac_zero = BackendMAC::new(zeros);
        let mac_one = BackendMAC::new(ones);

        let tag_zero = mac_zero.sign(&message);
        let tag_one = mac_one.sign(&message);

        assert_ne!(tag_zero, tag_one);
    }
}
