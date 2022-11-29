use crate::group_operations::{exponentiate, hash_to_scalar, random_scalar};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct DlogProof {
    a1: CompressedRistretto,
    a2: CompressedRistretto,
    t: Scalar,
}

/// Produces a challenge by hashing the points g^r and h^r into a scalar.
pub fn produce_challenge(
    leading_byte: u8,
    a1: &RistrettoPoint,
    a2: &RistrettoPoint,
    gx: &RistrettoPoint,
    gy: &RistrettoPoint,
    gxy: &RistrettoPoint,
) -> Scalar {
    let bitstring = format!(
        "a1: {:?} a2: {:?} gx: {:?} gy: {:?} gxy: {:?}",
        a1.compress(),
        a2.compress(),
        gx.compress(),
        gy.compress(),
        gxy.compress()
    )
    .into_bytes();

    let mut domain_separated_bytes = Vec::new();
    domain_separated_bytes.push(leading_byte);
    domain_separated_bytes.extend(bitstring);
    hash_to_scalar(&domain_separated_bytes)
}

/// Provides the values needed for a second party to verify that given g, h, g^x, and h^x that
/// x is equal in terms 3 and 4 without revealing x.
pub fn prove_dlog(
    leading_byte: u8,
    g: &RistrettoPoint,
    h: &RistrettoPoint,
    x: &Scalar,
    gx: &RistrettoPoint,
    hx: &RistrettoPoint,
) -> DlogProof {
    let r = random_scalar();

    // Compute a1 = g^r, a2 = h^r, and a corresponding challenge.
    let a1 = exponentiate(*g, r);
    let a2 = exponentiate(*h, r);
    let c = produce_challenge(leading_byte, &a1, &a2, gx, h, hx);

    // t = r + c * x.
    let t = r + (c * x);
    DlogProof {
        a1: a1.compress(),
        a2: a2.compress(),
        t: t,
    }
}

/// Verifies that given 4 points g, h, gx, and hx that DLOG between g and gx equals the DLOG
/// between h and hx; returns false otherwise.
pub fn verify_dlog(
    leading_byte: u8,
    g: &RistrettoPoint,
    h: &RistrettoPoint,
    gx: &RistrettoPoint,
    hx: &RistrettoPoint,
    proof: &DlogProof,
) -> bool {
    // Recompute the challenge, as it doesn't need to be passed over the wire.
    let a1 = proof.a1.decompress().unwrap();
    let a2 = proof.a2.decompress().unwrap();
    let c = produce_challenge(leading_byte, &a1, &a2, gx, h, hx);

    // If DLOG is the same for both pairs, the following should hold using the same value for t:
    // g^{r + c * x} = g^r * g^{x * c}
    // i.e. g^t = a1 * gx^c
    let part_one = exponentiate(*g, proof.t) == a1 + exponentiate(*gx, c);
    // h^{r + c * x} = h^r * h^{x * c}
    // i.e. h^t = a1 * hx^c
    let part_two = exponentiate(*h, proof.t) == a2 + exponentiate(*hx, c);
    part_one && part_two
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group_operations::hash_to_point;

    const TEST_LEADING_BYTE: u8 = 5u8;
    const TEST_LEADING_BYTE_BAD: u8 = 6u8;

    #[test]
    fn verifies_a_proof() {
        let g = hash_to_point(&[0u8; 16]);
        let h = hash_to_point(&[1u8; 16]);
        let x = hash_to_scalar(&[0u8, 1u8, 0u8, 1u8]);

        let gx = exponentiate(g, x);
        let hx = exponentiate(h, x);

        let proof = prove_dlog(TEST_LEADING_BYTE, &g, &h, &x, &gx, &hx);

        let gx = exponentiate(g, x);
        let hx = exponentiate(h, x);

        assert_eq!(
            verify_dlog(TEST_LEADING_BYTE, &g, &h, &gx, &hx, &proof),
            true
        );
    }

    #[test]
    fn invalidates_a_proof() {
        let g = hash_to_point(&[0u8; 16]);
        let h = hash_to_point(&[1u8; 16]);
        let x = hash_to_scalar(&[0u8, 1u8, 0u8, 1u8]);
        let y = hash_to_scalar(&[1u8, 1u8, 1u8, 1u8]);

        let gx = exponentiate(g, x);
        let hy = exponentiate(h, y);

        let proof = prove_dlog(TEST_LEADING_BYTE, &g, &h, &x, &gx, &hy);

        assert_eq!(
            verify_dlog(TEST_LEADING_BYTE, &g, &h, &gx, &hy, &proof),
            false
        );
    }

    #[test]
    fn fails_proof_with_different_domain() {
        let g = hash_to_point(&[0u8; 16]);
        let h = hash_to_point(&[1u8; 16]);
        let x = hash_to_scalar(&[0u8, 1u8, 0u8, 1u8]);

        let gx = exponentiate(g, x);
        let hx = exponentiate(h, x);

        let proof = prove_dlog(TEST_LEADING_BYTE, &g, &h, &x, &gx, &hx);

        let gx = exponentiate(g, x);
        let hx = exponentiate(h, x);

        assert_eq!(
            verify_dlog(TEST_LEADING_BYTE_BAD, &g, &h, &gx, &hx, &proof),
            false
        );
    }
}
