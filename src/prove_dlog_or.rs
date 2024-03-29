use crate::group_operations::hash_to_scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

/// Produces a challenge by hashing the points g^r and h^r into a scalar.
pub fn produce_challenge(
    leading_byte: u8,
    report: [u8; 32],
    duptag: CompressedRistretto,
    w_values: &Vec<CompressedRistretto>,
    t_values: &Vec<CompressedRistretto>,
    y1_values: &Vec<CompressedRistretto>,
    y2_values: &Vec<CompressedRistretto>,
) -> Scalar {
    let bitstring = format!(
        "report: {:?} duptag: {:?} w_values: {:?} t_values: {:?} y1_values: {:?} y2_values: {:?}",
        report, duptag, w_values, t_values, y1_values, y2_values
    )
    .into_bytes();

    let mut domain_separated_bytes = Vec::new();
    domain_separated_bytes.push(leading_byte);
    domain_separated_bytes.extend(bitstring);
    hash_to_scalar(&domain_separated_bytes)
}
