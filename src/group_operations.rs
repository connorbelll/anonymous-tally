use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use sha2::Sha512;

/// Performs an exponentiation with a point and a scalar.
pub fn exponentiate(point: RistrettoPoint, scalar: Scalar) -> RistrettoPoint {
    point * scalar
}

/// Returns an exponentiation with a point and the inverse of the scalar.
pub fn exponentiate_inverse(point: RistrettoPoint, scalar: Scalar) -> RistrettoPoint {
    point * scalar.invert()
}

/// Returns a RistrettoPoint from a SHA512 hash of the specified bytes.
pub fn hash_to_point(bytes: &[u8]) -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(bytes)
}

/// Returns a Scalar from a SHA512 hash of the specified bytes.
pub fn hash_to_scalar(bytes: &[u8]) -> Scalar {
    Scalar::hash_from_bytes::<Sha512>(bytes)
}

/// Return a random scalar using OS randomness.
pub fn random_scalar() -> Scalar {
    let mut csprng = OsRng;
    Scalar::random(&mut csprng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exponentiate_is_invertible() {
        let scalar = random_scalar();
        let point = hash_to_point(&[1, 2, 3, 4]);

        let ident = exponentiate_inverse(exponentiate(point, scalar), scalar);

        assert_eq!(ident, point);
    }

    #[test]
    fn exponentiate_is_deterministic() {
        let scalar = random_scalar();
        let point = hash_to_point(&[1, 2, 3, 4]);

        let exp1 = exponentiate(point, scalar);
        let exp2 = exponentiate(point, scalar);

        assert_eq!(exp1, exp2);
    }

    #[test]
    fn hash_to_scalar_is_deterministic() {
        let scalar1 = hash_to_scalar(&[1, 2, 3, 4]);
        let scalar2 = hash_to_scalar(&[1, 2, 3, 4]);

        assert_eq!(scalar1, scalar2);
    }
}
