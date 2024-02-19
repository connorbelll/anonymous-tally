use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::Sha512;

/// Performs an exponentiation with a point and a scalar.
pub fn exponentiate(point: RistrettoPoint, scalar: Scalar) -> RistrettoPoint {
    point * scalar
}

/// Returns an exponentiation with a point and the inverse of the scalar.
pub fn exponentiate_inverse(point: RistrettoPoint, scalar: Scalar) -> RistrettoPoint {
    point * scalar.invert()
}

/// Returns a multiplication of two points.
pub fn multiply(point1: RistrettoPoint, point2: RistrettoPoint) -> RistrettoPoint {
    // Multiplication of group elements is equivalent to addition of points on an elliptic curve.
    point1 + point2
}

/// Returns a division of two points.
pub fn divide(point1: RistrettoPoint, point2: RistrettoPoint) -> RistrettoPoint {
    // Division of group elements is equivalent to subtraction of points on an elliptic curve.
    point1 - point2
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
    let mut csprng = StdRng::from_entropy();
    Scalar::random(&mut csprng)
}

pub fn random_point() -> RistrettoPoint {
    let mut csprng = StdRng::from_entropy();
    RistrettoPoint::random(&mut csprng)
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

    #[test]
    fn multiply_is_inverse_of_divide() {
        let point1 = hash_to_point(&[1, 2, 3, 4]);
        let point2 = hash_to_point(&[5, 6, 7, 8]);

        let mult = multiply(point1, point2);

        assert_ne!(mult, point1);
        assert_ne!(mult, point2);

        let orig = divide(mult, point2);

        assert_eq!(orig, point1);
    }
}
