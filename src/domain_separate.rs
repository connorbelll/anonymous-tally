/// Extends a 16 byte array to a 17 byte array by prefixing the leading byte.
pub fn domain(leading: u8, vector: [u8; 16]) -> [u8; 17] {
    let mut result = [0u8; 17];
    result[0] = leading;
    result[1..].clone_from_slice(&vector);
    result
}

/// Extends a 32 byte array to a 33 byte array with the leading byte.
pub fn domain32(leading: u8, vector: [u8; 32]) -> [u8; 33] {
    let mut result = [0u8; 33];
    result[0] = leading;
    result[1..].clone_from_slice(&vector);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_adds_prefix() {
        let leading = 7u8;
        let vector = [1u8; 16];

        let output = domain(leading, vector);

        assert_eq!(
            output,
            [7u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8]
        );
    }

    #[test]
    fn domain32_adds_prefix() {
        let leading = 7u8;
        let vector = [1u8; 32];

        let output = domain32(leading, vector);

        assert_eq!(
            output,
            [
                7u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8,
                1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8, 1u8,
                1u8
            ]
        );
    }
}
