use rand::RngExt as _;

/// `django.utils.crypto.RANDOM_STRING_CHARS`
pub(crate) const RANDOM_STRING_CHARS: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// `django.utils.crypto.get_random_string(length)`, drawing every character
/// uniformly from [`RANDOM_STRING_CHARS`] with a CSPRNG (Django: `secrets.choice`).
pub fn get_random_string(length: usize) -> String {
    let mut rng = rand::rng();
    (0..length)
        .map(|_| char::from(RANDOM_STRING_CHARS[rng.random_range(0..RANDOM_STRING_CHARS.len())]))
        .collect()
}

/// `BasePasswordHasher.salt()`: enough characters for 128 bits of entropy (22).
pub(crate) fn default_salt() -> String {
    #[expect(clippy::cast_precision_loss, reason = "alphabet length is 62")]
    let bits_per_char = (RANDOM_STRING_CHARS.len() as f64).log2();
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "result is 22"
    )]
    let length = (crate::SALT_ENTROPY / bits_per_char).ceil() as usize;
    get_random_string(length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salt_length_matches_django() {
        let salt = default_salt();
        assert_eq!(salt.len(), 22);
        assert!(salt.bytes().all(|b| RANDOM_STRING_CHARS.contains(&b)));
    }
}
