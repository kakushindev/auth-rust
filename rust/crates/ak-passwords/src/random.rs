use rand::RngExt as _;

/// `django.utils.crypto.RANDOM_STRING_CHARS`
pub(crate) const RANDOM_STRING_CHARS: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// `django.utils.crypto.get_random_string(length)`, drawing every character
/// uniformly from [`RANDOM_STRING_CHARS`] with a CSPRNG (Django: `secrets.choice`).
pub fn get_random_string(length: usize) -> String {
    let mut rng = rand::rng();
    std::iter::repeat_with(|| {
        char::from(RANDOM_STRING_CHARS[rng.random_range(0..RANDOM_STRING_CHARS.len())])
    })
    .take(length)
    .collect()
}

/// `log2(len(RANDOM_STRING_CHARS))` = `log2(62)`
pub(crate) const BITS_PER_CHAR: f64 = 5.954_196_310_386_876;

/// `ceil(salt_entropy / BITS_PER_CHAR)` = `ceil(128 / log2(62))`
const DEFAULT_SALT_LENGTH: usize = 22;

/// `BasePasswordHasher.salt()`: enough characters for 128 bits of entropy.
pub(crate) fn default_salt() -> String {
    get_random_string(DEFAULT_SALT_LENGTH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_django_formula() {
        let alphabet = f64::from(u32::try_from(RANDOM_STRING_CHARS.len()).expect("62"));
        assert!((alphabet.log2() - BITS_PER_CHAR).abs() < 1e-12_f64);
        let length = (crate::SALT_ENTROPY / BITS_PER_CHAR).ceil();
        assert!((length - 22.0).abs() < f64::EPSILON);
    }

    #[test]
    fn salt_length_matches_django() {
        let salt = default_salt();
        assert_eq!(salt.len(), 22);
        assert!(salt.bytes().all(|b| RANDOM_STRING_CHARS.contains(&b)));
    }
}
