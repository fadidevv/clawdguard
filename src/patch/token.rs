//! Secure token generation.
//!
//! Generates cryptographically secure authentication tokens for
//! protecting gateway access. Tokens use a recognizable prefix
//! for easy identification.
//!
//! ## Token Format
//!
//! Tokens follow the format: `clwd_` + 32 random alphanumeric characters
//!
//! Example: `clwd_a8f2k9x3m1p7v4q2b6n8j5w7r9t3y1u`
//!
//! ## Security Properties
//!
//! - Uses cryptographically secure random number generator
//! - 62-character alphabet (a-z, A-Z, 0-9)
//! - 32 characters = ~190 bits of entropy
//! - Resistant to brute-force attacks

use rand::Rng;

/// Prefix for all generated tokens.
/// Helps identify tokens as ClawdGuard-generated.
const TOKEN_PREFIX: &str = "clwd_";

/// Character set for random token generation.
/// Includes lowercase, uppercase, and digits (62 characters total).
const TOKEN_CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Generates a cryptographically secure authentication token.
///
/// Creates a random string of the specified length using a secure
/// random number generator, prefixed with `clwd_` for identification.
///
/// # Arguments
///
/// * `length` - Number of random characters to generate (excluding prefix).
///   Recommended minimum: 16, default: 32.
///
/// # Returns
///
/// A token string in the format `clwd_` + random characters.
///
/// # Example
///
/// ```rust
/// use clawdguard::patch::generate_secure_token;
///
/// let token = generate_secure_token(32);
/// assert!(token.starts_with("clwd_"));
/// assert_eq!(token.len(), 5 + 32); // prefix + random
/// ```
///
/// # Security
///
/// Uses `rand::thread_rng()` which is cryptographically secure on most
/// platforms. The 62-character alphabet provides ~5.95 bits per character.
pub fn generate_secure_token(length: usize) -> String {
    let mut rng = rand::thread_rng();

    // Generate random characters from the charset
    let random_part: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..TOKEN_CHARSET.len());
            TOKEN_CHARSET[idx] as char
        })
        .collect();

    // Combine prefix with random part
    format!("{}{}", TOKEN_PREFIX, random_part)
}

/// Validates whether a string is a properly formatted token.
///
/// Checks that the token:
/// - Starts with the `clwd_` prefix
/// - Has at least 16 random characters
/// - Contains only alphanumeric characters in the random part
///
/// # Arguments
///
/// * `token` - The token string to validate.
///
/// # Returns
///
/// `true` if the token is valid, `false` otherwise.
///
/// # Example
///
/// ```rust,ignore
/// assert!(is_valid_token("clwd_a8f2k9x3m1p7v4q2b6n8"));
/// assert!(!is_valid_token("invalid_token"));
/// assert!(!is_valid_token("clwd_short")); // Too short
/// ```
#[allow(dead_code)]
pub fn is_valid_token(token: &str) -> bool {
    // Must start with the prefix
    if !token.starts_with(TOKEN_PREFIX) {
        return false;
    }

    // Extract the random part after the prefix
    let random_part = &token[TOKEN_PREFIX.len()..];

    // Must have minimum length for security
    if random_part.len() < 16 {
        return false;
    }

    // Must contain only alphanumeric characters
    random_part.chars().all(|c| c.is_ascii_alphanumeric())
}

/// Estimates the entropy (randomness) of a token in bits.
///
/// Calculates the theoretical entropy based on the character set
/// size and token length. Higher entropy means stronger security.
///
/// # Arguments
///
/// * `token` - The token to analyze.
///
/// # Returns
///
/// Estimated entropy in bits.
///
/// # Formula
///
/// entropy = length × log2(charset_size)
///
/// For our 62-character alphabet: ~5.95 bits per character.
/// A 32-character token has ~190 bits of entropy.
#[allow(dead_code)]
pub fn estimate_entropy(token: &str) -> f64 {
    // Remove prefix if present to measure just the random part
    let random_part = token.strip_prefix(TOKEN_PREFIX).unwrap_or(token);

    let charset_size = 62.0_f64; // a-z, A-Z, 0-9
    let length = random_part.len() as f64;

    // Entropy = length × log2(charset_size)
    length * charset_size.log2()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that generated tokens have the correct format.
    #[test]
    fn test_generate_token_format() {
        let token = generate_secure_token(32);
        assert!(token.starts_with(TOKEN_PREFIX));
        assert_eq!(token.len(), TOKEN_PREFIX.len() + 32);
    }

    /// Verifies that each generated token is unique.
    #[test]
    fn test_generate_token_uniqueness() {
        let token1 = generate_secure_token(32);
        let token2 = generate_secure_token(32);
        assert_ne!(token1, token2);
    }

    /// Verifies the token validation logic.
    #[test]
    fn test_is_valid_token() {
        let token = generate_secure_token(32);
        assert!(is_valid_token(&token));

        // Invalid cases
        assert!(!is_valid_token("invalid"));
        assert!(!is_valid_token("clwd_short")); // Too short (< 16 chars)
    }

    /// Verifies that tokens have sufficient entropy.
    #[test]
    fn test_entropy() {
        let token = generate_secure_token(32);
        let entropy = estimate_entropy(&token);
        // 32 chars × 5.95 bits/char ≈ 190 bits
        assert!(entropy > 150.0);
    }
}
