
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::{rng, Rng};
use shadowsocks_service::shadowsocks::crypto::CipherKind;

#[derive(Debug)]
#[allow(dead_code)]
pub enum KeyGenError {
    InvalidMethod(String),
    KeyGenerationFailed
}

impl std::fmt::Display for KeyGenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyGenError::InvalidMethod(m) => write!(f, "Invalid cipher method: {}", m),
            KeyGenError::KeyGenerationFailed => write!(f, "Failed to generate random key")
        }
    }
}

impl std::error::Error for KeyGenError {}

/// Generates a random base64-encoded key for the specified cipher method
pub fn generate_key(method: &str) -> Result<String, KeyGenError> {
    // Parse the method string into CipherKind
    let cipher = method.parse::<CipherKind>()
        .map_err(|_| KeyGenError::InvalidMethod(method.to_string()))?;

    // Get the required key length for this cipher
    let key_len = cipher.key_len();

    // Generate random bytes
    let mut key = vec![0u8; key_len];
    rng().fill(&mut key[..]);

    // Base64 encode the key
    Ok(BASE64.encode(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key() {
        // Test valid method
        let key = generate_key("aes-128-gcm").unwrap();
        assert!(!key.is_empty());

        // Test invalid method
        assert!(generate_key("invalid-method").is_err());
    }
}
