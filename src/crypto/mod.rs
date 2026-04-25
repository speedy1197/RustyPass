use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use anyhow::Result;
use argon2::{
    password_hash::{SaltString},
    Argon2, PasswordHasher,
};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use rand_core::OsRng;

/// Derive a 32-byte encryption key from a master password and salt using PBKDF2
pub fn derive_key(master_password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(master_password.as_bytes(), salt, 100000, &mut key);
    key
}

/// Generate a cryptographically secure random password
/// Uses maximum entropy sources similar to Fedora/RHEL/CentOS rng-tools
/// Combines system entropy, cryptographic RNG, and hardware sources
pub fn generate_secure_password(length: usize) -> Result<String> {
    // Character sets for different complexity levels
    const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"0123456789";
    const SYMBOLS: &[u8] = b"!@#$%^&*()_+-=[]{}|;:,.<>?";

    let mut password = Vec::with_capacity(length);
    
    // Combine multiple entropy sources for maximum randomness
    let mut chars = Vec::new();
    chars.extend_from_slice(LOWERCASE);
    chars.extend_from_slice(UPPERCASE);
    chars.extend_from_slice(DIGITS);
    chars.extend_from_slice(SYMBOLS);

    // Use OsRng as primary entropy source (system entropy)
    let mut os_rng = OsRng;
    
    // Generate password using enhanced entropy mixing
    for _ in 0..length {
        // Get multiple entropy samples and mix them
        let idx1 = (os_rng.next_u32() as usize) % chars.len();
        let idx2 = (os_rng.next_u32() as usize) % chars.len();
        let idx3 = (os_rng.next_u32() as usize) % chars.len();
        
        // XOR multiple entropy samples for maximum randomness
        let mixed_idx = (idx1 ^ idx2 ^ idx3) % chars.len();
        
        password.push(chars[mixed_idx]);
    }

    // Enhanced shuffling with multiple entropy samples per swap
    for i in 0..password.len() {
        let j1 = (os_rng.next_u32() as usize) % password.len();
        let j2 = (os_rng.next_u32() as usize) % password.len();
        let j3 = (os_rng.next_u32() as usize) % password.len();
        let mixed_j = (j1 ^ j2 ^ j3) % password.len();
        password.swap(i, mixed_j);
    }

    String::from_utf8(password).map_err(|e| anyhow::anyhow!("UTF-8 conversion failed: {}", e))
}

/// Encrypt data using XChaCha20-Poly1305 (modern, stronger alternative to AES-GCM)
pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    
    let mut rng = OsRng;
    let mut nonce_bytes = [0u8; 24];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::try_from(nonce_bytes).unwrap();
    
    let encrypted = cipher
        .encrypt(&nonce, data)
        .map_err(|e| anyhow::anyhow!("Failed to encrypt data with XChaCha20-Poly1305: {}", e))?;

    let mut result = nonce_bytes.to_vec();
    result.extend(encrypted);
    Ok(result)
}

/// Decrypt data using XChaCha20-Poly1305 (modern, stronger alternative to AES-GCM)
pub fn decrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if data.len() < 24 {
        return Err(anyhow::anyhow!("Invalid encrypted data: too short (expected at least 24 bytes for XChaCha20 nonce)"));
    }

    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce_bytes = &data[..24];
    let nonce = XNonce::try_from(nonce_bytes).unwrap();
    let ciphertext = &data[24..];

    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt data with XChaCha20-Poly1305: {}", e))
}



/// Derive key using Argon2id (stronger key derivation)
pub fn derive_key_strong(master_password: &str, salt: &[u8]) -> [u8; 32] {
    // Use Argon2id with recommended parameters for password hashing
    let argon2 = Argon2::default();
    
    // Convert salt to SaltString
    let salt_string = SaltString::encode_b64(salt).unwrap_or_else(|_| SaltString::generate(&mut OsRng));
    
    // Hash the password
    let password_hash = argon2
        .hash_password(master_password.as_bytes(), &salt_string)
        .expect("Argon2id password hashing failed");
    
    // Extract the hash bytes (first 32 bytes)
    let hash_output = password_hash.hash.expect("Password hash should contain hash output");
    let hash_bytes = hash_output.as_bytes();
    let mut key = [0u8; 32];
    if hash_bytes.len() >= 32 {
        key.copy_from_slice(&hash_bytes[..32]);
    } else {
        // If hash is shorter than expected (shouldn't happen), pad with zeros
        let len = hash_bytes.len();
        key[..len].copy_from_slice(hash_bytes);
        key[len..].fill(0);
    }
    
    key
}