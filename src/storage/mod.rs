use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{self, File, create_dir_all},
    io::Read,
    path::{PathBuf, Path},
};

/// Application settings structure
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppSettings {
    pub default_password_length: usize,
    pub auto_lock_enabled: bool,
    pub session_timeout_minutes: Option<usize>,
    pub use_symbols: bool,
    pub use_uppercase: bool,
    pub use_lowercase: bool,
    pub use_digits: bool,
    pub biometric_auth_enabled: bool,
    pub max_failed_attempts: Option<usize>,
    pub clipboard_clear_seconds: Option<usize>,
    pub encryption_key_rotation_days: Option<usize>,
    pub password_expiry_days: Option<usize>,
    pub require_min_complexity: bool,
    pub min_entropy_bits: Option<usize>,
    pub storage_location: Option<String>,
    pub auto_backup_enabled: bool,
    pub backup_frequency_days: Option<usize>,
    pub last_backup: Option<String>,
    pub performance_mode: String,
    pub theme: String,
    pub enable_debug_logging: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            default_password_length: 16,
            auto_lock_enabled: false,
            session_timeout_minutes: None,
            use_symbols: true,
            use_uppercase: true,
            use_lowercase: true,
            use_digits: true,
            biometric_auth_enabled: false,
            max_failed_attempts: Some(5),
            clipboard_clear_seconds: Some(30),
            encryption_key_rotation_days: Some(365),
            password_expiry_days: None,
            require_min_complexity: false,
            min_entropy_bits: Some(60),
            storage_location: None,
            auto_backup_enabled: false,
            backup_frequency_days: Some(7),
            last_backup: None,
            performance_mode: "balanced".to_string(),
            theme: "system".to_string(),
            enable_debug_logging: false,
        }
    }
}

/// Password store structure
#[derive(Serialize, Deserialize, Debug)]
#[derive(Clone, Default)]
pub struct PasswordStore {
    pub entries: HashMap<String, String>,
}

impl PasswordStore {
    /// Create a new empty password store
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Add a password entry for a service
    pub fn add_password(&mut self, service: String, password: String) {
        self.entries.insert(service, password);
    }

    /// Get a password for a service
    pub fn get_password(&self, service: &str) -> Option<&String> {
        self.entries.get(service)
    }

    /// Remove a password entry
    pub fn remove_password(&mut self, service: &str) -> Option<String> {
        self.entries.remove(service)
    }

    /// Get all service names
    pub fn get_services(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }
}

/// Get the storage directory path
fn get_storage_dir() -> Result<PathBuf> {
    // Use the specified .local directory
    let mut dir = PathBuf::from("/Users/eli/.local");
    dir.push("RustyPass");
    Ok(dir)
}

/// Get the password storage file path
pub fn get_passwords_file() -> Result<PathBuf> {
    let mut file = get_storage_dir()?;
    file.push("passwords.json.enc");
    Ok(file)
}

/// Get the salt file path
pub fn get_salt_file() -> Result<PathBuf> {
    let mut file = get_storage_dir()?;
    file.push("salt.bin");
    Ok(file)
}

/// Get the settings file path
pub fn get_settings_file() -> Result<PathBuf> {
    let mut file = get_storage_dir()?;
    file.push("settings.json.enc");
    Ok(file)
}

/// Ensure the storage directory exists
fn ensure_storage_dir_exists() -> Result<()> {
    let storage_dir = get_storage_dir()?;
    create_dir_all(storage_dir)?;
    Ok(())
}

/// Save passwords to encrypted storage
pub fn save_passwords(store: &PasswordStore, key: &[u8; 32]) -> Result<()> {
    ensure_storage_dir_exists()?;
    let json = serde_json::to_string(store)?;
    let encrypted = crate::crypto::encrypt(json.as_bytes(), key)?;
    let storage_file = get_passwords_file()?;
    fs::write(&storage_file, encrypted)?;
    Ok(())
}

/// Save passwords to a specific file (for atomic operations)
pub fn save_passwords_to(store: &PasswordStore, key: &[u8; 32], file_path: &Path) -> Result<()> {
    ensure_storage_dir_exists()?;
    let json = serde_json::to_string(store)?;
    let encrypted = crate::crypto::encrypt(json.as_bytes(), key)?;
    fs::write(file_path, encrypted)?;
    Ok(())
}

/// Load passwords from a specific file (for atomic operations)
pub fn load_passwords_from(file_path: &Path, key: &[u8; 32]) -> Result<PasswordStore> {
    let mut encrypted_data = Vec::new();
    let mut file = File::open(file_path)?;
    file.read_to_end(&mut encrypted_data)?;
    
    let decrypted = crate::crypto::decrypt(&encrypted_data, key)
        .with_context(|| "Failed to decrypt password data")?;
    
    let json = String::from_utf8(decrypted)
        .with_context(|| "Failed to convert decrypted data to UTF-8")?;
    
    let store: PasswordStore = serde_json::from_str(&json)
        .with_context(|| "Failed to parse password store JSON")?;
    
    Ok(store)
}

/// Load passwords from encrypted storage
pub fn load_passwords(key: &[u8; 32]) -> Result<PasswordStore> {
    let storage_file = get_passwords_file()?;
    if !storage_file.exists() {
        return Ok(PasswordStore::new());
    }

    let mut file = File::open(&storage_file)
        .with_context(|| format!("Failed to open password storage file: {}", storage_file.display()))?;
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data)
        .with_context(|| "Failed to read encrypted data from storage file")?;

    let decrypted = crate::crypto::decrypt(&encrypted_data, key)
        .with_context(|| "Failed to decrypt password data")?;
    let json = String::from_utf8(decrypted)
        .with_context(|| "Failed to convert decrypted data to UTF-8")?;
    let store: PasswordStore = serde_json::from_str(&json)
        .with_context(|| "Failed to parse password store JSON")?;
    Ok(store)
}

/// Save settings to encrypted storage
pub fn save_settings(settings: &AppSettings, key: &[u8; 32]) -> Result<()> {
    ensure_storage_dir_exists()?;
    let json = serde_json::to_string(settings)?;
    let encrypted = crate::crypto::encrypt(json.as_bytes(), key)?;
    let settings_file = get_settings_file()?;
    fs::write(&settings_file, encrypted)?;
    Ok(())
}

/// Save settings to a specific file (for atomic operations)
pub fn save_settings_to(settings: &AppSettings, key: &[u8; 32], file_path: &Path) -> Result<()> {
    ensure_storage_dir_exists()?;
    let json = serde_json::to_string(settings)?;
    let encrypted = crate::crypto::encrypt(json.as_bytes(), key)?;
    fs::write(file_path, encrypted)?;
    Ok(())
}

/// Load settings from a specific file (for atomic operations)
pub fn load_settings_from(file_path: &Path, key: &[u8; 32]) -> Result<AppSettings> {
    if !file_path.exists() {
        return Ok(AppSettings::default());
    }

    let mut file = File::open(file_path)
        .with_context(|| format!("Failed to open settings file: {}", file_path.display()))?;
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data)
        .with_context(|| "Failed to read encrypted settings data")?;

    let decrypted = crate::crypto::decrypt(&encrypted_data, key)
        .with_context(|| "Failed to decrypt settings data")?;

    let json = String::from_utf8(decrypted)
        .with_context(|| "Failed to convert decrypted settings to UTF-8")?;

    let settings: AppSettings = serde_json::from_str(&json)
        .with_context(|| "Failed to parse settings JSON")?;

    Ok(settings)
}

/// Load settings from encrypted storage
pub fn load_settings(key: &[u8; 32]) -> Result<AppSettings> {
    let settings_file = get_settings_file()?;
    if !settings_file.exists() {
        return Ok(AppSettings::default());
    }

    let mut file = File::open(&settings_file)
        .with_context(|| format!("Failed to open settings file: {}", settings_file.display()))?;
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data)
        .with_context(|| "Failed to read encrypted settings data")?;

    let decrypted = crate::crypto::decrypt(&encrypted_data, key)
        .with_context(|| "Failed to decrypt settings data")?;
    let json = String::from_utf8(decrypted)
        .with_context(|| "Failed to convert decrypted settings to UTF-8")?;
    let settings: AppSettings = serde_json::from_str(&json)
        .with_context(|| "Failed to parse settings JSON")?;
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_settings_persistence() {
        // Create a temporary directory for testing
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let test_settings_file = temp_dir.path().join("settings.json.enc");

        // Create test settings
        let mut settings = AppSettings::default();
        settings.default_password_length = 20;
        settings.auto_lock_enabled = true;

        // Test key (in real usage, this would be derived from master password)
        let test_key = [42u8; 32];

        // Save settings
        std::fs::write(&test_settings_file, 
            crate::crypto::encrypt(
                serde_json::to_string(&settings).unwrap().as_bytes(),
                &test_key
            ).unwrap()
        ).expect("Failed to save test settings");

        // Load settings back
        let loaded_settings = load_settings_from_path(&test_settings_file, &test_key).expect("Failed to load settings");

        // Verify the settings
        assert_eq!(loaded_settings.default_password_length, 20);
        assert!(loaded_settings.auto_lock_enabled);
    }

    /// Helper function for testing that uses a specific path
    fn load_settings_from_path(path: &std::path::Path, key: &[u8; 32]) -> Result<AppSettings> {
        let mut file = File::open(path)?;
        let mut encrypted_data = Vec::new();
        file.read_to_end(&mut encrypted_data)?;

        let decrypted = crate::crypto::decrypt(&encrypted_data, key)?;
        let json = String::from_utf8(decrypted)?;
        let settings: AppSettings = serde_json::from_str(&json)?;
        Ok(settings)
    }
}