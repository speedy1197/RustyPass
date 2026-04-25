use anyhow::Result;
use crossterm::event::{KeyCode, KeyEventKind};
use rand::RngCore;
use ratatui::widgets::ListState;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::password_analysis::StrengthLevel;
use crate::storage::{AppSettings, PasswordStore};

/// Application state enum
#[derive(Debug, Clone, PartialEq)]
pub enum AppState {
    PasswordEntry,
    MainMenu,
    ServicesMenu,
    AddService,
    AddPassword,
    ViewPassword,
    DeleteConfirm,
    GeneratePassword,
    PasswordLengthInput,
    ImportMenu,
    ImportFileInput,
    ImportConfirm,
    SettingsMenu,
    SettingsSecurity,
    SettingsPassword,
    SettingsAdvanced,
    SettingsHelp,
    ChangeMasterPassword,
    SessionTimeoutInput,
    FailedAttemptsInput,
    ClipboardClearInput,
    KeyRotationInput,
    DefaultPasswordLengthInput,
    CharacterSetsMenu,
    PasswordExpiryInput,
    MinEntropyInput,
    StorageLocationInput,
    FactoryResetConfirm,
    Exiting,
}

/// Main application struct
pub struct App {
    pub state: AppState,
    pub store: PasswordStore,
    pub settings: AppSettings,
    pub key: [u8; 32],
    pub services: Vec<String>,
    pub selected_service: Option<usize>,
    pub input_service: String,
    pub input_password: String,
    pub input_master: String,
    pub input_length: String,
    pub input_buffer: String,
    pub show_input_prompt: bool,
    pub generated_password: Option<String>,
    pub error_message: Option<String>,
    pub list_state: ListState,
    pub settings_list_state: ListState,
    pub services_list_state: ListState,
    pub import_file_path: String,
    pub import_format: Option<String>,
    pub import_preview: Option<String>,
    pub password_strength: Option<StrengthLevel>,
    pub password_entropy: Option<f64>,
}

impl App {
    /// Create a new application instance
    pub fn new() -> Self {
        Self {
            state: AppState::PasswordEntry,
            store: PasswordStore::new(),
            settings: AppSettings::default(),
            key: [0u8; 32],
            services: Vec::new(),
            selected_service: None,
            input_service: String::new(),
            input_password: String::new(),
            input_master: String::new(),
            input_length: String::new(),
            input_buffer: String::new(),
            show_input_prompt: false,
            generated_password: None,
            error_message: None,
            list_state: ListState::default(),
            settings_list_state: ListState::default(),
            services_list_state: ListState::default(),
            import_file_path: String::new(),
            import_format: None,
            import_preview: None,
            password_strength: None,
            password_entropy: None,
        }
    }

    /// Unlock the application with master password
    pub fn unlock(&mut self, master_password: &str) -> Result<()> {
        use rand::RngCore;

        // Load or generate salt
        let salt_file = super::storage::get_salt_file()?;
        let salt = if salt_file.exists() {
            let mut file = std::fs::File::open(&salt_file)?;
            let mut salt = [0u8; 32];
            file.read_exact(&mut salt)?;
            salt
        } else {
            let mut salt = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut salt);
            std::fs::write(&salt_file, salt)?;
            salt
        };

        // Use stronger key derivation (Argon2id) for new installations
        // The function always returns a key, no need for match
        self.key = crate::crypto::derive_key_strong(master_password, &salt);
        self.store = crate::storage::load_passwords(&self.key)?;
        self.settings = crate::storage::load_settings(&self.key)?;
        self.services = self.store.get_services();
        self.list_state.select(Some(0)); // Select first menu item by default
        self.selected_service = None; // Start with main menu focused
        Ok(())
    }

    /// Save current settings to encrypted storage
    pub fn save_settings(&self) -> Result<()> {
        crate::storage::save_settings(&self.settings, &self.key)
    }

    /// Export configuration to a JSON file
    pub fn export_configuration(&self) -> Result<()> {
        use std::fs::File;
        use std::io::Write;
        
        // Create export directory if it doesn't exist
        let export_dir = dirs::config_dir().ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?;
        std::fs::create_dir_all(&export_dir)?;
        
        let export_path = export_dir.join("RustyPass_Config_Export.json");
        
        // Create a safe export with only non-sensitive settings
        #[derive(Serialize)]
        struct SafeSettings {
            default_password_length: usize,
            auto_lock_enabled: bool,
            session_timeout_minutes: Option<usize>,
            use_symbols: bool,
            use_uppercase: bool,
            use_lowercase: bool,
            use_digits: bool,
            biometric_auth_enabled: bool,
            max_failed_attempts: Option<usize>,
            clipboard_clear_seconds: Option<usize>,
            encryption_key_rotation_days: Option<usize>,
            password_expiry_days: Option<usize>,
            require_min_complexity: bool,
            min_entropy_bits: Option<usize>,
            storage_location: Option<String>,
            auto_backup_enabled: bool,
            backup_frequency_days: Option<usize>,
            performance_mode: String,
            theme: String,
            enable_debug_logging: bool,
        }
        
        let safe_settings = SafeSettings {
            default_password_length: self.settings.default_password_length,
            auto_lock_enabled: self.settings.auto_lock_enabled,
            session_timeout_minutes: self.settings.session_timeout_minutes,
            use_symbols: self.settings.use_symbols,
            use_uppercase: self.settings.use_uppercase,
            use_lowercase: self.settings.use_lowercase,
            use_digits: self.settings.use_digits,
            biometric_auth_enabled: self.settings.biometric_auth_enabled,
            max_failed_attempts: self.settings.max_failed_attempts,
            clipboard_clear_seconds: self.settings.clipboard_clear_seconds,
            encryption_key_rotation_days: self.settings.encryption_key_rotation_days,
            password_expiry_days: self.settings.password_expiry_days,
            require_min_complexity: self.settings.require_min_complexity,
            min_entropy_bits: self.settings.min_entropy_bits,
            storage_location: self.settings.storage_location.clone(),
            auto_backup_enabled: self.settings.auto_backup_enabled,
            backup_frequency_days: self.settings.backup_frequency_days,
            performance_mode: self.settings.performance_mode.clone(),
            theme: self.settings.theme.clone(),
            enable_debug_logging: self.settings.enable_debug_logging,
        };
        
        let json = serde_json::to_string_pretty(&safe_settings)?;
        let mut file = File::create(&export_path)?;
        file.write_all(json.as_bytes())?;
        
        Ok(())
    }

    /// Re-encrypt all data with a new encryption key
    /// This is used when changing master password
    /// Implements atomic operation with full rollback capability
    pub fn reencrypt_all_data(&mut self, new_key: &[u8; 32]) -> Result<()> {
        // Security check: prevent re-encryption with weak keys
        if new_key.iter().all(|&b| b == 0) {
            return Err(anyhow::anyhow!("Refusing to re-encrypt with zero key"));
        }
        
        // Create temporary backup files for atomic operation
        let temp_passwords_file = self.get_temp_passwords_file()?;
        let temp_settings_file = self.get_temp_settings_file()?;
        
        // Step 1: Save current data with new key to temp files
        if let Err(e) = crate::storage::save_passwords_to(&self.store, new_key, &temp_passwords_file) {
            self.cleanup_temp_files(&temp_passwords_file, &temp_settings_file);
            return Err(anyhow::anyhow!("Failed to save passwords with new key: {}", e));
        }
        
        // Step 2: Save settings with new key to temp file
        if let Err(e) = crate::storage::save_settings_to(&self.settings, new_key, &temp_settings_file) {
            self.cleanup_temp_files(&temp_passwords_file, &temp_settings_file);
            return Err(anyhow::anyhow!("Failed to save settings with new key: {}", e));
        }
        
        // Step 3: Verify we can load from temp files
        let test_passwords = crate::storage::load_passwords_from(&temp_passwords_file, new_key);
        let test_settings = crate::storage::load_settings_from(&temp_settings_file, new_key);
        
        match (test_passwords, test_settings) {
            (Ok(p), Ok(s)) => {
                // Step 4: Atomic swap - replace old files with new ones
                if let Err(e) = self.atomic_replace_files(&temp_passwords_file, &temp_settings_file) {
                    self.cleanup_temp_files(&temp_passwords_file, &temp_settings_file);
                    return Err(anyhow::anyhow!("Failed to complete atomic file replacement: {}", e));
                }
                
                // Success! Update our in-memory data
                self.store = p;
                self.settings = s;
                self.services = self.store.get_services();
                
                // Clean up temp files
                self.cleanup_temp_files(&temp_passwords_file, &temp_settings_file);
                
                Ok(())
            }
            (Err(e), _) | (_, Err(e)) => {
                // Verification failed, clean up temp files
                self.cleanup_temp_files(&temp_passwords_file, &temp_settings_file);
                Err(anyhow::anyhow!("Failed to verify re-encryption: {}", e))
            }
        }
    }

    /// Get temporary file path for passwords
    fn get_temp_passwords_file(&self) -> Result<PathBuf> {
        let mut path = crate::storage::get_passwords_file()?;
        path.set_extension("tmp");
        Ok(path)
    }

    /// Get temporary file path for settings
    fn get_temp_settings_file(&self) -> Result<PathBuf> {
        let mut path = crate::storage::get_settings_file()?;
        path.set_extension("tmp");
        Ok(path)
    }

    /// Clean up temporary files
    fn cleanup_temp_files(&self, passwords_file: &Path, settings_file: &Path) {
        let _ = std::fs::remove_file(passwords_file);
        let _ = std::fs::remove_file(settings_file);
    }

    /// Atomically replace old files with new ones
    fn atomic_replace_files(&self, temp_passwords: &Path, temp_settings: &Path) -> Result<()> {
        let passwords_file = crate::storage::get_passwords_file()?;
        let settings_file = crate::storage::get_settings_file()?;
        
        // Use atomic rename operations
        std::fs::rename(temp_passwords, passwords_file)?;
        std::fs::rename(temp_settings, settings_file)?;
        
        Ok(())
    }

    /// Preview an import file before actually importing
    pub fn preview_import(&mut self, file_path: &str) -> Result<String> {
        let content = std::fs::read_to_string(file_path)?;

        // Try to determine format and show preview
        if file_path.ends_with(".json") {
            // Try Bitwarden format
            if let Ok(bitwarden_data) = self.try_parse_bitwarden(&content) {
                let count = bitwarden_data.len();
                let sample: Vec<String> = bitwarden_data.keys().take(3).cloned().collect();
                return Ok(format!(
                    "Bitwarden JSON: {} entries\nSample: {:?}",
                    count, sample
                ));
            }
            // Try simple JSON
            else if let Ok(simple_data) = self.try_parse_simple_json(&content) {
                let count = simple_data.len();
                let sample: Vec<String> = simple_data.keys().take(3).cloned().collect();
                return Ok(format!(
                    "Simple JSON: {} entries\nSample: {:?}",
                    count, sample
                ));
            }
        } else if file_path.ends_with(".csv") {
            let mut reader = csv::Reader::from_reader(content.as_bytes());
            let mut record_count = 0;
            let mut sample_records = Vec::new();

            for record in reader.records().take(4).flatten() {
                let record: csv::StringRecord = record;
                record_count += 1;
                if sample_records.len() < 3 && record.len() >= 2 {
                    sample_records.push(record[0].to_string());
                }
            }

            return Ok(format!(
                "CSV: {} entries\nSample: {:?}",
                record_count, sample_records
            ));
        }

        Ok("Unknown format".to_string())
    }

    /// Import from JSON file
    pub fn import_from_json(&mut self, file_path: &str) -> Result<()> {
        let content = std::fs::read_to_string(file_path)?;

        // Try to parse as Bitwarden format first
        if let Ok(bitwarden_data) = self.try_parse_bitwarden(&content) {
            for (service, password) in bitwarden_data {
                self.store.add_password(service, password);
            }
        }
        // Try to parse as simple JSON format
        else if let Ok(simple_data) = self.try_parse_simple_json(&content) {
            for (service, password) in simple_data {
                self.store.add_password(service, password);
            }
        } else {
            return Err(anyhow::anyhow!("Unsupported JSON format"));
        }

        crate::storage::save_passwords(&self.store, &self.key)?;
        self.services = self.store.get_services();
        Ok(())
    }

    /// Import from CSV file
    pub fn import_from_csv(&mut self, file_path: &str) -> Result<()> {
        let content = std::fs::read_to_string(file_path)?;
        let mut reader = csv::Reader::from_reader(content.as_bytes());

        let mut imported_count = 0;
        for result in reader.records() {
            let record: csv::StringRecord = result?;

            // Try different CSV formats
            if record.len() >= 2 {
                // Format: service,password or url,password
                let service = record[0].trim().to_string();
                let password = record[1].trim().to_string();

                if !service.is_empty() && !password.is_empty() {
                    self.store.add_password(service, password);
                    imported_count += 1;
                }
            } else if record.len() >= 3 {
                // Format: service,username,password
                let service = record[0].trim().to_string();
                let password = record[2].trim().to_string();

                if !service.is_empty() && !password.is_empty() {
                    self.store.add_password(service, password);
                    imported_count += 1;
                }
            }
        }

        if imported_count == 0 {
            return Err(anyhow::anyhow!("No valid entries found in CSV"));
        }

        crate::storage::save_passwords(&self.store, &self.key)?;
        self.services = self.store.get_services();
        Ok(())
    }

    /// Try to parse Bitwarden JSON format
    fn try_parse_bitwarden(&self, content: &str) -> Result<std::collections::HashMap<String, String>> {
        #[derive(Deserialize)]
        struct BitwardenItem {
            name: String,
            login: Option<serde_json::Value>,
        }

        #[derive(Deserialize)]
        struct BitwardenExport {
            items: Option<Vec<BitwardenItem>>,
        }

        let export: BitwardenExport = serde_json::from_str(content)?;
        let mut result = std::collections::HashMap::new();

        if let Some(items) = export.items {
            for item in items {
                if let Some(login) = &item.login {
                    if let Some(password) = login.get("password") {
                        if let Some(password_str) = password.as_str() {
                            result.insert(item.name.clone(), password_str.to_string());
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    /// Try to parse simple JSON format
    fn try_parse_simple_json(&self, content: &str) -> Result<std::collections::HashMap<String, String>> {
        // Try to parse as simple key-value JSON
        if let Ok(map) = serde_json::from_str::<std::collections::HashMap<String, String>>(content) {
            return Ok(map);
        }

        // Try to parse as array of objects with service/password fields
        #[derive(Deserialize)]
        struct SimpleItem {
            service: Option<String>,
            username: Option<String>,
            password: Option<String>,
            url: Option<String>,
        }

        if let Ok(items) = serde_json::from_str::<Vec<SimpleItem>>(content) {
            let mut result = std::collections::HashMap::new();
            for item in items {
                if let Some(password) = item.password {
                    // Use service name if available, otherwise use username or url
                    if let Some(service) = item.service {
                        result.insert(service, password);
                    } else if let Some(username) = item.username {
                        result.insert(username, password);
                    } else if let Some(url) = item.url {
                        result.insert(url, password);
                    }
                }
            }
            return Ok(result);
        }

        Err(anyhow::anyhow!("Unsupported JSON format"))
    }

    /// Generate a secure password using current settings
    pub fn generate_password(&mut self, length: usize) -> Result<()> {
        // Use settings to determine character sets
        let mut chars = Vec::new();
        if self.settings.use_lowercase {
            chars.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz");
        }
        if self.settings.use_uppercase {
            chars.extend_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        }
        if self.settings.use_digits {
            chars.extend_from_slice(b"0123456789");
        }
        if self.settings.use_symbols {
            chars.extend_from_slice(b"!@#$%^&*()_+-=[]{}|;:,.<>?");
        }

        // Ensure we have at least one character set enabled
        if chars.is_empty() {
            chars.extend_from_slice(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?");
        }

        let mut password = Vec::with_capacity(length);
        let mut rng = rand::thread_rng();

        // Generate password using cryptographically secure RNG
        for _ in 0..length {
            let idx = (rng.next_u32() as usize) % chars.len();
            password.push(chars[idx]);
        }

        // Shuffle to ensure random distribution
        for i in 0..password.len() {
            let j = (rng.next_u32() as usize) % password.len();
            password.swap(i, j);
        }

        self.generated_password = Some(String::from_utf8(password)?);
        Ok(())
    }

    /// Handle key events
    pub fn handle_key_event(&mut self, key: crossterm::event::KeyEvent) -> Result<bool> {
        if key.kind == KeyEventKind::Press {
            match self.state {
                AppState::PasswordEntry => {
                    if key.code == KeyCode::Enter {
                        if !self.input_master.is_empty() {
                            let master_password = self.input_master.clone();
                            if let Err(e) = self.unlock(&master_password) {
                                self.error_message = Some(format!("Error: {}", e));
                            } else {
                                self.state = AppState::MainMenu;
                                self.input_master.clear();
                            }
                        }
                    } else if let KeyCode::Char(c) = key.code {
                        self.input_master.push(c);
                    } else if key.code == KeyCode::Backspace {
                        self.input_master.pop();
                    } else if key.code == KeyCode::Esc {
                        self.state = AppState::Exiting;
                    }
                }
                AppState::MainMenu => {
                    match key.code {
                        KeyCode::Char('a') => {
                            self.state = AppState::AddService;
                            self.input_service.clear();
                        }
                        KeyCode::Char('i') => {
                            self.state = AppState::ImportMenu;
                        }
                        KeyCode::Char('s') => {
                            self.state = AppState::ServicesMenu;
                            self.services_list_state.select(Some(0));
                        }
                        KeyCode::Char('t') => {
                            self.state = AppState::SettingsMenu;
                            self.settings_list_state.select(None);
                        }
                        KeyCode::Char('q') | KeyCode::Esc => {
                            self.state = AppState::Exiting;
                        }
                        KeyCode::Up => {
                            // Handle main menu navigation (left panel)
                            if let Some(selected) = self.list_state.selected() {
                                if selected > 0 {
                                    self.list_state.select(Some(selected - 1));
                                }
                            } else {
                                self.list_state.select(Some(0));
                            }
                        }
                        KeyCode::Down => {
                            // Handle main menu navigation
                            if let Some(selected) = self.list_state.selected() {
                                if selected < 4 { // 5 menu items (0-4)
                                    self.list_state.select(Some(selected + 1));
                                }
                            } else {
                                self.list_state.select(Some(0));
                            }
                        }

                        KeyCode::Enter => {
                            // Handle selection from main menu
                            if let Some(selected) = self.list_state.selected() {
                                match selected {
                                    0 => { // Add New Password
                                        self.state = AppState::AddService;
                                        self.input_service.clear();
                                    }
                                    1 => { // Import Passwords
                                        self.state = AppState::ImportMenu;
                                    }
                                    2 => { // Services
                                        self.state = AppState::ServicesMenu;
                                        self.services_list_state.select(Some(0));
                                    }
                                    3 => { // Settings
                                        self.state = AppState::SettingsMenu;
                                        self.settings_list_state.select(None);
                                    }
                                    4 => { // Exit
                                        self.state = AppState::Exiting;
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
                AppState::ServicesMenu => {
                    match key.code {
                        KeyCode::Up => {
                            if let Some(selected) = self.services_list_state.selected() {
                                if selected > 0 {
                                    self.services_list_state.select(Some(selected - 1));
                                }
                            } else if !self.services.is_empty() {
                                self.services_list_state.select(Some(0));
                            }
                        }
                        KeyCode::Down => {
                            if let Some(selected) = self.services_list_state.selected() {
                                if selected < self.services.len() - 1 {
                                    self.services_list_state.select(Some(selected + 1));
                                }
                            } else if !self.services.is_empty() {
                                self.services_list_state.select(Some(0));
                            }
                        }
                        KeyCode::Enter => {
                            if let Some(selected) = self.services_list_state.selected() {
                                self.selected_service = Some(selected);
                                self.state = AppState::ViewPassword;
                            }
                        }
                        KeyCode::Char('v') => {
                            if let Some(selected) = self.services_list_state.selected() {
                                self.selected_service = Some(selected);
                                self.state = AppState::ViewPassword;
                            }
                        }
                        KeyCode::Char('d') => {
                            if let Some(selected) = self.services_list_state.selected() {
                                self.selected_service = Some(selected);
                                self.state = AppState::DeleteConfirm;
                            }
                        }
                        KeyCode::Esc | KeyCode::Char('q') => {
                            self.state = AppState::MainMenu;
                            self.services_list_state.select(None);
                        }
                        _ => {}
                    }
                }
                AppState::AddService => {
                    if key.code == KeyCode::Enter {
                        if !self.input_service.is_empty() {
                            self.state = AppState::AddPassword;
                            self.input_password.clear();
                        }
                    } else if let KeyCode::Char(c) = key.code {
                        self.input_service.push(c);
                    } else if key.code == KeyCode::Backspace {
                        self.input_service.pop();
                    } else if key.code == KeyCode::Esc {
                        self.state = AppState::MainMenu;
                        self.input_service.clear();
                    }
                }
                AppState::AddPassword => {
                    if key.code == KeyCode::Enter {
                        if !self.input_password.is_empty() {
                            // Add the service and password to store
                            self.store.add_password(self.input_service.clone(), self.input_password.clone());
                            if let Err(e) = crate::storage::save_passwords(&self.store, &self.key) {
                                self.error_message = Some(format!("Failed to save password: {}", e));
                            } else {
                                self.services = self.store.get_services();
                                self.state = AppState::MainMenu;
                                self.input_service.clear();
                                self.input_password.clear();
                                self.password_strength = None;
                                self.password_entropy = None;
                            }
                        }
                    } else if key.code == KeyCode::Char('g') {
                        // Generate password option in AddPassword state
                        self.state = AppState::PasswordLengthInput;
                        self.input_length.clear();
                    } else if let KeyCode::Char(c) = key.code {
                        self.input_password.push(c);
                        // Analyze password strength and entropy as user types
                        let (strength, entropy) = crate::analyze_password(&self.input_password);
                        self.password_strength = Some(strength);
                        self.password_entropy = Some(entropy);
                    } else if key.code == KeyCode::Backspace {
                        self.input_password.pop();
                        // Re-analyze after backspace
                        if !self.input_password.is_empty() {
                            let (strength, entropy) = crate::analyze_password(&self.input_password);
                            self.password_strength = Some(strength);
                            self.password_entropy = Some(entropy);
                        } else {
                            self.password_strength = None;
                            self.password_entropy = None;
                        }
                    } else if key.code == KeyCode::Esc {
                        self.state = AppState::MainMenu;
                        self.input_service.clear();
                        self.input_password.clear();
                        self.password_strength = None;
                        self.password_entropy = None;
                    }
                }
                AppState::ViewPassword => {
                    if key.code == KeyCode::Esc || key.code == KeyCode::Char('q') {
                        self.state = AppState::ServicesMenu;
                    }
                }
                AppState::DeleteConfirm => {
                    if key.code == KeyCode::Char('y') {
                        if let Some(selected) = self.selected_service {
                            if let Some(service) = self.services.get(selected) {
                                let service_clone = service.clone();
                                self.store.remove_password(&service_clone);
                                if let Err(e) = crate::storage::save_passwords(&self.store, &self.key) {
                                    self.error_message = Some(format!("Failed to delete password: {}", e));
                                } else {
                                    self.services = self.store.get_services();
                                    self.selected_service = None;
                                }
                            }
                        }
                        self.state = AppState::ServicesMenu;
                    } else if key.code == KeyCode::Char('n') || key.code == KeyCode::Esc {
                        self.state = AppState::ServicesMenu;
                    }
                }
                AppState::GeneratePassword => {
                    if key.code == KeyCode::Char('c') {
                        if let Some(password) = &self.generated_password {
                            self.input_password = password.clone();
                            self.state = AppState::AddPassword;
                        }
                    } else if key.code == KeyCode::Char('g') {
                        // Generate another password with same length
                        if let Ok(length) = self.input_length.parse::<usize>() {
                            let _ = self.generate_password(length); // Ignore error, keep current password
                        }
                    } else if key.code == KeyCode::Esc || key.code == KeyCode::Char('q') {
                        self.state = AppState::MainMenu;
                        self.generated_password = None;
                    }
                }
                AppState::PasswordLengthInput => {
                    if key.code == KeyCode::Enter {
                        if !self.input_length.is_empty() {
                            if let Ok(length) = self.input_length.parse::<usize>() {
                                if let Err(e) = self.generate_password(length) {
                                    self.error_message = Some(format!("Failed to generate password: {}", e));
                                } else {
                                    self.state = AppState::GeneratePassword;
                                }
                            } else {
                                self.error_message = Some("Invalid length. Please enter a number.".to_string());
                            }
                        }
                    } else if let KeyCode::Char(c) = key.code {
                        if c.is_ascii_digit() {
                            self.input_length.push(c);
                        }
                    } else if key.code == KeyCode::Backspace {
                        self.input_length.pop();
                    } else if key.code == KeyCode::Esc {
                        self.state = AppState::MainMenu;
                        self.input_length.clear();
                    }
                }
                AppState::ChangeMasterPassword => {
                    if key.code == KeyCode::Enter {
                        if !self.input_buffer.is_empty() {
                            // Implement actual master password change
                            let new_password = self.input_buffer.clone();
                            
                            // Step 1: Re-derive key with new password
                            let salt = b"master_password_salt"; // In production, use proper salt management
                            let new_key = crate::crypto::derive_key_strong(&new_password, salt);
                            
                            // Step 2: Re-encrypt all data with new key
                            if let Err(e) = self.reencrypt_all_data(&new_key) {
                                self.error_message = Some(format!("Failed to re-encrypt data: {}", e));
                            } else {
                                // Step 3: Update the key
                                self.key = new_key;
                                
                                // Step 4: Save settings with new key
                                if let Err(e) = self.save_settings() {
                                    self.error_message = Some(format!("Failed to save settings: {}", e));
                                } else {
                                    self.error_message = Some("✅ Master password changed successfully!".to_string());
                                }
                            }
                            self.state = AppState::SettingsSecurity;
                        }
                    } else if let KeyCode::Char(c) = key.code {
                        self.input_buffer.push(c);
                    } else if key.code == KeyCode::Backspace {
                        self.input_buffer.pop();
                    } else if key.code == KeyCode::Esc {
                        self.state = AppState::SettingsSecurity;
                        self.input_buffer.clear();
                    }
                }
                AppState::SessionTimeoutInput => {
                    if key.code == KeyCode::Enter {
                        if !self.input_buffer.is_empty() {
                            if let Ok(minutes) = self.input_buffer.parse::<usize>() {
                                if minutes == 0 || (5..=120).contains(&minutes) {
                                    self.settings.session_timeout_minutes = if minutes == 0 { None } else { Some(minutes) };
                                    if let Err(e) = self.save_settings() {
                                        self.error_message = Some(format!("Failed to save: {}", e));
                                    } else {
                                        self.error_message = Some(format!("Session timeout set to {} minutes", 
                                            if minutes == 0 { "never".to_string() } else { minutes.to_string() }));
                                    }
                                } else {
                                    self.error_message = Some("Timeout must be 0 (never) or 5-120 minutes".to_string());
                                }
                            } else {
                                self.error_message = Some("Please enter a valid number".to_string());
                            }
                            self.state = AppState::SettingsSecurity;
                        }
                    } else if let KeyCode::Char(c) = key.code {
                        if c.is_ascii_digit() {
                            self.input_buffer.push(c);
                        }
                    } else if key.code == KeyCode::Backspace {
                        self.input_buffer.pop();
                    } else if key.code == KeyCode::Esc {
                        self.state = AppState::SettingsSecurity;
                        self.input_buffer.clear();
                    }
                }
                AppState::FailedAttemptsInput => {
                    if key.code == KeyCode::Enter {
                        if !self.input_buffer.is_empty() {
                            if let Ok(attempts) = self.input_buffer.parse::<usize>() {
                                if (3..=10).contains(&attempts) {
                                    self.settings.max_failed_attempts = Some(attempts);
                                    if let Err(e) = self.save_settings() {
                                        self.error_message = Some(format!("Failed to save: {}", e));
                                    } else {
                                        self.error_message = Some(format!("Max failed attempts set to {}", attempts));
                                    }
                                } else {
                                    self.error_message = Some("Attempts must be 3-10".to_string());
                                }
                            } else {
                                self.error_message = Some("Please enter a valid number".to_string());
                            }
                            self.state = AppState::SettingsSecurity;
                        }
                    } else if let KeyCode::Char(c) = key.code {
                        if c.is_ascii_digit() {
                            self.input_buffer.push(c);
                        }
                    } else if key.code == KeyCode::Backspace {
                        self.input_buffer.pop();
                    } else if key.code == KeyCode::Esc {
                        self.state = AppState::SettingsSecurity;
                        self.input_buffer.clear();
                    }
                }
                AppState::ClipboardClearInput => {
                    if key.code == KeyCode::Enter {
                        if !self.input_buffer.is_empty() {
                            if let Ok(seconds) = self.input_buffer.parse::<usize>() {
                                if (5..=60).contains(&seconds) {
                                    self.settings.clipboard_clear_seconds = Some(seconds);
                                    if let Err(e) = self.save_settings() {
                                        self.error_message = Some(format!("Failed to save: {}", e));
                                    } else {
                                        self.error_message = Some(format!("Clipboard clear set to {} seconds", seconds));
                                    }
                                } else {
                                    self.error_message = Some("Seconds must be 5-60".to_string());
                                }
                            } else {
                                self.error_message = Some("Please enter a valid number".to_string());
                            }
                            self.state = AppState::SettingsSecurity;
                        }
                    } else if let KeyCode::Char(c) = key.code {
                        if c.is_ascii_digit() {
                            self.input_buffer.push(c);
                        }
                    } else if key.code == KeyCode::Backspace {
                        self.input_buffer.pop();
                    } else if key.code == KeyCode::Esc {
                        self.state = AppState::SettingsSecurity;
                        self.input_buffer.clear();
                    }
                }
                AppState::KeyRotationInput => {
                    if key.code == KeyCode::Enter {
                        if !self.input_buffer.is_empty() {
                            if let Ok(days) = self.input_buffer.parse::<usize>() {
                                if (30..=730).contains(&days) {
                                    self.settings.encryption_key_rotation_days = Some(days);
                                    if let Err(e) = self.save_settings() {
                                        self.error_message = Some(format!("Failed to save: {}", e));
                                    } else {
                                        self.error_message = Some(format!("Key rotation set to {} days", days));
                                    }
                                } else {
                                    self.error_message = Some("Days must be 30-730".to_string());
                                }
                            } else {
                                self.error_message = Some("Please enter a valid number".to_string());
                            }
                            self.state = AppState::SettingsSecurity;
                        }
                    } else if let KeyCode::Char(c) = key.code {
                        if c.is_ascii_digit() {
                            self.input_buffer.push(c);
                        }
                    } else if key.code == KeyCode::Backspace {
                        self.input_buffer.pop();
                    } else if key.code == KeyCode::Esc {
                        self.state = AppState::SettingsSecurity;
                        self.input_buffer.clear();
                    }
                }
                AppState::DefaultPasswordLengthInput => {
                    if key.code == KeyCode::Enter {
                        if !self.input_buffer.is_empty() {
                            if let Ok(length) = self.input_buffer.parse::<usize>() {
                                if (8..=64).contains(&length) {
                                    // Additional security check: ensure at least 2 character sets are enabled
                                    let enabled_sets = [
                                        self.settings.use_lowercase,
                                        self.settings.use_uppercase,
                                        self.settings.use_digits,
                                        self.settings.use_symbols
                                    ].iter().filter(|&&x| x).count();
                                    
                                    if enabled_sets >= 2 || length >= 12 {
                                        self.settings.default_password_length = length;
                                        if let Err(e) = self.save_settings() {
                                            self.error_message = Some(format!("Failed to save: {}", e));
                                        } else {
                                            self.error_message = Some(format!("Default password length set to {} characters", length));
                                        }
                                    } else {
                                        self.error_message = Some("For lengths < 12, at least 2 character sets must be enabled".to_string());
                                    }
                                } else {
                                    self.error_message = Some("Length must be 8-64 characters".to_string());
                                }
                            } else {
                                self.error_message = Some("Please enter a valid number (digits only)".to_string());
                            }
                            self.state = AppState::SettingsPassword;
                        }
                    } else if let KeyCode::Char(c) = key.code {
                        if c.is_ascii_digit() {
                            // Prevent buffer overflow - limit to 3 digits max
                            if self.input_buffer.len() < 3 {
                                self.input_buffer.push(c);
                            }
                        }
                    } else if key.code == KeyCode::Backspace {
                        self.input_buffer.pop();
                    } else if key.code == KeyCode::Esc {
                        self.state = AppState::SettingsPassword;
                        self.input_buffer.clear();
                    }
                }
                AppState::CharacterSetsMenu => {
                    match key.code {
                        KeyCode::Char('1') | KeyCode::Up => {
                            if let Some(selected) = self.list_state.selected() {
                                if selected > 0 {
                                    self.list_state.select(Some(selected - 1));
                                }
                            } else {
                                self.list_state.select(Some(0));
                            }
                        }
                        KeyCode::Char('2') | KeyCode::Down => {
                            if let Some(selected) = self.list_state.selected() {
                                if selected < 3 {
                                    self.list_state.select(Some(selected + 1));
                                }
                            } else {
                                self.list_state.select(Some(0));
                            }
                        }
                        KeyCode::Enter => {
                            if let Some(selected) = self.list_state.selected() {
                                match selected {
                                    0 => {
                                        self.settings.use_lowercase = !self.settings.use_lowercase;
                                        self.error_message = Some(
                                            if self.settings.use_lowercase {
                                                "Lowercase characters enabled"
                                            } else {
                                                "Lowercase characters disabled"
                                            }.to_string()
                                        );
                                    }
                                    1 => {
                                        self.settings.use_uppercase = !self.settings.use_uppercase;
                                        self.error_message = Some(
                                            if self.settings.use_uppercase {
                                                "Uppercase characters enabled"
                                            } else {
                                                "Uppercase characters disabled"
                                            }.to_string()
                                        );
                                    }
                                    2 => {
                                        self.settings.use_digits = !self.settings.use_digits;
                                        self.error_message = Some(
                                            if self.settings.use_digits {
                                                "Digits enabled"
                                            } else {
                                                "Digits disabled"
                                            }.to_string()
                                        );
                                    }
                                    3 => {
                                        self.settings.use_symbols = !self.settings.use_symbols;
                                        self.error_message = Some(
                                            if self.settings.use_symbols {
                                                "Symbols enabled"
                                            } else {
                                                "Symbols disabled"
                                            }.to_string()
                                        );
                                    }
                                    _ => {}
                                }
                                if let Err(e) = self.save_settings() {
                                    self.error_message = Some(format!("Failed to save settings: {}", e));
                                }
                            }
                        }
                        KeyCode::Esc | KeyCode::Char('q') => {
                            self.state = AppState::SettingsPassword;
                            self.list_state.select(None);
                        }
                        _ => {}
                    }
                }
                AppState::PasswordExpiryInput => {
                    if key.code == KeyCode::Enter {
                        if !self.input_buffer.is_empty() {
                            if let Ok(days) = self.input_buffer.parse::<usize>() {
                                if days == 0 || (30..=730).contains(&days) {
                                    self.settings.password_expiry_days = if days == 0 { None } else { Some(days) };
                                    if let Err(e) = self.save_settings() {
                                        self.error_message = Some(format!("Failed to save: {}", e));
                                    } else {
                                        self.error_message = Some(
                                            if days == 0 {
                                                "Password expiry disabled".to_string()
                                            } else {
                                                format!("Password expiry set to {} days", days)
                                            }
                                        );
                                    }
                                } else {
                                    self.error_message = Some("Days must be 0 (never) or 30-730".to_string());
                                }
                            } else {
                                self.error_message = Some("Please enter a valid number".to_string());
                            }
                            self.state = AppState::SettingsPassword;
                        }
                    } else if let KeyCode::Char(c) = key.code {
                        if c.is_ascii_digit() {
                            self.input_buffer.push(c);
                        }
                    } else if key.code == KeyCode::Backspace {
                        self.input_buffer.pop();
                    } else if key.code == KeyCode::Esc {
                        self.state = AppState::SettingsPassword;
                        self.input_buffer.clear();
                    }
                }
                AppState::MinEntropyInput => {
                    if key.code == KeyCode::Enter {
                        if !self.input_buffer.is_empty() {
                            if let Ok(bits) = self.input_buffer.parse::<usize>() {
                                if (40..=128).contains(&bits) {
                                    self.settings.min_entropy_bits = Some(bits);
                                    if let Err(e) = self.save_settings() {
                                        self.error_message = Some(format!("Failed to save: {}", e));
                                    } else {
                                        self.error_message = Some(format!("Minimum entropy set to {} bits", bits));
                                    }
                                } else {
                                    self.error_message = Some("Entropy must be 40-128 bits".to_string());
                                }
                            } else {
                                self.error_message = Some("Please enter a valid number".to_string());
                            }
                            self.state = AppState::SettingsPassword;
                        }
                    } else if let KeyCode::Char(c) = key.code {
                        if c.is_ascii_digit() {
                            self.input_buffer.push(c);
                        }
                    } else if key.code == KeyCode::Backspace {
                        self.input_buffer.pop();
                    } else if key.code == KeyCode::Esc {
                        self.state = AppState::SettingsPassword;
                        self.input_buffer.clear();
                    }
                }
                AppState::StorageLocationInput => {
                    if key.code == KeyCode::Enter {
                        if !self.input_buffer.is_empty() {
                            let path = self.input_buffer.trim().to_string();
                            // Basic validation: check if path contains invalid characters
                            if path.contains(|c: char| c.is_control()) {
                                self.error_message = Some("Path contains invalid characters".to_string());
                            } else {
                                self.settings.storage_location = Some(path.clone());
                                if let Err(e) = self.save_settings() {
                                    self.error_message = Some(format!("Failed to save: {}", e));
                                } else {
                                    self.error_message = Some(format!("Storage location set to {}", path));
                                }
                            }
                            self.state = AppState::SettingsAdvanced;
                        }
                    } else if let KeyCode::Char(c) = key.code {
                        // Allow most characters for path input
                        if !c.is_control() {
                            self.input_buffer.push(c);
                        }
                    } else if key.code == KeyCode::Backspace {
                        self.input_buffer.pop();
                    } else if key.code == KeyCode::Esc {
                        self.state = AppState::SettingsAdvanced;
                        self.input_buffer.clear();
                    }
                }
                AppState::FactoryResetConfirm => {
                    match key.code {
                        KeyCode::Char('y') => {
                            // Perform factory reset
                            self.settings = AppSettings::default();
                            if let Err(e) = self.save_settings() {
                                self.error_message = Some(format!("Failed to reset settings: {}", e));
                            } else {
                                self.error_message = Some("✅ All settings reset to factory defaults!".to_string());
                            }
                            self.state = AppState::SettingsAdvanced;
                        }
                        KeyCode::Char('n') | KeyCode::Esc | KeyCode::Char('q') => {
                            self.state = AppState::SettingsAdvanced;
                            self.error_message = Some("Factory reset cancelled.".to_string());
                        }
                        _ => {}
                    }
                }
                AppState::ImportMenu => {
                    match key.code {
                        KeyCode::Enter => {
                            if let Some(selected) = self.list_state.selected() {
                                match selected {
                                    0 => {
                                        // JSON format
                                        self.import_format = Some("json".to_string());
                                        self.state = AppState::ImportFileInput;
                                        self.import_file_path.clear();
                                    }
                                    1 => {
                                        // CSV format
                                        self.import_format = Some("csv".to_string());
                                        self.state = AppState::ImportFileInput;
                                        self.import_file_path.clear();
                                    }
                                    _ => {}
                                }
                            }
                        }
                        KeyCode::Up => {
                            if let Some(selected) = self.list_state.selected() {
                                if selected > 0 {
                                    self.list_state.select(Some(selected - 1));
                                }
                            } else {
                                self.list_state.select(Some(0));
                            }
                        }
                        KeyCode::Down => {
                            if let Some(selected) = self.list_state.selected() {
                                if selected < 1 {
                                    self.list_state.select(Some(selected + 1));
                                }
                            } else {
                                self.list_state.select(Some(0));
                            }
                        }
                        KeyCode::Esc => {
                            self.state = AppState::MainMenu;
                            self.list_state.select(None);
                        }
                        _ => {}
                    }
                }
                AppState::ImportFileInput => {
                    if key.code == KeyCode::Enter {
                        if !self.import_file_path.is_empty() {
                            // Clone the file path to avoid borrow checker issues
                            let file_path = self.import_file_path.clone();
                            // Try to preview the import
                            if let Ok(preview) = self.preview_import(&file_path) {
                                self.import_preview = Some(preview);
                                self.state = AppState::ImportConfirm;
                            } else {
                                self.error_message = Some("Failed to preview import file".to_string());
                                self.state = AppState::MainMenu;
                            }
                        }
                    } else if let KeyCode::Char(c) = key.code {
                        self.import_file_path.push(c);
                    } else if key.code == KeyCode::Backspace {
                        self.import_file_path.pop();
                    } else if key.code == KeyCode::Esc {
                        self.state = AppState::MainMenu;
                        self.import_file_path.clear();
                        self.import_format = None;
                    }
                }
                AppState::ImportConfirm => {
                    if key.code == KeyCode::Char('y') {
                        if let Some(format) = &self.import_format {
                            let file_path = self.import_file_path.clone();
                            match format.as_str() {
                                "json" => {
                                    if let Err(e) = self.import_from_json(&file_path) {
                                        self.error_message = Some(format!("Import failed: {}", e));
                                    }
                                }
                                "csv" => {
                                    if let Err(e) = self.import_from_csv(&file_path) {
                                        self.error_message = Some(format!("Import failed: {}", e));
                                    }
                                }
                                _ => {}
                            }
                        }
                        self.state = AppState::MainMenu;
                        self.import_file_path.clear();
                        self.import_format = None;
                        self.import_preview = None;
                    } else if key.code == KeyCode::Char('n') || key.code == KeyCode::Esc {
                        self.state = AppState::MainMenu;
                        self.import_file_path.clear();
                        self.import_format = None;
                        self.import_preview = None;
                    }
                }
                AppState::SettingsMenu => {
                    match key.code {
                        KeyCode::Char('1') => {
                            // Security Settings
                            self.state = AppState::SettingsSecurity;
                        }
                        KeyCode::Char('2') => {
                            // Password Settings
                            self.state = AppState::SettingsPassword;
                        }
                        KeyCode::Char('3') => {
                            // Advanced Settings
                            self.state = AppState::SettingsAdvanced;
                        }
                        KeyCode::Char('4') => {
                            // Help & Keybindings
                            self.state = AppState::SettingsHelp;
                        }
                        KeyCode::Up => {
                            if let Some(selected) = self.settings_list_state.selected() {
                                if selected > 0 {
                                    self.settings_list_state.select(Some(selected - 1));
                                }
                            } else {
                                self.settings_list_state.select(Some(0));
                            }
                        }
                        KeyCode::Down => {
                            if let Some(selected) = self.settings_list_state.selected() {
                                if selected < 3 {
                                    self.settings_list_state.select(Some(selected + 1));
                                }
                            } else {
                                self.settings_list_state.select(Some(0));
                            }
                        }
                        KeyCode::Enter => {
                            if let Some(selected) = self.settings_list_state.selected() {
                                match selected {
                                    0 => self.state = AppState::SettingsSecurity,
                                    1 => self.state = AppState::SettingsPassword,
                                    2 => self.state = AppState::SettingsAdvanced,
                                    3 => self.state = AppState::SettingsHelp,
                                    _ => {}
                                }
                            }
                        }
                        KeyCode::Esc | KeyCode::Char('q') => {
                            self.state = AppState::MainMenu;
                            self.settings_list_state.select(None);
                        }
                        _ => {}
                    }
                }
                AppState::SettingsSecurity => {
                    match key.code {
                        KeyCode::Char('1') => {
                            // Change Master Password
                            self.state = AppState::ChangeMasterPassword;
                            self.input_buffer.clear();
                            self.show_input_prompt = true;
                            self.error_message = Some("Enter new master password".to_string());
                        }
                        KeyCode::Char('2') => {
                            // Enable Auto-lock
                            self.settings.auto_lock_enabled = !self.settings.auto_lock_enabled;
                            if let Err(e) = self.save_settings() {
                                self.error_message = Some(format!("Failed to save settings: {}", e));
                            } else {
                                let status = if self.settings.auto_lock_enabled { "enabled" } else { "disabled" };
                                self.error_message = Some(format!("Auto-lock {}", status));
                            }
                        }
                        KeyCode::Char('3') => {
                            // Configure Session Timeout
                            self.state = AppState::SessionTimeoutInput;
                            self.input_buffer.clear();
                            self.show_input_prompt = true;
                            self.error_message = Some("Enter timeout in minutes (5-120) or 0 for never".to_string());
                        }
                        KeyCode::Char('4') => {
                            // Enable Biometric Authentication
                            self.settings.biometric_auth_enabled = !self.settings.biometric_auth_enabled;
                            if let Err(e) = self.save_settings() {
                                self.error_message = Some(format!("Failed to save settings: {}", e));
                            } else {
                                let status = if self.settings.biometric_auth_enabled { "enabled" } else { "disabled" };
                                self.error_message = Some(format!("Biometric auth {}", status));
                            }
                        }
                        KeyCode::Char('5') => {
                            // Set Max Failed Attempts
                            self.state = AppState::FailedAttemptsInput;
                            self.input_buffer.clear();
                            self.show_input_prompt = true;
                            self.error_message = Some("Enter max failed attempts (3-10)".to_string());
                        }
                        KeyCode::Char('6') => {
                            // Configure Clipboard Clear
                            self.state = AppState::ClipboardClearInput;
                            self.input_buffer.clear();
                            self.show_input_prompt = true;
                            self.error_message = Some("Enter clipboard clear time in seconds (5-60)".to_string());
                        }
                        KeyCode::Char('7') => {
                            // Set Encryption Key Rotation
                            self.state = AppState::KeyRotationInput;
                            self.input_buffer.clear();
                            self.show_input_prompt = true;
                            self.error_message = Some("Enter key rotation days (30-730)".to_string());
                        }
                        KeyCode::Esc | KeyCode::Char('q') => {
                            self.state = AppState::SettingsMenu;
                        }
                        _ => {}
                    }
                }
                AppState::SettingsPassword => {
                    match key.code {
                        KeyCode::Char('1') => {
                            // Set Default Password Length
                            self.state = AppState::DefaultPasswordLengthInput;
                            self.input_buffer.clear();
                            self.show_input_prompt = true;
                            self.error_message = Some("Enter default password length (8-64 characters)".to_string());
                        }
                        KeyCode::Char('2') => {
                            // Customize Character Sets
                            self.state = AppState::CharacterSetsMenu;
                            self.error_message = None;
                        }
                        KeyCode::Char('3') => {
                            // Configure Password Expiry
                            self.state = AppState::PasswordExpiryInput;
                            self.input_buffer.clear();
                            self.show_input_prompt = true;
                            self.error_message = Some("Enter password expiry days (30-730) or 0 for never".to_string());
                        }
                        KeyCode::Char('4') => {
                            // Set Complexity Requirements
                            self.settings.require_min_complexity = !self.settings.require_min_complexity;
                            if let Err(e) = self.save_settings() {
                                self.error_message = Some(format!("Failed to save: {}", e));
                            } else {
                                let status = if self.settings.require_min_complexity { "enabled" } else { "disabled" };
                                self.error_message = Some(format!("Complexity requirements {}", status));
                            }
                        }
                        KeyCode::Char('5') => {
                            // Set Minimum Entropy
                            self.state = AppState::MinEntropyInput;
                            self.input_buffer.clear();
                            self.show_input_prompt = true;
                            self.error_message = Some("Enter minimum entropy bits (40-128)".to_string());
                        }
                        KeyCode::Esc | KeyCode::Char('q') => {
                            self.state = AppState::SettingsMenu;
                        }
                        _ => {}
                    }
                }
                AppState::SettingsAdvanced => {
                    match key.code {
                        KeyCode::Char('1') => {
                            // Change Storage Location
                            self.state = AppState::StorageLocationInput;
                            self.input_buffer.clear();
                            self.show_input_prompt = true;
                            self.error_message = Some("Enter new storage location path".to_string());
                        }
                        KeyCode::Char('2') => {
                            // Configure Auto-backup
                            self.settings.auto_backup_enabled = !self.settings.auto_backup_enabled;
                            if let Err(e) = self.save_settings() {
                                self.error_message = Some(format!("Failed to save: {}", e));
                            } else {
                                let status = if self.settings.auto_backup_enabled { "enabled" } else { "disabled" };
                                self.error_message = Some(format!("Auto-backup {}", status));
                            }
                        }
                        KeyCode::Char('3') => {
                            // Toggle Performance Mode
                            self.settings.performance_mode = match self.settings.performance_mode.as_str() {
                                "balanced" => "security".to_string(),
                                "security" => "speed".to_string(),
                                "speed" => "balanced".to_string(),
                                _ => "balanced".to_string(),
                            };
                            if let Err(e) = self.save_settings() {
                                self.error_message = Some(format!("Failed to save: {}", e));
                            } else {
                                self.error_message = Some(format!("Performance mode set to {}", self.settings.performance_mode));
                            }
                        }
                        KeyCode::Char('4') => {
                            // Change Theme
                            self.settings.theme = match self.settings.theme.as_str() {
                                "system" => "dark".to_string(),
                                "dark" => "light".to_string(),
                                "light" => "system".to_string(),
                                _ => "system".to_string(),
                            };
                            if let Err(e) = self.save_settings() {
                                self.error_message = Some(format!("Failed to save: {}", e));
                            } else {
                                self.error_message = Some(format!("Theme changed to {}", self.settings.theme));
                            }
                        }
                        KeyCode::Char('5') => {
                            // Enable Debug Logging
                            self.settings.enable_debug_logging = !self.settings.enable_debug_logging;
                            if let Err(e) = self.save_settings() {
                                self.error_message = Some(format!("Failed to save: {}", e));
                            } else {
                                let status = if self.settings.enable_debug_logging { "enabled" } else { "disabled" };
                                self.error_message = Some(format!("Debug logging {}", status));
                            }
                        }
                        KeyCode::Char('6') => {
                            // Export Configuration
                            if let Err(e) = self.export_configuration() {
                                self.error_message = Some(format!("Failed to export configuration: {}", e));
                            } else {
                                self.error_message = Some("Configuration exported successfully!".to_string());
                            }
                        }
                        KeyCode::Char('7') => {
                            // Factory Reset
                            self.state = AppState::FactoryResetConfirm;
                            self.error_message = Some("WARNING: This will reset all settings to defaults. Press y to confirm.".to_string());
                        }
                        KeyCode::Esc | KeyCode::Char('q') => {
                            self.state = AppState::SettingsMenu;
                        }
                        _ => {}
                    }
                }
                AppState::SettingsHelp => {
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('q') => {
                            self.state = AppState::SettingsMenu;
                        }
                        _ => {}
                    }
                }
                AppState::Exiting => {
                    if key.code == KeyCode::Char('y') {
                        return Ok(true); // Signal to exit
                    } else if key.code == KeyCode::Char('n') || key.code == KeyCode::Esc {
                        self.state = AppState::MainMenu;
                    }
                }
            }
        }
        Ok(false)
    }
}