// RustyPass - A secure password manager
//
// This library provides the core functionality for RustyPass,
// including cryptographic operations, password storage, and UI components.

pub mod crypto;
pub mod password_analysis;
pub mod storage;
pub mod ui;
pub mod app;

pub use app::App;
pub use crypto::{encrypt, decrypt, derive_key, generate_secure_password};
pub use password_analysis::{analyze_password, strength_description, entropy_rating, StrengthLevel};
pub use storage::{AppSettings, PasswordStore, save_passwords, load_passwords, save_settings, load_settings};
pub use ui::{setup_terminal, restore_terminal, ui};