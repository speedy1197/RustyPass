1 use aes_gcm::{
  2     aead::{Aead, KeyInit},
  3     Aes256Gcm, Nonce
  4 };
  5 use serde::{Serialize, Deserialize};
  6 use std::{
  7     collections::HashMap,
  8     fs::{self, File, create_dir_all},
  9     io::Read,
 10 };
 11 use anyhow::Result;
 12 use rand::{RngCore, thread_rng, Rng};
 13 use ratatui::{
 14     prelude::*,
 15     widgets::{Block, Borders, Paragraph, List, ListItem, ListState, BorderType, Wrap}
 16 };
 17 use crossterm::{
 18     event::{self, Event, KeyCode, KeyEventKind},
 19     execute,
 20     terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen}
 21 };
 22 use dirs;
 23 // use chrono; // Commented out for now - would need to add to Cargo.toml
 24
 25 #[derive(Serialize, Deserialize, Clone)]
 26 pub struct PasswordEntry {
 27     pub password: String,
 28     pub username: String,
 29     pub url: Option<String>,
 30     pub notes: Option<String>,
 31     pub created_at: String,
 32     pub updated_at: String,
 33 }
 34
 35 #[derive(Serialize, Deserialize)]
 36 pub struct PasswordStore {
 37     pub entries: HashMap<String, PasswordEntry>,
 38 }
 39
 40 impl PasswordStore {
 41     fn new() -> Self {
 42         Self {
 43             entries: HashMap::new(),
 44         }
 45     }
 46
 47     /// Generate a secure random password
 48     fn generate_password(length: usize) -> String {
 49         const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<
 50         let mut rng = thread_rng();
 51         (0..length)
 52             .map(|_| {
 53                 let idx = rng.gen_range(0..CHARSET.len());
 54                 CHARSET[idx] as char
 55             })
 56             .collect()
 57     }
 58
 59     fn add_password(&mut self, service: String, password: String, username: String) -> bool {
 60         if service.is_empty() || password.len() < MIN_PASSWORD_LENGTH {
 61             return false;
 62         }
 63         let entry = PasswordEntry {
 64             password,
/Users/eli/Projects/Rust/RustyPass/src/main.rs (43,37) | ft:rust | unix | utf-8               Alt-g: bindings, Ctrl-g: help
