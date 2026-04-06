use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use serde::{Serialize, Deserialize};
use std::{
    collections::HashMap,
    fs::{self, File, create_dir_all},
    io::Read,
};
use anyhow::Result;
use rand::{RngCore, thread_rng, Rng};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, List, ListItem, ListState, BorderType, Wrap}
};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen}
};
use dirs;
// use chrono; // Commented out for now - would need to add to Cargo.toml

#[derive(Serialize, Deserialize, Clone)]
pub struct PasswordEntry {
    pub password: String,
    pub username: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize, Deserialize)]
pub struct PasswordStore {
    pub entries: HashMap<String, PasswordEntry>,
}

impl PasswordStore {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Generate a secure random password
    fn generate_password(length: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
        let mut rng = thread_rng();
        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    fn add_password(&mut self, service: String, password: String, username: String) -> bool {
        if service.is_empty() || password.len() < MIN_PASSWORD_LENGTH {
            return false;
        }
        let entry = PasswordEntry {
            password,
            username,
            url: None,
            notes: None,
            created_at: "2024-01-01T00:00:00Z".to_string(), // Placeholder - would use chrono in production
            updated_at: "2024-01-01T00:00:00Z".to_string(), // Placeholder - would use chrono in production
        };
        self.entries.insert(service, entry);
        true
    }

    fn get_password(&self, service: &str) -> Option<&PasswordEntry> {
        self.entries.get(service)
    }

    fn remove_password(&mut self, service: &str) -> Option<PasswordEntry> {
        self.entries.remove(service)
    }

    fn get_services(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    /// Search services by query
    fn search_services(&self, query: &str) -> Vec<String> {
        if query.is_empty() {
            return self.get_services();
        }
        self.get_services().iter()
            .filter(|s: &&String| s.to_lowercase().contains(&query.to_lowercase()))
            .cloned()
            .collect()
    }
}

fn derive_key(master_password: &str) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(master_password.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    key
}

pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("Key error: {}", e))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let encrypted = cipher.encrypt(&nonce, data).map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    let mut result = nonce.to_vec();
    result.extend(encrypted);
    Ok(result)
}

pub fn decrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("Key error: {}", e))?;

    if data.len() < 12 {
        return Err(anyhow::anyhow!("Invalid encrypted data: too short"));
    }

    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];

    cipher.decrypt(nonce, ciphertext).map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))
}

// Configuration constants
const STORAGE_DIR: &str = ".RustyPass";
const STORAGE_FILE: &str = "passwords.json.enc";
const MIN_PASSWORD_LENGTH: usize = 4;

fn ensure_storage_dir_exists() -> Result<()> {
    let home_dir = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
    let full_path = home_dir.join(STORAGE_DIR);
    create_dir_all(&full_path)?;
    Ok(())
}

fn get_storage_path() -> Result<std::path::PathBuf> {
    let home_dir = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
    Ok(home_dir.join(STORAGE_DIR).join(STORAGE_FILE))
}

fn save_passwords(store: &PasswordStore, key: &[u8; 32], storage_path: &Option<std::path::PathBuf>) -> Result<()> {
    ensure_storage_dir_exists()?;
    let storage_path = if let Some(path) = storage_path {
        path.clone()
    } else {
        get_storage_path()?
    };
    let json = serde_json::to_string(store)?;
    let encrypted = encrypt(json.as_bytes(), key)?;
    fs::write(&storage_path, encrypted)?;
    Ok(())
}

fn load_passwords(key: &[u8; 32]) -> Result<PasswordStore> {
    let storage_path = get_storage_path()?;
    if !storage_path.exists() {
        return Ok(PasswordStore::new());
    }

    let mut file = File::open(&storage_path)?;
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data)?;

    let decrypted = decrypt(&encrypted_data, key)?;
    let json = String::from_utf8(decrypted)?;
    let store: PasswordStore = serde_json::from_str(&json)?;
    Ok(store)
}

enum AppState {
    PasswordEntry,
    MainMenu,
    AddService,
    AddPassword,
    ViewPassword,
    DeleteConfirm,
    Exiting,
}

struct App {
    state: AppState,
    store: PasswordStore,
    key: [u8; 32],
    services: Vec<String>,
    filtered_services: Vec<String>,
    selected_service: Option<usize>,
    input_service: String,
    input_password: String,
    input_master: String,
    search_query: String,
    error_message: Option<String>,
    list_state: ListState,
    storage_path: Option<std::path::PathBuf>,
}

impl App {
    fn new() -> Self {
        Self {
            state: AppState::PasswordEntry,
            store: PasswordStore::new(),
            key: [0u8; 32],
            services: Vec::new(),
            filtered_services: Vec::new(),
            selected_service: None,
            input_service: String::new(),
            input_password: String::new(),
            input_master: String::new(),
            search_query: String::new(),
            error_message: None,
            list_state: ListState::default(),
            storage_path: None,
        }
    }

    fn unlock(&mut self, master_password: &str) -> Result<()> {
        self.key = derive_key(master_password);
        self.storage_path = Some(get_storage_path()?);
        self.store = load_passwords(&self.key)?;
        self.services = self.store.get_services();
        self.filtered_services = self.services.clone();
        self.list_state.select(None);
        self.selected_service = None;
        self.search_query.clear();
        self.error_message = None;
        Ok(())
    }

    fn update_search(&mut self) {
        self.filtered_services = self.store.search_services(&self.search_query);
        self.selected_service = None;
        self.list_state.select(None);
    }

    fn add_service(&mut self, service: String, password: String, username: String) -> Result<()> {
        if !self.store.add_password(service.clone(), password, username) {
            return Err(anyhow::anyhow!("Service name and password must not be empty, and password must be at least {} characters", MIN_PASSWORD_LENGTH));
        }
        save_passwords(&self.store, &self.key, &self.storage_path)?;
        self.services = self.store.get_services();
        self.update_search(); // Update filtered list after adding
        Ok(())
    }

    fn delete_service(&mut self, service: &str) -> Result<()> {
        self.store.remove_password(service);
        save_passwords(&self.store, &self.key, &self.storage_path)?;
        self.services = self.store.get_services();
        self.update_search(); // Update filtered list after deleting
        self.selected_service = None;
        Ok(())
    }




}

fn setup_terminal() -> Result<Terminal<impl Backend>> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

fn restore_terminal() -> Result<()> {
    disable_raw_mode()?;
    execute!(std::io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}

fn main() -> Result<()> {
    let mut terminal = setup_terminal()?;
    let mut app = App::new();

    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match app.state {
                    AppState::PasswordEntry => {
                        if key.code == KeyCode::Enter {
                            if !app.input_master.is_empty() {
                                let master_password = app.input_master.clone();
                                if let Err(e) = app.unlock(&master_password) {
                                    app.error_message = Some(format!("Error: {}", e));
                                } else {
                                    app.state = AppState::MainMenu;
                                    app.input_master.clear();
                                }
                            }
                        } else if let KeyCode::Char(c) = key.code {
                            app.input_master.push(c);
                        } else if key.code == KeyCode::Backspace {
                            if !app.input_master.is_empty() {
                                app.input_master.pop();
                            }
                        } else if key.code == KeyCode::Esc {
                            app.state = AppState::Exiting;
                        }
                    }
                    AppState::MainMenu => {
                        match key.code {
                            KeyCode::Char('a') => {
                                app.state = AppState::AddService;
                                app.input_service.clear();
                                app.error_message = None;
                            }
                            KeyCode::Char('v') => {
                                if let Some(selected) = app.selected_service {
                                    if selected < app.filtered_services.len() {
                                        app.state = AppState::ViewPassword;
                                    }
                                }
                            }
                            KeyCode::Char('d') => {
                                if app.selected_service.is_some() {
                                    app.state = AppState::DeleteConfirm;
                                }
                            }
                            KeyCode::Char('/') => {
                                // Toggle search mode
                            }
                            KeyCode::Char('q') | KeyCode::Esc => {
                                app.state = AppState::Exiting;
                            }
                            KeyCode::Up => {
                                if !app.filtered_services.is_empty() {
                                    if let Some(selected) = app.selected_service {
                                        if selected > 0 {
                                            app.selected_service = Some(selected - 1);
                                            app.list_state.select(Some(selected - 1));
                                        }
                                    } else {
                                        app.selected_service = Some(0);
                                        app.list_state.select(Some(0));
                                    }
                                }
                            }
                            KeyCode::Down => {
                                if !app.filtered_services.is_empty() {
                                    if let Some(selected) = app.selected_service {
                                        if selected < app.filtered_services.len() - 1 {
                                            app.selected_service = Some(selected + 1);
                                            app.list_state.select(Some(selected + 1));
                                        }
                                    } else {
                                        app.selected_service = Some(0);
                                        app.list_state.select(Some(0));
                                    }
                                }
                            }
                            KeyCode::Char(c) => {
                                // Search as you type
                                app.search_query.push(c);
                                app.update_search();
                            }
                            KeyCode::Backspace => {
                                if !app.search_query.is_empty() {
                                    app.search_query.pop();
                                    app.update_search();
                                }
                            }
                            _ => {}
                        }
                    }
                AppState::AddService => {
                    if key.code == KeyCode::Enter {
                        if !app.input_service.is_empty() {
                            app.state = AppState::AddPassword;
                            app.input_password.clear();
                            app.error_message = None;
                        }
                    } else if key.code == KeyCode::Char('g') {
                        // Generate password shortcut
                        app.input_password = PasswordStore::generate_password(16);
                        app.state = AppState::AddPassword;
                    } else if let KeyCode::Char(c) = key.code {
                        app.input_service.push(c);
                    } else if key.code == KeyCode::Backspace {
                        if !app.input_service.is_empty() {
                            app.input_service.pop();
                        }
                    } else if key.code == KeyCode::Esc {
                        app.state = AppState::MainMenu;
                        app.search_query.clear();
                        app.update_search();
                        app.error_message = None;
                    }
                }
                AppState::AddPassword => {
                    if key.code == KeyCode::Enter {
                        if !app.input_password.is_empty() {
                            if let Err(e) = app.add_service(app.input_service.clone(), app.input_password.clone(), "user".to_string()) {
                                app.error_message = Some(format!("Error: {}", e));
                            } else {
                                app.error_message = Some(format!("✓ Successfully added password for {}", app.input_service));
                            }
                            app.state = AppState::MainMenu;
                        }
                    } else if let KeyCode::Char(c) = key.code {
                        app.input_password.push(c);
                    } else if key.code == KeyCode::Backspace {
                        if !app.input_password.is_empty() {
                            app.input_password.pop();
                        }
                    } else if key.code == KeyCode::Esc {
                        app.state = AppState::MainMenu;
                        app.search_query.clear();
                        app.update_search();
                        app.error_message = None;
                    }
                }
                    AppState::ViewPassword => {
                        if key.code == KeyCode::Esc || key.code == KeyCode::Char('q') {
                            app.state = AppState::MainMenu;
                            app.search_query.clear();
                            app.update_search();
                            app.error_message = None;
                        }
                    }
                    AppState::DeleteConfirm => {
                        match key.code {
                            KeyCode::Char('y') => {
                                if let Some(selected) = app.selected_service {
                                    if let Some(service) = app.filtered_services.get(selected) {
                                        let service_clone = service.clone();
                                        if let Err(e) = app.delete_service(&service_clone) {
                                            app.error_message = Some(format!("Error: {}", e));
                                        } else {
                                            app.error_message = Some(format!("✓ Successfully deleted {}", service_clone));
                                        }
                                    }
                                }
                                app.state = AppState::MainMenu;
                            }
                            KeyCode::Char('n') | KeyCode::Esc => {
                                app.state = AppState::MainMenu;
                                app.search_query.clear();
                                app.update_search();
                                app.error_message = None;
                            }
                            _ => {}
                        }
                    },
                    AppState::Exiting => {
                        if key.code == KeyCode::Char('y') {
                            break;
                        } else if key.code == KeyCode::Char('n') || key.code == KeyCode::Esc {
                            app.state = AppState::MainMenu;
                            app.search_query.clear();
                            app.update_search();
                            app.error_message = None;
                        }
                    }
                }
            }
        }
    }

    restore_terminal()?;
    Ok(())
}

fn ui(f: &mut Frame, app: &mut App) {
    let rects = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .split(f.size());

    // Create a consistent color scheme
    let primary_color = Color::Cyan;
    let secondary_color = Color::Blue;
    let accent_color = Color::LightYellow;
    let text_color = Color::White;
    let error_color = Color::LightRed;
    let success_color = Color::LightGreen;

    match app.state {
        AppState::PasswordEntry => {
            let title = Paragraph::new("🔐 RustyPass - Password Manager")
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Enter Master Password ")
                        .border_style(Style::default().fg(primary_color))
                        .border_type(BorderType::Rounded)
                )
                .alignment(Alignment::Center)
                .style(Style::default().fg(accent_color).add_modifier(Modifier::BOLD));

            let input = Paragraph::new(app.input_master.clone())
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" 🔑 Password ")
                        .border_style(Style::default().fg(secondary_color))
                        .border_type(BorderType::Rounded)
                )
                .style(Style::default().fg(text_color))
                .wrap(Wrap { trim: true });

            let help = Paragraph::new("⏎ Enter to continue | Esc to exit")
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::Gray));

            f.render_widget(title, rects[0]);
            f.render_widget(input, rects[1]);

            // Create a layout for help and error messages
            let help_error_layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Length(1),
                    Constraint::Length(1),
                ])
                .split(rects[2]);

            f.render_widget(help, help_error_layout[1]);

            if let Some(error) = &app.error_message {
                let error_paragraph = Paragraph::new(error.clone())
                    .style(Style::default().fg(error_color).add_modifier(Modifier::BOLD))
                    .alignment(Alignment::Center)
                    .block(
                        Block::default()
                            .borders(Borders::NONE)
                            .style(Style::default().bg(error_color).fg(Color::Black))
                    );
                f.render_widget(error_paragraph, help_error_layout[0]);
            }
        }
        AppState::MainMenu => {
            let title = Paragraph::new("🔐 RustyPass - Main Menu")
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(primary_color))
                        .border_type(BorderType::Rounded)
                )
                .alignment(Alignment::Center)
                .style(Style::default().fg(accent_color).add_modifier(Modifier::BOLD));

            let services_list: Vec<ListItem> = app.filtered_services
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    let mut item = ListItem::new(format!("{}. {}", i + 1, s))
                        .style(Style::default().fg(text_color));
                    if app.selected_service == Some(i) {
                        item = item.style(Style::default().fg(Color::Black).bg(accent_color).add_modifier(Modifier::BOLD));
                    }
                    item
                })
                .collect();

            let list = List::new(services_list)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" 📋 Services ")
                        .border_style(Style::default().fg(secondary_color))
                        .border_type(BorderType::Rounded)
                )
                .highlight_style(Style::default().fg(Color::Black).bg(accent_color).add_modifier(Modifier::BOLD));

            let search_hint = if app.search_query.is_empty() {
                "Type to search...".to_string()
            } else {
                format!("Search: {}", app.search_query)
            };

            let help = Paragraph::new(format!("📝 a: Add | 👁️ v: View | 🗑️ d: Delete | 🚪 q: Quit | ↑/↓: Navigate | /: Search | Backspace: Clear"))
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::Gray));

            let search_display = Paragraph::new(search_hint)
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::DarkGray));

            f.render_widget(title, rects[0]);
            f.render_widget(list, rects[1]);

            // Create layout for help and search
            let bottom_layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Length(1),
                ])
                .split(rects[2]);

            f.render_widget(search_display, bottom_layout[0]);
            f.render_widget(help, bottom_layout[1]);
        }
        AppState::AddService => {
            let title = Paragraph::new("📝 Add New Service")
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(primary_color))
                        .border_type(BorderType::Rounded)
                )
                .alignment(Alignment::Center)
                .style(Style::default().fg(accent_color).add_modifier(Modifier::BOLD));

            let input = Paragraph::new(app.input_service.clone())
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" 🏷️  Service Name ")
                        .border_style(Style::default().fg(secondary_color))
                        .border_type(BorderType::Rounded)
                )
                .style(Style::default().fg(text_color));

            let help = Paragraph::new("⏎ Enter to continue | g: Generate password | Esc to cancel")
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::Gray));

            f.render_widget(title, rects[0]);
            f.render_widget(input, rects[1]);
            f.render_widget(help, rects[2]);
        }
        AppState::AddPassword => {
            let title = Paragraph::new(format!("🔑 Add Password for {}", app.input_service))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(primary_color))
                        .border_type(BorderType::Rounded)
                )
                .alignment(Alignment::Center)
                .style(Style::default().fg(accent_color).add_modifier(Modifier::BOLD));

            let input = Paragraph::new(app.input_password.clone())
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" 🔐 Password ")
                        .border_style(Style::default().fg(secondary_color))
                        .border_type(BorderType::Rounded)
                )
                .style(Style::default().fg(text_color));

            let help = Paragraph::new("⏎ Enter to save | Esc to cancel")
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::Gray));

            f.render_widget(title, rects[0]);
            f.render_widget(input, rects[1]);
            f.render_widget(help, rects[2]);
        }
        AppState::ViewPassword => {
            if let Some(selected) = app.selected_service {
                if let Some(service) = app.filtered_services.get(selected) {
                    if let Some(entry) = app.store.get_password(service) {
                        let title = Paragraph::new(format!("👁️ Password for {}", service))
                            .block(
                                Block::default()
                                    .borders(Borders::ALL)
                                    .border_style(Style::default().fg(primary_color))
                                    .border_type(BorderType::Rounded)
                            )
                            .alignment(Alignment::Center)
                            .style(Style::default().fg(accent_color).add_modifier(Modifier::BOLD));

                        let password_display = Paragraph::new(format!("Password: {}\\nUsername: {}", entry.password, entry.username))
                            .block(
                                Block::default()
                                    .borders(Borders::ALL)
                                    .border_style(Style::default().fg(secondary_color))
                                    .border_type(BorderType::Rounded)
                            )
                            .style(Style::default().fg(success_color).add_modifier(Modifier::BOLD))
                            .alignment(Alignment::Center)
                            .wrap(Wrap { trim: true });

                        let help = Paragraph::new("🔙 Back (q/Esc)")
                            .alignment(Alignment::Center)
                            .style(Style::default().fg(Color::Gray));

                        f.render_widget(title, rects[0]);
                        f.render_widget(password_display, rects[1]);
                        f.render_widget(help, rects[2]);
                    }
                }
            }
        }
        AppState::DeleteConfirm => {
            if let Some(selected) = app.selected_service {
                if let Some(service) = app.services.get(selected) {
                    let title = Paragraph::new("🗑️ Confirm Delete")
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .border_style(Style::default().fg(primary_color))
                                .border_type(BorderType::Rounded)
                        )
                        .alignment(Alignment::Center)
                        .style(Style::default().fg(error_color).add_modifier(Modifier::BOLD));

                    let confirm = Paragraph::new(format!("⚠️  Delete '{}'? (y/n)", service))
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .border_style(Style::default().fg(error_color))
                                .border_type(BorderType::Rounded)
                        )
                        .style(Style::default().fg(text_color).add_modifier(Modifier::BOLD))
                        .alignment(Alignment::Center);

                    f.render_widget(title, rects[0]);
                    f.render_widget(confirm, rects[1]);
                }
            }
        }
        AppState::Exiting => {
            let title = Paragraph::new("🚪 Exit RustyPass")
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(primary_color))
                        .border_type(BorderType::Rounded)
                )
                .alignment(Alignment::Center)
                .style(Style::default().fg(accent_color).add_modifier(Modifier::BOLD));

            let confirm = Paragraph::new("Are you sure you want to exit? (y/n)")
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(secondary_color))
                        .border_type(BorderType::Rounded)
                )
                .style(Style::default().fg(accent_color).add_modifier(Modifier::BOLD))
                .alignment(Alignment::Center);

            f.render_widget(title, rects[0]);
            f.render_widget(confirm, rects[1]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_persistence() {
        // Test data
        let master_password = "testpassword";
        let key = derive_key(master_password);

        // Create a test store
        let mut store = PasswordStore::new();
        store.add_password("github".to_string(), "mysecretpassword".to_string(), "testuser".to_string());

        // Save it
        save_passwords(&store, &key, &None).expect("Failed to save passwords");

        // Check if file exists
        let storage_path = get_storage_path().expect("Failed to get storage path");
        assert!(storage_path.exists(), "Encrypted file not created");

        // Load it back
        let loaded_store = load_passwords(&key).expect("Failed to load passwords");

        // Verify the password
        let retrieved_entry = loaded_store.get_password("github")
            .expect("Password not found in loaded store");

        assert_eq!(retrieved_entry.password, "mysecretpassword", "Password mismatch");
        assert_eq!(retrieved_entry.username, "testuser", "Username mismatch");

        // Clean up
        let _ = fs::remove_file(storage_path);
        let home_dir = dirs::home_dir().expect("Failed to get home directory");
        let _ = fs::remove_dir(home_dir.join(".RustyPass"));
    }
}
