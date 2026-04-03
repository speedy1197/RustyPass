use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use serde::{Serialize, Deserialize};
use std::{
    collections::HashMap,
    fs::{self, File, create_dir_all},
    io::Read,
    path::Path,
};
use anyhow::Result;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, List, ListItem, ListState}
};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen}
};

#[derive(Serialize, Deserialize)]
pub struct PasswordStore {
    pub entries: HashMap<String, String>,
}

impl PasswordStore {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn add_password(&mut self, service: String, password: String) {
        self.entries.insert(service, password);
    }

    fn get_password(&self, service: &str) -> Option<&String> {
        self.entries.get(service)
    }

    fn remove_password(&mut self, service: &str) -> Option<String> {
        self.entries.remove(service)
    }

    fn get_services(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
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
    let nonce = Nonce::from_slice(b"unique_nonce");

    let encrypted = cipher.encrypt(nonce, data).map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    let mut result = nonce.as_slice().to_vec();
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

const STORAGE_DIR: &str = "/home/eli/.RustyPass";
const STORAGE_FILE: &str = "/home/eli/.RustyPass/passwords.json.enc";

fn ensure_storage_dir_exists() -> Result<()> {
    create_dir_all(STORAGE_DIR)?;
    Ok(())
}

fn save_passwords(store: &PasswordStore, key: &[u8; 32]) -> Result<()> {
    ensure_storage_dir_exists()?;
    let json = serde_json::to_string(store)?;
    let encrypted = encrypt(json.as_bytes(), key)?;
    fs::write(STORAGE_FILE, encrypted)?;
    Ok(())
}

fn load_passwords(key: &[u8; 32]) -> Result<PasswordStore> {
    if !Path::new(STORAGE_FILE).exists() {
        return Ok(PasswordStore::new());
    }

    let mut file = File::open(STORAGE_FILE)?;
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
    selected_service: Option<usize>,
    input_service: String,
    input_password: String,
    input_master: String,
    error_message: Option<String>,
    list_state: ListState,
}

impl App {
    fn new() -> Self {
        Self {
            state: AppState::PasswordEntry,
            store: PasswordStore::new(),
            key: [0u8; 32],
            services: Vec::new(),
            selected_service: None,
            input_service: String::new(),
            input_password: String::new(),
            input_master: String::new(),
            error_message: None,
            list_state: ListState::default(),
        }
    }

    fn unlock(&mut self, master_password: &str) -> Result<()> {
        self.key = derive_key(master_password);
        self.store = load_passwords(&self.key)?;
        self.services = self.store.get_services();
        self.list_state.select(None);
        Ok(())
    }

    fn add_service(&mut self, service: String, password: String) -> Result<()> {
        self.store.add_password(service.clone(), password);
        save_passwords(&self.store, &self.key)?;
        self.services = self.store.get_services();
        Ok(())
    }

    fn delete_service(&mut self, service: &str) -> Result<()> {
        self.store.remove_password(service);
        save_passwords(&self.store, &self.key)?;
        self.services = self.store.get_services();
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
                            app.input_master.pop();
                        } else if key.code == KeyCode::Esc {
                            app.state = AppState::Exiting;
                        }
                    }
                    AppState::MainMenu => {
                        match key.code {
                            KeyCode::Char('a') => {
                                app.state = AppState::AddService;
                                app.input_service.clear();
                            }
                            KeyCode::Char('v') => {
                                if let Some(_selected) = app.selected_service {
                                    app.state = AppState::ViewPassword;
                                }
                            }
                            KeyCode::Char('d') => {
                                if app.selected_service.is_some() {
                                    app.state = AppState::DeleteConfirm;
                                }
                            }
                            KeyCode::Char('q') | KeyCode::Esc => {
                                app.state = AppState::Exiting;
                            }
                            KeyCode::Up => {
                                if let Some(selected) = app.selected_service {
                                    if selected > 0 {
                                        app.selected_service = Some(selected - 1);
                                        app.list_state.select(Some(selected - 1));
                                    }
                                } else if !app.services.is_empty() {
                                    app.selected_service = Some(0);
                                    app.list_state.select(Some(0));
                                }
                            }
                            KeyCode::Down => {
                                if let Some(selected) = app.selected_service {
                                    if selected < app.services.len() - 1 {
                                        app.selected_service = Some(selected + 1);
                                        app.list_state.select(Some(selected + 1));
                                    }
                                } else if !app.services.is_empty() {
                                    app.selected_service = Some(0);
                                    app.list_state.select(Some(0));
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
                            }
                        } else if let KeyCode::Char(c) = key.code {
                            app.input_service.push(c);
                        } else if key.code == KeyCode::Backspace {
                            app.input_service.pop();
                        } else if key.code == KeyCode::Esc {
                            app.state = AppState::MainMenu;
                        }
                    }
                    AppState::AddPassword => {
                        if key.code == KeyCode::Enter {
                            if !app.input_password.is_empty() {
                                if let Err(e) = app.add_service(app.input_service.clone(), app.input_password.clone()) {
                                    app.error_message = Some(format!("Error: {}", e));
                                }
                                app.state = AppState::MainMenu;
                            }
                        } else if let KeyCode::Char(c) = key.code {
                            app.input_password.push(c);
                        } else if key.code == KeyCode::Backspace {
                            app.input_password.pop();
                        } else if key.code == KeyCode::Esc {
                            app.state = AppState::MainMenu;
                        }
                    }
                    AppState::ViewPassword => {
                        if key.code == KeyCode::Esc || key.code == KeyCode::Char('q') {
                            app.state = AppState::MainMenu;
                        }
                    }
                    AppState::DeleteConfirm => {
                        match key.code {
                            KeyCode::Char('y') => {
                                if let Some(selected) = app.selected_service {
                                    if let Some(service) = app.services.get(selected) {
                                        let service_clone = service.clone();
                                        if let Err(e) = app.delete_service(&service_clone) {
                                            app.error_message = Some(format!("Error: {}", e));
                                        }
                                    }
                                }
                                app.state = AppState::MainMenu;
                            }
                            KeyCode::Char('n') | KeyCode::Esc => {
                                app.state = AppState::MainMenu;
                            }
                            _ => {}
                        }
                    }
                    AppState::Exiting => {
                        if key.code == KeyCode::Char('y') {
                            break;
                        } else if key.code == KeyCode::Char('n') || key.code == KeyCode::Esc {
                            app.state = AppState::MainMenu;
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

    match app.state {
        AppState::PasswordEntry => {
            let title = Paragraph::new("RustyPass - Password Manager")
                .block(Block::default().borders(Borders::ALL).title("Enter Master Password"))
                .alignment(Alignment::Center);

            let input = Paragraph::new(app.input_master.clone())
                .block(Block::default().borders(Borders::ALL).title("Password"));

            let help = Paragraph::new("Press Enter to continue or Esc to exit")
                .alignment(Alignment::Center);

            f.render_widget(title, rects[0]);
            f.render_widget(input, rects[1]);
            f.render_widget(help, rects[2]);

            if let Some(error) = &app.error_message {
                let error_paragraph = Paragraph::new(error.clone())
                    .style(Style::default().fg(Color::Red))
                    .alignment(Alignment::Center);
                f.render_widget(error_paragraph, rects[2]);
            }
        }
        AppState::MainMenu => {
            let title = Paragraph::new("RustyPass - Main Menu")
                .block(Block::default().borders(Borders::ALL))
                .alignment(Alignment::Center);

            let services_list: Vec<ListItem> = app.services
                .iter()
                .map(|s| ListItem::new(s.clone()))
                .collect();

            let list = List::new(services_list)
                .block(Block::default().borders(Borders::ALL).title("Services"))
                .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

            let help = Paragraph::new("a: Add | v: View | d: Delete | q: Quit | ↑/↓: Navigate")
                .alignment(Alignment::Center);

            f.render_widget(title, rects[0]);
            f.render_stateful_widget(list, rects[1], &mut app.list_state);
            f.render_widget(help, rects[2]);
        }
        AppState::AddService => {
            let title = Paragraph::new("Add New Service")
                .block(Block::default().borders(Borders::ALL))
                .alignment(Alignment::Center);

            let input = Paragraph::new(app.input_service.clone())
                .block(Block::default().borders(Borders::ALL).title("Service Name"));

            let help = Paragraph::new("Press Enter to continue or Esc to cancel")
                .alignment(Alignment::Center);

            f.render_widget(title, rects[0]);
            f.render_widget(input, rects[1]);
            f.render_widget(help, rects[2]);
        }
        AppState::AddPassword => {
            let title = Paragraph::new(format!("Add Password for {}", app.input_service))
                .block(Block::default().borders(Borders::ALL))
                .alignment(Alignment::Center);

            let input = Paragraph::new(app.input_password.clone())
                .block(Block::default().borders(Borders::ALL).title("Password"));

            let help = Paragraph::new("Press Enter to save or Esc to cancel")
                .alignment(Alignment::Center);

            f.render_widget(title, rects[0]);
            f.render_widget(input, rects[1]);
            f.render_widget(help, rects[2]);
        }
        AppState::ViewPassword => {
            if let Some(selected) = app.selected_service {
                if let Some(service) = app.services.get(selected) {
                    if let Some(password) = app.store.get_password(service) {
                        let title = Paragraph::new(format!("Password for {}", service))
                            .block(Block::default().borders(Borders::ALL))
                            .alignment(Alignment::Center);

                        let password_display = Paragraph::new(password.clone())
                            .block(Block::default().borders(Borders::ALL));

                        let help = Paragraph::new("Press q or Esc to return")
                            .alignment(Alignment::Center);

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
                    let title = Paragraph::new("Confirm Delete")
                        .block(Block::default().borders(Borders::ALL))
                        .alignment(Alignment::Center);

                    let confirm = Paragraph::new(format!("Delete '{}'? (y/n)", service))
                        .block(Block::default().borders(Borders::ALL));

                    f.render_widget(title, rects[0]);
                    f.render_widget(confirm, rects[1]);
                }
            }
        }
        AppState::Exiting => {
            let title = Paragraph::new("Exit RustyPass")
                .block(Block::default().borders(Borders::ALL))
                .alignment(Alignment::Center);

            let confirm = Paragraph::new("Are you sure you want to exit? (y/n)")
                .block(Block::default().borders(Borders::ALL));

            f.render_widget(title, rects[0]);
            f.render_widget(confirm, rects[1]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn test_persistence() {
        // Clean up
        let _ = fs::remove_file(STORAGE_FILE);
        let _ = fs::remove_dir("/home/eli/.RustyPass");

        // Test data
        let master_password = "testpassword";
        let key = derive_key(master_password);

        // Create a test store
        let mut store = PasswordStore::new();
        store.add_password("github".to_string(), "mysecretpassword".to_string());

        // Save it
        save_passwords(&store, &key).expect("Failed to save passwords");

        // Check if file exists
        assert!(Path::new(STORAGE_FILE).exists(), "Encrypted file not created");

        // Load it back
        let loaded_store = load_passwords(&key).expect("Failed to load passwords");

        // Verify the password
        let retrieved_password = loaded_store.get_password("github")
            .expect("Password not found in loaded store");

        assert_eq!(retrieved_password, "mysecretpassword", "Password mismatch");

        // Clean up
        let _ = fs::remove_file(STORAGE_FILE);
        let _ = fs::remove_dir("/home/eli/.RustyPass");
    }
}
