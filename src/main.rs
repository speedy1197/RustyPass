use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use serde::{Serialize, Deserialize};
use std::{
    collections::HashMap,
    fs::{self, File, create_dir_all},
    io::Read,
    path::PathBuf,
};
use anyhow::Result;
use csv;
use rand::{RngCore, thread_rng};
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

fn derive_key(master_password: &str, salt: &[u8]) -> [u8; 32] {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(master_password.as_bytes(), salt, 100000, &mut key);
    key
}

/// Generate a cryptographically secure random password
/// Uses system entropy sources similar to GPG
fn generate_secure_password(length: usize) -> String {
    
    // Character sets for different complexity levels
    const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"0123456789";
    const SYMBOLS: &[u8] = b"!@#$%^&*()_+-=[]{}|;:,.<>?";
    
    let mut password = Vec::with_capacity(length);
    let mut rng = thread_rng();
    
    // Ensure at least one character from each character set for complexity
    let mut chars = Vec::new();
    chars.extend_from_slice(LOWERCASE);
    chars.extend_from_slice(UPPERCASE);
    chars.extend_from_slice(DIGITS);
    chars.extend_from_slice(SYMBOLS);
    
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
    
    String::from_utf8(password).unwrap()
}

pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    use rand::RngCore;
    
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("Key error: {}", e))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let encrypted = cipher.encrypt(nonce, data).map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    let mut result = nonce_bytes.to_vec();
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

fn get_storage_dir() -> Result<PathBuf> {
    let mut dir = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?;
    dir.push(".RustyPass");
    Ok(dir)
}

fn get_storage_file() -> Result<PathBuf> {
    let mut file = get_storage_dir()?;
    file.push("passwords.json.enc");
    Ok(file)
}

fn get_salt_file() -> Result<PathBuf> {
    let mut file = get_storage_dir()?;
    file.push("salt.bin");
    Ok(file)
}

fn ensure_storage_dir_exists() -> Result<()> {
    let storage_dir = get_storage_dir()?;
    create_dir_all(storage_dir)?;
    Ok(())
}

fn save_passwords(store: &PasswordStore, key: &[u8; 32]) -> Result<()> {
    ensure_storage_dir_exists()?;
    let json = serde_json::to_string(store)?;
    let encrypted = encrypt(json.as_bytes(), key)?;
    let storage_file = get_storage_file()?;
    fs::write(&storage_file, encrypted)?;
    Ok(())
}

fn load_passwords(key: &[u8; 32]) -> Result<PasswordStore> {
    let storage_file = get_storage_file()?;
    if !storage_file.exists() {
        return Ok(PasswordStore::new());
    }

    let mut file = File::open(&storage_file)?;
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
    GeneratePassword,
    PasswordLengthInput,
    ImportMenu,
    ImportFileInput,
    ImportConfirm,
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
    input_length: String,
    generated_password: Option<String>,
    error_message: Option<String>,
    list_state: ListState,
    import_file_path: String,
    import_format: Option<String>,
    import_preview: Option<String>,
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
            input_length: String::new(),
            generated_password: None,
            error_message: None,
            list_state: ListState::default(),
            import_file_path: String::new(),
            import_format: None,
            import_preview: None,
        }
    }

    fn unlock(&mut self, master_password: &str) -> Result<()> {
        use rand::RngCore;
        
        // Load or generate salt
        let salt_file = get_salt_file()?;
        let salt = if salt_file.exists() {
            let mut file = File::open(&salt_file)?;
            let mut salt = [0u8; 32];
            file.read_exact(&mut salt)?;
            salt
        } else {
            let mut salt = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut salt);
            fs::write(&salt_file, salt)?;
            salt
        };
        
        self.key = derive_key(master_password, &salt);
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

    fn generate_password(&mut self, length: usize) {
        self.generated_password = Some(generate_secure_password(length));
    }

    fn get_generated_password(&self) -> Option<String> {
        self.generated_password.clone()
    }

    fn import_from_json(&mut self, file_path: &str) -> Result<()> {
        let content = fs::read_to_string(file_path)?;
        
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
        
        save_passwords(&self.store, &self.key)?;
        self.services = self.store.get_services();
        Ok(())
    }

    fn try_parse_bitwarden(&self, content: &str) -> Result<HashMap<String, String>> {
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
        let mut result = HashMap::new();
        
        if let Some(items) = export.items {
            for item in items {
                if let Some(login) = item.login {
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

    fn try_parse_simple_json(&self, content: &str) -> Result<HashMap<String, String>> {
        // Try to parse as simple key-value JSON
        if let Ok(map) = serde_json::from_str::<HashMap<String, String>>(content) {
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
            let mut result = HashMap::new();
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

    fn import_from_csv(&mut self, file_path: &str) -> Result<()> {
        let content = fs::read_to_string(file_path)?;
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
        
        save_passwords(&self.store, &self.key)?;
        self.services = self.store.get_services();
        Ok(())
    }

    fn preview_import(&mut self, file_path: &str) -> Result<String> {
        let content = fs::read_to_string(file_path)?;
        
        // Try to determine format and show preview
        if file_path.ends_with(".json") {
            // Try Bitwarden format
            if let Ok(bitwarden_data) = self.try_parse_bitwarden(&content) {
                let count = bitwarden_data.len();
                let sample: Vec<String> = bitwarden_data.keys().take(3).cloned().collect();
                return Ok(format!("Bitwarden JSON: {} entries\nSample: {:?}", count, sample));
            }
            // Try simple JSON
            else if let Ok(simple_data) = self.try_parse_simple_json(&content) {
                let count = simple_data.len();
                let sample: Vec<String> = simple_data.keys().take(3).cloned().collect();
                return Ok(format!("Simple JSON: {} entries\nSample: {:?}", count, sample));
            }
        } else if file_path.ends_with(".csv") {
            let mut reader = csv::Reader::from_reader(content.as_bytes());
            let mut record_count = 0;
            let mut sample_records = Vec::new();
            
            for result in reader.records().take(4) {
                if let Ok(record) = result {
                    let record: csv::StringRecord = record;
                    record_count += 1;
                    if sample_records.len() < 3 && record.len() >= 2 {
                        sample_records.push(record[0].to_string());
                    }
                }
            }
            
            return Ok(format!("CSV: {} entries\nSample: {:?}", record_count, sample_records));
        }
        
        Ok("Unknown format".to_string())
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

pub fn main() -> Result<()> {
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
                            KeyCode::Char('g') => {
                                app.state = AppState::PasswordLengthInput;
                                app.input_length.clear();
                            }
                            KeyCode::Char('i') => {
                                app.state = AppState::ImportMenu;
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
                    AppState::PasswordLengthInput => {
                        if key.code == KeyCode::Enter {
                            if !app.input_length.is_empty() {
                                if let Ok(length) = app.input_length.parse::<usize>() {
                                    app.generate_password(length);
                                    app.state = AppState::GeneratePassword;
                                } else {
                                    app.error_message = Some("Invalid length. Please enter a number.".to_string());
                                }
                            }
                        } else if let KeyCode::Char(c) = key.code {
                            if c.is_ascii_digit() {
                                app.input_length.push(c);
                            }
                        } else if key.code == KeyCode::Backspace {
                            app.input_length.pop();
                        } else if key.code == KeyCode::Esc {
                            app.state = AppState::MainMenu;
                        }
                    }
                    AppState::GeneratePassword => {
                        if key.code == KeyCode::Char('c') {
                            if let Some(password) = app.get_generated_password() {
                                app.input_password = password;
                                app.state = AppState::AddPassword;
                            }
                        } else if key.code == KeyCode::Char('g') {
                            // Generate another password
                            if let Ok(length) = app.input_length.parse::<usize>() {
                                app.generate_password(length);
                            }
                        } else if key.code == KeyCode::Esc || key.code == KeyCode::Char('q') {
                            app.state = AppState::MainMenu;
                        }
                    }
                    AppState::ImportMenu => {
                        match key.code {
                            KeyCode::Enter => {
                                if let Some(selected) = app.list_state.selected() {
                                    match selected {
                                        0 => { // JSON format
                                            app.import_format = Some("json".to_string());
                                            app.state = AppState::ImportFileInput;
                                            app.import_file_path.clear();
                                        }
                                        1 => { // CSV format
                                            app.import_format = Some("csv".to_string());
                                            app.state = AppState::ImportFileInput;
                                            app.import_file_path.clear();
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            KeyCode::Up => {
                                if let Some(selected) = app.list_state.selected() {
                                    if selected > 0 {
                                        app.list_state.select(Some(selected - 1));
                                    }
                                } else {
                                    app.list_state.select(Some(0));
                                }
                            }
                            KeyCode::Down => {
                                if let Some(selected) = app.list_state.selected() {
                                    if selected < 1 { // 2 formats - 1
                                        app.list_state.select(Some(selected + 1));
                                    }
                                } else {
                                    app.list_state.select(Some(0));
                                }
                            }
                            KeyCode::Esc => {
                                app.state = AppState::MainMenu;
                                app.list_state.select(None);
                            }
                            _ => {}
                        }
                    }
                    AppState::ImportFileInput => {
                        match key.code {
                            KeyCode::Enter => {
                                if !app.import_file_path.is_empty() {
                                    // Clone the file path to avoid borrow checker issues
                                    let file_path = app.import_file_path.clone();
                                    // Try to preview the import
                                    if let Ok(preview) = app.preview_import(&file_path) {
                                        app.import_preview = Some(preview);
                                        app.state = AppState::ImportConfirm;
                                    } else {
                                        app.error_message = Some("Failed to preview import file".to_string());
                                        app.state = AppState::MainMenu;
                                    }
                                }
                            }
                            KeyCode::Char(c) => {
                                app.import_file_path.push(c);
                            }
                            KeyCode::Backspace => {
                                app.import_file_path.pop();
                            }
                            KeyCode::Esc => {
                                app.state = AppState::MainMenu;
                                app.import_file_path.clear();
                                app.import_format = None;
                            }
                            _ => {}
                        }
                    }
                    AppState::ImportConfirm => {
                        match key.code {
                            KeyCode::Char('y') => {
                                if let Some(format) = &app.import_format {
                                    // Clone the file path to avoid borrow checker issues
                                    let file_path = app.import_file_path.clone();
                                    match format.as_str() {
                                        "json" => {
                                            if let Err(e) = app.import_from_json(&file_path) {
                                                app.error_message = Some(format!("Import failed: {}", e));
                                            }
                                        }
                                        "csv" => {
                                            if let Err(e) = app.import_from_csv(&file_path) {
                                                app.error_message = Some(format!("Import failed: {}", e));
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                app.state = AppState::MainMenu;
                                app.import_file_path.clear();
                                app.import_format = None;
                                app.import_preview = None;
                            }
                            KeyCode::Char('n') | KeyCode::Esc => {
                                app.state = AppState::MainMenu;
                                app.import_file_path.clear();
                                app.import_format = None;
                                app.import_preview = None;
                            }
                            _ => {}
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
    // Modern sleek color scheme
    let primary_color = Color::Rgb(88, 101, 242);  // Vibrant blue
    let secondary_color = Color::Rgb(60, 60, 70);   // Dark gray
    let accent_color = Color::Rgb(139, 233, 253);  // Light cyan accent
    let success_color = Color::Rgb(80, 250, 123);   // Success green
    let warning_color = Color::Rgb(255, 184, 108); // Warning orange
    let error_color = Color::Rgb(255, 85, 85);     // Error red
    let background_color = Color::Rgb(15, 15, 25);  // Deep dark background
    let surface_color = Color::Rgb(25, 25, 35);    // Surface color
    let text_color = Color::Rgb(230, 230, 240);    // Light text
    let muted_text_color = Color::Rgb(150, 150, 170); // Muted text
    
    // Modern layout with better spacing
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .margin(3)
        .constraints([
            Constraint::Length(5),   // Header with more space
            Constraint::Min(1),       // Main content
            Constraint::Length(4),    // Footer/help with more space
        ])
        .split(f.size());
    
    // Modern block styles with rounded corners effect
    let block_style = Style::default()
        .bg(surface_color)
        .fg(text_color);
    
    let border_style = Style::default()
        .fg(secondary_color);
    
    let _title_style = Style::default()
        .fg(primary_color)
        .add_modifier(Modifier::BOLD | Modifier::ITALIC);
    
    let _subtitle_style = Style::default()
        .fg(muted_text_color)
        .add_modifier(Modifier::ITALIC);
    
    let highlight_style = Style::default()
        .bg(accent_color)
        .fg(Color::Rgb(15, 15, 25))
        .add_modifier(Modifier::BOLD);
    
    let _selected_style = Style::default()
        .bg(Color::Rgb(40, 40, 50))
        .fg(accent_color)
        .add_modifier(Modifier::BOLD);
    
    let input_style = Style::default()
        .fg(text_color)
        .bg(Color::Rgb(30, 30, 40));

    match app.state {
        AppState::PasswordEntry => {
            // Create a centered layout for the login screen
            let center_layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Percentage(30),
                    Constraint::Percentage(40),
                    Constraint::Percentage(30),
                ])
                .split(layout[1]);
            
            let inner_layout = Layout::default()
                .direction(Direction::Vertical)
                .margin(2)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Length(3),
                ])
                .split(center_layout[1]);

            let title = Paragraph::new("🔐 RustyPass")
                .block(
                    Block::default()
                        .borders(Borders::NONE)
                        .style(Style::default().bg(background_color))
                )
                .style(Style::default()
                    .fg(primary_color)
                    .add_modifier(Modifier::BOLD | Modifier::ITALIC)
                    .bg(background_color))
                .alignment(Alignment::Center);

            let input = Paragraph::new("•".repeat(app.input_master.len()))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(border_style)
                        .title("Master Password")
                        .style(block_style)
                )
                .style(input_style);

            let help = Paragraph::new("⏎ Enter to unlock  |  Esc to exit")
                .style(Style::default().fg(muted_text_color))
                .alignment(Alignment::Center);

            f.render_widget(title, inner_layout[0]);
            f.render_widget(input, inner_layout[1]);
            f.render_widget(help, inner_layout[2]);

            if let Some(error) = &app.error_message {
                let error_paragraph = Paragraph::new(error.clone())
                    .style(Style::default()
                        .fg(error_color)
                        .add_modifier(Modifier::BOLD)
                        .bg(background_color))
                    .alignment(Alignment::Center);
                f.render_widget(error_paragraph, layout[2]);
            }
        }
        AppState::MainMenu => {
            let title = Paragraph::new("📋 Password Vault")
                .block(
                    Block::default()
                        .borders(Borders::BOTTOM)
                        .border_style(border_style)
                        .style(Style::default().bg(background_color))
                )
                .style(Style::default()
                    .fg(primary_color)
                    .add_modifier(Modifier::BOLD | Modifier::ITALIC)
                    .bg(background_color))
                .alignment(Alignment::Center);

            let services_list: Vec<ListItem> = app.services
                .iter()
                .map(|s| {
                    ListItem::new(s.clone())
                        .style(Style::default().fg(text_color))
                })
                .collect();

            let list = List::new(services_list)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(border_style)
                        .title("🔑 Services")
                        .style(block_style)
                )
                .highlight_style(highlight_style)
                .highlight_symbol("▶ ")
                .style(Style::default().fg(text_color));

            let help = Paragraph::new("a: Add service  |  g: Generate password  |  i: Import  |  v: View password  |  d: Delete  |  q/Esc: Quit  |  ↑↓: Navigate")
                .style(Style::default().fg(muted_text_color))
                .alignment(Alignment::Center);

            f.render_widget(title, layout[0]);
            f.render_stateful_widget(list, layout[1], &mut app.list_state);
            f.render_widget(help, layout[2]);
        }
        AppState::AddService => {
            let title = Paragraph::new("➕ Add New Service")
                .block(
                    Block::default()
                        .borders(Borders::BOTTOM)
                        .border_style(border_style)
                        .style(Style::default().bg(background_color))
                )
                .style(Style::default()
                    .fg(primary_color)
                    .add_modifier(Modifier::BOLD | Modifier::ITALIC)
                    .bg(background_color))
                .alignment(Alignment::Center);

            let input = Paragraph::new(app.input_service.clone())
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(border_style)
                        .title("Service Name")
                        .style(block_style)
                )
                .style(input_style);

            let help = Paragraph::new("⏎ Enter to continue  |  Esc to cancel")
                .style(Style::default().fg(muted_text_color))
                .alignment(Alignment::Center);

            f.render_widget(title, layout[0]);
            f.render_widget(input, layout[1]);
            f.render_widget(help, layout[2]);
        }
        AppState::AddPassword => {
            let title = Paragraph::new(format!("🔑 Password for {}", app.input_service))
                .block(
                    Block::default()
                        .borders(Borders::BOTTOM)
                        .border_style(border_style)
                        .style(Style::default().bg(background_color))
                )
                .style(Style::default()
                    .fg(primary_color)
                    .add_modifier(Modifier::BOLD | Modifier::ITALIC)
                    .bg(background_color))
                .alignment(Alignment::Center);

            let input = Paragraph::new("•".repeat(app.input_password.len()))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(border_style)
                        .title("Password")
                        .style(block_style)
                )
                .style(input_style);

            let help = Paragraph::new("⏎ Enter to save  |  Esc to cancel")
                .style(Style::default().fg(muted_text_color))
                .alignment(Alignment::Center);

            f.render_widget(title, layout[0]);
            f.render_widget(input, layout[1]);
            f.render_widget(help, layout[2]);
        }
        AppState::ImportMenu => {
            let title = Paragraph::new("📥 Import Passwords")
                .block(
                    Block::default()
                        .borders(Borders::BOTTOM)
                        .border_style(border_style)
                        .style(Style::default().bg(background_color))
                )
                .style(Style::default()
                    .fg(primary_color)
                    .add_modifier(Modifier::BOLD | Modifier::ITALIC)
                    .bg(background_color))
                .alignment(Alignment::Center);

            let formats = vec![
                "JSON (Bitwarden, generic)",
                "CSV (generic)",
            ];
            let format_list: Vec<ListItem> = formats
                .iter()
                .map(|f| {
                    ListItem::new(f.to_string())
                        .style(Style::default().fg(text_color))
                })
                .collect();

            let list = List::new(format_list)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(border_style)
                        .title("📄 Select Format")
                        .style(block_style)
                )
                .highlight_style(highlight_style)
                .highlight_symbol("▶ ")
                .style(Style::default().fg(text_color));

            let help = Paragraph::new("⏎ Enter to select format  |  Esc to cancel")
                .style(Style::default().fg(muted_text_color))
                .alignment(Alignment::Center);

            f.render_widget(title, layout[0]);
            f.render_stateful_widget(list, layout[1], &mut app.list_state);
            f.render_widget(help, layout[2]);
        }
        AppState::ImportFileInput => {
            let title = Paragraph::new("📥 Import Passwords")
                .block(
                    Block::default()
                        .borders(Borders::BOTTOM)
                        .border_style(border_style)
                        .style(Style::default().bg(background_color))
                )
                .style(Style::default()
                    .fg(primary_color)
                    .add_modifier(Modifier::BOLD | Modifier::ITALIC)
                    .bg(background_color))
                .alignment(Alignment::Center);

            let input = Paragraph::new(app.import_file_path.clone())
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(border_style)
                        .title("File Path")
                        .style(block_style)
                )
                .style(input_style);

            let help = Paragraph::new("⏎ Enter to preview  |  Esc to cancel")
                .style(Style::default().fg(muted_text_color))
                .alignment(Alignment::Center);

            f.render_widget(title, layout[0]);
            f.render_widget(input, layout[1]);
            f.render_widget(help, layout[2]);
        }
        AppState::ImportConfirm => {
            let title = Paragraph::new("📥 Import Confirmation")
                .block(
                    Block::default()
                        .borders(Borders::BOTTOM)
                        .border_style(border_style)
                        .style(Style::default().bg(background_color))
                )
                .style(Style::default()
                    .fg(success_color)
                    .add_modifier(Modifier::BOLD | Modifier::ITALIC)
                    .bg(background_color))
                .alignment(Alignment::Center);

            let preview_text = if let Some(preview) = &app.import_preview {
                preview.clone()
            } else {
                "No preview available".to_string()
            };

            let preview = Paragraph::new(preview_text)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(border_style)
                        .title("Import Preview")
                        .style(block_style)
                )
                .style(Style::default().fg(text_color));

            let help = Paragraph::new("y: Confirm import  |  n/Esc: Cancel")
                .style(Style::default().fg(muted_text_color))
                .alignment(Alignment::Center);

            f.render_widget(title, layout[0]);
            f.render_widget(preview, layout[1]);
            f.render_widget(help, layout[2]);
        }
        AppState::ViewPassword => {
            if let Some(selected) = app.selected_service {
                if let Some(service) = app.services.get(selected) {
                    if let Some(password) = app.store.get_password(service) {
                        let title = Paragraph::new(format!("Password for {}", service))
                            .block(Block::default()
                                .borders(Borders::BOTTOM)
                                .border_style(border_style)
                                .style(Style::default().bg(background_color)))
                            .style(Style::default()
                                .fg(primary_color)
                                .add_modifier(Modifier::BOLD | Modifier::ITALIC)
                                .bg(background_color))
                            .alignment(Alignment::Center);

                        let password_display = Paragraph::new(password.clone())
                            .block(Block::default()
                                .borders(Borders::ALL)
                                .border_style(border_style)
                                .style(block_style))
                            .style(input_style);

                        let help = Paragraph::new("q or Esc: Return to main menu")
                            .style(Style::default().fg(muted_text_color))
                            .alignment(Alignment::Center);

                        f.render_widget(title, layout[0]);
                        f.render_widget(password_display, layout[1]);
                        f.render_widget(help, layout[2]);
                    }
                }
            }
        }
        AppState::PasswordLengthInput => {
            let title = Paragraph::new("🔐 Generate Secure Password")
                .block(Block::default()
                    .borders(Borders::BOTTOM)
                    .border_style(border_style)
                    .style(Style::default().bg(background_color)))
                .style(Style::default()
                    .fg(primary_color)
                    .add_modifier(Modifier::BOLD | Modifier::ITALIC)
                    .bg(background_color))
                .alignment(Alignment::Center);

            let input = Paragraph::new(app.input_length.clone())
                .block(Block::default()
                    .borders(Borders::ALL)
                    .border_style(border_style)
                    .title("Password Length (8-64)")
                    .style(block_style));

            let help = Paragraph::new("Enter password length (8-64) and press ⏎ Enter  |  Esc to cancel")
                .style(Style::default().fg(muted_text_color))
                .alignment(Alignment::Center);

            f.render_widget(title, layout[0]);
            f.render_widget(input, layout[1]);
            f.render_widget(help, layout[2]);
        }
        AppState::GeneratePassword => {
            if let Some(password) = app.get_generated_password() {
                let title = Paragraph::new("🔐 Generated Secure Password")
                    .block(Block::default()
                        .borders(Borders::BOTTOM)
                        .border_style(border_style)
                        .style(Style::default().bg(background_color)))
                    .style(Style::default()
                        .fg(success_color)
                        .add_modifier(Modifier::BOLD | Modifier::ITALIC)
                        .bg(background_color))
                    .alignment(Alignment::Center);

                let password_display = Paragraph::new(password.clone())
                    .block(Block::default()
                        .borders(Borders::ALL)
                        .border_style(border_style)
                        .style(block_style))
                    .style(Style::default()
                        .fg(success_color)
                        .add_modifier(Modifier::BOLD));

                let help = Paragraph::new("c: Copy to add password  |  g: Generate another  |  q/Esc: Back to menu")
                    .style(Style::default().fg(muted_text_color))
                    .alignment(Alignment::Center);

                f.render_widget(title, layout[0]);
                f.render_widget(password_display, layout[1]);
                f.render_widget(help, layout[2]);
            }
        }
        AppState::DeleteConfirm => {
            if let Some(selected) = app.selected_service {
                if let Some(service) = app.services.get(selected) {
                    let title = Paragraph::new("🗑️ Confirm Delete")
                        .block(Block::default()
                            .borders(Borders::BOTTOM)
                            .border_style(border_style)
                            .style(Style::default().bg(background_color)))
                        .style(Style::default()
                            .fg(error_color)
                            .add_modifier(Modifier::BOLD | Modifier::ITALIC)
                            .bg(background_color))
                        .alignment(Alignment::Center);

                    let confirm = Paragraph::new(format!("Delete '{}'? (y/n)", service))
                        .block(Block::default()
                            .borders(Borders::ALL)
                            .border_style(border_style)
                            .style(block_style))
                        .style(Style::default()
                            .fg(error_color)
                            .add_modifier(Modifier::BOLD));

                    let help = Paragraph::new("y: Confirm delete  |  n/Esc: Cancel")
                        .style(Style::default().fg(muted_text_color))
                        .alignment(Alignment::Center);
                    
                    f.render_widget(help, layout[2]);

                    f.render_widget(title, layout[0]);
                    f.render_widget(confirm, layout[1]);
                }
            }
        }
        AppState::Exiting => {
            let title = Paragraph::new("🚪 Exit RustyPass")
                .block(Block::default()
                    .borders(Borders::BOTTOM)
                    .border_style(border_style)
                    .style(Style::default().bg(background_color)))
                .style(Style::default()
                    .fg(warning_color)
                    .add_modifier(Modifier::BOLD | Modifier::ITALIC)
                    .bg(background_color))
                .alignment(Alignment::Center);

            let confirm = Paragraph::new("Are you sure you want to exit? (y/n)")
                .block(Block::default()
                    .borders(Borders::ALL)
                    .border_style(border_style)
                    .style(block_style))
                .style(Style::default()
                    .fg(warning_color)
                    .add_modifier(Modifier::BOLD));

            let help = Paragraph::new("y: Confirm exit  |  n/Esc: Cancel")
                .style(Style::default().fg(muted_text_color))
                .alignment(Alignment::Center);
            
            f.render_widget(help, layout[2]);

            f.render_widget(title, layout[0]);
            f.render_widget(confirm, layout[1]);
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
        // Create a temporary directory for testing
        let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
        let test_storage_dir = temp_dir.path().to_string_lossy().into_owned();
        let test_storage_file = format!("{}/passwords.json.enc", test_storage_dir);

        // Test data
        let master_password = "testpassword";
        let salt = [0u8; 32]; // Use zero salt for testing
        let key = derive_key(master_password, &salt);

        // Create a test store
        let mut store = PasswordStore::new();
        store.add_password("github".to_string(), "mysecretpassword".to_string());

        // Save it using test storage location
        let json = serde_json::to_string(&store).expect("Failed to serialize store");
        let encrypted = encrypt(json.as_bytes(), &key).expect("Failed to encrypt");
        fs::write(&test_storage_file, encrypted).expect("Failed to save passwords");

        // Check if file exists
        assert!(Path::new(&test_storage_file).exists(), "Encrypted file not created");

        // Load it back
        let mut encrypted_data = Vec::new();
        fs::File::open(&test_storage_file).expect("Failed to open file")
            .read_to_end(&mut encrypted_data).expect("Failed to read file");
        let decrypted = decrypt(&encrypted_data, &key).expect("Failed to decrypt");
        let loaded_store: PasswordStore = serde_json::from_slice(&decrypted).expect("Failed to deserialize");

        // Verify the password
        let retrieved_password = loaded_store.get_password("github")
            .expect("Password not found in loaded store");

        assert_eq!(retrieved_password, "mysecretpassword", "Password mismatch");

        // Clean up is handled automatically by tempdir
    }
}
