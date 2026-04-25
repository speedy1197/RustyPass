use anyhow::Result;
use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Gauge, List, ListItem, Paragraph, Wrap},
};


use crate::app::{App, AppState};
use crate::password_analysis::{entropy_rating, StrengthLevel};

/// Set up the terminal for TUI
pub fn setup_terminal() -> Result<Terminal<impl Backend>> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

/// Restore the terminal to its original state
pub fn restore_terminal() -> Result<()> {
    disable_raw_mode()?;
    execute!(std::io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}

/// Modern color palette for RustyPass
struct Colors {
    primary: Color,
    secondary: Color,
    accent: Color,
    success: Color,
    warning: Color,
    error: Color,
    background: Color,
    surface: Color,
    text: Color,
    muted: Color,
}

impl Colors {
    fn new() -> Self {
        Self {
            primary: Color::Rgb(88, 101, 242),      // Vibrant blue
            secondary: Color::Rgb(60, 60, 70),     // Dark gray
            accent: Color::Rgb(139, 233, 253),     // Light cyan
            success: Color::Rgb(80, 250, 123),     // Success green
            warning: Color::Rgb(255, 184, 108),    // Warning orange
            error: Color::Rgb(255, 85, 85),       // Error red
            background: Color::Rgb(15, 15, 25),   // Deep dark background
            surface: Color::Rgb(25, 25, 35),      // Surface color
            text: Color::Rgb(230, 230, 240),      // Light text
            muted: Color::Rgb(150, 150, 170),      // Muted text
        }
    }
}

/// Create a styled block with consistent theming
fn styled_block(title: &str, colors: &Colors) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(colors.secondary))
        .style(Style::default().bg(colors.surface).fg(colors.text))
        .title(
            Span::styled(
                format!(" {} ", title),
                Style::default()
                    .fg(colors.primary)
                    .add_modifier(Modifier::BOLD),
            ),
        )
}

/// Create a gradient header
fn gradient_header(text: &str, colors: &Colors) -> Paragraph<'static> {
    let gradient_spans = text.chars().enumerate().map(|(i, c)| {
        let ratio = i as f32 / text.len() as f32;
        let r = 88 + ((139 - 88) as f32 * ratio) as u8;
        let g = 101 + ((233 - 101) as f32 * ratio) as u8;
        let b = 242 + ((253 - 242) as f32 * ratio) as u8;
        Span::styled(
            c.to_string(),
            Style::default().fg(Color::Rgb(r, g, b)),
        )
    }).collect::<Vec<_>>();

    Paragraph::new(Line::from(gradient_spans))
        .alignment(Alignment::Center)
        .style(Style::default().bg(colors.background))
}

/// Create a styled list item
fn styled_list_item<'a>(text: &'a str, icon: &'a str, is_selected: bool, colors: &Colors) -> ListItem<'a> {
    let style = if is_selected {
        Style::default()
            .fg(Color::Black)
            .bg(colors.accent)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(colors.text)
            .bg(colors.surface)
    };

    ListItem::new(
        Line::from(vec![
            Span::styled(format!("{}  ", icon), style),
            Span::styled(text, style),
        ]),
    )
}

/// Create footer help text
fn footer_help<'a>(help_text: &'a str, colors: &Colors) -> Paragraph<'a> {
    Paragraph::new(help_text)
        .style(Style::default().fg(colors.muted))
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true })
}

/// Render the UI
pub fn ui(f: &mut Frame, app: &mut App) {
    let colors = Colors::new();
    let rects = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([
            Constraint::Length(3),   // Header
            Constraint::Length(3),   // Title/Status
            Constraint::Min(10),     // Main content
            Constraint::Length(3),   // Footer
        ])
        .split(f.size());

    // Clear the entire area first
    f.render_widget(Clear, f.size());

    // Render header with gradient
    f.render_widget(
        gradient_header("🔐 RustyPass - Secure Password Manager", &colors),
        rects[0],
    );

    // Render main content based on app state
    match app.state {
        AppState::PasswordEntry => {
            render_password_entry(f, app, &rects, &colors);
        }
        AppState::MainMenu => {
            render_main_menu(f, app, &rects, &colors);
        }
        AppState::ServicesMenu => {
            render_services_menu(f, app, &rects, &colors);
        }
        AppState::AddService => {
            render_add_service(f, app, &rects, &colors);
        }
        AppState::AddPassword => {
            render_add_password(f, app, &rects, &colors);
        }
        AppState::ViewPassword => {
            render_view_password(f, app, &rects, &colors);
        }
        AppState::DeleteConfirm => {
            render_delete_confirm(f, app, &rects, &colors);
        }
        AppState::GeneratePassword => {
            render_generate_password(f, app, &rects, &colors);
        }
        AppState::PasswordLengthInput => {
            render_password_length_input(f, app, &rects, &colors);
        }
        AppState::ImportMenu => {
            render_import_menu(f, app, &rects, &colors);
        }
        AppState::ImportFileInput => {
            render_import_file_input(f, app, &rects, &colors);
        }
        AppState::ImportConfirm => {
            render_import_confirm(f, app, &rects, &colors);
        }
        AppState::SettingsMenu => {
            render_settings_menu(f, app, &rects, &colors);
        }
        AppState::SettingsSecurity => {
            render_settings_security(f, app, &rects, &colors);
        }
        AppState::SettingsPassword => {
            render_settings_password(f, app, &rects, &colors);
        }
        AppState::SettingsAdvanced => {
            render_settings_advanced(f, app, &rects, &colors);
        }
        AppState::SettingsHelp => {
            render_settings_help(f, app, &rects, &colors);
        }
        AppState::CharacterSetsMenu => {
            render_character_sets_menu(f, app, &rects, &colors);
        }
        AppState::ChangeMasterPassword | AppState::SessionTimeoutInput | 
        AppState::FailedAttemptsInput | AppState::ClipboardClearInput | 
        AppState::KeyRotationInput | AppState::DefaultPasswordLengthInput | 
        AppState::PasswordExpiryInput | AppState::MinEntropyInput | 
        AppState::StorageLocationInput => {
            render_input_prompt(f, app, &rects, &colors);
        }
        AppState::FactoryResetConfirm => {
            render_factory_reset_confirm(f, app, &rects, &colors);
        }
        AppState::Exiting => {
            render_exit_confirm(f, app, &rects, &colors);
        }
    }

    // Render footer help
    let help_text = match app.state {
        AppState::PasswordEntry => "Type your master password and press Enter | Esc to exit",
        AppState::MainMenu => "Use menu options above | Press q/Esc to exit",
        AppState::ServicesMenu => "↑↓ Navigate | Enter View | v View | d Delete | q/Esc Back",
        AppState::AddService => "Type service name and press Enter | Esc Cancel",
        AppState::AddPassword => "Type password and press Enter | g Generate Password | Esc Cancel | Strength/Entropy shown below",
        AppState::ViewPassword => "Press any key to return to menu",
        AppState::DeleteConfirm => "y Confirm | n/Esc Cancel",
        AppState::GeneratePassword => "c Copy | g Regenerate | q/Esc Back",
        AppState::PasswordLengthInput => "Enter length (8-64) and press Enter | Esc Cancel",
        AppState::ImportMenu => "Select import format | Esc Cancel",
        AppState::ImportFileInput => "Enter file path and press Enter | Esc Cancel",
        AppState::ImportConfirm => "y Confirm import | n/Esc Cancel",
        AppState::SettingsMenu => "Select setting | q/Esc Back",
        AppState::SettingsSecurity => "Select security option | q/Esc Back",
        AppState::SettingsPassword => "Select password option | q/Esc Back",
        AppState::CharacterSetsMenu => "Toggle character sets | q/Esc Back",
        AppState::SettingsAdvanced => "Select advanced option | q/Esc Back",
        AppState::SettingsHelp => "Press q/Esc to go back",
        AppState::ChangeMasterPassword => "Enter new master password | Esc Cancel",
        AppState::SessionTimeoutInput => "Enter timeout minutes (5-120) or 0 for never | Esc Cancel",
        AppState::FailedAttemptsInput => "Enter max failed attempts (3-10) | Esc Cancel",
        AppState::ClipboardClearInput => "Enter clipboard clear seconds (5-60) | Esc Cancel",
        AppState::KeyRotationInput => "Enter key rotation days (30-730) | Esc Cancel",
        AppState::DefaultPasswordLengthInput => "Enter default password length (8-64) | Esc Cancel",
        AppState::PasswordExpiryInput => "Enter password expiry days (30-730) or 0 for never | Esc Cancel",
        AppState::MinEntropyInput => "Enter minimum entropy bits (40-128) | Esc Cancel",
        AppState::StorageLocationInput => "Enter storage location path | Esc Cancel",
        AppState::FactoryResetConfirm => "Press y to confirm factory reset | n to cancel",
        AppState::Exiting => "y Confirm exit | n/Esc Cancel",
    };

    f.render_widget(footer_help(help_text, &colors), rects[3]);

    // Render error message if present
    if let Some(error) = &app.error_message {
        let error_paragraph = Paragraph::new(error.clone())
            .style(Style::default().fg(colors.error).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::NONE)
                    .style(Style::default().bg(colors.background)),
            );
        f.render_widget(error_paragraph, rects[2]);
    }
}

/// Render password entry screen
fn render_password_entry(f: &mut Frame, app: &mut App, rects: &[Rect], colors: &Colors) {
    let input_block = styled_block("🔑 Master Password", colors);
    let input_paragraph = Paragraph::new("•".repeat(app.input_master.len()))
        .style(Style::default().fg(colors.text).bg(colors.surface))
        .block(input_block);

    f.render_widget(input_paragraph, rects[2]);
}

/// Render main menu
fn render_main_menu(f: &mut Frame, app: &mut App, rects: &[Rect], colors: &Colors) {
    // Title
    let title = Paragraph::new("📋 Main Menu")
        .style(Style::default().fg(colors.primary).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors.secondary))
                .style(Style::default().bg(colors.background)),
        );
    f.render_widget(title, rects[1]);

    // Menu items
    let items = vec![
        styled_list_item("Add New Password", "➕", app.list_state.selected() == Some(0), colors),
        styled_list_item("Import Passwords", "📥", app.list_state.selected() == Some(1), colors),
        styled_list_item("Services", "🔑", app.list_state.selected() == Some(2), colors),
        styled_list_item("Settings", "⚙️", app.list_state.selected() == Some(3), colors),
        styled_list_item("Exit", "🚪", app.list_state.selected() == Some(4), colors),
    ];

    let list = List::new(items)
        .block(styled_block("📋 Options", colors))
        .highlight_symbol("▶ ")
        .highlight_style(
            Style::default()
                .bg(colors.accent)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        );

    f.render_stateful_widget(list, rects[2], &mut app.list_state);
}

/// Render services menu
fn render_services_menu(f: &mut Frame, app: &mut App, rects: &[Rect], colors: &Colors) {
    let title = Paragraph::new("🔑 Services")
        .style(Style::default().fg(colors.primary).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors.secondary))
                .style(Style::default().bg(colors.background)),
        );
    f.render_widget(title, rects[1]);

    if app.services.is_empty() {
        let empty_block = styled_block("No Services", colors);
        let empty_paragraph = Paragraph::new("No services found. Add a new service to get started.")
            .style(Style::default().fg(colors.muted).bg(colors.surface))
            .block(empty_block)
            .alignment(Alignment::Center);
        f.render_widget(empty_paragraph, rects[2]);
    } else {
        let services_items: Vec<ListItem> = app
            .services
            .iter()
            .enumerate()
            .map(|(i, service)| {
                let is_selected = app.services_list_state.selected() == Some(i);
                styled_list_item(service, "🔑", is_selected, colors)
            })
            .collect();

        let services_list = List::new(services_items)
            .block(styled_block("Your Services", colors))
            .highlight_symbol("▶ ")
            .highlight_style(
                Style::default()
                    .bg(colors.accent)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            );

        f.render_stateful_widget(services_list, rects[2], &mut app.services_list_state);
    }
}

/// Render add service screen
fn render_add_service(f: &mut Frame, app: &mut App, rects: &[Rect], colors: &Colors) {
    let title = Paragraph::new("➕ Add New Service")
        .style(Style::default().fg(colors.primary).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors.secondary))
                .style(Style::default().bg(colors.background)),
        );

    let input_block = styled_block("Service Name", colors);
    let input_paragraph = Paragraph::new(app.input_service.clone())
        .style(Style::default().fg(colors.text).bg(colors.surface))
        .block(input_block);

    f.render_widget(title, rects[1]);
    f.render_widget(input_paragraph, rects[2]);
}



/// Render compact strength meter
fn render_compact_strength_meter(f: &mut Frame, strength: &StrengthLevel, rect: Rect, colors: &Colors) {
    let (color, label) = match strength {
        StrengthLevel::VeryWeak => (colors.error, "Very Weak"),
        StrengthLevel::Weak => (colors.warning, "Weak"),
        StrengthLevel::Moderate => (colors.accent, "Moderate"),
        StrengthLevel::Strong => (colors.success, "Strong"),
        StrengthLevel::VeryStrong => (colors.success, "Very Strong"),
    };

    let gauge = Gauge::default()
        .block(Block::default().title("Strength").borders(Borders::NONE))
        .gauge_style(Style::default().fg(color).bg(colors.secondary))
        .percent(match strength {
            StrengthLevel::VeryWeak => 20,
            StrengthLevel::Weak => 40,
            StrengthLevel::Moderate => 60,
            StrengthLevel::Strong => 80,
            StrengthLevel::VeryStrong => 100,
        })
        .label(label);

    f.render_widget(gauge, rect);
}

/// Render compact entropy meter
fn render_compact_entropy_meter(f: &mut Frame, bits: f64, rect: Rect, colors: &Colors) {
    let entropy_color = if bits < 28.0 {
        colors.error
    } else if bits < 36.0 {
        colors.warning
    } else if bits < 60.0 {
        colors.accent
    } else if bits < 80.0 {
        colors.success
    } else {
        colors.success
    };

    let gauge = Gauge::default()
        .block(Block::default().title(format!("Entropy: {:.0} bits", bits)).borders(Borders::NONE))
        .gauge_style(Style::default().fg(entropy_color).bg(colors.secondary))
        .percent((bits / 5.0).min(100.0) as u16)
        .label(entropy_rating(bits));

    f.render_widget(gauge, rect);
}



/// Render add password screen
fn render_add_password(f: &mut Frame, app: &mut App, rects: &[Rect], colors: &Colors) {
    let title = Paragraph::new(format!("🔑 Password for {}", app.input_service))
        .style(Style::default().fg(colors.primary).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors.secondary))
                .style(Style::default().bg(colors.background)),
        );

    let input_block = styled_block("Password", colors);
    let input_paragraph = Paragraph::new("•".repeat(app.input_password.len()))
        .style(Style::default().fg(colors.text).bg(colors.surface))
        .block(input_block);

    f.render_widget(title, rects[1]);
    f.render_widget(input_paragraph, rects[2]);

    // Render password strength and entropy meters if available
    if let (Some(strength), Some(entropy)) = (&app.password_strength, &app.password_entropy) {
        let meter_area = Rect::new(
            rects[2].x,
            rects[2].y + 3, // Position below the password input
            rects[2].width,
            3 // Smaller height for compact display
        );

        let meter_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(meter_area);

        // Create compact meters
        render_compact_strength_meter(f, strength, meter_layout[0], colors);
        render_compact_entropy_meter(f, *entropy, meter_layout[1], colors);
    }
}

/// Render view password screen
fn render_view_password(f: &mut Frame, app: &mut App, rects: &[Rect], colors: &Colors) {
    if let Some(selected) = app.selected_service {
        if let Some(service) = app.services.get(selected) {
            if let Some(password) = app.store.get_password(service) {
                let title = Paragraph::new(format!("🔑 Password for {}", service))
                    .style(Style::default().fg(colors.primary).add_modifier(Modifier::BOLD))
                    .alignment(Alignment::Center)
                    .block(
                        Block::default()
                            .borders(Borders::BOTTOM)
                            .border_style(Style::default().fg(colors.secondary))
                            .style(Style::default().bg(colors.background)),
                    );

                let password_block = styled_block("Password", colors);
                let password_paragraph = Paragraph::new(password.clone())
                    .style(Style::default().fg(colors.success).bg(colors.surface))
                    .block(password_block);

                f.render_widget(title, rects[1]);
                f.render_widget(password_paragraph, rects[2]);
            }
        }
    }
}

/// Render delete confirmation
fn render_delete_confirm(f: &mut Frame, app: &mut App, rects: &[Rect], colors: &Colors) {
    if let Some(selected) = app.selected_service {
        if let Some(service) = app.services.get(selected) {
            let title = Paragraph::new("🗑️ Confirm Delete")
                .style(Style::default().fg(colors.error).add_modifier(Modifier::BOLD))
                .alignment(Alignment::Center)
                .block(
                    Block::default()
                        .borders(Borders::BOTTOM)
                        .border_style(Style::default().fg(colors.secondary))
                        .style(Style::default().bg(colors.background)),
                );

            let confirm_block = styled_block("Confirmation", colors);
            let confirm_paragraph = Paragraph::new(format!("Delete '{}'? (y/n)", service))
                .style(Style::default().fg(colors.error).bg(colors.surface))
                .block(confirm_block);

            f.render_widget(title, rects[1]);
            f.render_widget(confirm_paragraph, rects[2]);
        }
    }
}

/// Render generate password screen
fn render_generate_password(f: &mut Frame, app: &mut App, rects: &[Rect], colors: &Colors) {
    if let Some(password) = &app.generated_password {
        let title = Paragraph::new("🔐 Generated Secure Password")
            .style(Style::default().fg(colors.success).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::BOTTOM)
                    .border_style(Style::default().fg(colors.secondary))
                    .style(Style::default().bg(colors.background)),
            );

        let password_block = styled_block("Generated Password", colors);
        let password_paragraph = Paragraph::new(password.clone())
            .style(Style::default().fg(colors.success).bg(colors.surface).add_modifier(Modifier::BOLD))
            .block(password_block);

        f.render_widget(title, rects[1]);
        f.render_widget(password_paragraph, rects[2]);
    }
}

/// Render password length input
fn render_password_length_input(f: &mut Frame, app: &mut App, rects: &[Rect], colors: &Colors) {
    let title = Paragraph::new("🔐 Generate Secure Password")
        .style(Style::default().fg(colors.primary).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors.secondary))
                .style(Style::default().bg(colors.background)),
        );

    let input_block = styled_block("Password Length (8-64)", colors);
    let input_paragraph = Paragraph::new(app.input_length.clone())
        .style(Style::default().fg(colors.text).bg(colors.surface))
        .block(input_block);

    f.render_widget(title, rects[1]);
    f.render_widget(input_paragraph, rects[2]);
}

/// Render import menu
fn render_import_menu(f: &mut Frame, app: &mut App, rects: &[Rect], colors: &Colors) {
    let title = Paragraph::new("📥 Import Passwords")
        .style(Style::default().fg(colors.primary).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors.secondary))
                .style(Style::default().bg(colors.background)),
        );

    let items = vec![
        styled_list_item("JSON (Bitwarden, generic)", "📄", app.list_state.selected() == Some(0), colors),
        styled_list_item("CSV (generic)", "📊", app.list_state.selected() == Some(1), colors),
    ];

    let list = List::new(items)
        .block(styled_block("📄 Select Format", colors))
        .highlight_symbol("▶ ")
        .highlight_style(
            Style::default()
                .bg(colors.accent)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        );

    f.render_widget(title, rects[1]);
    f.render_stateful_widget(list, rects[2], &mut app.list_state);
}

/// Render import file input
fn render_import_file_input(f: &mut Frame, app: &mut App, rects: &[Rect], colors: &Colors) {
    let title = Paragraph::new("📥 Import Passwords")
        .style(Style::default().fg(colors.primary).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors.secondary))
                .style(Style::default().bg(colors.background)),
        );

    let input_block = styled_block("File Path", colors);
    let input_paragraph = Paragraph::new(app.import_file_path.clone())
        .style(Style::default().fg(colors.text).bg(colors.surface))
        .block(input_block);

    f.render_widget(title, rects[1]);
    f.render_widget(input_paragraph, rects[2]);
}

/// Render import confirmation
fn render_import_confirm(f: &mut Frame, app: &mut App, rects: &[Rect], colors: &Colors) {
    let title = Paragraph::new("📥 Import Confirmation")
        .style(Style::default().fg(colors.success).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors.secondary))
                .style(Style::default().bg(colors.background)),
        );

    let preview_text = if let Some(preview) = &app.import_preview {
        preview.clone()
    } else {
        "No preview available".to_string()
    };

    let preview_block = styled_block("Import Preview", colors);
    let preview_paragraph = Paragraph::new(preview_text)
        .style(Style::default().fg(colors.text).bg(colors.surface))
        .block(preview_block);

    f.render_widget(title, rects[1]);
    f.render_widget(preview_paragraph, rects[2]);
}

/// Render settings menu
fn render_settings_menu(f: &mut Frame, app: &mut App, rects: &[Rect], colors: &Colors) {
    let title = Paragraph::new("⚙️  Settings")
        .style(Style::default().fg(colors.primary).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors.secondary))
                .style(Style::default().bg(colors.background)),
        );

    let items = vec![
        styled_list_item("🔒  Security Settings", "🔒", app.settings_list_state.selected() == Some(0), colors),
        styled_list_item("🔑  Password Settings", "🔑", app.settings_list_state.selected() == Some(1), colors),
        styled_list_item("⚡  Advanced Settings", "⚡", app.settings_list_state.selected() == Some(2), colors),
        styled_list_item("❓  Help & Keybindings", "❓", app.settings_list_state.selected() == Some(3), colors),
    ];

    let list = List::new(items)
        .block(styled_block("Settings Categories", colors))
        .highlight_symbol("▶ ")
        .highlight_style(
            Style::default()
                .bg(colors.accent)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        );

    f.render_widget(title, rects[1]);
    f.render_stateful_widget(list, rects[2], &mut app.settings_list_state);
}

/// Render security settings
fn render_settings_security(f: &mut Frame, _app: &mut App, rects: &[Rect], colors: &Colors) {
    let title = Paragraph::new("🔒  Security Settings")
        .style(Style::default().fg(colors.primary).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors.secondary))
                .style(Style::default().bg(colors.background)),
        );

    let content = Paragraph::new(
        "Security Settings\n\n
Encryption: XChaCha20-Poly1305\nKey Derivation: Argon2id\nMaster Password: Required\nSession Timeout: None\nAuto-lock: Disabled\nBiometric Auth: Disabled\nMax Failed Attempts: 5\nClipboard Clear: 30 seconds\nKey Rotation: 365 days\n\n[1] Change Master Password\n[2] Enable Auto-lock\n[3] Configure Session Timeout\n[4] Enable Biometric Authentication\n[5] Set Max Failed Attempts\n[6] Configure Clipboard Clear\n[7] Set Encryption Key Rotation"
    )
    .style(Style::default().fg(colors.text).bg(colors.surface))
    .block(styled_block("Current Security Configuration", colors));

    f.render_widget(title, rects[1]);
    f.render_widget(content, rects[2]);
}

/// Render password settings
fn render_settings_password(f: &mut Frame, _app: &mut App, rects: &[Rect], colors: &Colors) {
    let title = Paragraph::new("🔑  Password Settings")
        .style(Style::default().fg(colors.primary).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors.secondary))
                .style(Style::default().bg(colors.background)),
        );

    let content = Paragraph::new(
        "Password Settings\n\n
Generated Password Length: 16 characters\nCharacter Sets: Lowercase, Uppercase, Digits, Symbols\nDefault Complexity: High\nPassword Expiry: Never\nMinimum Entropy: 60 bits\nComplexity Enforcement: Disabled\n\n[1] Set Default Password Length\n[2] Customize Character Sets\n[3] Configure Password Expiry\n[4] Set Complexity Requirements\n[5] Set Minimum Entropy"
    )
    .style(Style::default().fg(colors.text).bg(colors.surface))
    .block(styled_block("Current Password Configuration", colors));

    f.render_widget(title, rects[1]);
    f.render_widget(content, rects[2]);
}

/// Render advanced settings
fn render_settings_advanced(f: &mut Frame, _app: &mut App, rects: &[Rect], colors: &Colors) {
    let title = Paragraph::new("⚡  Advanced Settings")
        .style(Style::default().fg(colors.primary).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors.secondary))
                .style(Style::default().bg(colors.background)),
        );

    let content = Paragraph::new(
        "Advanced Settings\n\n
Storage Location: ~/.local/RustyPass\nBackup Frequency: Weekly\nLast Backup: Never\nData Format: JSON (encrypted)\nPerformance Mode: Balanced\nTheme: System Default\nDebug Logging: Disabled\n\n[1] Change Storage Location\n[2] Configure Auto-backup\n[3] Toggle Performance Mode\n[4] Change Theme\n[5] Enable Debug Logging\n[6] Export Configuration\n[7] Factory Reset"
    )
    .style(Style::default().fg(colors.text).bg(colors.surface))
    .block(styled_block("Current Advanced Configuration", colors));

    f.render_widget(title, rects[1]);
    f.render_widget(content, rects[2]);
}

/// Render character sets customization menu
fn render_character_sets_menu(f: &mut Frame, app: &mut App, rects: &[Rect], colors: &Colors) {
    let title = Paragraph::new("🔤 Customize Character Sets")
        .style(Style::default().fg(colors.primary).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors.secondary))
                .style(Style::default().bg(colors.background)),
        );

    let items = vec![
        styled_list_item(
            if app.settings.use_lowercase {
                "✅ Lowercase (a-z)"
            } else {
                "❌ Lowercase (a-z)"
            },
            "a-z",
            app.list_state.selected() == Some(0),
            colors
        ),
        styled_list_item(
            if app.settings.use_uppercase {
                "✅ Uppercase (A-Z)"
            } else {
                "❌ Uppercase (A-Z)"
            },
            "A-Z",
            app.list_state.selected() == Some(1),
            colors
        ),
        styled_list_item(
            if app.settings.use_digits {
                "✅ Digits (0-9)"
            } else {
                "❌ Digits (0-9)"
            },
            "0-9",
            app.list_state.selected() == Some(2),
            colors
        ),
        styled_list_item(
            if app.settings.use_symbols {
                "✅ Symbols (!@#$%^&*)"
            } else {
                "❌ Symbols (!@#$%^&*)"
            },
            "!@#",
            app.list_state.selected() == Some(3),
            colors
        ),
    ];

    let list = List::new(items)
        .block(styled_block("Available Character Sets", colors))
        .highlight_symbol("▶ ")
        .highlight_style(
            Style::default()
                .bg(colors.accent)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        );

    f.render_widget(title, rects[1]);
    f.render_stateful_widget(list, rects[2], &mut app.list_state);
}

/// Render help and keybindings
fn render_settings_help(f: &mut Frame, _app: &mut App, rects: &[Rect], colors: &Colors) {
    let title = Paragraph::new("📖 Help & Keybindings")
        .style(Style::default().fg(colors.primary).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors.secondary))
                .style(Style::default().bg(colors.background)),
        );

    let content = Paragraph::new(
        "RustyPass Keybindings Guide


📋 Main Menu Navigation:
  ↑↓ Arrow Keys - Navigate menu items
  ⏎ Enter - Select highlighted item
  ←→ Arrow Keys - Switch between panels
  q or Esc - Exit/Go back

🔧 Main Menu Shortcuts:
  a - Add new password entry
  i - Import passwords
  s - Open Settings
  v - View all passwords
  d - Delete selected entry

➕ Adding Passwords:
  Type service name, press Enter
  Type password or press 'g' to generate
  Press Enter to save, Esc to cancel

🔍 Viewing Passwords:
  Use arrow keys to navigate
  Press any key to return to menu

⚙️ Settings Navigation:
  Use ↑↓ to navigate settings categories
  Press Enter to select a category
  In submenus, enter option number or use menu

💾 Import/Export:
  Select format (JSON, CSV)
  Enter file path when prompted
  Confirm import/export operation

🔒 Security Features:
  XChaCha20-Poly1305 encryption
  Argon2id key derivation
  Master password protection
  Automatic session locking"
    )
    .style(Style::default().fg(colors.text).bg(colors.surface))
    .block(styled_block("Keybindings Reference", colors));

    f.render_widget(title, rects[1]);
    f.render_widget(content, rects[2]);
}

/// Render input prompt for security settings
fn render_input_prompt(f: &mut Frame, app: &mut App, rects: &[Rect], colors: &Colors) {
    let title = Paragraph::new(match app.state {
        AppState::ChangeMasterPassword => "🔒 Change Master Password",
        AppState::SessionTimeoutInput => "⏳ Set Session Timeout",
        AppState::FailedAttemptsInput => "🚫 Set Max Failed Attempts",
        AppState::ClipboardClearInput => "📋 Set Clipboard Clear Time",
        AppState::KeyRotationInput => "🔑 Set Key Rotation Interval",
        AppState::DefaultPasswordLengthInput => "📏 Set Default Password Length",
        AppState::PasswordExpiryInput => "🕒 Set Password Expiry",
        AppState::MinEntropyInput => "🎲 Set Minimum Entropy",
        AppState::StorageLocationInput => "💾 Set Storage Location",
        _ => "Input Required",
    })
    .style(Style::default().fg(colors.primary).add_modifier(Modifier::BOLD))
    .alignment(Alignment::Center)
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(colors.secondary))
            .style(Style::default().bg(colors.background)),
    );

    let input_display = if app.input_buffer.is_empty() {
        "_".to_string()
    } else {
        app.input_buffer.clone()
    };

    let content = Paragraph::new(format!("\n\nEnter value:\n\n{}", input_display))
        .style(Style::default().fg(colors.text).bg(colors.surface))
        .block(styled_block("Input", colors))
        .alignment(Alignment::Center);

    f.render_widget(title, rects[1]);
    f.render_widget(content, rects[2]);
}

/// Render factory reset confirmation
fn render_factory_reset_confirm(f: &mut Frame, _app: &mut App, rects: &[Rect], colors: &Colors) {
    let title = Paragraph::new("⚠️  Factory Reset Confirmation")
        .style(Style::default().fg(colors.warning).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors.secondary))
                .style(Style::default().bg(colors.background)),
        );

    let content = Paragraph::new(
        "WARNING: This will reset ALL settings to factory defaults!\n\n
This includes:\n  • Password generation settings\n  • Security preferences\n  • Performance options\n  • Theme and UI settings\n\nYour password data will NOT be affected.\n\nPress 'y' to confirm or 'n' to cancel."
    )
    .style(Style::default().fg(colors.text).bg(colors.surface))
    .block(styled_block("Confirm Factory Reset", colors))
    .alignment(Alignment::Center);

    f.render_widget(title, rects[1]);
    f.render_widget(content, rects[2]);
}

/// Render exit confirmation
fn render_exit_confirm(f: &mut Frame, _app: &mut App, rects: &[Rect], colors: &Colors) {
    let title = Paragraph::new("🚪 Exit RustyPass")
        .style(Style::default().fg(colors.warning).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(colors.secondary))
                .style(Style::default().bg(colors.background)),
        );

    let confirm_block = styled_block("Confirmation", colors);
    let confirm_paragraph = Paragraph::new("Are you sure you want to exit? (y/n)")
        .style(Style::default().fg(colors.warning).bg(colors.surface))
        .block(confirm_block);

    f.render_widget(title, rects[1]);
    f.render_widget(confirm_paragraph, rects[2]);
}