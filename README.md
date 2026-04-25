# RustyPass - Secure Password Manager

**License**: GPL v3

RustyPass is a secure, terminal-based password manager built with Rust, offering robust encryption and intuitive password management.

## Security Features

- **Military-grade encryption**: XChaCha20-Poly1305 for all stored credentials
- **Secure key derivation**: Argon2id for master password protection
- **Password quality analysis**: Real-time strength and entropy meters
- **Pattern detection**: Identifies and warns about weak password patterns
- **Secure memory handling**: Proper cleanup of sensitive data

## Current Feature Set

### Password Management
- **Service-based organization**: Logical grouping of credentials by service
- **Add/Edit/Delete**: Full CRUD operations for password entries
- **Password generation**: Secure random password creation
- **Import/Export**: JSON and CSV format support

### User Interface
- **Terminal-based**: Clean TUI using Ratatui
- **Intuitive navigation**: Keyboard-driven with context-sensitive help
- **Visual feedback**: Color-coded strength and entropy meters
- **Dedicated services menu**: Focused interface for credential management

### Security Analysis
- **Strength meter**: Visual representation of password quality
- **Entropy calculation**: Mathematical measurement of unpredictability
- **Real-time feedback**: Updates as you type
- **Pattern detection**: Warns about sequential/repeated characters

### Settings & Configuration
- **Security preferences**: Customizable protection settings
- **Password policies**: Configurable generation rules
- **Performance options**: Balance between security and speed

## Technical Implementation

- **Language**: Rust (2024 edition)
- **Encryption**: XChaCha20-Poly1305 via `chacha20poly1305` crate
- **Key derivation**: Argon2id for resistant password hashing
- **Password analysis**: Custom entropy calculation with pattern detection
- **UI Framework**: Ratatui for terminal interface

## Usage Highlights

- **Main menu**: Quick access to all features via keyboard shortcuts
- **Services menu**: Dedicated interface for credential management
- **Password input**: Real-time quality feedback during entry
- **Navigation**: Intuitive keyboard controls with visual feedback

## Recent Enhancements

### Services Menu Overhaul
- **Removed side panel**: Eliminated distracting side panel
- **Dedicated Services Menu**: Proper menu option for managing services
- **Improved navigation**: Services accessible via main menu with `s` shortcut
- **Enhanced workflow**: View, delete, and manage services through focused interface

### Password Strength & Entropy Analysis
- **Real-time strength meter**: Visual gauge showing password strength level
- **Entropy calculation**: Mathematical measurement of password unpredictability
- **Pattern detection**: Identifies common weak patterns
- **Compact display**: Meters fit neatly under password input

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/RustyPass.git
cd RustyPass

# Build the application
cargo build --release

# Run the application
./target/release/russty_pass
```

## Keybindings

### Main Menu
- `a`: Add new password
- `i`: Import passwords
- `s`: Services menu
- `t`: Settings
- `q`/`Esc`: Exit

### Services Menu
- `↑`/`↓`: Navigate services
- `Enter`/`v`: View password
- `d`: Delete service
- `q`/`Esc`: Back to main menu

### Password Input
- Type password for real-time strength/entropy analysis
- `g`: Generate secure password
- `Enter`: Save password
- `Esc`: Cancel

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

## License

This project is licensed under the GPL v3 License - see the [LICENSE](LICENSE) file for details.

## Contact

For questions or support, please open an issue on GitHub.

RustyPass provides enterprise-grade security with a user-friendly interface, helping users maintain strong, unique passwords for all their services while ensuring data remains protected with state-of-the-art encryption.
