# RustyPass - Secure Password Manager

**RustyPass** is a secure, terminal-based password manager written in Rust. It provides AES-256-GCM encryption, secure password generation, and support for importing from popular password managers.

## Features

✅ **Military-Grade Encryption**: AES-256-GCM with PBKDF2 key derivation
✅ **Cross-Platform**: Works on Linux, macOS, and Windows
✅ **Terminal-Based UI**: Beautiful TUI with Ratatui and Crossterm
✅ **Secure Password Generation**: Cryptographically strong random passwords
✅ **Import Functionality**: Import from Bitwarden, CSV, and other formats
✅ **Zero Dependencies**: All data stored locally, no cloud required
✅ **Open Source**: Fully auditable security

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/RustyPass.git
cd RustyPass

# Build and install
cargo build --release
sudo cp target/release/rustypass /usr/local/bin/
```

### Keyboard Shortcuts

- **Main Menu**:
  - `a`: Add new service
  - `g`: Generate secure password
  - `i`: Import passwords
  - `v`: View selected password
  - `d`: Delete selected service
  - `q`/`Esc`: Quit
  - `↑`/`↓`: Navigate services

- **Password Generation**:
  - Enter desired length (8-64 characters)
  - `c`: Copy generated password to add service
  - `g`: Generate another password

- **Import**:
  - Select format (JSON or CSV)
  - Enter file path
  - Preview and confirm import

## Security Features

### Encryption

- **AES-256-GCM**: Industry-standard authenticated encryption
- **PBKDF2-HMAC-SHA256**: 100,000 iterations for key derivation
- **Unique Salt**: Random salt generated per installation
- **Secure Storage**: Encrypted data stored in `~/.RustyPass/`

### Password Generation

- Cryptographically secure random number generation
- Character sets: lowercase, uppercase, digits, symbols
- Configurable length (8-64 characters)
- Guaranteed complexity with all character types

## Import Formats

### JSON Import

Supports multiple JSON formats:

**Bitwarden Format**:
```json
{
  "items": [
    {
      "name": "GitHub",
      "login": {
        "password": "mysecurepassword"
      }
    }
  ]
}
```

**Simple Key-Value Format**:
```json
{
  "github": "password123",
  "email": "anotherpassword"
}
```

**Array Format**:
```json
[
  {"service": "github", "password": "pass123"},
  {"service": "email", "password": "pass456"}
]
```

### CSV Import

Supports common CSV formats:

**Service,Password**:
```csv
github,password123
gmail,anotherpassword
```

**Service,Username,Password**:
```csv
github,user1,password123
gmail,user2,anotherpassword
```

## Data Storage

All passwords are stored encrypted in:
- **Linux/macOS**: `~/.RustyPass/passwords.json.enc`
- **Windows**: `%USERPROFILE%\.RustyPass\passwords.json.enc`

The encryption key is derived from your master password using PBKDF2 with a unique salt.

## Security Best Practices

1. **Use a strong master password** (12+ characters, mixed case, numbers, symbols)
2. **Never share your master password**
3. **Backup your `.RustyPass` directory** regularly
4. **Use full disk encryption** on your system
5. **Keep RustyPass updated** for the latest security fixes

## Building from Source

### Requirements

- Rust 1.70+ (install via [rustup](https://rustup.rs/))
- Cargo (comes with Rust)
- Git

### Build Steps

```bash
# Clone the repository
git clone https://github.com/yourusername/RustyPass.git
cd RustyPass

# Build in release mode
cargo build --release

# Run the application
./target/release/rustypass
```

## Dependencies

RustyPass uses these excellent Rust crates:

- `aes-gcm`: AES-256-GCM encryption
- `pbkdf2`: Key derivation function
- `sha2`: SHA-256 hashing
- `ratatui`: Terminal UI framework
- `crossterm`: Terminal control
- `serde`: JSON serialization
- `rand`: Cryptographically secure random number generation

## Roadmap

- [ ] Browser extension for auto-fill
- [ ] Mobile app (Android/iOS)
- [ ] Cloud sync with end-to-end encryption
- [ ] Password strength analysis
- [ ] Two-factor authentication support
- [ ] Biometric unlock (where supported)

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Submit a pull request

### Development Setup

```bash
git clone https://github.com/yourusername/RustyPass.git
cd RustyPass
cargo run
```

## License

RustyPass is licensed under the [GPL v.3](LICENSE).

## Alternatives

If RustyPass doesn't meet your needs, consider these alternatives:

- **Bitwarden**: Open-source, cloud-based password manager
- **KeePass**: Offline password manager with extensive plugin ecosystem
- **1Password**: Commercial password manager with excellent UX
- **Pass**: Unix password manager using GPG encryption

## Support

For help and discussions:

- **Email**: eliii105@proton.me

## Credits

RustyPass was created by speedy and is maintained by the open-source community. Special thanks to all contributors and the Rust ecosystem for providing excellent libraries.

## Donations

RustyPass is free and open-source software.
---

**Stay secure!** 🔒 The RustyPass Team
