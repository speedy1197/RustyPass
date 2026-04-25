# RustyPass - Secure Password Manager

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust](https://img.shields.io/badge/Built_with-Rust-orange)](https://www.rust-lang.org/)

A terminal-based password manager built with Rust, offering military-grade encryption and intuitive password management with real-time security analysis.

---

## 🔒 Security Features

- **XChaCha20-Poly1305 encryption**: Authenticated encryption for all stored credentials
- **Argon2id key derivation**: Memory-hard password hashing resistant to brute force
- **Secure memory handling**: Zeroization of sensitive data after use
- **Password quality analysis**:
  - Real-time strength/entropy meters
  - Pattern detection for weak passwords
  - Visual feedback during password creation

---

## 🚀 Features

### Password Management
✅ Service-based organization
✅ Full CRUD operations
✅ Secure password generation
✅ JSON/CSV import/export

### User Interface
🖥️ Terminal-based TUI (Ratatui)
🎯 Keyboard-driven navigation
📊 Color-coded security indicators
🔄 Responsive real-time feedback

### Security Analysis
📈 Password strength visualization
🔢 Entropy calculation
⚠️ Weak pattern detection
🔍 Comprehensive security metrics

---

## 🛠️ Technical Stack

| Component       | Technology                          |
|-----------------|-------------------------------------|
| Language        | Rust                 |
| Encryption      | XChaCha20-Poly1305 (`chacha20poly1305` crate) |
| Key Derivation  | Argon2id (`argon2` crate)           |
| UI Framework    | Ratatui                             |
| Password Analysis | Custom entropy/pattern detection |

---

## 📥 Installation

### Prerequisites
- Rust toolchain (latest stable)
- Cargo package manager

### Build & Run
```bash
git clone https://github.com/yourusername/RustyPass.git
cd RustyPass
cargo build --release
./target/release/rustypass  # Note: corrected binary name
```

### Install (Optional)
```bash
cargo install --path .
```

---

## ⌨️ Keybindings

### Main Menu
| Key  | Action               |
|------|----------------------|
| `a`  | Add new password     |
| `i`  | Import passwords     |
| `s`  | Services menu        |
| `t`  | Settings             |
| `q`  | Exit                 |
| `Esc`| Exit                 |

### Services Menu
| Key      | Action               |
|----------|----------------------|
| `↑`/`↓`  | Navigate services    |
| `Enter`  | View password        |
| `v`      | View password        |
| `d`      | Delete service       |
| `q`      | Back to main menu    |
| `Esc`    | Back to main menu    |

### Password Input
| Key  | Action                       |
|------|------------------------------|
| `g`  | Generate secure password     |
| `Enter` | Save password              |
| `Esc`| Cancel                       |

---

## 📦 Recent Updates

### 🆕 Services Menu Redesign (v0.4.0)
- Removed distracting side panel
- Added dedicated services menu option (`s` shortcut)
- Improved navigation flow
- Enhanced service management workflow

### 🔍 Security Analysis Improvements
- Compact strength/entropy meters
- Real-time pattern detection
- Visual feedback during password creation

---

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch:
   ```bash
   git checkout -b feature/your-feature
   ```
3. **Commit** your changes:
   ```bash
   git commit -am 'Add some feature'
   ```
4. **Push** to the branch:
   ```bash
   git push origin feature/your-feature
   ```
5. **Open** a Pull Request

### Development Setup
```bash
git clone https://github.com/yourusername/RustyPass.git
cd RustyPass
cargo test  # Run all tests
cargo run   # Start development version
```

---

## 📄 License

This project is licensed under **GPLv3** - see (https://github.com/speedy1197/RustyPass/blob/main/GNU%20General%20Public%20License%20v3.0) for details.

---

## 📬 Contact

For questions or support:
- Email eliii105@proton.me
  
---

## 🛡️ Security Notice

While RustyPass implements strong security measures:
- Always use a **strong master password**
- Keep your system **free of malware**
- Regularly **backup your password database**
- Consider using **full-disk encryption**

---

## 🎯 Roadmap

Upcoming features we're working on:
- [ ] Browser extension integration
- [ ] Mobile companion app
- [ ] Password breach monitoring
- [ ] TOTP/2FA support
- [ ] Cloud sync (E2E encrypted)

---

**RustyPass** - Your passwords deserve enterprise-grade security with open-source transparency.
