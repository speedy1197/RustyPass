use password_strength::estimate_strength;

/// Password strength level
#[derive(Debug, Clone, PartialEq)]
pub enum StrengthLevel {
    VeryWeak,
    Weak,
    Moderate,
    Strong,
    VeryStrong,
}

/// Analyze password strength and entropy
pub fn analyze_password(password: &str) -> (StrengthLevel, f64) {
    // Calculate strength score (0.0 - 1.0)
    let strength_score = estimate_strength(password);

    // Calculate entropy in bits using custom implementation
    let entropy_bits = calculate_password_entropy(password);

    // Determine strength level
    let strength_level = if strength_score < 0.3 {
        StrengthLevel::VeryWeak
    } else if strength_score < 0.6 {
        StrengthLevel::Weak
    } else if strength_score < 0.8 {
        StrengthLevel::Moderate
    } else if strength_score < 0.95 {
        StrengthLevel::Strong
    } else {
        StrengthLevel::VeryStrong
    };

    (strength_level, entropy_bits)
}

/// Get strength level description
pub fn strength_description(level: &StrengthLevel) -> &'static str {
    match level {
        StrengthLevel::VeryWeak => "Very Weak",
        StrengthLevel::Weak => "Weak",
        StrengthLevel::Moderate => "Moderate",
        StrengthLevel::Strong => "Strong",
        StrengthLevel::VeryStrong => "Very Strong",
    }
}

/// Calculate password entropy in bits
fn calculate_password_entropy(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }

    // Count character types
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    let mut unique_chars = std::collections::HashSet::new();

    for c in password.chars() {
        unique_chars.insert(c);
        if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else {
            has_symbol = true;
        }
    }

    // Calculate possible character set size
    let mut charset_size: f64 = 0.0;
    if has_lower { charset_size += 26.0; }
    if has_upper { charset_size += 26.0; }
    if has_digit { charset_size += 10.0; }
    if has_symbol { charset_size += 32.0; } // Common symbols

    // If we couldn't detect any character types, assume basic ASCII
    if charset_size == 0.0 {
        charset_size = 94.0; // Full printable ASCII
    }

    // Apply reduction for common patterns
    let mut effective_length = password.len() as f64;

    // Reduce for sequential characters (abc, 123, etc.)
    if has_sequential_chars(password) {
        effective_length *= 0.8;
    }

    // Reduce for repeated patterns
    if has_repeated_patterns(password) {
        effective_length *= 0.7;
    }

    // Calculate entropy: log2(charset_size^effective_length) = effective_length * log2(charset_size)
    let entropy = effective_length * charset_size.log2();

    entropy.max(0.0)
}

/// Check for sequential characters (abc, 123, etc.)
fn has_sequential_chars(password: &str) -> bool {
    let password = password.to_lowercase();
    let chars: Vec<char> = password.chars().collect();

    // Check for 3+ sequential letters
    for i in 0..chars.len().saturating_sub(2) {
        let c1 = chars[i];
        let c2 = chars[i + 1];
        let c3 = chars[i + 2];

        if c1.is_ascii_alphabetic() && c2.is_ascii_alphabetic() && c3.is_ascii_alphabetic() {
            if (c2 as u32) == (c1 as u32) + 1 && (c3 as u32) == (c2 as u32) + 1 {
                return true;
            }
        }

        // Check for sequential digits
        if c1.is_ascii_digit() && c2.is_ascii_digit() && c3.is_ascii_digit() {
            if (c2 as u32) == (c1 as u32) + 1 && (c3 as u32) == (c2 as u32) + 1 {
                return true;
            }
        }
    }

    false
}

/// Check for repeated patterns
fn has_repeated_patterns(password: &str) -> bool {
    if password.len() < 6 {
        return false;
    }

    // Check for simple repetition (abcabc, 123123, etc.)
    for pattern_len in 2..=(password.len() / 2) {
        let pattern = &password[..pattern_len];
        let repeated = pattern.repeat(password.len() / pattern_len + 1);
        if repeated.starts_with(password) {
            return true;
        }
    }

    false
}

/// Get entropy rating
pub fn entropy_rating(bits: f64) -> &'static str {
    if bits < 28.0 {
        "Very Low"
    } else if bits < 36.0 {
        "Low"
    } else if bits < 60.0 {
        "Moderate"
    } else if bits < 80.0 {
        "High"
    } else {
        "Very High"
    }
}