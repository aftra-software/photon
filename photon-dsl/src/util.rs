use std::sync::OnceLock;

use regex::Regex;

pub static BRACKET_PATTERN: OnceLock<Regex> = OnceLock::new();

pub fn get_bracket_pattern() -> &'static Regex {
    BRACKET_PATTERN.get_or_init(|| Regex::new(r"\{\{([^{}]*)}}").unwrap())
}
