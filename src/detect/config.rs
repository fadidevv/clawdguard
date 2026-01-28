//! Configuration file detection and parsing.
//!
//! Provides utilities for locating and parsing Clawdbot/Moltbot configuration
//! files. Supports both standard JSON and JSON5 formats for flexible configuration.
//!
//! ## Configuration Search Order
//!
//! 1. `MOLTBOT_CONFIG_PATH` environment variable (if set, preferred)
//! 2. `CLAWDBOT_CONFIG_PATH` environment variable (if set, legacy)
//! 3. `moltbot.json` in the state directory
//! 4. `clawdbot.json` in the state directory

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

/// Searches for a configuration file in the given state directory.
///
/// Checks multiple locations in priority order: environment variables,
/// then standard config file names within the state directory.
///
/// # Arguments
///
/// * `state_dir` - The state directory to search (~/.moltbot or ~/.clawdbot)
/// * `verbose` - When true, prints diagnostic information to stderr
///
/// # Returns
///
/// The path to the configuration file if found, or `None` if no config exists.
///
/// # Environment Variables
///
/// * `MOLTBOT_CONFIG_PATH` - Preferred, if set uses this path directly
/// * `CLAWDBOT_CONFIG_PATH` - Legacy fallback, if set uses this path directly
pub fn find_config_file(state_dir: &Path, verbose: bool) -> Option<PathBuf> {
    // Check environment variable overrides first (preferred: MOLTBOT, fallback: CLAWDBOT)
    for env_var in &["MOLTBOT_CONFIG_PATH", "CLAWDBOT_CONFIG_PATH"] {
        if let Ok(env_path) = std::env::var(env_var) {
            let path = PathBuf::from(&env_path);
            if path.exists() {
                if verbose {
                    eprintln!("Found config via {}: {}", env_var, path.display());
                }
                return Some(path);
            }
        }
    }

    // Search for standard config file names
    for filename in crate::CONFIG_FILENAMES {
        let path = state_dir.join(filename);
        if path.exists() && path.is_file() {
            if verbose {
                eprintln!("Found config file: {}", path.display());
            }
            return Some(path);
        }
    }

    // Fallback check for moltbot.json specifically
    let moltbot_config = state_dir.join("moltbot.json");
    if moltbot_config.exists() {
        if verbose {
            eprintln!("Found moltbot config: {}", moltbot_config.display());
        }
        return Some(moltbot_config);
    }

    if verbose {
        eprintln!("No config file found in {}", state_dir.display());
    }

    None
}

/// Parses a configuration file into a JSON value.
///
/// Supports both standard JSON and JSON5 formats. JSON5 allows for
/// comments, trailing commas, and unquoted keys which provides more
/// flexibility for user-edited configuration files.
///
/// # Arguments
///
/// * `config_path` - Path to the configuration file
///
/// # Returns
///
/// The parsed JSON value on success.
///
/// # Errors
///
/// Returns an error string if the file cannot be read or parsed.
pub fn parse_config(config_path: &Path) -> Result<Value, String> {
    let content = fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read config file: {}", e))?;

    // Attempt JSON5 parsing first (more permissive), fall back to standard JSON
    json5::from_str::<Value>(&content)
        .or_else(|_| serde_json::from_str::<Value>(&content))
        .map_err(|e| format!("Failed to parse config: {}", e))
}

/// Retrieves a string value from a nested JSON path.
///
/// Navigates through the JSON structure using dot-separated path components.
///
/// # Arguments
///
/// * `config` - The root JSON value to search
/// * `path` - Dot-separated path (e.g., "gateway.auth.mode")
///
/// # Returns
///
/// The string value if found and is a string type, or `None` otherwise.
///
/// # Example
///
/// ```rust,ignore
/// let mode = get_config_string(&config, "gateway.auth.mode");
/// ```
#[allow(dead_code)]
pub fn get_config_string(config: &Value, path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = config;

    for part in parts {
        current = current.get(part)?;
    }

    current.as_str().map(|s| s.to_string())
}

/// Retrieves a boolean value from a nested JSON path.
///
/// # Arguments
///
/// * `config` - The root JSON value to search
/// * `path` - Dot-separated path (e.g., "gateway.enabled")
///
/// # Returns
///
/// The boolean value if found and is a boolean type, or `None` otherwise.
#[allow(dead_code)]
pub fn get_config_bool(config: &Value, path: &str) -> Option<bool> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = config;

    for part in parts {
        current = current.get(part)?;
    }

    current.as_bool()
}

/// Checks if a configuration key exists at the given path.
///
/// # Arguments
///
/// * `config` - The root JSON value to search
/// * `path` - Dot-separated path to check
///
/// # Returns
///
/// `true` if the path exists in the configuration, `false` otherwise.
#[allow(dead_code)]
pub fn config_key_exists(config: &Value, path: &str) -> bool {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = config;

    for part in parts {
        match current.get(part) {
            Some(v) => current = v,
            None => return false,
        }
    }

    true
}
