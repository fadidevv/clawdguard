//! Configuration file patching.
//!
//! Modifies Clawdbot/Moltbot JSON configuration files to apply
//! security fixes. Supports both standard JSON and JSON5 formats.
//!
//! ## Patching Strategy
//!
//! Configuration values are updated in-place while preserving the
//! overall structure and any unrelated settings. The file is then
//! written back in pretty-printed JSON format.
//!
//! ## Supported Patches
//!
//! - `gateway.bind`: Set to "loopback" to restrict network access
//! - `gateway.auth.mode`: Set to "token" to enable authentication
//! - `gateway.auth.token`: Set to the provided secure token
//! - `discovery.mdns.mode`: Set to "minimal" to reduce information leak

use serde_json::{Map, Value};
use std::fs;
use std::path::Path;

/// Patches a configuration file with security fixes.
///
/// Reads the configuration file, applies the specified fixes, and
/// writes it back. Returns a list of human-readable change descriptions.
///
/// # Arguments
///
/// * `config_path` - Path to the configuration file to patch.
/// * `fix_bind` - If true, set `gateway.bind` to "loopback".
/// * `fix_auth` - If true, set `gateway.auth.mode` to "token".
/// * `token` - Token value to set for `gateway.auth.token`.
/// * `fix_mdns` - If true, set `discovery.mdns.mode` to "minimal".
/// * `verbose` - When true, prints diagnostic information to stderr.
///
/// # Returns
///
/// A vector of strings describing each change made.
///
/// # Errors
///
/// Returns an error if:
/// - The configuration file cannot be read
/// - The configuration cannot be parsed as JSON/JSON5
/// - The patched configuration cannot be written back
///
/// # Example
///
/// ```rust,ignore
/// let changes = patch_config(
///     Path::new("~/.clawdbot/clawdbot.json"),
///     true,  // Fix bind
///     true,  // Fix auth
///     Some("clwd_abc123..."),
///     true,  // Fix mDNS
///     false, // Non-verbose
/// )?;
/// for change in changes {
///     println!("Applied: {}", change);
/// }
/// ```
pub fn patch_config(
    config_path: &Path,
    fix_bind: bool,
    fix_auth: bool,
    token: Option<&str>,
    fix_mdns: bool,
    verbose: bool,
) -> Result<Vec<String>, String> {
    let mut changes = Vec::new();

    // Read configuration file content
    let content =
        fs::read_to_string(config_path).map_err(|e| format!("Failed to read config: {}", e))?;

    // Parse as JSON, falling back to JSON5 for more permissive parsing
    let mut config: Value = serde_json::from_str(&content)
        .or_else(|_| json5::from_str(&content))
        .map_err(|e| format!("Failed to parse config: {}", e))?;

    // Apply gateway.bind fix
    if fix_bind {
        let old_value = get_nested_string(&config, &["gateway", "bind"]);
        set_nested_value(
            &mut config,
            &["gateway", "bind"],
            Value::String("loopback".to_string()),
        );
        changes.push(format!(
            "Set gateway.bind = \"loopback\" (was: \"{}\")",
            old_value.unwrap_or_else(|| "unset".to_string())
        ));

        if verbose {
            eprintln!("Patched gateway.bind to loopback");
        }
    }

    // Apply gateway.auth fix
    if fix_auth {
        let old_mode = get_nested_string(&config, &["gateway", "auth", "mode"]);
        set_nested_value(
            &mut config,
            &["gateway", "auth", "mode"],
            Value::String("token".to_string()),
        );
        changes.push(format!(
            "Set gateway.auth.mode = \"token\" (was: \"{}\")",
            old_mode.unwrap_or_else(|| "none".to_string())
        ));

        // Set the token value if provided
        if let Some(t) = token {
            set_nested_value(
                &mut config,
                &["gateway", "auth", "token"],
                Value::String(t.to_string()),
            );
            changes.push("Set gateway.auth.token = <generated>".to_string());

            if verbose {
                eprintln!("Patched auth mode and token");
            }
        }
    }

    // Apply discovery.mdns fix
    if fix_mdns {
        let old_mode = get_nested_string(&config, &["discovery", "mdns", "mode"]);
        set_nested_value(
            &mut config,
            &["discovery", "mdns", "mode"],
            Value::String("minimal".to_string()),
        );
        changes.push(format!(
            "Set discovery.mdns.mode = \"minimal\" (was: \"{}\")",
            old_mode.unwrap_or_else(|| "full".to_string())
        ));

        if verbose {
            eprintln!("Patched mDNS mode to minimal");
        }
    }

    // Serialize and write back to file
    let output = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;

    fs::write(config_path, output).map_err(|e| format!("Failed to write config: {}", e))?;

    Ok(changes)
}

/// Retrieves a string value from a nested JSON path.
///
/// Navigates through the JSON structure following the provided path
/// and returns the string value if found.
///
/// # Arguments
///
/// * `config` - The root JSON value.
/// * `path` - Array of keys forming the path to the value.
///
/// # Returns
///
/// The string value if found, or `None` if the path doesn't exist
/// or the value is not a string.
fn get_nested_string(config: &Value, path: &[&str]) -> Option<String> {
    let mut current = config;

    // Navigate through each key in the path
    for key in path {
        current = current.get(*key)?;
    }

    current.as_str().map(|s| s.to_string())
}

/// Sets a value at a nested JSON path, creating intermediate objects as needed.
///
/// If any intermediate keys don't exist, they are created as empty objects.
///
/// # Arguments
///
/// * `config` - Mutable reference to the root JSON value.
/// * `path` - Array of keys forming the path to the value.
/// * `value` - The value to set at the path.
fn set_nested_value(config: &mut Value, path: &[&str], value: Value) {
    if path.is_empty() {
        return;
    }

    let mut current = config;

    for (i, key) in path.iter().enumerate() {
        // If this is the last key, set the value
        if i == path.len() - 1 {
            if let Value::Object(map) = current {
                map.insert(key.to_string(), value);
            }
            return;
        }

        // Create intermediate object if it doesn't exist
        if !current.get(*key).map(|v| v.is_object()).unwrap_or(false) {
            if let Value::Object(map) = current {
                map.insert(key.to_string(), Value::Object(Map::new()));
            }
        }

        // Move to the next level
        current = current.get_mut(*key).unwrap();
    }
}

/// Removes a key at a nested JSON path.
///
/// Navigates to the parent object and removes the specified key.
///
/// # Arguments
///
/// * `config` - Mutable reference to the root JSON value.
/// * `path` - Array of keys forming the path to the key to remove.
///
/// # Returns
///
/// The removed value if it existed, or `None` otherwise.
#[allow(dead_code)]
pub fn remove_nested_key(config: &mut Value, path: &[&str]) -> Option<Value> {
    if path.is_empty() {
        return None;
    }

    let mut current = config;

    // Navigate to the parent of the key to remove
    for (i, key) in path.iter().enumerate() {
        if i == path.len() - 1 {
            // Remove the key from the parent object
            if let Value::Object(map) = current {
                return map.remove(*key);
            }
            return None;
        }

        // Move to the next level
        current = current.get_mut(*key)?;
    }

    None
}
