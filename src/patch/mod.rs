//! Configuration patching module.
//!
//! Provides functionality to apply security fixes to Clawdbot/Moltbot
//! configurations, including binding changes, authentication setup,
//! and firewall rules.
//!
//! ## Patching Process
//!
//! 1. Create timestamped backup of original configuration
//! 2. Generate secure authentication token (if needed)
//! 3. Patch configuration settings (bind, auth, mDNS)
//! 4. Fix file permissions to 0600
//! 5. Add firewall rules (Linux only)
//!
//! ## Configuration Changes
//!
//! | Setting | Before | After |
//! |---------|--------|-------|
//! | `gateway.bind` | 0.0.0.0 | loopback |
//! | `gateway.auth.mode` | none | token |
//! | `gateway.auth.token` | (empty) | Generated |
//! | `discovery.mdns.mode` | full | minimal |

mod config;
mod firewall;
mod token;

pub use config::patch_config;
pub use firewall::add_firewall_rule;
pub use token::generate_secure_token;

use crate::analyze::RiskReport;
use crate::detect::Installation;
use std::path::PathBuf;

/// Results of applying security patches.
///
/// Contains information about what changes were made, including
/// backup location and generated credentials.
#[derive(Debug, Clone, Default)]
pub struct PatchResult {
    /// Path to the backup file created before patching.
    pub backup_path: Option<PathBuf>,

    /// The authentication token that was generated (if any).
    /// Users must save this token to connect to the gateway.
    pub generated_token: Option<String>,

    /// Human-readable descriptions of all changes made.
    pub changes_made: Vec<String>,

    /// Whether the configuration file was modified.
    pub config_modified: bool,

    /// Whether firewall rules were added.
    pub firewall_modified: bool,
}

/// Applies security patches to fix identified vulnerabilities.
///
/// This is the main entry point for the patching phase. It creates
/// a backup, applies all necessary configuration changes, fixes
/// file permissions, and optionally adds firewall rules.
///
/// # Arguments
///
/// * `installation` - The detected installation to patch.
/// * `risk_report` - Analysis results indicating which fixes are needed.
/// * `custom_token` - Optional custom token to use instead of generating one.
/// * `backup_dir` - Optional custom directory for backup files.
/// * `skip_firewall` - If true, skip firewall rule modifications.
/// * `verbose` - When true, prints diagnostic information to stderr.
///
/// # Returns
///
/// A [`PatchResult`] containing details of all changes made.
///
/// # Errors
///
/// Returns an error if:
/// - No configuration file is found
/// - Backup creation fails
/// - Configuration patching fails
/// - Permission fixing fails
///
/// # Example
///
/// ```rust,ignore
/// let result = apply_patches(
///     &installation,
///     &risk_report,
///     None,      // Auto-generate token
///     None,      // Default backup location
///     false,     // Include firewall rules
///     false,     // Non-verbose
/// )?;
/// println!("Token: {}", result.generated_token.unwrap());
/// ```
pub fn apply_patches(
    installation: &Installation,
    risk_report: &RiskReport,
    custom_token: Option<&str>,
    backup_dir: Option<&str>,
    skip_firewall: bool,
    verbose: bool,
) -> Result<PatchResult, String> {
    let mut result = PatchResult::default();

    // Ensure we have a config file to patch
    let config_path = installation
        .config_path
        .as_ref()
        .ok_or("No configuration file found to patch")?;

    // Step 1: Create backup before making any changes
    let backup_path = create_backup(config_path, backup_dir, verbose)?;
    result.backup_path = Some(backup_path);

    // Step 2: Generate or use provided token if auth is missing
    let token = if risk_report.auth_missing {
        let t = match custom_token {
            Some(ct) => {
                if ct.len() < 16 {
                    return Err("Custom token must be at least 16 characters long".to_string());
                }
                ct.to_string()
            }
            None => generate_secure_token(32),
        };
        result.generated_token = Some(t.clone());
        Some(t)
    } else {
        None
    };

    // Step 3: Apply configuration patches
    let patch_changes = patch_config(
        config_path,
        risk_report.bind_exposed,
        risk_report.auth_missing,
        token.as_deref(),
        risk_report.mdns_leaking,
        verbose,
    )?;

    result.changes_made.extend(patch_changes);
    result.config_modified = !result.changes_made.is_empty();

    // Step 4: Fix file permissions if too open
    if risk_report.permissions_too_open {
        crate::analyze::permissions::fix_file_permissions(config_path)?;
        result
            .changes_made
            .push("Fixed file permissions (600)".to_string());
    }

    // Also fix directory permissions for the state directory
    if let Some(ref state_dir) = installation.state_dir {
        if let Err(e) = crate::analyze::permissions::fix_directory_permissions(state_dir) {
            if verbose {
                eprintln!("Warning: Could not fix directory permissions: {}", e);
            }
        }
    }

    // Step 5: Add firewall rules if needed and not skipped
    if !skip_firewall && risk_report.bind_exposed {
        match add_firewall_rule(verbose) {
            Ok(true) => {
                result.firewall_modified = true;
                result
                    .changes_made
                    .push("Added firewall rule to block port 18789".to_string());
            }
            Ok(false) => {
                if verbose {
                    eprintln!("Firewall modification skipped");
                }
            }
            Err(e) => {
                if verbose {
                    eprintln!("Warning: Could not add firewall rule: {}", e);
                }
                // Don't fail the entire patch operation for firewall issues
            }
        }
    }

    Ok(result)
}

/// Creates a timestamped backup of the configuration file.
///
/// The backup is named `{original}.backup.{timestamp}` and placed
/// either in the specified backup directory or alongside the original.
///
/// # Arguments
///
/// * `config_path` - Path to the configuration file to backup.
/// * `backup_dir` - Optional custom directory for the backup.
/// * `verbose` - Enable diagnostic output.
///
/// # Returns
///
/// Path to the created backup file.
///
/// # Errors
///
/// Returns an error if the file copy operation fails.
fn create_backup(
    config_path: &std::path::Path,
    backup_dir: Option<&str>,
    verbose: bool,
) -> Result<PathBuf, String> {
    use chrono::Local;
    use std::fs;

    // Determine backup directory
    let backup_directory = match backup_dir {
        Some(dir) => PathBuf::from(dir),
        None => config_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".")),
    };

    // Create timestamped backup filename
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let original_name = config_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config");

    let backup_name = format!("{}.backup.{}", original_name, timestamp);
    let backup_path = backup_directory.join(backup_name);

    if verbose {
        eprintln!("Creating backup at: {}", backup_path.display());
    }

    // Copy original file to backup location
    fs::copy(config_path, &backup_path).map_err(|e| format!("Failed to create backup: {}", e))?;

    Ok(backup_path)
}
