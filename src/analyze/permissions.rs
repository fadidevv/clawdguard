//! File permission analysis and remediation.
//!
//! Analyzes Unix file permissions on configuration files to ensure
//! sensitive data (API keys, tokens) is protected from unauthorized access.
//!
//! ## Secure Permissions
//!
//! | Type | Mode | Description |
//! |------|------|-------------|
//! | Config files | 0600 | Owner read/write only |
//! | State directories | 0700 | Owner read/write/execute only |
//!
//! ## Security Rationale
//!
//! Configuration files may contain:
//! - API keys (OpenAI, Anthropic, etc.)
//! - Authentication tokens
//! - Sensitive user preferences
//!
//! These files should only be readable by the owner to prevent
//! credential theft by other users on the system.

use std::path::Path;

/// Results of file permission analysis.
///
/// Contains information about whether file permissions are
/// too permissive and the current permission mode.
#[derive(Debug, Clone, Default)]
pub struct PermissionResult {
    /// Whether the file has overly permissive permissions.
    /// True if group or other users have read/write access.
    pub too_open: bool,

    /// The current permission mode as an octal string (e.g., "644").
    pub mode_string: Option<String>,

    /// The current permission mode as a numeric value.
    pub mode_octal: Option<u32>,
}

/// Checks if a file's permissions are too permissive.
///
/// Analyzes Unix file permissions and determines if the file is
/// readable or writable by group or other users, which would be
/// a security risk for configuration files.
///
/// # Arguments
///
/// * `path` - Path to the file to check.
/// * `verbose` - When true, prints diagnostic information to stderr.
///
/// # Returns
///
/// A [`PermissionResult`] containing the analysis results.
///
/// # Platform Support
///
/// - Unix/Linux/macOS: Full functionality
/// - Windows: Returns default result (permissions not applicable)
///
/// # Example
///
/// ```rust,ignore
/// let result = check_file_permissions(Path::new("/path/to/config.json"), false);
/// if result.too_open {
///     println!("Warning: Config file is readable by others!");
/// }
/// ```
pub fn check_file_permissions(path: &Path, verbose: bool) -> PermissionResult {
    let mut result = PermissionResult::default();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        match std::fs::metadata(path) {
            Ok(metadata) => {
                // Get the full mode and extract file permission bits (last 9 bits)
                let mode = metadata.permissions().mode();
                let file_mode = mode & 0o777;

                result.mode_octal = Some(file_mode);
                result.mode_string = Some(format!("{:o}", file_mode));

                // Check for group permissions (bits 6-4)
                let group_read = (file_mode & 0o040) != 0;
                let group_write = (file_mode & 0o020) != 0;

                // Check for other permissions (bits 3-1)
                let other_read = (file_mode & 0o004) != 0;
                let other_write = (file_mode & 0o002) != 0;

                // File is too open if anyone besides owner can read/write
                result.too_open = group_read || group_write || other_read || other_write;

                if verbose {
                    eprintln!(
                        "File permissions for {}: {:o} (too_open={})",
                        path.display(),
                        file_mode,
                        result.too_open
                    );
                }
            }
            Err(e) => {
                if verbose {
                    eprintln!("Could not read permissions for {}: {}", path.display(), e);
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        if verbose {
            eprintln!("Permission checking not supported on this platform");
        }
    }

    result
}

/// Fixes file permissions to be secure (owner-only access).
///
/// Sets the file mode to 0600 (rw-------), ensuring only the owner
/// can read or write the file.
///
/// # Arguments
///
/// * `path` - Path to the file to fix.
///
/// # Returns
///
/// * `Ok(())` - Permissions were successfully changed.
/// * `Err(msg)` - Failed to change permissions with error message.
///
/// # Platform Support
///
/// - Unix/Linux/macOS: Full functionality
/// - Windows: No-op (returns Ok)
///
/// # Example
///
/// ```rust,ignore
/// fix_file_permissions(Path::new("/path/to/config.json"))?;
/// ```
pub fn fix_file_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        // Read current metadata
        let metadata =
            std::fs::metadata(path).map_err(|e| format!("Failed to read file metadata: {}", e))?;

        // Create new permissions with mode 0600 (rw-------)
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);

        // Apply new permissions
        std::fs::set_permissions(path, permissions)
            .map_err(|e| format!("Failed to set permissions: {}", e))?;

        Ok(())
    }

    #[cfg(not(unix))]
    {
        // Windows doesn't use Unix permissions
        let _ = path;
        Ok(())
    }
}

/// Fixes directory permissions to be secure (owner-only access).
///
/// Sets the directory mode to 0700 (rwx------), ensuring only the owner
/// can read, write, or traverse the directory.
///
/// # Arguments
///
/// * `path` - Path to the directory to fix.
///
/// # Returns
///
/// * `Ok(())` - Permissions were successfully changed.
/// * `Err(msg)` - Failed to change permissions with error message.
///
/// # Platform Support
///
/// - Unix/Linux/macOS: Full functionality
/// - Windows: No-op (returns Ok)
pub fn fix_directory_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        // Read current metadata
        let metadata = std::fs::metadata(path)
            .map_err(|e| format!("Failed to read directory metadata: {}", e))?;

        // Create new permissions with mode 0700 (rwx------)
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o700);

        // Apply new permissions
        std::fs::set_permissions(path, permissions)
            .map_err(|e| format!("Failed to set directory permissions: {}", e))?;

        Ok(())
    }

    #[cfg(not(unix))]
    {
        // Windows doesn't use Unix permissions
        let _ = path;
        Ok(())
    }
}
