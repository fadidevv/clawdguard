//! Installation detection module.
//!
//! Provides functionality to locate and identify Clawdbot/Moltbot installations
//! on the system, including configuration files, running processes, and system services.
//!
//! ## Detection Strategy
//!
//! The detection process follows this order:
//!
//! 1. **State Directory**: Checks for `~/.moltbot/` (preferred) or `~/.clawdbot/` directory
//! 2. **Configuration Files**: Searches for `moltbot.json` or `clawdbot.json`
//! 3. **Running Processes**: Scans for gateway processes by name and command line
//! 4. **System Services**: Checks for launchd (macOS) or systemd (Linux) services
//! 5. **Port Activity**: Verifies if port 18789 is in use
//!
//! ## Platform Support
//!
//! | Platform | Config Detection | Process Detection | Service Detection |
//! |----------|-----------------|-------------------|-------------------|
//! | macOS    | Full            | Full              | launchd           |
//! | Linux    | Full            | Full              | systemd           |
//! | Windows  | WSL2 only       | WSL2 only         | Not supported     |

mod config;
mod process;
pub mod service;

pub use config::{find_config_file, parse_config};
pub use process::{find_running_process, is_process_running};
pub use service::{find_service, restart_service_manager, stop_service_manager, ServiceInfo};

use std::path::PathBuf;

/// Represents a detected Clawdbot/Moltbot installation.
///
/// Contains all discovered information about the installation including
/// configuration paths, service status, and process information.
///
/// # Fields
///
/// * `config_path` - Path to the configuration file (moltbot.json or clawdbot.json)
/// * `state_dir` - Path to the state directory (~/.moltbot or ~/.clawdbot)
/// * `service_info` - System service details if registered as a service
/// * `running_pid` - Process ID if the gateway is currently running
/// * `port_detected` - Whether port 18789 is responding
/// * `config` - Parsed configuration JSON if successfully loaded
#[derive(Debug, Clone)]
pub struct Installation {
    /// Path to the configuration file, if found.
    pub config_path: Option<PathBuf>,

    /// Path to the state directory (~/.moltbot or ~/.clawdbot).
    pub state_dir: Option<PathBuf>,

    /// Information about the registered system service.
    pub service_info: Option<ServiceInfo>,

    /// Process ID of the running gateway, if detected.
    pub running_pid: Option<u32>,

    /// Whether the gateway port is responding to connections.
    pub port_detected: bool,

    /// Parsed configuration JSON, if successfully loaded.
    pub config: Option<serde_json::Value>,
}

impl Installation {
    /// Creates a new empty Installation instance.
    ///
    /// All fields are initialized to `None` or `false`, representing
    /// no detected installation.
    pub fn new() -> Self {
        Self {
            config_path: None,
            state_dir: None,
            service_info: None,
            running_pid: None,
            port_detected: false,
            config: None,
        }
    }
}

impl Default for Installation {
    fn default() -> Self {
        Self::new()
    }
}

/// Detects a Clawdbot/Moltbot installation on the system.
///
/// Performs a comprehensive search for installation components including
/// configuration files, running processes, and system services.
///
/// # Arguments
///
/// * `verbose` - When true, prints diagnostic information to stderr
///
/// # Returns
///
/// An `Installation` struct containing all detected components.
/// If no installation is found, returns an empty Installation with
/// all fields set to `None` or `false`.
///
/// # Errors
///
/// Returns an error string if a critical failure occurs during detection.
///
/// # Example
///
/// ```rust,ignore
/// let installation = clawdguard::detect::find_installation(false)?;
/// if installation.config_path.is_some() {
///     println!("Found installation!");
/// }
/// ```
pub fn find_installation(verbose: bool) -> Result<Installation, String> {
    let mut installation = Installation::new();

    // Check for state directory and configuration file
    // Prefers ~/.moltbot over ~/.clawdbot if both exist
    if let Some(home) = dirs::home_dir() {
        for state_dir_name in crate::STATE_DIRS {
            let state_dir = home.join(state_dir_name);
            if state_dir.exists() && state_dir.is_dir() {
                installation.state_dir = Some(state_dir.clone());

                // Search for configuration file within state directory
                if let Some(config_path) = find_config_file(&state_dir, verbose) {
                    match parse_config(&config_path) {
                        Ok(config) => {
                            installation.config = Some(config);
                            installation.config_path = Some(config_path);
                        }
                        Err(e) => {
                            if verbose {
                                eprintln!("Warning: Could not parse config: {}", e);
                            }
                            // Store path even if parsing fails
                            installation.config_path = Some(config_path);
                        }
                    }
                }

                // Found a valid state directory, stop searching
                break;
            }
        }
    }

    // Check for running gateway process
    if let Some(pid) = find_running_process(verbose) {
        installation.running_pid = Some(pid);
        installation.port_detected = true;
    }

    // Check for registered system service
    if let Some(service) = find_service(verbose) {
        installation.service_info = Some(service);
    }

    // Verify port activity if not already detected via process
    if !installation.port_detected {
        installation.port_detected = check_port_in_use(crate::DEFAULT_PORT);
    }

    Ok(installation)
}

/// Checks if a TCP port is in use by attempting to connect.
///
/// # Arguments
///
/// * `port` - The port number to check
///
/// # Returns
///
/// `true` if a connection can be established, `false` otherwise
fn check_port_in_use(port: u16) -> bool {
    use std::net::TcpStream;
    use std::time::Duration;

    let addr = format!("127.0.0.1:{}", port);
    TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(500)).is_ok()
}
