//! System service detection for Clawdbot/Moltbot.
//!
//! Detects and manages gateway services registered with the operating system's
//! service manager. Supports launchd on macOS and systemd on Linux.
//!
//! ## Supported Service Managers
//!
//! | Platform | Manager  | Service Location |
//! |----------|----------|------------------|
//! | macOS    | launchd  | ~/Library/LaunchAgents/*.plist |
//! | Linux    | systemd  | ~/.config/systemd/user/*.service |
//!
//! ## Service Names
//!
//! The following service names are searched (in order):
//!
//! **macOS (launchd):**
//! - `bot.molt.gateway` (current primary)
//! - `com.clawdbot.gateway` (legacy)
//! - `com.moltbot.gateway` (legacy)
//! - `com.steipete.clawdbot.gateway` (deprecated legacy)
//!
//! **Linux (systemd):**
//! - `moltbot-gateway` (current primary)
//! - `moltbot.service` (legacy)
//! - `clawdbot.service` (legacy)

use std::path::PathBuf;
use std::process::Command;

/// Information about a detected system service.
///
/// Contains details needed to manage the service lifecycle including
/// restart, stop, and status operations.
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    /// The service identifier (e.g., "bot.molt.gateway" or "moltbot-gateway").
    pub name: String,

    /// The type of service manager (launchd or systemd).
    pub service_type: ServiceType,

    /// Path to the service configuration file.
    pub config_path: PathBuf,

    /// Whether the service is currently running.
    pub is_running: bool,

    /// Process ID if the service is running.
    pub pid: Option<u32>,
}

/// Supported service manager types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceType {
    /// macOS launchd service manager.
    Launchd,

    /// Linux systemd service manager (user mode).
    Systemd,
}

impl std::fmt::Display for ServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceType::Launchd => write!(f, "launchd"),
            ServiceType::Systemd => write!(f, "systemd"),
        }
    }
}

/// Service names for macOS launchd.
/// Checked in order: current primary first, then legacy names.
#[cfg(target_os = "macos")]
const LAUNCHD_SERVICE_NAMES: &[&str] = &[
    "bot.molt.gateway",           // Current primary
    "com.clawdbot.gateway",       // Legacy
    "com.moltbot.gateway",        // Legacy
    "com.steipete.clawdbot.gateway", // Deprecated legacy
];

/// Service names for Linux systemd.
/// Checked in order: current primary first, then legacy names.
#[cfg(target_os = "linux")]
const SYSTEMD_SERVICE_NAMES: &[&str] = &[
    "moltbot-gateway",     // Current primary
    "moltbot-gateway.service",
    "moltbot",             // Legacy
    "moltbot.service",
    "clawdbot",            // Legacy
    "clawdbot.service",
];

/// Detects a registered gateway service on the system.
///
/// Checks for launchd services on macOS and systemd services on Linux.
///
/// # Arguments
///
/// * `verbose` - When true, prints diagnostic information to stderr.
///
/// # Returns
///
/// Service information if a registered service is found, or `None` otherwise.
pub fn find_service(verbose: bool) -> Option<ServiceInfo> {
    #[cfg(target_os = "macos")]
    {
        find_launchd_service(verbose)
    }

    #[cfg(target_os = "linux")]
    {
        find_systemd_service(verbose)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        if verbose {
            eprintln!("Service detection not supported on this platform");
        }
        None
    }
}

/// Searches for a launchd service on macOS.
#[cfg(target_os = "macos")]
fn find_launchd_service(verbose: bool) -> Option<ServiceInfo> {
    let home = dirs::home_dir()?;
    let launch_agents_dir = home.join("Library/LaunchAgents");

    if !launch_agents_dir.exists() {
        if verbose {
            eprintln!("LaunchAgents directory not found");
        }
        return None;
    }

    for service_name in LAUNCHD_SERVICE_NAMES {
        let plist_path = launch_agents_dir.join(format!("{}.plist", service_name));

        if plist_path.exists() {
            if verbose {
                eprintln!("Found launchd service: {}", plist_path.display());
            }

            let (is_running, pid) = check_launchd_status(service_name);

            return Some(ServiceInfo {
                name: service_name.to_string(),
                service_type: ServiceType::Launchd,
                config_path: plist_path,
                is_running,
                pid,
            });
        }
    }

    if verbose {
        eprintln!("No launchd service found");
    }

    None
}

/// Checks the status of a launchd service.
///
/// Uses `launchctl list` to determine if the service is running and get its PID.
#[cfg(target_os = "macos")]
fn check_launchd_status(service_name: &str) -> (bool, Option<u32>) {
    let output = Command::new("launchctl")
        .args(["list", service_name])
        .output();

    match output {
        Ok(output) => {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // Parse PID from launchctl output (first column)
                let pid = stdout.lines().next().and_then(|line| {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    parts
                        .first()
                        .and_then(|s| s.parse::<u32>().ok())
                        .filter(|&p| p > 0)
                });

                (true, pid)
            } else {
                (false, None)
            }
        }
        Err(_) => (false, None),
    }
}

/// Searches for a systemd service on Linux.
#[cfg(target_os = "linux")]
fn find_systemd_service(verbose: bool) -> Option<ServiceInfo> {
    let home = dirs::home_dir()?;
    let systemd_user_dir = home.join(".config/systemd/user");

    // Check for service unit files
    if systemd_user_dir.exists() {
        for service_name in SYSTEMD_SERVICE_NAMES {
            let service_file = if service_name.ends_with(".service") {
                systemd_user_dir.join(service_name)
            } else {
                systemd_user_dir.join(format!("{}.service", service_name))
            };

            if service_file.exists() {
                if verbose {
                    eprintln!("Found systemd service: {}", service_file.display());
                }

                let base_name = service_name.trim_end_matches(".service");
                let (is_running, pid) = check_systemd_status(base_name);

                return Some(ServiceInfo {
                    name: base_name.to_string(),
                    service_type: ServiceType::Systemd,
                    config_path: service_file,
                    is_running,
                    pid,
                });
            }
        }
    }

    // Check if service is running even without a unit file
    for service_name in SYSTEMD_SERVICE_NAMES {
        let base_name = service_name.trim_end_matches(".service");
        let (is_running, pid) = check_systemd_status(base_name);

        if is_running {
            if verbose {
                eprintln!("Found running systemd service: {}", base_name);
            }

            return Some(ServiceInfo {
                name: base_name.to_string(),
                service_type: ServiceType::Systemd,
                config_path: systemd_user_dir.join(format!("{}.service", base_name)),
                is_running,
                pid,
            });
        }
    }

    if verbose {
        eprintln!("No systemd service found");
    }

    None
}

/// Checks the status of a systemd user service.
///
/// Uses `systemctl --user` to determine if the service is active and get its PID.
#[cfg(target_os = "linux")]
fn check_systemd_status(service_name: &str) -> (bool, Option<u32>) {
    let status = Command::new("systemctl")
        .args(["--user", "is-active", service_name])
        .output();

    let is_running = status.map(|o| o.status.success()).unwrap_or(false);

    let pid = if is_running {
        Command::new("systemctl")
            .args([
                "--user",
                "show",
                service_name,
                "--property=MainPID",
                "--value",
            ])
            .output()
            .ok()
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .parse::<u32>()
                    .ok()
                    .filter(|&p| p > 0)
            })
    } else {
        None
    };

    (is_running, pid)
}

/// Restarts a service using the appropriate service manager.
///
/// # Arguments
///
/// * `service` - The service to restart.
///
/// # Returns
///
/// * `Ok(())` - Service restarted successfully
/// * `Err(msg)` - Failed to restart with error message
pub fn restart_service_manager(service: &ServiceInfo) -> Result<(), String> {
    match service.service_type {
        ServiceType::Launchd => restart_launchd_service(service),
        ServiceType::Systemd => restart_systemd_service(service),
    }
}

/// Restarts a launchd service by unloading and reloading the plist.
fn restart_launchd_service(service: &ServiceInfo) -> Result<(), String> {
    // Unload the service (ignore errors if not loaded)
    let _ = Command::new("launchctl")
        .args(["unload", service.config_path.to_str().unwrap_or("")])
        .output();

    // Brief pause to ensure clean unload
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Load the service
    let load = Command::new("launchctl")
        .args(["load", service.config_path.to_str().unwrap_or("")])
        .output()
        .map_err(|e| format!("Failed to load service: {}", e))?;

    if !load.status.success() {
        let stderr = String::from_utf8_lossy(&load.stderr);
        return Err(format!("Failed to load service: {}", stderr));
    }

    Ok(())
}

/// Restarts a systemd user service.
fn restart_systemd_service(service: &ServiceInfo) -> Result<(), String> {
    let output = Command::new("systemctl")
        .args(["--user", "restart", &service.name])
        .output()
        .map_err(|e| format!("Failed to restart service: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to restart service: {}", stderr));
    }

    Ok(())
}

/// Stops a service using the appropriate service manager.
///
/// # Arguments
///
/// * `service` - The service to stop.
///
/// # Returns
///
/// * `Ok(())` - Service stopped successfully
/// * `Err(msg)` - Failed to stop with error message
#[allow(dead_code)]
pub fn stop_service_manager(service: &ServiceInfo) -> Result<(), String> {
    match service.service_type {
        ServiceType::Launchd => {
            Command::new("launchctl")
                .args(["unload", service.config_path.to_str().unwrap_or("")])
                .output()
                .map_err(|e| format!("Failed to stop service: {}", e))?;
            Ok(())
        }
        ServiceType::Systemd => {
            Command::new("systemctl")
                .args(["--user", "stop", &service.name])
                .output()
                .map_err(|e| format!("Failed to stop service: {}", e))?;
            Ok(())
        }
    }
}
