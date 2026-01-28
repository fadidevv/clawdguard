//! Service restart and verification.
//!
//! Handles gateway service lifecycle operations including restart and status checks,
//! supporting both system service managers (launchd, systemd) and CLI fallbacks.
//!
//! ## Restart Strategy
//!
//! 1. Try system service manager (launchd on macOS, systemd on Linux)
//! 2. Fall back to CLI commands (`clawdbot gateway restart`, `moltbot gateway restart`)
//!
//! ## Platform Support
//!
//! | Platform | Service Manager | CLI Fallback |
//! |----------|-----------------|--------------|
//! | macOS    | launchd         | clawdbot/moltbot CLI |
//! | Linux    | systemd (user)  | clawdbot/moltbot CLI |
//! | Windows  | Not supported   | clawdbot/moltbot CLI |

use crate::detect::{
    is_process_running, restart_service_manager, stop_service_manager, Installation,
};
use std::process::Command;

/// Restarts the gateway service to apply configuration changes.
///
/// Attempts to restart using the system service manager first, falling
/// back to CLI commands if no service manager is available.
///
/// # Arguments
///
/// * `installation` - The installation containing service information.
/// * `verbose` - When true, prints diagnostic information to stderr.
///
/// # Returns
///
/// * `Ok(())` - Service was successfully restarted.
/// * `Err(msg)` - Failed to restart the service.
///
/// # Example
///
/// ```rust,ignore
/// restart_service(&installation, false)?;
/// // Wait for service to become available
/// tokio::time::sleep(Duration::from_secs(2)).await;
/// ```
pub fn restart_service(installation: &Installation, verbose: bool) -> Result<(), String> {
    // Try service manager first (preferred method)
    if let Some(ref service) = installation.service_info {
        if verbose {
            eprintln!("Restarting via service manager: {}", service.service_type);
        }

        return restart_service_manager(service);
    }

    // Fall back to CLI commands
    if verbose {
        eprintln!("No service manager, trying CLI restart");
    }

    restart_via_cli(verbose)
}

/// Attempts to restart the gateway using CLI commands.
///
/// Tries both `clawdbot` and `moltbot` CLI tools in sequence until
/// one succeeds.
///
/// # Arguments
///
/// * `verbose` - Enable diagnostic output.
///
/// # Returns
///
/// * `Ok(())` - CLI restart succeeded.
/// * `Err(msg)` - Neither CLI tool could restart the gateway.
fn restart_via_cli(verbose: bool) -> Result<(), String> {
    // Try clawdbot CLI first
    let clawdbot_result = Command::new("clawdbot")
        .args(["gateway", "restart"])
        .output();

    if let Ok(output) = clawdbot_result {
        if output.status.success() {
            if verbose {
                eprintln!("Restarted via clawdbot CLI");
            }
            return Ok(());
        }
    }

    // Try moltbot CLI as fallback
    let moltbot_result = Command::new("moltbot")
        .args(["gateway", "restart"])
        .output();

    if let Ok(output) = moltbot_result {
        if output.status.success() {
            if verbose {
                eprintln!("Restarted via moltbot CLI");
            }
            return Ok(());
        }
    }

    Err("Could not restart gateway via CLI".to_string())
}

/// Checks if the gateway service is currently running.
///
/// First checks the service manager status, then falls back to
/// checking if the process is running by PID.
///
/// # Arguments
///
/// * `installation` - The installation to check.
///
/// # Returns
///
/// `true` if the service is running, `false` otherwise.
#[allow(dead_code)]
pub fn is_service_running(installation: &Installation) -> bool {
    // Check service manager status
    if let Some(ref service) = installation.service_info {
        return service.is_running;
    }

    // Fall back to process check
    if let Some(pid) = installation.running_pid {
        return is_process_running(pid);
    }

    false
}

/// Stops the gateway service.
///
/// Attempts to stop using the system service manager first, falling
/// back to CLI commands if no service manager is available.
///
/// # Arguments
///
/// * `installation` - The installation to stop.
/// * `verbose` - Enable diagnostic output.
///
/// # Returns
///
/// * `Ok(())` - Service was stopped (or was already stopped).
/// * `Err(msg)` - Failed to stop the service.
#[allow(dead_code)]
pub fn stop_gateway(installation: &Installation, verbose: bool) -> Result<(), String> {
    // Try service manager first
    if let Some(ref service) = installation.service_info {
        if verbose {
            eprintln!("Stopping via service manager");
        }
        return stop_service_manager(service);
    }

    // Try CLI commands (ignore errors as service may already be stopped)
    let _ = Command::new("clawdbot").args(["gateway", "stop"]).output();
    let _ = Command::new("moltbot").args(["gateway", "stop"]).output();

    Ok(())
}
