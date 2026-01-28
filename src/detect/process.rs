//! Process detection for Clawdbot/Moltbot gateway.
//!
//! Scans running processes to identify active gateway instances,
//! enabling service management and status verification.
//!
//! ## Detection Method
//!
//! Processes are identified by matching:
//! - Process names: clawdbot, moltbot, node
//! - Command-line arguments containing: clawdbot, moltbot, gateway, port 18789
//!
//! ## Platform Support
//!
//! Uses the `sysinfo` crate for cross-platform process enumeration.
//! Works on macOS, Linux, and Windows (via WSL2).

use sysinfo::{ProcessRefreshKind, RefreshKind, System};

/// Process names that indicate a Clawdbot/Moltbot installation.
const PROCESS_NAMES: &[&str] = &["clawdbot", "moltbot", "node"];

/// Command-line patterns that identify gateway processes.
const COMMAND_PATTERNS: &[&str] = &["clawdbot", "moltbot", "gateway"];

/// Searches for a running Clawdbot/Moltbot gateway process.
///
/// Scans all running processes and matches against known process names
/// and command-line patterns to identify the gateway.
///
/// # Arguments
///
/// * `verbose` - When true, prints diagnostic information to stderr.
///
/// # Returns
///
/// The process ID (PID) of the gateway if found, or `None` if no gateway is running.
///
/// # Example
///
/// ```rust,no_run
/// if let Some(pid) = clawdguard::detect::find_running_process(false) {
///     println!("Gateway running with PID: {}", pid);
/// }
/// ```
pub fn find_running_process(verbose: bool) -> Option<u32> {
    let mut system = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    system.refresh_processes();

    for (pid, process) in system.processes() {
        let process_name = process.name().to_lowercase();
        let cmd_line: String = process
            .cmd()
            .iter()
            .map(|s| s.to_lowercase())
            .collect::<Vec<_>>()
            .join(" ");

        // Check if process name matches known gateway names
        let is_match = PROCESS_NAMES.iter().any(|name| process_name.contains(name))
            || COMMAND_PATTERNS
                .iter()
                .any(|pattern| cmd_line.contains(pattern));

        // Verify it's actually the gateway (not just any node process)
        let is_gateway = cmd_line.contains("gateway")
            || cmd_line.contains("18789")
            || process_name.contains("clawdbot")
            || process_name.contains("moltbot");

        if is_match && is_gateway {
            if verbose {
                eprintln!("Found gateway process: PID={}, name={}", pid, process_name);
            }
            return Some(pid.as_u32());
        }
    }

    if verbose {
        eprintln!("No running gateway process found");
    }

    None
}

/// Retrieves detailed information about a process by its PID.
///
/// # Arguments
///
/// * `pid` - The process ID to query.
///
/// # Returns
///
/// A tuple of (process_name, command_line) if the process exists, or `None` otherwise.
#[allow(dead_code)]
pub fn get_process_info(pid: u32) -> Option<(String, String)> {
    let mut system = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    system.refresh_processes();

    let sysinfo_pid = sysinfo::Pid::from_u32(pid);

    system.process(sysinfo_pid).map(|p| {
        let name = p.name().to_string();
        let cmd = p
            .cmd()
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        (name, cmd)
    })
}

/// Checks whether a process with the given PID is currently running.
///
/// # Arguments
///
/// * `pid` - The process ID to check.
///
/// # Returns
///
/// `true` if the process exists and is running, `false` otherwise.
pub fn is_process_running(pid: u32) -> bool {
    let mut system = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    system.refresh_processes();

    let sysinfo_pid = sysinfo::Pid::from_u32(pid);
    system.process(sysinfo_pid).is_some()
}

/// Terminates a process by its PID.
///
/// Sends a termination signal to the specified process. This is used
/// for stopping the gateway when service managers are unavailable.
///
/// # Arguments
///
/// * `pid` - The process ID to terminate.
///
/// # Returns
///
/// * `Ok(())` - Process was killed or doesn't exist
/// * `Err(msg)` - Failed to terminate the process
///
/// # Security Note
///
/// This function only terminates processes owned by the current user.
#[allow(dead_code)]
pub fn kill_process(pid: u32) -> Result<(), String> {
    let mut system = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    system.refresh_processes();

    let sysinfo_pid = sysinfo::Pid::from_u32(pid);

    if let Some(process) = system.process(sysinfo_pid) {
        if process.kill() {
            Ok(())
        } else {
            Err(format!("Failed to kill process {}", pid))
        }
    } else {
        // Process doesn't exist, consider it success
        Ok(())
    }
}
