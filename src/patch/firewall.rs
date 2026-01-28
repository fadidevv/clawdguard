//! Firewall rule management.
//!
//! Provides platform-specific firewall configuration to block external access
//! to the gateway port while preserving localhost connectivity.

/// The default gateway port that requires firewall protection.
#[cfg(target_os = "linux")]
const GATEWAY_PORT: u16 = 18789;

/// Adds a firewall rule to block external access to the gateway port.
///
/// On Linux, attempts to use UFW first, falling back to iptables.
/// On macOS, firewall modification is skipped (relies on loopback binding).
///
/// # Arguments
///
/// * `verbose` - When true, prints diagnostic information to stderr.
///
/// # Returns
///
/// * `Ok(true)` - Firewall rule was successfully added.
/// * `Ok(false)` - Firewall modification was skipped or not supported.
/// * `Err(msg)` - Firewall modification failed with the given error message.
pub fn add_firewall_rule(verbose: bool) -> Result<bool, String> {
    #[cfg(target_os = "linux")]
    {
        add_linux_firewall_rule(verbose)
    }

    #[cfg(target_os = "macos")]
    {
        add_macos_firewall_rule(verbose)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        if verbose {
            eprintln!("Firewall modification not supported on this platform");
        }
        Ok(false)
    }
}

/// Adds firewall rules on Linux systems using UFW or iptables.
#[cfg(target_os = "linux")]
fn add_linux_firewall_rule(verbose: bool) -> Result<bool, String> {
    if is_ufw_available() {
        if verbose {
            eprintln!("Using ufw to add firewall rule");
        }
        return add_ufw_rule(verbose);
    }

    if is_iptables_available() {
        if verbose {
            eprintln!("Using iptables to add firewall rule");
        }
        return add_iptables_rule(verbose);
    }

    if verbose {
        eprintln!("No supported firewall found (tried ufw, iptables)");
    }

    Ok(false)
}

/// Checks if UFW (Uncomplicated Firewall) is installed on the system.
#[cfg(target_os = "linux")]
fn is_ufw_available() -> bool {
    use std::process::Command;
    Command::new("which")
        .arg("ufw")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Checks if iptables is installed on the system.
#[cfg(target_os = "linux")]
fn is_iptables_available() -> bool {
    use std::process::Command;
    Command::new("which")
        .arg("iptables")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Adds a UFW rule to deny external access to the gateway port.
#[cfg(target_os = "linux")]
fn add_ufw_rule(verbose: bool) -> Result<bool, String> {
    use std::process::Command;
    let status = Command::new("sudo")
        .args(["ufw", "status"])
        .output()
        .map_err(|e| format!("Failed to check ufw status: {}", e))?;

    let status_str = String::from_utf8_lossy(&status.stdout);

    if !status_str.contains("active") {
        if verbose {
            eprintln!("ufw is not active, skipping firewall rule");
        }
        return Ok(false);
    }

    let output = Command::new("sudo")
        .args([
            "ufw",
            "deny",
            "from",
            "any",
            "to",
            "any",
            "port",
            &GATEWAY_PORT.to_string(),
            "proto",
            "tcp",
        ])
        .output()
        .map_err(|e| format!("Failed to add ufw rule: {}", e))?;

    if output.status.success() {
        if verbose {
            eprintln!("Added ufw rule to deny port {}", GATEWAY_PORT);
        }
        Ok(true)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);

        if stderr.contains("existing") || stderr.contains("already") {
            if verbose {
                eprintln!("Firewall rule already exists");
            }
            return Ok(false);
        }

        Err(format!("Failed to add ufw rule: {}", stderr))
    }
}

/// Adds iptables rules to allow localhost and block external access to the gateway port.
#[cfg(target_os = "linux")]
fn add_iptables_rule(verbose: bool) -> Result<bool, String> {
    use std::process::Command;
    let check = Command::new("sudo")
        .args([
            "iptables",
            "-C",
            "INPUT",
            "-p",
            "tcp",
            "--dport",
            &GATEWAY_PORT.to_string(),
            "-s",
            "127.0.0.1",
            "-j",
            "ACCEPT",
        ])
        .output();

    if let Ok(output) = check {
        if output.status.success() {
            if verbose {
                eprintln!("iptables rule already exists for port {}", GATEWAY_PORT);
            }
            return Ok(false);
        }
    }

    let accept_output = Command::new("sudo")
        .args([
            "iptables",
            "-A",
            "INPUT",
            "-p",
            "tcp",
            "--dport",
            &GATEWAY_PORT.to_string(),
            "-s",
            "127.0.0.1",
            "-j",
            "ACCEPT",
        ])
        .output()
        .map_err(|e| format!("Failed to add iptables accept rule: {}", e))?;

    if !accept_output.status.success() {
        let stderr = String::from_utf8_lossy(&accept_output.stderr);
        return Err(format!("Failed to add iptables accept rule: {}", stderr));
    }

    let drop_output = Command::new("sudo")
        .args([
            "iptables",
            "-A",
            "INPUT",
            "-p",
            "tcp",
            "--dport",
            &GATEWAY_PORT.to_string(),
            "-j",
            "DROP",
        ])
        .output()
        .map_err(|e| format!("Failed to add iptables drop rule: {}", e))?;

    if drop_output.status.success() {
        if verbose {
            eprintln!("Added iptables rules for port {}", GATEWAY_PORT);
        }
        Ok(true)
    } else {
        let stderr = String::from_utf8_lossy(&drop_output.stderr);
        Err(format!("Failed to add iptables drop rule: {}", stderr))
    }
}

#[cfg(target_os = "macos")]
fn add_macos_firewall_rule(verbose: bool) -> Result<bool, String> {
    if verbose {
        eprintln!("macOS firewall (pf) modification skipped");
        eprintln!("The config has been patched to bind to loopback only");
    }

    Ok(false)
}

/// Checks if a firewall rule for the gateway port already exists.
///
/// # Returns
///
/// `true` if a firewall rule exists for the gateway port, `false` otherwise.
#[allow(dead_code)]
pub fn firewall_rule_exists() -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        if is_ufw_available() {
            let output = Command::new("sudo")
                .args(["ufw", "status", "numbered"])
                .output();

            if let Ok(o) = output {
                let stdout = String::from_utf8_lossy(&o.stdout);
                return stdout.contains(&GATEWAY_PORT.to_string());
            }
        }

        if is_iptables_available() {
            let output = Command::new("sudo").args(["iptables", "-L", "-n"]).output();

            if let Ok(o) = output {
                let stdout = String::from_utf8_lossy(&o.stdout);
                return stdout.contains(&GATEWAY_PORT.to_string());
            }
        }

        false
    }

    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Removes the firewall rule blocking the gateway port.
///
/// # Returns
///
/// `Ok(())` on success, `Err` with message on failure.
#[allow(dead_code)]
pub fn remove_firewall_rule() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        if is_ufw_available() {
            Command::new("sudo")
                .args(["ufw", "delete", "deny", &GATEWAY_PORT.to_string(), "tcp"])
                .output()
                .map_err(|e| format!("Failed to remove ufw rule: {}", e))?;
        }
    }

    Ok(())
}
