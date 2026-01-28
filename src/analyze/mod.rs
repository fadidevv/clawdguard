//! Security analysis module.
//!
//! Analyzes Clawdbot/Moltbot installations for security vulnerabilities
//! including exposed bindings, missing authentication, and insecure permissions.
//!
//! ## Risk Score Calculation
//!
//! Security vulnerabilities are weighted and summed to produce a 0-10 risk score:
//!
//! | Vulnerability | Points | Severity |
//! |--------------|--------|----------|
//! | Exposed bind address (0.0.0.0, lan, all) | +3 | Critical |
//! | Missing authentication | +4 | Critical |
//! | Port externally reachable | +2 | Critical |
//! | mDNS information leak | +1 | Medium |
//! | Open file permissions | +1 | Low |
//!
//! ## Risk Levels
//!
//! | Score | Level | Action |
//! |-------|-------|--------|
//! | 0-3   | Low   | Monitor only |
//! | 4-6   | Medium | Review recommended |
//! | 7-10  | Critical | Immediate remediation required |

mod config_risk;
mod network;
pub mod permissions;

pub use config_risk::{analyze_config, ConfigRisk};
pub use network::check_external_exposure;
pub use permissions::{check_file_permissions, fix_directory_permissions, fix_file_permissions};

use crate::detect::Installation;
use serde::Serialize;

/// Comprehensive security risk report for an installation.
///
/// Contains detailed findings from all security checks along with
/// the calculated risk score.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RiskReport {
    /// Whether the gateway bind address exposes the service to the network.
    pub bind_exposed: bool,

    /// The current bind address value (e.g., "0.0.0.0", "loopback").
    pub bind_value: Option<String>,

    /// Whether authentication is missing or improperly configured.
    pub auth_missing: bool,

    /// The current authentication mode (e.g., "none", "token").
    pub auth_mode: Option<String>,

    /// Whether mDNS is broadcasting sensitive system information.
    pub mdns_leaking: bool,

    /// The current mDNS mode (e.g., "full", "minimal").
    pub mdns_mode: Option<String>,

    /// Whether file permissions are too permissive.
    pub permissions_too_open: bool,

    /// The current file permission mode as octal string (e.g., "644").
    pub current_permissions: Option<String>,

    /// Whether the port is reachable from external networks.
    pub port_externally_reachable: bool,

    /// The external IP address used for reachability testing.
    pub external_ip: Option<String>,
}

impl RiskReport {
    /// Creates a new empty risk report.
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculates the overall risk score from 0-10.
    ///
    /// The score is calculated by summing weighted risk factors:
    /// - Exposed bind: +3
    /// - Missing auth: +4
    /// - External port reachable: +2
    /// - mDNS leaking: +1
    /// - Open permissions: +1
    ///
    /// The maximum score is capped at 10.
    ///
    /// # Returns
    ///
    /// A risk score from 0 (secure) to 10 (critical).
    pub fn risk_score(&self) -> u8 {
        let mut score: u8 = 0;

        if self.bind_exposed {
            score += 3;
        }
        if self.auth_missing {
            score += 4;
        }
        if self.port_externally_reachable {
            score += 2;
        }
        if self.mdns_leaking {
            score += 1;
        }
        if self.permissions_too_open {
            score += 1;
        }

        score.min(10)
    }

    /// Checks if the installation is considered secure.
    ///
    /// An installation is secure if all of the following are true:
    /// - Bind address is loopback only
    /// - Authentication is properly configured
    /// - mDNS is not leaking information
    /// - File permissions are restrictive
    /// - Port is not externally reachable
    ///
    /// # Returns
    ///
    /// `true` if no security vulnerabilities are detected.
    pub fn is_secure(&self) -> bool {
        !self.bind_exposed
            && !self.auth_missing
            && !self.mdns_leaking
            && !self.permissions_too_open
            && !self.port_externally_reachable
    }

    /// Generates human-readable descriptions of all identified risks.
    ///
    /// # Returns
    ///
    /// A vector of risk descriptions suitable for display to users.
    #[allow(dead_code)]
    pub fn risk_descriptions(&self) -> Vec<String> {
        let mut descriptions = Vec::new();

        if self.bind_exposed {
            descriptions.push(format!(
                "Gateway bound to '{}' (accessible from network)",
                self.bind_value.as_deref().unwrap_or("unknown")
            ));
        }

        if self.auth_missing {
            descriptions.push(format!(
                "No authentication configured (mode: {})",
                self.auth_mode.as_deref().unwrap_or("none")
            ));
        }

        if self.port_externally_reachable {
            descriptions.push(format!(
                "Port 18789 is reachable from external IP ({})",
                self.external_ip.as_deref().unwrap_or("unknown")
            ));
        }

        if self.mdns_leaking {
            descriptions.push(format!(
                "mDNS broadcasting system information (mode: {})",
                self.mdns_mode.as_deref().unwrap_or("full")
            ));
        }

        if self.permissions_too_open {
            descriptions.push(format!(
                "Config file permissions too open ({})",
                self.current_permissions.as_deref().unwrap_or("unknown")
            ));
        }

        descriptions
    }
}

/// Performs a comprehensive security analysis of an installation.
///
/// Checks all security aspects including configuration settings,
/// file permissions, and network exposure.
///
/// # Arguments
///
/// * `installation` - The installation to analyze
/// * `verbose` - When true, prints diagnostic information to stderr
///
/// # Returns
///
/// A complete risk report with all findings and calculated risk score.
///
/// # Errors
///
/// Returns an error string if analysis fails critically.
///
/// # Example
///
/// ```rust,ignore
/// let report = clawdguard::analyze::analyze_installation(&installation, false).await?;
/// if report.risk_score() > 6 {
///     println!("Critical security issues found!");
/// }
/// ```
pub async fn analyze_installation(
    installation: &Installation,
    verbose: bool,
) -> Result<RiskReport, String> {
    let mut report = RiskReport::new();

    // Analyze configuration settings
    if let Some(ref config) = installation.config {
        let config_risk = analyze_config(config, verbose);

        report.bind_exposed = config_risk.bind_exposed;
        report.bind_value = config_risk.bind_value;
        report.auth_missing = config_risk.auth_missing;
        report.auth_mode = config_risk.auth_mode;
        report.mdns_leaking = config_risk.mdns_leaking;
        report.mdns_mode = config_risk.mdns_mode;
    }

    // Check file permissions
    if let Some(ref config_path) = installation.config_path {
        let perms = check_file_permissions(config_path, verbose);
        report.permissions_too_open = perms.too_open;
        report.current_permissions = perms.mode_string;
    }

    // Check external network exposure
    if report.bind_exposed || installation.port_detected {
        let exposure = check_external_exposure(verbose).await;
        report.port_externally_reachable = exposure.is_reachable;
        report.external_ip = exposure.external_ip;
    }

    Ok(report)
}
