//! # ClawdGuard
//!
//! Security hardening library for Clawdbot/Moltbot installations.

#![allow(unused)]
//!
//! ClawdGuard provides automated detection, analysis, and remediation of security
//! vulnerabilities in Clawdbot/Moltbot gateway configurations. It addresses the
//! critical issue of exposed gateways that allow unauthorized access to API keys,
//! shell command execution, and sensitive user data.
//!
//! ## Architecture
//!
//! The library follows a four-phase security workflow:
//!
//! 1. **Detection** ([`detect`]) - Locates installation files, running processes, and system services
//! 2. **Analysis** ([`analyze`]) - Evaluates security posture and calculates risk scores
//! 3. **Patching** ([`patch`]) - Applies configuration fixes with automatic backups
//! 4. **Verification** ([`verify`]) - Confirms remediation success
//!
//! ## Risk Assessment
//!
//! Security vulnerabilities are scored on a 0-10 scale:
//!
//! | Score | Level | Description |
//! |-------|-------|-------------|
//! | 0-3   | Low   | Minor issues or already secure |
//! | 4-6   | Medium| Some security concerns present |
//! | 7-10  | Critical | Exposed to internet, immediate action required |
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use clawdguard::{detect, analyze, patch, verify};
//!
//! async fn secure_installation() -> Result<(), String> {
//!     // Phase 1: Detect installation
//!     let installation = detect::find_installation(false)?;
//!
//!     // Phase 2: Analyze security risks
//!     let risk_report = analyze::analyze_installation(&installation, false).await?;
//!
//!     if !risk_report.is_secure() {
//!         // Phase 3: Apply security patches
//!         let patch_result = patch::apply_patches(
//!             &installation,
//!             &risk_report,
//!             None,  // Auto-generate token
//!             None,  // Default backup location
//!             false, // Include firewall rules
//!             false, // Non-verbose
//!         )?;
//!
//!         // Phase 4: Verify fixes
//!         let verification = verify::verify_fixes(&installation, false).await?;
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Platform Support
//!
//! | Platform | Detection | Patching | Firewall |
//! |----------|-----------|----------|----------|
//! | macOS    | Full      | Full     | Via loopback binding |
//! | Linux    | Full      | Full     | UFW/iptables |
//! | Windows  | WSL2 only | WSL2 only| Not supported |

pub mod analyze;
pub mod detect;
pub mod output;
pub mod patch;
pub mod verify;

/// Default gateway port used by Clawdbot/Moltbot.
///
/// This port (18789) is the standard communication endpoint for the gateway service.
/// External exposure of this port without authentication is a critical security risk.
pub const DEFAULT_PORT: u16 = 18789;

/// Configuration file names to search for during installation detection.
///
/// The detection module searches for these files in the state directory
/// to locate and parse gateway configuration.
pub const CONFIG_FILENAMES: &[&str] = &["clawdbot.json", "moltbot.json"];

/// State directory names relative to the user's home directory.
///
/// Contains configuration files, logs, and runtime state for the installation.
/// The detection module checks these in order, preferring `.moltbot` if it exists.
pub const STATE_DIRS: &[&str] = &[".moltbot", ".clawdbot"];
