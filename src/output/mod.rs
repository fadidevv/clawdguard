//! Terminal output formatting module.
//!
//! Provides colorful, user-friendly terminal output for the ClawdGuard CLI.
//! All visual elements including banners, progress indicators, tables, and
//! status messages are centralized here for consistent presentation.
//!
//! ## Module Structure
//!
//! - [`printer`] - Core output functions for terminal display
//!
//! ## Features
//!
//! - Colorized output using ANSI escape codes
//! - Progress spinners and bars for long-running operations
//! - Formatted tables for risk assessment display
//! - Consistent iconography and styling throughout
//!
//! ## Usage
//!
//! ```rust,ignore
//! use clawdguard::output::printer;
//!
//! printer::print_banner();
//! printer::print_section(1, 4, "Detecting installation");
//! printer::print_success("Found configuration file");
//! ```

pub mod printer;
