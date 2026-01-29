//! Colorful terminal output formatting.
//!
//! Provides all visual output functions for the ClawdGuard CLI including
//! banners, status messages, progress indicators, and formatted tables.
//! Uses ANSI color codes for enhanced terminal presentation.
//!
//! ## Output Categories
//!
//! | Function Type | Purpose | Icon |
//! |---------------|---------|------|
//! | `print_success` | Completed operations | ✓ (green) |
//! | `print_error` | Failed operations | ✗ (red) |
//! | `print_warning` | Caution messages | ⚠ (yellow) |
//! | `print_info` | Informational notes | ℹ (blue) |
//!
//! ## Progress Indicators
//!
//! - Spinners for indeterminate operations
//! - Progress bars for operations with known length
//!
//! ## Color Scheme
//!
//! - Cyan: Primary accent, headers, progress
//! - Green: Success states
//! - Yellow: Warnings, important notices
//! - Red: Errors, critical issues
//! - White/Gray: Standard text, secondary information

use colored::Colorize;
use comfy_table::{presets::UTF8_FULL_CONDENSED, ContentArrangement, Table};
use indicatif::{ProgressBar, ProgressStyle};

/// Prints the application banner with version information.
pub fn print_banner() {
    println!();
    println!("{}", "  🦞 ClawdGuard".cyan().bold());
    println!("{}", "  Security hardening for Clawdbot/Moltbot".bright_black());
    println!("{}", "  v1.0.0".bright_black());
    println!();
    println!("{}", "━".repeat(70).bright_black());
    println!();
}

/// Prints a numbered section header for workflow steps.
///
/// Displays the current step number, total steps, and a descriptive
/// message with an appropriate icon based on the step number.
///
/// # Arguments
///
/// * `step` - Current step number (1-4 for standard workflow).
/// * `total` - Total number of steps in the workflow.
/// * `message` - Description of the current step.
///
/// # Icon Mapping
///
/// | Step | Icon | Typical Usage |
/// |------|------|---------------|
/// | 1 | 🔍 | Detection phase |
/// | 2 | ⚠️ | Analysis phase |
/// | 3 | 🔧 | Patching phase |
/// | 4 | ✅ | Verification phase |
/// | Other | → | Generic step |
///
/// # Output Format
///
/// ```text
/// [1/4] 🔍 Detecting installation
/// ```
pub fn print_section(step: u8, total: u8, message: &str) {
    let icon = match step {
        1 => "🔍",
        2 => "⚠️ ",
        3 => "🔧",
        4 => "✅",
        _ => "→",
    };

    println!(
        "{} {} {}",
        format!("[{}/{}]", step, total).cyan().bold(),
        icon,
        message.white().bold()
    );
}

/// Prints a success message with a green checkmark.
///
/// Indicates that an operation completed successfully.
///
/// # Arguments
///
/// * `message` - The success message to display.
///
/// # Output Format
///
/// ```text
///       ✓ Configuration file found
/// ```
pub fn print_success(message: &str) {
    println!("      {} {}", "✓".green().bold(), message);
}

/// Prints an error message with a red X mark.
///
/// Indicates that an operation failed or encountered a problem.
///
/// # Arguments
///
/// * `message` - The error message to display.
///
/// # Output Format
///
/// ```text
///       ✗ Failed to read configuration
/// ```
pub fn print_error(message: &str) {
    println!("      {} {}", "✗".red().bold(), message.red());
}

/// Prints a warning message with a yellow warning symbol.
///
/// Indicates a condition that requires attention but is not fatal.
///
/// # Arguments
///
/// * `message` - The warning message to display.
///
/// # Output Format
///
/// ```text
///       ⚠ Authentication not configured
/// ```
pub fn print_warning(message: &str) {
    println!("      {} {}", "⚠".yellow().bold(), message.yellow());
}

/// Prints an informational message with a blue info symbol.
///
/// Provides additional context or non-critical information.
///
/// # Arguments
///
/// * `message` - The informational message to display.
///
/// # Output Format
///
/// ```text
///       ℹ Running on macOS with launchd
/// ```
pub fn print_info(message: &str) {
    println!("      {} {}", "ℹ".blue(), message.bright_black());
}

/// Prints a progress indicator message with a cyan arrow.
///
/// Indicates that an operation is in progress.
///
/// # Arguments
///
/// * `message` - The progress message to display.
///
/// # Output Format
///
/// ```text
///       → Processing configuration...
/// ```
#[allow(dead_code)]
pub fn print_progress(message: &str) {
    println!("      {} {}", "→".cyan(), message);
}

/// Prints a key-value pair with styled formatting.
///
/// Displays configuration details or status information in a
/// consistent format with the key in gray and value in white.
///
/// # Arguments
///
/// * `key` - The label or key name.
/// * `value` - The value to display.
///
/// # Output Format
///
/// ```text
///       Config path: ~/.clawdbot/clawdbot.json
/// ```
pub fn print_kv(key: &str, value: &str) {
    println!("      {}: {}", key.bright_black(), value.white());
}

/// Prints a horizontal separator line.
///
/// Creates visual separation between sections of output.
/// Renders as 70 horizontal line characters in gray.
///
/// # Output Format
///
/// ```text
///
/// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
///
/// ```
pub fn print_separator() {
    println!();
    println!("{}", "━".repeat(70).bright_black());
    println!();
}

/// Creates an animated spinner for indeterminate progress.
///
/// Returns a progress bar configured as a spinner that animates
/// while work is being performed. The spinner auto-ticks every 80ms.
///
/// # Arguments
///
/// * `message` - The message to display next to the spinner.
///
/// # Returns
///
/// A [`ProgressBar`] instance configured as a spinner. Call `.finish()`
/// or `.finish_with_message()` when the operation completes.
///
/// # Example
///
/// ```rust,ignore
/// let spinner = create_spinner("Restarting service...");
/// // ... perform operation ...
/// spinner.finish_with_message("Service restarted");
/// ```
///
/// # Output Format
///
/// ```text
///       ⠋ Restarting service...
/// ```
pub fn create_spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
            .template("      {spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb
}

/// Creates a progress bar for operations with known length.
///
/// Returns a progress bar that visually indicates completion percentage.
/// Useful for operations like file processing or batch operations.
///
/// # Arguments
///
/// * `len` - Total number of items or steps.
/// * `message` - The message to display with the progress bar.
///
/// # Returns
///
/// A [`ProgressBar`] instance. Call `.inc(1)` to advance and `.finish()`
/// when complete.
///
/// # Example
///
/// ```rust,ignore
/// let pb = create_progress_bar(100, "Processing files");
/// for _ in 0..100 {
///     // ... process item ...
///     pb.inc(1);
/// }
/// pb.finish();
/// ```
///
/// # Output Format
///
/// ```text
///       Processing files [████████████░░░░░░░░░░░░░░░░░░] 12/100
/// ```
#[allow(dead_code)]
pub fn create_progress_bar(len: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("      {msg} [{bar:30.cyan/bright_black}] {pos}/{len}")
            .unwrap()
            .progress_chars("█▓░"),
    );
    pb.set_message(message.to_string());
    pb
}

/// Prints a formatted table with headers and rows.
///
/// Renders a UTF-8 bordered table suitable for terminal display.
/// Content is dynamically arranged to fit the terminal width.
///
/// # Arguments
///
/// * `headers` - Column header labels.
/// * `rows` - Table data as vectors of strings.
///
/// # Example
///
/// ```rust,ignore
/// print_table(
///     vec!["Name", "Value"],
///     vec![
///         vec!["bind".to_string(), "0.0.0.0".to_string()],
///         vec!["port".to_string(), "31337".to_string()],
///     ],
/// );
/// ```
#[allow(dead_code)]
pub fn print_table(headers: Vec<&str>, rows: Vec<Vec<String>>) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(headers);

    for row in rows {
        table.add_row(row);
    }

    println!("{}", table);
}

/// Prints a risk assessment table with severity coloring.
///
/// Displays security issues in a formatted table with color-coded
/// severity levels for quick visual assessment.
///
/// # Arguments
///
/// * `risks` - Vector of tuples containing (issue, current_value, severity).
///
/// # Severity Colors
///
/// | Severity | Color |
/// |----------|-------|
/// | CRITICAL | Red Bold |
/// | HIGH | Red |
/// | MEDIUM | Yellow |
/// | LOW | Green |
///
/// # Example
///
/// ```rust,ignore
/// print_risk_table(vec![
///     ("Gateway exposed", "bind=0.0.0.0", "CRITICAL"),
///     ("No authentication", "mode=none", "HIGH"),
/// ]);
/// ```
pub fn print_risk_table(risks: Vec<(&str, &str, &str)>) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["Issue", "Current Value", "Severity"]);

    for (issue, value, severity) in risks {
        let severity_colored = match severity {
            "CRITICAL" => severity.red().bold().to_string(),
            "HIGH" => severity.red().to_string(),
            "MEDIUM" => severity.yellow().to_string(),
            "LOW" => severity.green().to_string(),
            _ => severity.to_string(),
        };
        table.add_row(vec![issue.to_string(), value.to_string(), severity_colored]);
    }

    println!("{}", table);
}

/// Prints a success message box after security fixes are applied.
///
/// Displays a green bordered box confirming successful security
/// hardening. Optionally displays the generated authentication
/// token in a separate yellow warning box.
///
/// # Arguments
///
/// * `token` - Optional authentication token to display. If provided,
///   a separate warning box reminds the user to save it.
///
/// # Output Format (without token)
///
/// ```text
/// ╭────────────────────────────────────────────────────────────────────╮
/// │                                                                    │
/// │  🎉 SUCCESS! Your Clawdbot/Moltbot is now secure.                  │
/// │                                                                    │
/// ╰────────────────────────────────────────────────────────────────────╯
/// ```
///
/// # Output Format (with token)
///
/// Additionally displays:
///
/// ```text
/// ╭────────────────────────────────────────────────────────────────────╮
/// │  ⚠️  IMPORTANT: Save your new gateway token!                       │
/// │                                                                    │
/// │    clwd_a8f2k9x3m1p7v4q2b6n8j5w7r9t3y1u                           │
/// │                                                                    │
/// │  You'll need this to connect from the Control UI or CLI.          │
/// ╰────────────────────────────────────────────────────────────────────╯
/// ```
pub fn print_success_box(token: Option<&str>) {
    println!();
    println!(
        "{}",
        "╭────────────────────────────────────────────────────────────────────╮".green()
    );
    println!(
        "{}",
        "│                                                                    │".green()
    );
    println!(
        "{}  {}  {}",
        "│".green(),
        "🎉 SUCCESS! Your Clawdbot/Moltbot is now secure."
            .green()
            .bold(),
        "       │".green()
    );
    println!(
        "{}",
        "│                                                                    │".green()
    );
    println!(
        "{}",
        "╰────────────────────────────────────────────────────────────────────╯".green()
    );

    if let Some(t) = token {
        println!();
        println!(
            "{}",
            "╭────────────────────────────────────────────────────────────────────╮".yellow()
        );
        println!(
            "{}",
            "│  ⚠️  IMPORTANT: Save your new gateway token!                       │".yellow()
        );
        println!(
            "{}",
            "│                                                                    │".yellow()
        );
        println!(
            "{}    {}{}│",
            "│".yellow(),
            t.cyan().bold(),
            " ".repeat(66 - t.len().min(62))
        );
        println!(
            "{}",
            "│                                                                    │".yellow()
        );
        println!(
            "{}",
            "│  You'll need this to connect from the Control UI or CLI.          │".yellow()
        );
        println!(
            "{}",
            "╰────────────────────────────────────────────────────────────────────╯".yellow()
        );
    }
    println!();
}

/// Prints a warning box when no installation is found.
///
/// Displays a yellow bordered box explaining that no Clawdbot/Moltbot
/// installation was detected, along with troubleshooting suggestions.
///
/// # Output Format
///
/// ```text
/// ╭────────────────────────────────────────────────────────────────────╮
/// │                                                                    │
/// │  ⚠️  No Clawdbot/Moltbot installation found.                       │
/// │                                                                    │
/// │  Make sure:                                                        │
/// │    • Clawdbot or Moltbot is installed                              │
/// │    • You've run it at least once (creates ~/.moltbot/)             │
/// │    • Config exists at ~/.moltbot/moltbot.json                      │
/// │                                                                    │
/// ╰────────────────────────────────────────────────────────────────────╯
/// ```
pub fn print_not_found_box() {
    println!();
    println!(
        "{}",
        "╭────────────────────────────────────────────────────────────────────╮".yellow()
    );
    println!(
        "{}",
        "│                                                                    │".yellow()
    );
    println!(
        "{}  {}  {}",
        "│".yellow(),
        "⚠️  No Clawdbot/Moltbot installation found."
            .yellow()
            .bold(),
        "                 │".yellow()
    );
    println!(
        "{}",
        "│                                                                    │".yellow()
    );
    println!(
        "{}",
        "│  Make sure:                                                        │".yellow()
    );
    println!(
        "{}",
        "│    • Clawdbot or Moltbot is installed                              │".yellow()
    );
    println!(
        "{}",
        "│    • You've run it at least once (creates ~/.moltbot/)             │".yellow()
    );
    println!(
        "{}",
        "│    • Config exists at ~/.moltbot/moltbot.json                      │".yellow()
    );
    println!(
        "{}",
        "│                                                                    │".yellow()
    );
    println!(
        "{}",
        "╰────────────────────────────────────────────────────────────────────╯".yellow()
    );
    println!();
}

/// Prints a success box when installation is already secure.
///
/// Displays a green bordered box confirming that the installation
/// has no security issues and no changes are needed.
///
/// # Output Format
///
/// ```text
/// ╭────────────────────────────────────────────────────────────────────╮
/// │                                                                    │
/// │  ✓ Your installation is already secure!                           │
/// │                                                                    │
/// │  No changes needed. Stay safe! 🦞                                  │
/// │                                                                    │
/// ╰────────────────────────────────────────────────────────────────────╯
/// ```
pub fn print_already_secure_box() {
    println!();
    println!(
        "{}",
        "╭────────────────────────────────────────────────────────────────────╮".green()
    );
    println!(
        "{}",
        "│                                                                    │".green()
    );
    println!(
        "{}  {}  {}",
        "│".green(),
        "✓ Your installation is already secure!".green().bold(),
        "                     │".green()
    );
    println!(
        "{}",
        "│                                                                    │".green()
    );
    println!(
        "{}",
        "│  No changes needed. Stay safe! 🦞                                  │".green()
    );
    println!(
        "{}",
        "│                                                                    │".green()
    );
    println!(
        "{}",
        "╰────────────────────────────────────────────────────────────────────╯".green()
    );
    println!();
}

/// Formats a file path for display, abbreviating the home directory.
///
/// Replaces the user's home directory prefix with `~` for cleaner
/// output while preserving the full path information.
///
/// # Arguments
///
/// * `path` - The file path to format.
///
/// # Returns
///
/// A string with the home directory replaced by `~` if applicable,
/// or the original path if it's not under the home directory.
///
/// # Example
///
/// ```rust,ignore
/// let path = Path::new("/Users/alice/.clawdbot/clawdbot.json");
/// let formatted = format_path(path);
/// assert_eq!(formatted, "~/.clawdbot/clawdbot.json");
/// ```
pub fn format_path(path: &std::path::Path) -> String {
    if let Some(home) = dirs::home_dir() {
        if let Ok(relative) = path.strip_prefix(&home) {
            return format!("~/{}", relative.display());
        }
    }
    path.display().to_string()
}
