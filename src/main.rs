//! ClawdGuard CLI - Security hardening for Clawdbot/Moltbot
//!
//! This is the command-line interface for ClawdGuard, providing an interactive
//! four-phase security workflow: detection, analysis, patching, and verification.
//!
//! ## Exit Codes
//!
//! - `0`: Success - installation secured or already secure
//! - `1`: Failure - an error occurred during the workflow
//! - `130`: Interrupted - user pressed Ctrl+C

#![allow(unused)]

use clap::Parser;
use colored::Colorize;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clawdguard::{
    analyze,
    analyze::RiskReport,
    detect,
    detect::Installation,
    output,
    output::printer::{
        create_spinner, print_already_secure_box, print_banner, print_error, print_info, print_kv,
        print_not_found_box, print_risk_table, print_section, print_separator, print_success,
        print_success_box, print_warning,
    },
    patch, verify,
};

/// Command-line arguments for ClawdGuard.
///
/// Controls the behavior of the security workflow including output format,
/// patching options, and automation settings.
#[derive(Parser, Debug)]
#[command(name = "clawdguard")]
#[command(author = "ClawdGuard Contributors")]
#[command(version = "1.0.0")]
#[command(about = "🦞 Security hardening for Clawdbot/Moltbot", long_about = None)]
struct Args {
    /// Only scan for issues, don't apply fixes.
    /// Useful for CI/CD pipelines or security audits.
    #[arg(long, default_value_t = false)]
    scan_only: bool,

    /// Apply all fixes without confirmation prompts.
    /// Enables unattended operation for automation.
    #[arg(long, default_value_t = false)]
    auto: bool,

    /// Custom directory for backup files.
    /// Defaults to the same directory as the config file.
    #[arg(long)]
    backup_dir: Option<String>,

    /// Skip adding firewall rules.
    /// Use when firewall is managed externally.
    #[arg(long, default_value_t = false)]
    skip_firewall: bool,

    /// Skip restarting the gateway service.
    /// Manual restart required for changes to take effect.
    #[arg(long, default_value_t = false)]
    skip_restart: bool,

    /// Use a specific token instead of generating one.
    /// Token must be at least 16 characters.
    #[arg(long)]
    token: Option<String>,

    /// Show detailed output including debug information.
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Output results as JSON for scripting and automation.
    /// Disables interactive elements and colored output.
    #[arg(long, default_value_t = false)]
    json: bool,
}

/// Application entry point.
///
/// Initializes the async runtime, sets up signal handlers, and executes
/// the main security workflow. Returns appropriate exit codes based on
/// workflow success or failure.
#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    // Set up Ctrl+C handler for graceful interruption
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        println!();
        println!("{}", "⚠ Interrupted! Exiting...".yellow());
        std::process::exit(130);
    })
    .expect("Error setting Ctrl+C handler");

    // Display banner in interactive mode
    if !args.json {
        print_banner();
        println!("{}", "ℹ Press Ctrl+C to cancel at any time".bright_black());
        println!();
    }

    match run_workflow(&args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if args.json {
                println!(r#"{{"error": "{}"}}"#, e);
            } else {
                print_error(&format!("Fatal error: {}", e));
            }
            ExitCode::FAILURE
        }
    }
}

/// Executes the four-phase security workflow.
///
/// # Phases
///
/// 1. **Detection**: Locates configuration files, running processes, and services
/// 2. **Analysis**: Evaluates security posture and calculates risk score
/// 3. **Patching**: Applies fixes with automatic backup creation
/// 4. **Verification**: Confirms fixes are effective
///
/// # Arguments
///
/// * `args` - Command-line arguments controlling workflow behavior
///
/// # Returns
///
/// * `Ok(())` - Workflow completed successfully
/// * `Err(String)` - Workflow failed with the given error message
async fn run_workflow(args: &Args) -> Result<(), String> {
    // =========================================================================
    // Phase 1: Detection
    // Locate installation components: config files, processes, and services
    // =========================================================================
    if !args.json {
        print_section(1, 4, "Detecting installation...");
    }

    let spinner = if !args.json && !args.verbose {
        Some(create_spinner("Searching for Clawdbot/Moltbot..."))
    } else {
        None
    };

    let installation =
        detect::find_installation(args.verbose).map_err(|e| format!("Detection failed: {}", e))?;

    if let Some(sp) = spinner {
        sp.finish_and_clear();
    }

    if !args.json {
        print_installation_info(&installation);
    }

    // Exit early if no installation found
    if installation.config_path.is_none() {
        if args.json {
            println!(
                r#"{{"status": "not_found", "message": "No Clawdbot/Moltbot installation found"}}"#
            );
        } else {
            print_not_found_box();
        }
        return Ok(());
    }

    // =========================================================================
    // Phase 2: Analysis
    // Evaluate security configuration and calculate risk score
    // =========================================================================
    if !args.json {
        println!();
        print_section(2, 4, "Analyzing security risks...");
    }

    let spinner = if !args.json && !args.verbose {
        Some(create_spinner("Checking configuration..."))
    } else {
        None
    };

    let risk_report = analyze::analyze_installation(&installation, args.verbose)
        .await
        .map_err(|e| format!("Analysis failed: {}", e))?;

    if let Some(sp) = spinner {
        sp.finish_and_clear();
    }

    if !args.json {
        print_risk_report(&risk_report);
    }

    // Exit early if already secure
    if risk_report.is_secure() {
        if args.json {
            println!(
                r#"{{"status": "secure", "message": "Installation is already secure", "risk_score": 0}}"#
            );
        } else {
            print_already_secure_box();
        }
        return Ok(());
    }

    // Handle scan-only mode
    if args.scan_only {
        if args.json {
            println!(
                r#"{{"status": "vulnerable", "risk_score": {}, "issues": {}}}"#,
                risk_report.risk_score(),
                serde_json::to_string(&risk_report).unwrap_or_default()
            );
        } else {
            println!();
            print_warning("Scan-only mode: No fixes applied.");
            print_info("Run without --scan-only to apply fixes.");
        }
        return Ok(());
    }

    // Request confirmation in interactive mode
    if !args.auto && !args.json {
        println!();
        print_warning("This will modify your configuration to fix security issues.");
        print_info("A backup will be created before any changes.");
        println!();

        if !confirm_action("Proceed with fixes?") {
            print_info("Aborted by user.");
            return Ok(());
        }
    }

    // =========================================================================
    // Phase 3: Patching
    // Apply security fixes with automatic backup
    // =========================================================================
    if !args.json {
        println!();
        print_section(3, 4, "Applying fixes...");
    }

    let spinner = if !args.json && !args.verbose {
        Some(create_spinner("Patching configuration..."))
    } else {
        None
    };

    let patch_result = patch::apply_patches(
        &installation,
        &risk_report,
        args.token.as_deref(),
        args.backup_dir.as_deref(),
        args.skip_firewall,
        args.verbose,
    )
    .map_err(|e| format!("Patching failed: {}", e))?;

    if let Some(sp) = spinner {
        sp.finish_and_clear();
    }

    if !args.json {
        print_patch_results(&patch_result);
    }

    // =========================================================================
    // Phase 4: Verification
    // Confirm fixes are effective by testing connectivity and auth
    // =========================================================================
    if !args.json {
        println!();
        print_section(4, 4, "Verifying fixes...");
    }

    // Restart the gateway service to apply configuration changes
    if !args.skip_restart {
        let spinner = if !args.json {
            Some(create_spinner("Restarting gateway service..."))
        } else {
            None
        };

        if let Err(e) = verify::restart_service(&installation, args.verbose) {
            if let Some(sp) = spinner {
                sp.finish_and_clear();
            }
            if !args.json {
                print_warning(&format!("Could not restart service: {}", e));
                print_info("You may need to restart manually: clawdbot gateway restart");
            }
        } else {
            if let Some(sp) = spinner {
                sp.finish_and_clear();
            }
            if !args.json {
                print_success("Gateway service restarted");
            }
        }
    }

    // Allow time for service to fully restart before verification
    if !args.skip_restart {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }

    let spinner = if !args.json && !args.verbose {
        Some(create_spinner("Verifying security..."))
    } else {
        None
    };

    let verification = verify::verify_fixes(&installation, args.verbose)
        .await
        .map_err(|e| format!("Verification failed: {}", e))?;

    if let Some(sp) = spinner {
        sp.finish_and_clear();
    }

    if !args.json {
        print_verification_results(&verification);
    }

    // =========================================================================
    // Final Output
    // Display success message and generated token
    // =========================================================================
    if args.json {
        let token_json = match &patch_result.generated_token {
            Some(t) => format!("\"{}\"", t),
            None => "null".to_string(),
        };
        let backup_json = match &patch_result.backup_path {
            Some(p) => format!("\"{}\"", p.display()),
            None => "null".to_string(),
        };
        println!(
            r#"{{"status": "fixed", "token": {}, "backup": {}}}"#,
            token_json, backup_json
        );
    } else {
        print_separator();
        print_success_box(patch_result.generated_token.as_deref());
    }

    Ok(())
}

/// Displays detected installation information.
///
/// Shows the configuration file path, service status, and port activity.
///
/// # Arguments
///
/// * `installation` - The detected installation details
fn print_installation_info(installation: &Installation) {
    if let Some(ref path) = installation.config_path {
        print_success(&format!("Config: {}", output::printer::format_path(path)));
    } else {
        print_warning("No config file found");
    }

    if let Some(ref service) = installation.service_info {
        let status = if service.is_running {
            "running".green().to_string()
        } else {
            "stopped".yellow().to_string()
        };
        print_success(&format!(
            "Service: {} ({}{})",
            service.name,
            status,
            service
                .pid
                .map(|p| format!(", PID {}", p))
                .unwrap_or_default()
        ));
    } else {
        print_info("No service detected (may be running manually)");
    }

    if installation.port_detected {
        print_success("Port 18789 is active");
    }
}

/// Displays the security risk report in a formatted table.
///
/// Shows identified vulnerabilities with their severity levels and
/// calculates an overall risk score from 0-10.
///
/// # Arguments
///
/// * `report` - The security risk analysis report
fn print_risk_report(report: &RiskReport) {
    let mut risks: Vec<(&str, &str, &str)> = Vec::new();

    // Collect all identified risks with severity levels
    if report.bind_exposed {
        risks.push((
            "Gateway Bind",
            report.bind_value.as_deref().unwrap_or("unknown"),
            "CRITICAL",
        ));
    }

    if report.auth_missing {
        risks.push((
            "Authentication",
            report.auth_mode.as_deref().unwrap_or("none"),
            "CRITICAL",
        ));
    }

    if report.port_externally_reachable {
        risks.push(("Port Exposure", "Reachable from internet", "CRITICAL"));
    }

    if report.mdns_leaking {
        risks.push((
            "mDNS Broadcast",
            report.mdns_mode.as_deref().unwrap_or("full"),
            "MEDIUM",
        ));
    }

    if report.permissions_too_open {
        risks.push((
            "File Permissions",
            report.current_permissions.as_deref().unwrap_or("unknown"),
            "LOW",
        ));
    }

    if !risks.is_empty() {
        println!();
        print_risk_table(risks);
    }

    // Display color-coded risk score
    let score = report.risk_score();
    let (score_color, risk_indicator) = match score {
        0..=3 => ("green", "LOW"),
        4..=6 => ("yellow", "MEDIUM"),
        _ => ("red", "CRITICAL"),
    };

    println!();
    println!(
        "      {} {}/10 {}",
        "Risk Score:".bold(),
        match score_color {
            "green" => score.to_string().green().bold(),
            "yellow" => score.to_string().yellow().bold(),
            _ => score.to_string().red().bold(),
        },
        match score_color {
            "green" => format!("🟢 {}", risk_indicator).green(),
            "yellow" => format!("🟡 {}", risk_indicator).yellow(),
            _ => format!("🔴 {}", risk_indicator).red(),
        }
    );
}

/// Displays the results of the patching phase.
///
/// Shows backup location, configuration changes made, and the generated
/// authentication token if applicable.
///
/// # Arguments
///
/// * `result` - The patching operation results
fn print_patch_results(result: &patch::PatchResult) {
    if let Some(ref backup) = result.backup_path {
        print_success(&format!("Backup: {}", output::printer::format_path(backup)));
    }

    for change in &result.changes_made {
        print_success(change);
    }

    if let Some(ref token) = result.generated_token {
        println!();
        print_kv("Generated Token", &token.cyan().bold().to_string());
    }
}

/// Displays the results of the verification phase.
///
/// Shows whether the port is closed externally, localhost access works,
/// and authentication is properly enforced.
///
/// # Arguments
///
/// * `verification` - The verification results
fn print_verification_results(verification: &verify::VerificationResult) {
    if verification.port_closed {
        print_success("Port 18789 no longer reachable externally");
    } else {
        print_warning("Port may still be accessible (check firewall)");
    }

    if verification.localhost_works {
        print_success("Gateway responding on localhost");
    }

    if verification.auth_required {
        print_success("Authentication is now required");
    }
}

/// Prompts the user for confirmation.
///
/// Displays the message with a [y/N] prompt and waits for user input.
/// Only accepts 'y' or 'yes' (case-insensitive) as affirmative.
///
/// # Arguments
///
/// * `message` - The confirmation message to display
///
/// # Returns
///
/// `true` if user confirmed, `false` otherwise
fn confirm_action(message: &str) -> bool {
    use std::io::{self, Write};

    print!("      {} [y/N]: ", message.cyan());
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}
