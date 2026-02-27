mod models;
mod scanner;
mod probe;
mod tls;
mod audit;
mod output;
mod target;

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use colored::*;

use crate::models::Severity;
use crate::output::*;

/// A fast, async port scanner built in Rust
#[derive(Parser)]
#[command(name = "punt", version = "0.1.0")]
struct Args {
    /// Target IP, hostname, or CIDR range (e.g., 192.168.1.0/24)
    target: String,

    /// Start of port range
    #[arg(short = 's', long, default_value_t = 1)]
    start_port: u16,

    /// End of port range
    #[arg(short = 'e', long, default_value_t = 1024)]
    end_port: u16,

    /// Connection timeout in milliseconds
    #[arg(short, long, default_value_t = 500)]
    timeout: u64,

    /// Number of concurrent connections per batch
    #[arg(short, long, default_value_t = 5000)]
    batch_size: usize,

    /// Grab banners from open ports
    #[arg(long, default_value_t = false)]
    banners: bool,

    /// Probe open ports with HTTP/HTTPS requests
    #[arg(long, default_value_t = false)]
    probe: bool,

    /// Analyze security headers on probed ports
    #[arg(long, default_value_t = false)]
    audit: bool,

    /// Inspect TLS certificates on open ports
    #[arg(long, default_value_t = false)]
    tls: bool,

    /// Output results as JSON
    #[arg(long, default_value_t = false)]
    json: bool,
}

struct HostResult {
    host: String,
    results: Vec<models::ScanResult>,
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    #[cfg(windows)]
    {
        let _ = colored::control::set_virtual_terminal(true);
    }

    let args = Args::parse();
    let conn_timeout = Duration::from_millis(args.timeout);
    let ports_per_host = (args.end_port - args.start_port + 1) as u64;

    let do_probe = args.probe || args.audit;
    let do_audit = args.audit || args.tls;

    // Parse targets
    let targets = match target::parse_targets(&args.target) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("    {} {}", "ERROR:".red().bold(), e);
            std::process::exit(1);
        }
    };

    let is_cidr = targets.len() > 1;

    // Host discovery for CIDR ranges
    let live_targets = if is_cidr {
        println!(
            "    {} discovering live hosts in {} ({} addresses)...",
            "→".cyan(),
            args.target.yellow(),
            targets.len().to_string().white()
        );

        let discovery_progress = ProgressBar::new(targets.len() as u64);
        discovery_progress.set_style(
            ProgressStyle::default_bar()
                .template("    {spinner:.yellow} [{bar:40.yellow/white}] {pos}/{len} hosts ({percent}%) | ETA: {eta}")
                .expect("Invalid progress bar template")
                .progress_chars("█▓░")
        );

        let mut live: Vec<std::net::IpAddr> = Vec::new();

        for chunk in targets.chunks(50) {
            let mut tasks = Vec::new();

            for ip in chunk {
                let ip = *ip;
                tasks.push(async move {
                    let alive = target::is_host_alive(ip, args.timeout).await;
                    (ip, alive)
                });
            }

            let results = futures::future::join_all(tasks).await;

            for (ip, alive) in results {
                if alive {
                    live.push(ip);
                }
            }

            discovery_progress.inc(chunk.len() as u64);
        }

        discovery_progress.finish_and_clear();

        println!(
            "    {} {} live hosts found\n",
            "✓".green().bold(),
            live.len().to_string().green().bold()
        );

        live
    } else {
        targets.clone()
    };

    let total_ports = ports_per_host * live_targets.len() as u64;

    print_banner();
    print_divider();

    if is_cidr {
        println!(
            "    {} {} ({} live / {} total)",
            "TARGET:".bold(),
            args.target.yellow(),
            live_targets.len().to_string().green(),
            targets.len().to_string().dimmed()
        );
    } else {
        println!(
            "    {} {}",
            "TARGET:".bold(),
            targets[0].to_string().yellow()
        );
    }

    println!(
        "    {} {}-{} ({} per host, {} total)",
        "RANGE:".bold(),
        args.start_port.to_string().white(),
        args.end_port.to_string().white(),
        format!("{} ports", ports_per_host).dimmed(),
        format!("{} ports", total_ports).dimmed()
    );
    println!(
        "    {} {}ms  {} {}  {} {}  {} {}  {} {}  {} {}",
        "TIMEOUT:".bold(),
        args.timeout,
        "BATCH:".bold(),
        args.batch_size,
        "BANNERS:".bold(),
        if args.banners { "on".green().to_string() } else { "off".dimmed().to_string() },
        "PROBE:".bold(),
        if do_probe { "on".green().to_string() } else { "off".dimmed().to_string() },
        "AUDIT:".bold(),
        if do_audit { "on".green().to_string() } else { "off".dimmed().to_string() },
        "TLS:".bold(),
        if args.tls { "on".green().to_string() } else { "off".dimmed().to_string() }
    );

    print_divider();
    println!();

    let start_time = Instant::now();
    let mut all_host_results: Vec<HostResult> = Vec::new();

    for (_host_idx, host_ip) in live_targets.iter().enumerate() {
        let host = host_ip.to_string();

        // ── Phase 1: Port scan ──
        let progress = ProgressBar::new(ports_per_host);
        if is_cidr {
            progress.set_style(
                ProgressStyle::default_bar()
                    .template(&format!(
                        "    {{spinner:.cyan}} {} [{{bar:30.cyan/blue}}] {{pos}}/{{len}} ({{percent}}%) | ETA: {{eta}}",
                        host.yellow()
                    ))
                    .expect("Invalid progress bar template")
                    .progress_chars("█▓░")
            );
        } else {
            progress.set_style(
                ProgressStyle::default_bar()
                    .template("    {spinner:.cyan} [{bar:40.cyan/blue}] {pos}/{len} ports ({percent}%) | ETA: {eta}")
                    .expect("Invalid progress bar template")
                    .progress_chars("█▓░")
            );
        }

        let mut results: Vec<models::ScanResult> = Vec::new();

        for batch_start in (args.start_port..=args.end_port).step_by(args.batch_size) {
            let batch_end =
                (batch_start as usize + args.batch_size - 1).min(args.end_port as usize) as u16;

            let mut tasks = Vec::new();

            for port in batch_start..=batch_end {
                let addr: SocketAddr = format!("{}:{}", host, port)
                    .parse()
                    .expect("Invalid address");

                tasks.push(scanner::scan_port(addr, conn_timeout, args.banners));
            }

            let batch_results = futures::future::join_all(tasks).await;
            let batch_count = batch_results.len() as u64;

            for result in batch_results {
                if let Some(scan_result) = result {
                    results.push(scan_result);
                }
            }

            progress.inc(batch_count);
        }

        progress.finish_and_clear();

        // ── Phase 2: HTTP probing ──
        if do_probe && !results.is_empty() {
            let probe_progress = ProgressBar::new(results.len() as u64);
            probe_progress.set_style(
                ProgressStyle::default_bar()
                    .template("    {spinner:.magenta} [{bar:40.magenta/red}] {pos}/{len} probed | ETA: {eta}")
                    .expect("Invalid progress bar template")
                    .progress_chars("█▓░")
            );

            let probe_timeout = Duration::from_secs(5);

            for result in results.iter_mut() {
                result.http_info = probe::probe_http(&host, result.port, probe_timeout).await;
                probe_progress.inc(1);
            }

            probe_progress.finish_and_clear();
        }

        // ── Phase 3: TLS inspection ──
        if args.tls && !results.is_empty() {
            let tls_progress = ProgressBar::new(results.len() as u64);
            tls_progress.set_style(
                ProgressStyle::default_bar()
                    .template("    {spinner:.green} [{bar:40.green/white}] {pos}/{len} inspected | ETA: {eta}")
                    .expect("Invalid progress bar template")
                    .progress_chars("█▓░")
            );

            let tls_timeout = Duration::from_secs(5);

            for result in results.iter_mut() {
                result.tls_info = tls::inspect_tls(&host, result.port, tls_timeout).await;
                tls_progress.inc(1);
            }

            tls_progress.finish_and_clear();
        }

        // ── Phase 4: Audit ──
        if do_audit {
            for result in results.iter_mut() {
                if let Some(info) = &result.http_info {
                    result.findings.extend(audit::audit_headers(result.port, info));
                }
                if let Some(info) = &result.tls_info {
                    result.findings.extend(audit::audit_tls(result.port, info));
                }
            }
        }

        results.sort_by_key(|r| r.port);

        // Per-host inline summary during scan phase
        if is_cidr && !results.is_empty() {
            let ports_list: Vec<String> = results.iter()
                .map(|r| r.port.to_string())
                .collect();
            println!(
                "    {} {} — {} open: {}",
                "►".cyan(),
                host.yellow(),
                results.len().to_string().green().bold(),
                ports_list.join(", ").dimmed()
            );
        } else if is_cidr {
            println!(
                "    {} {} — {}",
                "►".dimmed(),
                host.to_string().dimmed(),
                "no open ports".dimmed()
            );
        }

        // Store results for display phase
        if !results.is_empty() {
            all_host_results.push(HostResult { host, results });
        }
    }

    let elapsed = start_time.elapsed();

    // ── Display detailed results ──
    println!();

    for host_result in &all_host_results {
        let results = &host_result.results;
        let host = &host_result.host;

        if is_cidr {
            println!("    {} {}", "═══".cyan(), host.bold().yellow());
            println!();
        }

        // Results table
        println!("    {}", "RESULTS".bold().underline());
        println!();

        let show_banner = args.banners;
        let show_probe = do_probe;

        print!("    {:<12} {:<10}", "PORT".bold(), "STATE".bold());
        if show_banner { print!(" {:<30}", "BANNER".bold()); }
        if show_probe { print!(" {}", "HTTP".bold()); }
        println!();

        print!("    {:<12} {:<10}", "────", "─────");
        if show_banner { print!(" {:<30}", "──────"); }
        if show_probe { print!(" {}", "────"); }
        println!();

        for result in results {
            print!(
                "    {:<12} {:<10}",
                format!("{}/tcp", result.port),
                "open".green().bold()
            );

            if show_banner {
                let banner_display = match &result.banner {
                    Some(b) => {
                        let truncated = if b.len() > 28 {
                            format!("{}...", &b[..25])
                        } else {
                            b.clone()
                        };
                        format!("{:<30}", truncated.cyan())
                    }
                    None => format!("{:<30}", "—".dimmed()),
                };
                print!(" {}", banner_display);
            }

            if show_probe {
                let http_display = match &result.http_info {
                    Some(info) => info.summary().magenta().to_string(),
                    None => "—".dimmed().to_string(),
                };
                print!(" {}", http_display);
            }

            println!();
        }

        // Headers
        if show_probe {
            let http_results: Vec<&models::ScanResult> = results
                .iter()
                .filter(|r| r.http_info.is_some())
                .collect();

            if !http_results.is_empty() {
                println!();
                println!("    {}", "HEADERS".bold().underline());

                for result in http_results {
                    let info = result.http_info.as_ref().unwrap();
                    println!();
                    println!(
                        "    {} {} (HTTP {})",
                        "●".cyan(),
                        format!(":{}", result.port).bold(),
                        info.status.to_string().yellow()
                    );

                    let mut sorted_headers: Vec<(&String, &String)> =
                        info.headers.iter().collect();
                    sorted_headers.sort_by_key(|(k, _)| k.to_lowercase());

                    for (key, value) in sorted_headers {
                        let display_val = if value.len() > 70 {
                            format!("{}...", &value[..67])
                        } else {
                            value.clone()
                        };
                        println!(
                            "      {}: {}",
                            key.dimmed(),
                            display_val
                        );
                    }
                }
            }
        }

        // TLS
        if args.tls {
            let tls_results: Vec<&models::ScanResult> = results
                .iter()
                .filter(|r| r.tls_info.is_some())
                .collect();

            if !tls_results.is_empty() {
                println!();
                println!("    {}", "TLS CERTIFICATES".bold().underline());

                for result in tls_results {
                    let info = result.tls_info.as_ref().unwrap();
                    println!();
                    println!(
                        "    {} {} ({}, {})",
                        "●".green(),
                        format!(":{}", result.port).bold(),
                        info.tls_version.cyan(),
                        info.cipher_suite.dimmed()
                    );

                    println!("      {}: {}", "Subject".dimmed(), info.subject);
                    println!("      {}: {}", "Issuer".dimmed(), info.issuer);
                    println!("      {}: {}", "Not Before".dimmed(), info.not_before);

                    let expiry_display = if info.days_until_expiry < 0 {
                        format!("{} (EXPIRED {} days ago)", info.not_after, info.days_until_expiry.abs()).red().to_string()
                    } else if info.days_until_expiry <= 30 {
                        format!("{} ({} days left)", info.not_after, info.days_until_expiry).yellow().to_string()
                    } else {
                        format!("{} ({} days left)", info.not_after, info.days_until_expiry).green().to_string()
                    };
                    println!("      {}: {}", "Not After".dimmed(), expiry_display);

                    if !info.sans.is_empty() {
                        println!("      {}: {}", "SANs".dimmed(), info.sans.join(", "));
                    }

                    if info.self_signed {
                        println!("      {}", "⚠ Self-signed certificate".yellow());
                    }
                }
            }
        }

        // Audit
        if do_audit {
            let all_findings: Vec<&models::Finding> = results
                .iter()
                .flat_map(|r| r.findings.iter())
                .collect();

            if !all_findings.is_empty() {
                println!();
                println!("    {}", "SECURITY AUDIT".bold().underline());
                println!();

                let high_count = all_findings.iter()
                    .filter(|f| f.severity == Severity::High).count();
                let med_count = all_findings.iter()
                    .filter(|f| f.severity == Severity::Medium).count();
                let info_count = all_findings.iter()
                    .filter(|f| f.severity == Severity::Info).count();

                println!(
                    "    {}  {}  {}",
                    format!("{} HIGH", high_count).red().bold(),
                    format!("{} MED", med_count).yellow().bold(),
                    format!("{} INFO", info_count).blue(),
                );
                println!();

                for finding in all_findings.iter().filter(|f| f.severity == Severity::High) {
                    println!(
                        "    {} [{}] {}",
                        finding.severity.icon(),
                        finding.severity.label(),
                        finding.title.bold()
                    );
                    println!("           {}", finding.detail.dimmed());
                }
                if high_count > 0 { println!(); }

                for finding in all_findings.iter().filter(|f| f.severity == Severity::Medium) {
                    println!(
                        "    {} [{}]  {}",
                        finding.severity.icon(),
                        finding.severity.label(),
                        finding.title.bold()
                    );
                    println!("           {}", finding.detail.dimmed());
                }
                if med_count > 0 { println!(); }

                for finding in all_findings.iter().filter(|f| f.severity == Severity::Info) {
                    println!(
                        "    {} [{}] {}",
                        finding.severity.icon(),
                        finding.severity.label(),
                        finding.title
                    );
                    println!("           {}", finding.detail.dimmed());
                }
            }
        }

        if is_cidr {
            println!();
        }
    }

    print_divider();

    // ── Summary ──
    let total_open: usize = all_host_results.iter().map(|h| h.results.len()).sum();
    let hosts_with_ports = all_host_results.len();

    let summary_color = if total_open == 0 {
        "0".dimmed().to_string()
    } else if total_open <= 5 {
        total_open.to_string().green().bold().to_string()
    } else if total_open <= 20 {
        total_open.to_string().yellow().bold().to_string()
    } else {
        total_open.to_string().red().bold().to_string()
    };

    if is_cidr {
        println!(
            "    {} open ports across {} hosts ({} alive, {} in range)",
            summary_color,
            hosts_with_ports.to_string().bold(),
            live_targets.len().to_string().green(),
            targets.len().to_string().dimmed()
        );
    } else {
        println!(
            "    {} open {} on {}",
            summary_color,
            if total_open == 1 { "port" } else { "ports" },
            all_host_results.first()
                .map(|h| h.host.as_str())
                .unwrap_or(&args.target).bold()
        );
    }

    println!(
        "    {} ports scanned in {}",
        total_ports.to_string().bold(),
        format_duration(elapsed).yellow()
    );

    if do_audit {
        let total_findings: usize = all_host_results.iter()
            .flat_map(|h| h.results.iter())
            .map(|r| r.findings.len())
            .sum();
        let high_total: usize = all_host_results.iter()
            .flat_map(|h| h.results.iter())
            .flat_map(|r| r.findings.iter())
            .filter(|f| f.severity == Severity::High)
            .count();

        if total_findings > 0 {
            println!(
                "    {} security findings ({} high)",
                total_findings.to_string().yellow().bold(),
                high_total.to_string().red().bold()
            );
        }
    }

    // ── JSON output ──
    if args.json {
        let json_hosts: Vec<serde_json::Value> = all_host_results.iter().map(|hr| {
            let json_results: Vec<JsonPortResult> = hr.results.iter().map(|r| {
                JsonPortResult {
                    port: r.port,
                    state: "open".to_string(),
                    banner: r.banner.clone(),
                    http: r.http_info.as_ref().map(|h| JsonHttp {
                        status: h.status,
                        scheme: h.scheme.clone(),
                        headers: h.headers.clone(),
                    }),
                    tls: r.tls_info.as_ref().map(|t| JsonTls {
                        subject: t.subject.clone(),
                        issuer: t.issuer.clone(),
                        not_before: t.not_before.clone(),
                        not_after: t.not_after.clone(),
                        days_until_expiry: t.days_until_expiry,
                        sans: t.sans.clone(),
                        tls_version: t.tls_version.clone(),
                        cipher_suite: t.cipher_suite.clone(),
                        self_signed: t.self_signed,
                    }),
                    findings: r.findings.iter().map(|f| JsonFinding {
                        severity: match f.severity {
                            Severity::High => "high",
                            Severity::Medium => "medium",
                            Severity::Info => "info",
                        }.to_string(),
                        title: f.title.clone(),
                        detail: f.detail.clone(),
                    }).collect(),
                }
            }).collect();

            serde_json::json!({
                "host": hr.host,
                "results": json_results,
            })
        }).collect();

        let json_output = serde_json::json!({
            "target": args.target,
            "hosts_total": targets.len(),
            "hosts_alive": live_targets.len(),
            "ports_per_host": ports_per_host,
            "scan_duration": format_duration(elapsed),
            "hosts": json_hosts,
        });

        let json_string = serde_json::to_string_pretty(&json_output).expect("Failed to serialize JSON");

        let filename = format!("punt_{}.json", args.target.replace("/", "_").replace(".", "_"));
        std::fs::write(&filename, &json_string).expect("Failed to write JSON file");
        println!(
            "    {} saved to {}",
            "→".cyan(),
            filename.bold()
        );
    }

    print_signoff();
}