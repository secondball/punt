use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio::io::AsyncReadExt;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use colored::*;
use rand::seq::IndexedRandom;

/// A fast, async port scanner built in Rust
#[derive(Parser)]
#[command(name = "punt", version = "0.1.0")]
struct Args {
    /// Target IP address or hostname
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
}

struct ScanResult {
    port: u16,
    banner: Option<String>,
    http_info: Option<HttpInfo>,
}

struct HttpInfo {
    status: u16,
    headers: HashMap<String, String>,
}

impl HttpInfo {
    /// Returns the most interesting headers in a compact display string
    fn summary(&self) -> String {
        let interesting = [
            "server",
            "x-powered-by",
            "x-aspnet-version",
            "x-generator",
        ];

        let mut parts: Vec<String> = Vec::new();

        for key in &interesting {
            if let Some(val) = self.headers.get(*key) {
                parts.push(format!("{}: {}", key, val));
            }
        }

        if parts.is_empty() {
            format!("HTTP {}", self.status)
        } else {
            format!("HTTP {} | {}", self.status, parts.join(" | "))
        }
    }
}

fn print_banner() {
    let banner = r#"
    ██████╗ ██╗   ██╗███╗   ██╗████████╗
    ██╔══██╗██║   ██║████╗  ██║╚══██╔══╝
    ██████╔╝██║   ██║██╔██╗ ██║   ██║
    ██╔═══╝ ██║   ██║██║╚██╗██║   ██║
    ██║     ╚██████╔╝██║ ╚████║   ██║
    ╚═╝      ╚═════╝ ╚═╝  ╚═══╝   ╚═╝"#;

    println!("{}", banner.cyan().bold());
    println!(
        "    {}",
        "Port Utility for Network Testing v0.1".white().dimmed()
    );

    let taglines = [
        "because nmap was too mainstream",
        "it's not illegal if you own it",
        "scanning ports, not your emails",
        "loud and proud on your network",
        "RST packets go brrrrr",
        "enterprise-grade shitposting",
        "now with 100% more Rust",
        "blazingly fast (we're contractually obligated to say that)",
        "i am not scraping your data, i don't know how",
    ];

    let mut rng = rand::rng();
    if let Some(tagline) = taglines.choose(&mut rng) {
        println!("    {}", format!("\"{}\"", tagline).dimmed().italic());
    }
    println!();
}

fn print_divider() {
    println!("{}", "    ─────────────────────────────────────".dimmed());
}

async fn scan_port(addr: SocketAddr, conn_timeout: Duration, grab_banner: bool) -> Option<ScanResult> {
    let port = addr.port();

    let mut stream = match timeout(conn_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    if !grab_banner {
        return Some(ScanResult {
            port,
            banner: None,
            http_info: None,
        });
    }

    let mut buf = vec![0u8; 1024];
    let banner = match timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let raw = String::from_utf8_lossy(&buf[..n]);
            let cleaned: String = raw
                .chars()
                .filter(|c| !c.is_control() || *c == ' ')
                .collect::<String>()
                .trim()
                .to_string();

            if cleaned.is_empty() { None } else { Some(cleaned) }
        }
        _ => None,
    };

    Some(ScanResult {
        port,
        banner,
        http_info: None,
    })
}

async fn probe_http(target: &str, port: u16, conn_timeout: Duration) -> Option<HttpInfo> {
    // Try HTTPS first for common HTTPS ports, then fall back to HTTP
    // For other ports, try HTTP first, then HTTPS
    let schemes = if matches!(port, 443 | 8443 | 8006 | 9443) {
        vec!["https", "http"]
    } else {
        vec!["http", "https"]
    };

    let client = reqwest::Client::builder()
        .timeout(conn_timeout)
        .danger_accept_invalid_certs(true) // self-signed certs are common internally
        .redirect(reqwest::redirect::Policy::none()) // don't follow redirects, we want raw response
        .build()
        .ok()?;

    for scheme in schemes {
        let url = format!("{}://{}:{}/", scheme, target, port);

        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();

            let mut headers = HashMap::new();
            for (key, value) in resp.headers() {
                if let Ok(val_str) = value.to_str() {
                    headers.insert(
                        key.as_str().to_lowercase(),
                        val_str.to_string(),
                    );
                }
            }

            return Some(HttpInfo { status, headers });
        }
    }

    None
}

fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs_f64();
    if total_secs < 1.0 {
        format!("{:.0}ms", total_secs * 1000.0)
    } else if total_secs < 60.0 {
        format!("{:.2}s", total_secs)
    } else {
        let mins = (total_secs / 60.0).floor() as u64;
        let secs = total_secs % 60.0;
        format!("{}m {:.2}s", mins, secs)
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let conn_timeout = Duration::from_millis(args.timeout);
    let total_ports = (args.end_port - args.start_port + 1) as u64;

    print_banner();
    print_divider();

    println!(
        "    {} {}",
        "TARGET:".bold(),
        args.target.yellow()
    );
    println!(
        "    {} {}-{} ({})",
        "RANGE:".bold(),
        args.start_port.to_string().white(),
        args.end_port.to_string().white(),
        format!("{} ports", total_ports).dimmed()
    );
    println!(
        "    {} {}ms  {} {}  {} {}  {} {}",
        "TIMEOUT:".bold(),
        args.timeout,
        "BATCH:".bold(),
        args.batch_size,
        "BANNERS:".bold(),
        if args.banners { "on".green().to_string() } else { "off".dimmed().to_string() },
        "PROBE:".bold(),
        if args.probe { "on".green().to_string() } else { "off".dimmed().to_string() }
    );

    print_divider();
    println!();

    // Phase 1: Port scan
    let progress = ProgressBar::new(total_ports);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("    {spinner:.cyan} [{bar:40.cyan/blue}] {pos}/{len} ports ({percent}%) | ETA: {eta}")
            .expect("Invalid progress bar template")
            .progress_chars("█▓░")
    );

    let start_time = Instant::now();
    let mut results: Vec<ScanResult> = Vec::new();

    for batch_start in (args.start_port..=args.end_port).step_by(args.batch_size) {
        let batch_end =
            (batch_start as usize + args.batch_size - 1).min(args.end_port as usize) as u16;

        let mut tasks = Vec::new();

        for port in batch_start..=batch_end {
            let addr: SocketAddr = format!("{}:{}", args.target, port)
                .parse()
                .expect("Invalid address");

            tasks.push(scan_port(addr, conn_timeout, args.banners));
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

    // Phase 2: HTTP probing on open ports
    if args.probe && !results.is_empty() {
        println!(
            "    {} probing {} open {} for HTTP/HTTPS...",
            "→".cyan(),
            results.len(),
            if results.len() == 1 { "port" } else { "ports" }
        );

        let probe_progress = ProgressBar::new(results.len() as u64);
        probe_progress.set_style(
            ProgressStyle::default_bar()
                .template("    {spinner:.magenta} [{bar:40.magenta/red}] {pos}/{len} probed | ETA: {eta}")
                .expect("Invalid progress bar template")
                .progress_chars("█▓░")
        );

        // Probe with longer timeout — HTTP handshakes + TLS take more time
        let probe_timeout = Duration::from_secs(5);

        for result in results.iter_mut() {
            result.http_info = probe_http(&args.target, result.port, probe_timeout).await;
            probe_progress.inc(1);
        }

        probe_progress.finish_and_clear();
    }

    let elapsed = start_time.elapsed();

    results.sort_by_key(|r| r.port);

    // Results output
    println!("    {}", "RESULTS".bold().underline());
    println!();

    if results.is_empty() {
        println!("    {} No open ports found. Either it's locked down", "¯\\_(ツ)_/¯".yellow());
        println!("    or something went wrong. Try a longer timeout?");
    } else {
        // Determine which columns to show
        let show_banner = args.banners;
        let show_probe = args.probe;

        // Header
        print!("    {:<12} {:<10}", "PORT".bold(), "STATE".bold());
        if show_banner { print!(" {:<30}", "BANNER".bold()); }
        if show_probe { print!(" {}", "HTTP".bold()); }
        println!();

        print!("    {:<12} {:<10}", "────", "─────");
        if show_banner { print!(" {:<30}", "──────"); }
        if show_probe { print!(" {}", "────"); }
        println!();

        for result in &results {
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

        // If probing, show detailed headers for ports that responded
        if show_probe {
            let http_results: Vec<&ScanResult> = results
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

                    // Show all captured headers, sorted
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
    }

    println!();
    print_divider();

    // Summary
    let port_count = results.len();
    let summary_color = if port_count == 0 {
        "0".dimmed().to_string()
    } else if port_count <= 5 {
        port_count.to_string().green().bold().to_string()
    } else if port_count <= 20 {
        port_count.to_string().yellow().bold().to_string()
    } else {
        port_count.to_string().red().bold().to_string()
    };

    println!(
        "    {} open {} on {}",
        summary_color,
        if port_count == 1 { "port" } else { "ports" },
        args.target.bold()
    );
    println!(
        "    {} ports scanned in {}",
        total_ports.to_string().bold(),
        format_duration(elapsed).yellow()
    );

    let signoffs = [
        "good luck!",
        "scan responsibly... or don't, I'm a CLI not a cop.",
        "done. go touch grass.",
        "that's all folks.",
    ];

    let mut rng = rand::rng();
    if let Some(signoff) = signoffs.choose(&mut rng) {
        println!("\n    {}\n", signoff.dimmed().italic());
    }
}