use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio::io::AsyncReadExt;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use colored::*;
use rand::seq::IndexedRandom;
use rustls::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

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

    /// Analyze security headers on probed ports
    #[arg(long, default_value_t = false)]
    audit: bool,

    /// Inspect TLS certificates on open ports
    #[arg(long, default_value_t = false)]
    tls: bool,
}

struct ScanResult {
    port: u16,
    banner: Option<String>,
    http_info: Option<HttpInfo>,
    tls_info: Option<TlsInfo>,
    findings: Vec<Finding>,
}

struct HttpInfo {
    status: u16,
    headers: HashMap<String, String>,
    scheme: String,
}

struct TlsInfo {
    subject: String,
    issuer: String,
    not_before: String,
    not_after: String,
    days_until_expiry: i64,
    sans: Vec<String>,
    tls_version: String,
    cipher_suite: String,
    self_signed: bool,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
enum Severity {
    High,
    Medium,
    Info,
}

impl Severity {
    fn label(&self) -> ColoredString {
        match self {
            Severity::High => "HIGH".red().bold(),
            Severity::Medium => "MED".yellow().bold(),
            Severity::Info => "INFO".blue(),
        }
    }

    fn icon(&self) -> ColoredString {
        match self {
            Severity::High => "✗".red().bold(),
            Severity::Medium => "⚠".yellow(),
            Severity::Info => "○".blue(),
        }
    }
}

struct Finding {
    severity: Severity,
    title: String,
    detail: String,
}

impl HttpInfo {
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

// Custom TLS verifier that accepts any certificate (we want to inspect, not reject)
#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

async fn inspect_tls(target: &str, port: u16, conn_timeout: Duration) -> Option<TlsInfo> {
    // Build a TLS config that accepts any cert
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    // Connect TCP first
    let addr: SocketAddr = format!("{}:{}", target, port).parse().ok()?;
    let tcp_stream = match timeout(conn_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    // Do TLS handshake
    let server_name = ServerName::try_from(target.to_string()).unwrap_or(
        ServerName::try_from("invalid".to_string()).unwrap()
    );

    let tls_stream = match timeout(conn_timeout, connector.connect(server_name, tcp_stream)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    // Extract connection info
    let (_, client_conn) = tls_stream.get_ref();

    let tls_version = match client_conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_0) => "TLS 1.0".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_1) => "TLS 1.1".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLS 1.2".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLS 1.3".to_string(),
        Some(v) => format!("{:?}", v),
        None => "Unknown".to_string(),
    };

    let cipher_suite = client_conn
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()))
        .unwrap_or("Unknown".to_string());

    // Get the peer certificate
    let certs = client_conn.peer_certificates()?;
    let cert_der = certs.first()?;

    // Parse the certificate
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref()).ok()?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let self_signed = cert.subject() == cert.issuer();

    let not_before = cert.validity().not_before.to_rfc2822().unwrap_or("Unknown".to_string());
    let not_after = cert.validity().not_after.to_rfc2822().unwrap_or("Unknown".to_string());

    // Calculate days until expiry
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let expiry = cert.validity().not_after.timestamp();
    let days_until_expiry = (expiry - now) / 86400;

    // Extract SANs
    let mut sans: Vec<String> = Vec::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            match name {
                GeneralName::DNSName(dns) => sans.push(dns.to_string()),
                GeneralName::IPAddress(ip) => {
                    if ip.len() == 4 {
                        sans.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                    } else {
                        sans.push(format!("{:?}", ip));
                    }
                }
                _ => {}
            }
        }
    }

    Some(TlsInfo {
        subject,
        issuer,
        not_before,
        not_after,
        days_until_expiry,
        sans,
        tls_version,
        cipher_suite,
        self_signed,
    })
}

fn audit_headers(port: u16, info: &HttpInfo) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();

    if let Some(server) = info.headers.get("server") {
        if server.chars().any(|c| c.is_ascii_digit()) {
            findings.push(Finding {
                severity: Severity::High,
                title: "Server header leaks version".to_string(),
                detail: format!(":{} — Server: {} (aids targeted exploits)", port, server),
            });
        }
    }

    if let Some(powered) = info.headers.get("x-powered-by") {
        findings.push(Finding {
            severity: Severity::High,
            title: "X-Powered-By header present".to_string(),
            detail: format!(":{} — X-Powered-By: {} (disclose framework/version)", port, powered),
        });
    }

    if let Some(aspnet) = info.headers.get("x-aspnet-version") {
        findings.push(Finding {
            severity: Severity::High,
            title: "X-AspNet-Version header present".to_string(),
            detail: format!(":{} — X-AspNet-Version: {} (disclose runtime version)", port, aspnet),
        });
    }

    if info.scheme == "https" && !info.headers.contains_key("strict-transport-security") {
        findings.push(Finding {
            severity: Severity::High,
            title: "Missing Strict-Transport-Security".to_string(),
            detail: format!(":{} — HTTPS without HSTS, vulnerable to downgrade attacks", port),
        });
    }

    if !info.headers.contains_key("x-content-type-options") {
        findings.push(Finding {
            severity: Severity::Medium,
            title: "Missing X-Content-Type-Options".to_string(),
            detail: format!(":{} — should be 'nosniff' to prevent MIME-type sniffing", port),
        });
    } else if let Some(val) = info.headers.get("x-content-type-options") {
        if val.to_lowercase() != "nosniff" {
            findings.push(Finding {
                severity: Severity::Medium,
                title: "X-Content-Type-Options misconfigured".to_string(),
                detail: format!(":{} — value is '{}', should be 'nosniff'", port, val),
            });
        }
    }

    if !info.headers.contains_key("x-frame-options") {
        findings.push(Finding {
            severity: Severity::Medium,
            title: "Missing X-Frame-Options".to_string(),
            detail: format!(":{} — page can be embedded in iframes (clickjacking risk)", port),
        });
    }

    if !info.headers.contains_key("content-security-policy") {
        findings.push(Finding {
            severity: Severity::Info,
            title: "Missing Content-Security-Policy".to_string(),
            detail: format!(":{} — no CSP, reduced XSS protection", port),
        });
    }

    if !info.headers.contains_key("referrer-policy") {
        findings.push(Finding {
            severity: Severity::Info,
            title: "Missing Referrer-Policy".to_string(),
            detail: format!(":{} — browser will send full referrer by default", port),
        });
    }

    if !info.headers.contains_key("permissions-policy") {
        findings.push(Finding {
            severity: Severity::Info,
            title: "Missing Permissions-Policy".to_string(),
            detail: format!(":{} — no restrictions on browser features (camera, mic, etc.)", port),
        });
    }

    findings
}

fn audit_tls(port: u16, info: &TlsInfo) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();

    // Expired cert
    if info.days_until_expiry < 0 {
        findings.push(Finding {
            severity: Severity::High,
            title: "TLS certificate expired".to_string(),
            detail: format!(":{} — expired {} days ago", port, info.days_until_expiry.abs()),
        });
    } else if info.days_until_expiry <= 30 {
        findings.push(Finding {
            severity: Severity::Medium,
            title: "TLS certificate expiring soon".to_string(),
            detail: format!(":{} — expires in {} days", port, info.days_until_expiry),
        });
    }

    // Self-signed
    if info.self_signed {
        findings.push(Finding {
            severity: Severity::Medium,
            title: "Self-signed certificate".to_string(),
            detail: format!(":{} — not issued by a trusted CA", port),
        });
    }

    // Weak TLS version
    match info.tls_version.as_str() {
        "TLS 1.0" => {
            findings.push(Finding {
                severity: Severity::High,
                title: "TLS 1.0 in use".to_string(),
                detail: format!(":{} — deprecated, known vulnerabilities (BEAST, POODLE)", port),
            });
        }
        "TLS 1.1" => {
            findings.push(Finding {
                severity: Severity::High,
                title: "TLS 1.1 in use".to_string(),
                detail: format!(":{} — deprecated since 2021, upgrade to 1.2+", port),
            });
        }
        "TLS 1.2" => {
            findings.push(Finding {
                severity: Severity::Info,
                title: "TLS 1.2 in use".to_string(),
                detail: format!(":{} — acceptable, but TLS 1.3 is preferred", port),
            });
        }
        _ => {}
    }

    // Check for weak cipher suites
    let cipher_lower = info.cipher_suite.to_lowercase();
    if cipher_lower.contains("rc4") {
        findings.push(Finding {
            severity: Severity::High,
            title: "RC4 cipher in use".to_string(),
            detail: format!(":{} — {} (broken, trivially exploitable)", port, info.cipher_suite),
        });
    } else if cipher_lower.contains("des") || cipher_lower.contains("3des") {
        findings.push(Finding {
            severity: Severity::High,
            title: "DES/3DES cipher in use".to_string(),
            detail: format!(":{} — {} (weak, vulnerable to Sweet32)", port, info.cipher_suite),
        });
    } else if cipher_lower.contains("null") {
        findings.push(Finding {
            severity: Severity::High,
            title: "NULL cipher in use".to_string(),
            detail: format!(":{} — {} (no encryption!)", port, info.cipher_suite),
        });
    } else if cipher_lower.contains("cbc") {
        findings.push(Finding {
            severity: Severity::Info,
            title: "CBC mode cipher in use".to_string(),
            detail: format!(":{} — {} (GCM or CHACHA20 preferred)", port, info.cipher_suite),
        });
    }

    findings
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
        "RST packets go brrrrr",
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
            tls_info: None,
            findings: Vec::new(),
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
        tls_info: None,
        findings: Vec::new(),
    })
}

async fn probe_http(target: &str, port: u16, conn_timeout: Duration) -> Option<HttpInfo> {
    let schemes = if matches!(port, 443 | 8443 | 8006 | 9443) {
        vec!["https", "http"]
    } else {
        vec!["http", "https"]
    };

    let client = reqwest::Client::builder()
        .timeout(conn_timeout)
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
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

            return Some(HttpInfo {
                status,
                headers,
                scheme: scheme.to_string(),
            });
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
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");
    
    let args = Args::parse();
    let conn_timeout = Duration::from_millis(args.timeout);
    let total_ports = (args.end_port - args.start_port + 1) as u64;

    let do_probe = args.probe || args.audit;
    let do_audit = args.audit || args.tls;

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

    // Phase 2: HTTP probing
    if do_probe && !results.is_empty() {
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

        let probe_timeout = Duration::from_secs(5);

        for result in results.iter_mut() {
            result.http_info = probe_http(&args.target, result.port, probe_timeout).await;
            probe_progress.inc(1);
        }

        probe_progress.finish_and_clear();
    }

    // Phase 3: TLS inspection
    if args.tls && !results.is_empty() {
        println!(
            "    {} inspecting TLS on {} open {}...",
            "→".cyan(),
            results.len(),
            if results.len() == 1 { "port" } else { "ports" }
        );

        let tls_progress = ProgressBar::new(results.len() as u64);
        tls_progress.set_style(
            ProgressStyle::default_bar()
                .template("    {spinner:.green} [{bar:40.green/white}] {pos}/{len} inspected | ETA: {eta}")
                .expect("Invalid progress bar template")
                .progress_chars("█▓░")
        );

        let tls_timeout = Duration::from_secs(5);

        for result in results.iter_mut() {
            result.tls_info = inspect_tls(&args.target, result.port, tls_timeout).await;
            tls_progress.inc(1);
        }

        tls_progress.finish_and_clear();
    }

    // Phase 4: Audit
    if do_audit {
        for result in results.iter_mut() {
            if let Some(info) = &result.http_info {
                result.findings.extend(audit_headers(result.port, info));
            }
            if let Some(info) = &result.tls_info {
                result.findings.extend(audit_tls(result.port, info));
            }
        }
    }

    let elapsed = start_time.elapsed();

    results.sort_by_key(|r| r.port);

    // ── Results table ──
    println!("    {}", "RESULTS".bold().underline());
    println!();

    if results.is_empty() {
        println!("    {} No open ports found. Either it's locked down", "¯\\_(ツ)_/¯".yellow());
        println!("    or something went wrong. Try a longer timeout?");
    } else {
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

        // ── Headers section ──
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

        // ── TLS section ──
        if args.tls {
            let tls_results: Vec<&ScanResult> = results
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

                    // Color the expiry based on urgency
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
            } else {
                println!();
                println!("    {}", "TLS CERTIFICATES".bold().underline());
                println!();
                println!("    {} No TLS services detected on open ports.", "—".dimmed());
            }
        }

        // ── Audit section ──
        if do_audit {
            let all_findings: Vec<(&ScanResult, &Finding)> = results
                .iter()
                .flat_map(|r| r.findings.iter().map(move |f| (r, f)))
                .collect();

            if !all_findings.is_empty() {
                println!();
                println!("    {}", "SECURITY AUDIT".bold().underline());
                println!();

                let high_count = all_findings.iter()
                    .filter(|(_, f)| f.severity == Severity::High).count();
                let med_count = all_findings.iter()
                    .filter(|(_, f)| f.severity == Severity::Medium).count();
                let info_count = all_findings.iter()
                    .filter(|(_, f)| f.severity == Severity::Info).count();

                println!(
                    "    {}  {}  {}",
                    format!("{} HIGH", high_count).red().bold(),
                    format!("{} MED", med_count).yellow().bold(),
                    format!("{} INFO", info_count).blue(),
                );
                println!();

                let highs: Vec<&(&ScanResult, &Finding)> = all_findings.iter()
                    .filter(|(_, f)| f.severity == Severity::High).collect();
                if !highs.is_empty() {
                    for (_, finding) in &highs {
                        println!(
                            "    {} [{}] {}",
                            finding.severity.icon(),
                            finding.severity.label(),
                            finding.title.bold()
                        );
                        println!("           {}", finding.detail.dimmed());
                    }
                    println!();
                }

                let meds: Vec<&(&ScanResult, &Finding)> = all_findings.iter()
                    .filter(|(_, f)| f.severity == Severity::Medium).collect();
                if !meds.is_empty() {
                    for (_, finding) in &meds {
                        println!(
                            "    {} [{}]  {}",
                            finding.severity.icon(),
                            finding.severity.label(),
                            finding.title.bold()
                        );
                        println!("           {}", finding.detail.dimmed());
                    }
                    println!();
                }

                let infos: Vec<&(&ScanResult, &Finding)> = all_findings.iter()
                    .filter(|(_, f)| f.severity == Severity::Info).collect();
                if !infos.is_empty() {
                    for (_, finding) in &infos {
                        println!(
                            "    {} [{}] {}",
                            finding.severity.icon(),
                            finding.severity.label(),
                            finding.title
                        );
                        println!("           {}", finding.detail.dimmed());
                    }
                }
            } else {
                println!();
                println!("    {}", "SECURITY AUDIT".bold().underline());
                println!();
                println!("    {} No findings. Looking solid.", "✓".green().bold());
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

    if do_audit {
        let total_findings: usize = results.iter().map(|r| r.findings.len()).sum();
        let high_total: usize = results.iter()
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