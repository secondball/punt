use std::collections::HashMap;
use std::time::Duration;
use colored::*;
use rand::seq::IndexedRandom;
use serde::Serialize;

// ── Display helpers ──

pub fn print_banner() {
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

pub fn print_divider() {
    println!("{}", "    ─────────────────────────────────────".dimmed());
}

pub fn print_signoff() {
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

pub fn format_duration(duration: Duration) -> String {
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

// ── JSON output structs ──

#[derive(Serialize)]
pub struct JsonOutput {
    pub target: String,
    pub ports_scanned: u64,
    pub scan_duration: String,
    pub results: Vec<JsonPortResult>,
}

#[derive(Serialize)]
pub struct JsonPortResult {
    pub port: u16,
    pub state: String,
    pub banner: Option<String>,
    pub http: Option<JsonHttp>,
    pub tls: Option<JsonTls>,
    pub findings: Vec<JsonFinding>,
}

#[derive(Serialize)]
pub struct JsonHttp {
    pub status: u16,
    pub scheme: String,
    pub headers: HashMap<String, String>,
}

#[derive(Serialize)]
pub struct JsonTls {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub days_until_expiry: i64,
    pub sans: Vec<String>,
    pub tls_version: String,
    pub cipher_suite: String,
    pub self_signed: bool,
}

#[derive(Serialize)]
pub struct JsonFinding {
    pub severity: String,
    pub title: String,
    pub detail: String,
}
