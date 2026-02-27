use std::collections::HashMap;
use colored::*;

// ── Core scan result ──

pub struct ScanResult {
    pub port: u16,
    pub banner: Option<String>,
    pub http_info: Option<HttpInfo>,
    pub tls_info: Option<TlsInfo>,
    pub findings: Vec<Finding>,
}

// ── HTTP ──

pub struct HttpInfo {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub scheme: String,
}

impl HttpInfo {
    pub fn summary(&self) -> String {
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

// ── TLS ──

pub struct TlsInfo {
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

// ── Findings ──

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum Severity {
    High,
    Medium,
    Info,
}

impl Severity {
    pub fn label(&self) -> ColoredString {
        match self {
            Severity::High => "HIGH".red().bold(),
            Severity::Medium => "MED".yellow().bold(),
            Severity::Info => "INFO".blue(),
        }
    }

    pub fn icon(&self) -> ColoredString {
        match self {
            Severity::High => "✗".red().bold(),
            Severity::Medium => "⚠".yellow(),
            Severity::Info => "○".blue(),
        }
    }
}

pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
}
