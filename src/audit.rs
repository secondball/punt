use crate::models::{Finding, HttpInfo, Severity, TlsInfo};

pub fn audit_headers(port: u16, info: &HttpInfo) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();

    // HIGH: Version info leaking
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

    // HIGH: Missing HSTS on HTTPS
    if info.scheme == "https" && !info.headers.contains_key("strict-transport-security") {
        findings.push(Finding {
            severity: Severity::High,
            title: "Missing Strict-Transport-Security".to_string(),
            detail: format!(":{} — HTTPS without HSTS, vulnerable to downgrade attacks", port),
        });
    }

    // MEDIUM: Missing core security headers
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

    // INFO: Nice-to-have headers
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

pub fn audit_tls(port: u16, info: &TlsInfo) -> Vec<Finding> {
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
