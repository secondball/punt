use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio::io::AsyncReadExt;

use crate::models::ScanResult;

pub async fn scan_port(addr: SocketAddr, conn_timeout: Duration, grab_banner: bool) -> Option<ScanResult> {
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
