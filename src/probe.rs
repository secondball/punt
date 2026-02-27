use std::collections::HashMap;
use std::time::Duration;

use crate::models::HttpInfo;

pub async fn probe_http(target: &str, port: u16, conn_timeout: Duration) -> Option<HttpInfo> {
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
