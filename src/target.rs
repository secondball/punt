use std::net::IpAddr;
use std::time::Duration;
use ipnetwork::IpNetwork;
use tokio::net::TcpStream;
use tokio::time::timeout;

pub fn parse_targets(input: &str) -> Result<Vec<IpAddr>, String> {
    if input.contains('/') {
        let network: IpNetwork = input.parse()
            .map_err(|e| format!("Invalid CIDR notation: {}", e))?;

        let hosts: Vec<IpAddr> = network.iter()
            .filter(|ip| {
                if let (IpAddr::V4(addr), IpNetwork::V4(net)) = (ip, &network) {
                    if net.prefix() < 31 {
                        return *addr != net.network() && *addr != net.broadcast();
                    }
                }
                true
            })
            .collect();

        if hosts.is_empty() {
            return Err("CIDR range contains no usable hosts".to_string());
        }

        Ok(hosts)
    } else {
        let addr: IpAddr = input.parse()
            .map_err(|_| {
                use std::net::ToSocketAddrs;
                match (input, 0u16).to_socket_addrs() {
                    Ok(mut addrs) => match addrs.next() {
                        Some(addr) => return addr.ip().to_string(),
                        None => {}
                    },
                    Err(_) => {}
                }
                format!("Could not resolve '{}'", input)
            })
            .or_else(|resolved| resolved.parse()
                .map_err(|_| format!("Could not resolve '{}'", input))
            )?;

        Ok(vec![addr])
    }
}

/// Check if a host is alive by trying to connect to common ports
pub async fn is_host_alive(ip: IpAddr, timeout_ms: u64) -> bool {
    let probe_ports = [80, 443, 22, 445, 139, 3389, 8080, 8443, 53, 21];
    let dur = Duration::from_millis(timeout_ms);

    let mut tasks = Vec::new();

    for port in probe_ports {
        let addr = format!("{}:{}", ip, port);
        tasks.push(async move {
            if let Ok(addr) = addr.parse::<std::net::SocketAddr>() {
                timeout(dur, TcpStream::connect(addr)).await.is_ok()
            } else {
                false
            }
        });
    }

    let results = futures::future::join_all(tasks).await;
    results.iter().any(|r| *r)
}