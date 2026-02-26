```
    ██████╗ ██╗   ██╗███╗   ██╗████████╗
    ██╔══██╗██║   ██║████╗  ██║╚══██╔══╝
    ██████╔╝██║   ██║██╔██╗ ██║   ██║
    ██╔═══╝ ██║   ██║██║╚██╗██║   ██║
    ██║     ╚██████╔╝██║ ╚████║   ██║
    ╚═╝      ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
```
Port Utility for Network Testing — a fast, async port scanner in Rust.

## Usage
```
punt <TARGET> [OPTIONS]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--start-port` | `-s` | `1` | Start of port range |
| `--end-port` | `-e` | `1024` | End of port range |
| `--timeout` | `-t` | `500` | Connection timeout (ms) |
| `--batch-size` | `-b` | `5000` | Concurrent connections per batch |
| `--banners` | | `off` | Grab service banners |
| `--probe` | | `off` | HTTP/HTTPS header probing |

## Examples
```bash
punt 192.168.1.1 -e 65535                        # full port range
punt 192.168.1.1 -e 65535 --banners --probe      # recon mode
punt 192.168.1.1 -e 65535 -t 200 -b 10000        # speed run
```

## Roadmap
- [x] Async TCP connect scanning
- [x] Banner grabbing
- [x] HTTP/HTTPS header probing
- [ ] Security header analysis
- [ ] TLS certificate inspection
- [ ] CVE lookup
- [ ] JSON output
- [ ] CIDR range scanning

## Install
```bash
git clone https://github.com/YOURUSERNAME/punt.git
cd punt
cargo build --release
```

Only scan networks you own or have permission to test.