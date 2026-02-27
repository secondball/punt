use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use rustls::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

use crate::models::TlsInfo;

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

pub async fn inspect_tls(target: &str, port: u16, conn_timeout: Duration) -> Option<TlsInfo> {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let addr: SocketAddr = format!("{}:{}", target, port).parse().ok()?;
    let tcp_stream = match timeout(conn_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let server_name = ServerName::try_from(target.to_string()).unwrap_or(
        ServerName::try_from("invalid".to_string()).unwrap()
    );

    let tls_stream = match timeout(conn_timeout, connector.connect(server_name, tcp_stream)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

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

    let certs = client_conn.peer_certificates()?;
    let cert_der = certs.first()?;

    let (_, cert) = X509Certificate::from_der(cert_der.as_ref()).ok()?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let self_signed = cert.subject() == cert.issuer();

    let not_before = cert.validity().not_before.to_rfc2822().unwrap_or("Unknown".to_string());
    let not_after = cert.validity().not_after.to_rfc2822().unwrap_or("Unknown".to_string());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let expiry = cert.validity().not_after.timestamp();
    let days_until_expiry = (expiry - now) / 86400;

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
