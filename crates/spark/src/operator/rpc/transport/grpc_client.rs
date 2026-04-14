use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use http::Uri;
use hyper_util::rt::TokioIo;
use rustls::crypto::ring;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector as RustlsConnector;
use tonic::transport::{ClientTlsConfig, Endpoint};
use tower_service::Service;

use super::retry_channel::RetryChannel;
use crate::{default_user_agent, operator::rpc::OperatorRpcError};

pub type Transport = RetryChannel<tonic::transport::Channel>;

const ALPN_H2: &[u8] = b"h2";

#[derive(Clone)]
pub struct GrpcClient {
    inner: Transport,
}

impl GrpcClient {
    pub fn new(
        url: String,
        ca_cert: Option<Vec<u8>>,
        user_agent: Option<String>,
    ) -> Result<Self, OperatorRpcError> {
        let _ = ring::default_provider().install_default();
        let use_local_tls_bypass = should_bypass_tls_verification(&url, ca_cert.as_deref());
        let endpoint = Self::create_endpoint(&url, ca_cert, user_agent, use_local_tls_bypass)?;
        let channel = if use_local_tls_bypass {
            endpoint.connect_with_connector_lazy(LocalTlsBypassConnector::new())
        } else {
            endpoint.connect_lazy()
        };

        Ok(Self {
            inner: RetryChannel::new(channel),
        })
    }

    pub fn into_inner(self) -> Transport {
        self.inner
    }

    fn create_endpoint(
        server_url: &str,
        ca_cert: Option<Vec<u8>>,
        user_agent: Option<String>,
        use_local_tls_bypass: bool,
    ) -> Result<Endpoint, OperatorRpcError> {
        let endpoint_url = if use_local_tls_bypass {
            server_url.replacen("https://", "http://", 1)
        } else {
            server_url.to_string()
        };
        let endpoint = Endpoint::from_shared(endpoint_url)?;
        let endpoint = if use_local_tls_bypass {
            endpoint
        } else {
            let client_tls_config = match ca_cert {
                Some(ca_cert) => {
                    ClientTlsConfig::new()
                        .ca_certificate(tonic::transport::Certificate::from_pem(ca_cert))
                }
                None => ClientTlsConfig::new().with_webpki_roots(),
            };
            endpoint.tls_config(client_tls_config)?
        };

        Ok(endpoint
            .http2_keep_alive_interval(Duration::new(5, 0))
            .tcp_keepalive(Some(Duration::from_secs(5)))
            .keep_alive_timeout(Duration::from_secs(5))
            .keep_alive_while_idle(true)
            .timeout(Duration::from_secs(60))
            .user_agent(user_agent.unwrap_or_else(default_user_agent))?)
    }
}

impl From<tonic::transport::Error> for OperatorRpcError {
    fn from(error: tonic::transport::Error) -> Self {
        OperatorRpcError::Transport(error.to_string())
    }
}

fn should_bypass_tls_verification(server_url: &str, ca_cert: Option<&[u8]>) -> bool {
    if ca_cert.is_some() {
        return false;
    }

    let Ok(uri) = server_url.parse::<Uri>() else {
        return false;
    };

    matches!(uri.host(), Some("localhost" | "127.0.0.1" | "::1"))
        || uri
            .host()
            .is_some_and(|host| host.ends_with(".minikube.local"))
}

#[derive(Clone)]
struct LocalTlsBypassConnector {
    connector: RustlsConnector,
}

impl LocalTlsBypassConnector {
    fn new() -> Self {
        let mut config = ClientConfig::builder_with_provider(ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .expect("ring provider supports rustls default protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        config.alpn_protocols.push(ALPN_H2.to_vec());

        Self {
            connector: RustlsConnector::from(Arc::new(config)),
        }
    }
}

impl Service<Uri> for LocalTlsBypassConnector {
    type Response = TokioIo<tokio_rustls::client::TlsStream<TcpStream>>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connector = self.connector.clone();

        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing host"))?
                .to_string();
            let port = uri.port_u16().unwrap_or(443);
            let server_name = ServerName::try_from(host.as_str())
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid host {host}: {error}"),
                    )
                })?
                .to_owned();

            let stream = TcpStream::connect((host.as_str(), port)).await?;
            let tls_stream = connector
                .connect(server_name, stream)
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;

            let (_, session) = tls_stream.get_ref();
            if session.alpn_protocol() != Some(ALPN_H2) {
                return Err(io::Error::other("gRPC TLS handshake did not negotiate h2"));
            }

            Ok(TokioIo::new(tls_stream))
        })
    }
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::should_bypass_tls_verification;

    #[test]
    fn bypasses_tls_only_for_loopback_without_custom_ca() {
        assert!(should_bypass_tls_verification(
            "https://localhost:8535",
            None,
        ));
        assert!(should_bypass_tls_verification(
            "https://127.0.0.1:8535",
            None,
        ));
        assert!(!should_bypass_tls_verification(
            "https://localhost:8535",
            Some(b"custom-ca"),
        ));
        assert!(!should_bypass_tls_verification(
            "https://0.spark.minikube.local",
            Some(b"custom-ca"),
        ));
        assert!(should_bypass_tls_verification(
            "https://0.spark.minikube.local",
            None,
        ));
        assert!(!should_bypass_tls_verification(
            "https://0.spark.lightspark.com",
            None,
        ));
    }
}
