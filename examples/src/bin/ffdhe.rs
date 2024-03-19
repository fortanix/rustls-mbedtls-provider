/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls_mbedcrypto_provider::kx_group;
use rustls_mbedcrypto_provider::mbedtls_crypto_provider;
use rustls_mbedpki_provider::MbedTlsServerCertVerifier;

fn main() {
    env_logger::init();

    let check_server_cert = true;
    let server = "browserleaks.com";
    let path = "/";
    let port = 443;

    let server_cert_verifier: Arc<dyn ServerCertVerifier> = if check_server_cert {
        let root_certs: Vec<_> = rustls_native_certs::load_native_certs()
            .expect("could not load platform certs")
            .into_iter()
            .map(|cert| cert.into())
            .collect();
        Arc::new(MbedTlsServerCertVerifier::new(&root_certs).unwrap())
    } else {
        Arc::new(NoopServerCertVerifier)
    };

    let config = rustls::ClientConfig::builder_with_provider(
        CryptoProvider {
            cipher_suites: vec![
                rustls_mbedcrypto_provider::cipher_suite::TLS13_AES_256_GCM_SHA384,
                rustls_mbedcrypto_provider::cipher_suite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                rustls_mbedcrypto_provider::cipher_suite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
                rustls_mbedcrypto_provider::cipher_suite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ],
            kx_groups: vec![kx_group::FFDHE2048, kx_group::FFDHE3072, kx_group::FFDHE4096],
            ..mbedtls_crypto_provider()
        }
        .into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(server_cert_verifier)
    .with_no_client_auth();

    let server_name = server.try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect((server, port)).unwrap();
    conn.complete_io(&mut sock).unwrap();
    println!("tls connection established");
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(
        format!(
            "HEAD {path} HTTP/1.1\r\n \
            Host: {server}\r\n \
            Connection: close\r\n \
            Accept-Encoding: identity\r\n \
            \r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    tls.flush().unwrap();

    let ciphersuite = tls
        .conn
        .negotiated_cipher_suite()
        .unwrap();
    println!("Current ciphersuite: {:?}", ciphersuite.suite());

    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    println!("Response:");
    stdout().write_all(&plaintext).unwrap();
}

#[derive(Debug)]
#[allow(dead_code)]
struct NoopServerCertVerifier;
impl ServerCertVerifier for NoopServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls_mbedpki_provider::SUPPORTED_SIGNATURE_SCHEMA.to_vec()
    }
}
