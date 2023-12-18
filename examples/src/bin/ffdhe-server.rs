/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use std::io::Write;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls_mbedcrypto_provider::{kx_group, mbedtls_crypto_provider};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Get a certificate chain from the contents of a pem file
fn get_chain(bytes: &[u8]) -> Vec<CertificateDer> {
    rustls_pemfile::certs(&mut std::io::BufReader::new(bytes))
        .map(Result::unwrap)
        .map(CertificateDer::from)
        .collect()
}

/// Get a private key from the contents of a pem file
fn get_key(bytes: &[u8]) -> PrivateKeyDer {
    let value = rustls_pemfile::pkcs8_private_keys(&mut std::io::BufReader::new(bytes))
        .next()
        .unwrap()
        .unwrap();
    PrivateKeyDer::from(value)
}

fn main() {
    env_logger::init();

    let cert = get_chain(include_bytes!("../../../rustls-mbedpki-provider/test-data/rsa/end.fullchain").as_ref());
    let key = get_key(include_bytes!("../../../rustls-mbedpki-provider/test-data/rsa/end.key").as_ref());
    let config = rustls::ServerConfig::builder_with_provider(
        CryptoProvider {
            cipher_suites: vec![
                rustls_mbedcrypto_provider::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                rustls_mbedcrypto_provider::cipher_suite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            ],
            kx_groups: vec![kx_group::FFDHE2048],
            ..mbedtls_crypto_provider()
        }
        .into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(cert, key)
    .unwrap();

    let config = Arc::new(config);

    let server = std::net::TcpListener::bind(("localhost", 8888)).unwrap();
    loop {
        let mut sock = server.accept().unwrap();
        let mut conn = rustls::ServerConnection::new(config.clone()).unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut sock.0);
        println!("write res: {:?}", tls.write_all(b"Hi there!"));
        let _ = tls.flush();
    }
}
