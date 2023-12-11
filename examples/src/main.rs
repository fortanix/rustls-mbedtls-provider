/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
**/

use std::io::{stderr, stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls_mbedcrypto_provider::mbedtls_crypto_provider;
use rustls_mbedpki_provider::MbedTlsServerCertVerifier;

fn main() {
    env_logger::init();

    let root_certs: Vec<_> = rustls_native_certs::load_native_certs()
        .expect("could not load platform certs")
        .into_iter()
        .map(|cert| cert.into())
        .collect();
    let server_cert_verifier = MbedTlsServerCertVerifier::new(&root_certs).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(mbedtls_crypto_provider().into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(server_cert_verifier))
        .with_no_client_auth();

    let server_name = "www.rust-lang.org".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect("www.rust-lang.org:443").unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: www.rust-lang.org\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let ciphersuite = tls
        .conn
        .negotiated_cipher_suite()
        .unwrap();
    writeln!(&mut stderr(), "Current ciphersuite: {:?}", ciphersuite.suite()).unwrap();
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
}
