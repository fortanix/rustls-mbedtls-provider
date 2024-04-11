/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use std::io;

use core::{
    fmt::Debug,
    ops::DerefMut,
};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{client::danger::ServerCertVerifier, ClientConnection, ConnectionCommon, ServerConnection, SideData};

/// Get a certificate chain from the contents of a pem file
pub(crate) fn get_chain(bytes: &[u8]) -> Vec<CertificateDer> {
    rustls_pemfile::certs(&mut io::BufReader::new(bytes))
        .map(Result::unwrap)
        .map(CertificateDer::from)
        .collect()
}

/// Get a private key from the contents of a pem file
pub(crate) fn get_key(bytes: &[u8]) -> PrivateKeyDer {
    let value = rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(bytes))
        .next()
        .unwrap()
        .unwrap();
    PrivateKeyDer::from(value)
}

// Copied from rustls repo
pub(crate) fn transfer(
    left: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
    right: &mut impl DerefMut <Target = ConnectionCommon<impl SideData>>,
) -> usize {
    let mut buf = [0u8; 262144];
    let mut total = 0;

    while left.wants_write() {
        let sz = {
            let into_buf: &mut dyn io::Write = &mut &mut buf[..];
            left.write_tls(into_buf).unwrap()
        };
        total += sz;
        if sz == 0 {
            return total;
        }

        let mut offs = 0;
        loop {
            let from_buf: &mut dyn io::Read = &mut &buf[offs..sz];
            offs += right.read_tls(from_buf).unwrap();
            if sz == offs {
                break;
            }
        }
    }

    total
}

// Copied from rustls repo
pub(crate) fn do_handshake_until_error(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), rustls::Error> {
    while server.is_handshaking() || client.is_handshaking() {
        transfer(client, server);
        server.process_new_packets()?;
        transfer(server, client);
        client.process_new_packets()?;
    }
    Ok(())
}

pub(crate) struct VerifierWithSupportedVerifySchemes<V> {
    pub(crate) verifier: V,
    pub(crate) supported_verify_schemes: Vec<rustls::SignatureScheme>,
}

impl<V> Debug for VerifierWithSupportedVerifySchemes<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifierWithSupportedVerifySchemes")
            .field("verifier", &"..")
            .field("supported_verify_schemes", &self.supported_verify_schemes)
            .finish()
    }
}

impl<V: ServerCertVerifier> ServerCertVerifier for VerifierWithSupportedVerifySchemes<V> {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        server_name: &ServerName,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        self.verifier
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_verify_schemes.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_with_supported_verify_schemes_debug() {
        let verifier = VerifierWithSupportedVerifySchemes {
            verifier: "Sample Verifier".to_string(),
            supported_verify_schemes: vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA1,
                rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            ],
        };

        assert_eq!("VerifierWithSupportedVerifySchemes { verifier: \"..\", supported_verify_schemes: [RSA_PKCS1_SHA1, ECDSA_NISTP521_SHA512] }",format!("{:?}", verifier));
    }
}
