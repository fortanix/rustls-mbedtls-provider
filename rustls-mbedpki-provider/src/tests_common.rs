/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use std::{
    io,
    ops::{Deref, DerefMut},
};

use rustls::{
    client::ServerCertVerifier, Certificate, ClientConnection, ConnectionCommon, PrivateKey, ServerConnection, SideData,
};

/// Get a certificate chain from the contents of a pem file
pub fn get_chain(bytes: &[u8]) -> Vec<Certificate> {
    rustls_pemfile::certs(&mut io::BufReader::new(bytes))
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect()
}

/// Get a private key from the contents of a pem file
pub fn get_key(bytes: &[u8]) -> PrivateKey {
    PrivateKey(
        rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(bytes))
            .unwrap()
            .into_iter()
            .next()
            .unwrap(),
    )
}

// Copied from rustls repo
pub fn transfer(
    left: &mut (impl DerefMut + Deref<Target = ConnectionCommon<impl SideData>>),
    right: &mut (impl DerefMut + Deref<Target = ConnectionCommon<impl SideData>>),
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
pub fn do_handshake_until_error(client: &mut ClientConnection, server: &mut ServerConnection) -> Result<(), rustls::Error> {
    while server.is_handshaking() || client.is_handshaking() {
        transfer(client, server);
        server.process_new_packets()?;
        transfer(server, client);
        client.process_new_packets()?;
    }
    Ok(())
}

pub struct VerifierWithSupportedVerifySchemes<V> {
    pub verifier: V,
    pub supported_verify_schemes: Vec<rustls::SignatureScheme>,
}

impl<V: ServerCertVerifier> ServerCertVerifier for VerifierWithSupportedVerifySchemes<V> {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &rustls::ServerName,
        scts: &mut dyn Iterator<Item = &[u8]>,
        ocsp_response: &[u8],
        now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        self.verifier
            .verify_server_cert(end_entity, intermediates, server_name, scts, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        self.verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        self.verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_verify_schemes.clone()
    }

    fn request_scts(&self) -> bool {
        self.verifier.request_scts()
    }
}
