/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use std::time::SystemTime;

use rustls::{
    server::{ClientCertVerified, ClientCertVerifier},
    DistinguishedName,
};

use crate::{
    mbedtls_err_into_rustls_err, mbedtls_err_into_rustls_err_with_error_msg, rustls_cert_to_mbedtls_cert,
    verify_certificates_active, verify_tls_signature,
};

/// A `rustls` `ClientCertVerifier` implemented using the PKI functionality of
/// `mbedtls`
#[derive(Clone)]
pub struct MbedTlsClientCertVerifier {
    trusted_cas: mbedtls::alloc::List<mbedtls::x509::Certificate>,
    root_subjects: Vec<rustls::DistinguishedName>,
}

impl MbedTlsClientCertVerifier {
    /// Constructs a new `MbedTlsClientCertVerifier` object given the provided trusted certificate authority
    /// certificates.
    ///
    /// Returns an error if any of the certificates are invalid.
    pub fn new<'a>(trusted_cas: impl IntoIterator<Item = &'a rustls::Certificate>) -> mbedtls::Result<Self> {
        let trusted_cas = trusted_cas
            .into_iter()
            .map(rustls_cert_to_mbedtls_cert)
            .collect::<mbedtls::Result<Vec<_>>>()?
            .into_iter()
            .collect();
        Self::new_from_mbedtls_trusted_cas(trusted_cas)
    }

    /// Constructs a new `MbedTlsClientCertVerifier` object given the provided trusted certificate authority
    /// certificates.
    pub fn new_from_mbedtls_trusted_cas(
        trusted_cas: mbedtls::alloc::List<mbedtls::x509::Certificate>,
    ) -> mbedtls::Result<Self> {
        let mut root_subjects = vec![];
        for ca in trusted_cas.iter() {
            root_subjects.push(DistinguishedName::from(ca.subject_raw()?));
        }
        Ok(Self { trusted_cas, root_subjects })
    }

    /// The certificate authority certificates used to construct this object
    pub fn trusted_cas(&self) -> &mbedtls::alloc::List<mbedtls::x509::Certificate> {
        &self.trusted_cas
    }

    /// the Subjects of the client authentication trust anchors to share with the client when
    /// requesting client authentication, extractd from CA certificates.
    pub fn root_subjects(&self) -> &[DistinguishedName] {
        self.root_subjects.as_ref()
    }
}

impl ClientCertVerifier for MbedTlsClientCertVerifier {
    fn client_auth_root_subjects(&self) -> &[DistinguishedName] {
        &self.root_subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        now: SystemTime,
    ) -> Result<rustls::server::ClientCertVerified, rustls::Error> {
        let now = chrono::DateTime::<chrono::Local>::from(now).naive_local();

        let chain: mbedtls::alloc::List<_> = [end_entity]
            .into_iter()
            .chain(intermediates)
            .map(rustls_cert_to_mbedtls_cert)
            .collect::<mbedtls::Result<Vec<_>>>()
            .map_err(mbedtls_err_into_rustls_err)?
            .into_iter()
            .collect();

        verify_certificates_active(chain.iter().map(|c| &**c), now)?;

        let mut error_msg = String::default();
        mbedtls::x509::Certificate::verify(&chain, &self.trusted_cas, None, Some(&mut error_msg))
            .map_err(|e| mbedtls_err_into_rustls_err_with_error_msg(e, &error_msg))?;

        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::Certificate,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        verify_tls_signature(message, cert, dss, false)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::Certificate,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        verify_tls_signature(message, cert, dss, true)
    }
}

// ../test-data/rsa/client.fullchain has these three certificates:
// cert subject: CN=ponytown client, cert issuer: CN=ponytown RSA level 2 intermediate
// cert subject: CN=ponytown RSA level 2 intermediate, cert issuer: CN=ponytown RSA CA
// cert subject: CN=ponytown RSA CA, cert issuer: CN=ponytown RSA CA
#[cfg(test)]
mod tests {

    use chrono::DateTime;
    use rustls::{
        server::ClientCertVerifier, Certificate, ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection,
    };
    use std::{sync::Arc, time::SystemTime};

    use super::MbedTlsClientCertVerifier;
    use crate::tests_common::{do_handshake_until_error, get_chain, get_key};

    fn server_config_with_verifier(client_cert_verifier: MbedTlsClientCertVerifier) -> ServerConfig {
        ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::new(client_cert_verifier))
            .with_single_cert(
                get_chain(include_bytes!("../test-data/rsa/end.fullchain")),
                get_key(include_bytes!("../test-data/rsa/end.key")),
            )
            .unwrap()
    }

    #[test]
    fn connection_client_cert_verifier() {
        let client_config = ClientConfig::builder().with_safe_defaults();
        let root_ca = Certificate(include_bytes!("../test-data/rsa/ca.der").to_vec());
        let mut root_store = RootCertStore::empty();
        root_store.add(&root_ca).unwrap();
        let cert_chain = get_chain(include_bytes!("../test-data/rsa/client.fullchain"));

        let client_config = client_config
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, get_key(include_bytes!("../test-data/rsa/client.key")))
            .unwrap();

        let client_cert_verifier = MbedTlsClientCertVerifier::new([&root_ca]).unwrap();

        let server_config = server_config_with_verifier(client_cert_verifier);

        let mut client_conn = ClientConnection::new(Arc::new(client_config), "localhost".try_into().unwrap()).unwrap();
        let mut server_conn = ServerConnection::new(Arc::new(server_config)).unwrap();

        assert!(do_handshake_until_error(&mut client_conn, &mut server_conn).is_ok());
    }

    fn test_connection_client_cert_verifier_with_invalid_certs(invalid_cert_chain: Vec<Certificate>) {
        let client_config = ClientConfig::builder().with_safe_defaults();
        let root_ca = Certificate(include_bytes!("../test-data/rsa/ca.der").to_vec());
        let mut root_store = RootCertStore::empty();
        root_store.add(&root_ca).unwrap();

        let client_config = client_config
            .with_root_certificates(root_store)
            .with_client_auth_cert(invalid_cert_chain, get_key(include_bytes!("../test-data/rsa/client.key")))
            .unwrap();

        let client_cert_verifier = MbedTlsClientCertVerifier::new([&root_ca]).unwrap();

        let server_config = server_config_with_verifier(client_cert_verifier);

        let mut client_conn = ClientConnection::new(Arc::new(client_config), "localhost".try_into().unwrap()).unwrap();
        let mut server_conn = ServerConnection::new(Arc::new(server_config)).unwrap();

        let res = do_handshake_until_error(&mut client_conn, &mut server_conn);
        assert!(matches!(res, Err(rustls::Error::InvalidCertificate(_))));
    }

    #[test]
    fn connection_client_cert_verifier_with_invalid_certs() {
        let cert_chain = get_chain(include_bytes!("../test-data/rsa/client.fullchain"));

        let mut invalid_chain1 = cert_chain.clone();
        invalid_chain1.remove(1);

        let mut invalid_chain2 = cert_chain.clone();
        invalid_chain2.remove(0);

        let mut invalid_chain3 = cert_chain.clone();
        invalid_chain3.swap(0, 1);

        for invalid_chain in [invalid_chain1, invalid_chain2, invalid_chain3] {
            test_connection_client_cert_verifier_with_invalid_certs(invalid_chain);
        }
    }

    #[test]
    fn client_cert_verifier_valid_chain() {
        let cert_chain = get_chain(include_bytes!("../test-data/rsa/client.fullchain"));
        let trusted_cas = [Certificate(include_bytes!("../test-data/rsa/ca.der").to_vec())];

        let verifier = MbedTlsClientCertVerifier::new(trusted_cas.iter()).unwrap();

        let now = SystemTime::from(chrono::DateTime::parse_from_rfc3339("2023-11-26T12:00:00+00:00").unwrap());

        assert!(verifier
            .verify_client_cert(&cert_chain[0], &cert_chain[1..], now)
            .is_ok());
    }

    #[test]
    fn client_cert_verifier_broken_chain() {
        let mut cert_chain = get_chain(include_bytes!("../test-data/rsa/client.fullchain"));
        cert_chain.remove(1);
        let trusted_cas = [Certificate(include_bytes!("../test-data/rsa/ca.der").to_vec())];

        let verifier = MbedTlsClientCertVerifier::new(trusted_cas.iter()).unwrap();

        let now = SystemTime::from(DateTime::parse_from_rfc3339("2023-11-26T12:00:00+00:00").unwrap());

        let verify_res = verifier.verify_client_cert(&cert_chain[0], &cert_chain[1..], now);
        assert!(matches!(verify_res, Err(rustls::Error::InvalidCertificate(_))));
    }

    #[test]
    fn client_cert_verifier_expired_certs() {
        let cert_chain = get_chain(include_bytes!("../test-data/rsa/client.fullchain"));
        let trusted_cas = [Certificate(include_bytes!("../test-data/rsa/ca.der").to_vec())];

        let verifier = MbedTlsClientCertVerifier::new(trusted_cas.iter()).unwrap();

        let now = SystemTime::from(DateTime::parse_from_rfc3339("2052-11-26T12:00:00+00:00").unwrap());

        assert_eq!(
            verifier
                .verify_client_cert(&cert_chain[0], &cert_chain[1..], now)
                .unwrap_err(),
            rustls::Error::InvalidCertificate(rustls::CertificateError::Expired)
        );
    }
}
