/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use std::sync::Arc;

use chrono::NaiveDateTime;
use pki_types::{CertificateDer, UnixTime};
use rustls::{
    server::danger::{ClientCertVerified, ClientCertVerifier},
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
    verify_callback: Option<Arc<dyn mbedtls::x509::VerifyCallback + 'static>>,
    ignore_expired: bool,
}

impl MbedTlsClientCertVerifier {
    /// Constructs a new `MbedTlsClientCertVerifier` object given the provided trusted certificate authority
    /// certificates.
    ///
    /// Returns an error if any of the certificates are invalid.
    pub fn new<'a>(trusted_cas: impl IntoIterator<Item = &'a CertificateDer<'a>>) -> mbedtls::Result<Self> {
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
        Ok(Self { trusted_cas, root_subjects, verify_callback: None, ignore_expired: false })
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

    /// Sets the optional verification callback function for the certificate verification process.
    ///
    /// The verification callback allows you to customize how the certificate verification is performed.
    ///
    /// # Arguments
    ///
    /// * `callback` - A trait object implementing the `mbedtls::x509::VerifyCallback` trait, wrapped in an `Arc`.
    pub fn set_verify_callback(&mut self, callback: Arc<dyn mbedtls::x509::VerifyCallback + 'static>) {
        self.verify_callback = Some(callback);
    }

    /// Retrieves the verification callback function set for the certificate verification process.
    ///
    /// Returns `Some(callback)` if a verification callback has been set, or `None` otherwise.
    ///
    pub fn verify_callback(&self) -> Option<Arc<dyn mbedtls::x509::VerifyCallback + 'static>> {
        self.verify_callback.clone()
    }

    /// Sets whether the system should ignore expired certificates during the verification process.
    ///
    /// By default, the system does not ignore expired certificates.
    ///
    /// # Arguments
    ///
    /// * `ignore_expired` - A boolean flag indicating whether to ignore expired certificates (`true`) or not (`false`).
    pub fn set_ignore_expired(&mut self, ignore_expired: bool) {
        self.ignore_expired = ignore_expired;
    }

    /// Checks if the system is configured to ignore expired certificates during the verification process.
    ///
    /// Returns `true` if expired certificates are being ignored, or `false` otherwise.
    pub fn ignore_expired(&self) -> bool {
        self.ignore_expired
    }
}

impl ClientCertVerifier for MbedTlsClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.root_subjects
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        now: UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let now = NaiveDateTime::from_timestamp_opt(
            now.as_secs()
                .try_into()
                .map_err(|_| rustls::Error::General(String::from("Invalid current unix timestamp")))?,
            0,
        )
        .ok_or(rustls::Error::General(String::from("Invalid current unix timestamp")))?;

        let chain: mbedtls::alloc::List<_> = [end_entity]
            .into_iter()
            .chain(intermediates)
            .map(rustls_cert_to_mbedtls_cert)
            .collect::<mbedtls::Result<Vec<_>>>()
            .map_err(mbedtls_err_into_rustls_err)?
            .into_iter()
            .collect();

        verify_certificates_active(chain.iter().map(|c| &**c), now, self.ignore_expired)?;

        let mut error_msg = String::default();
        match &self.verify_callback {
            Some(callback) => {
                let callback = callback.clone();
                mbedtls::x509::Certificate::verify_with_callback(
                    &chain,
                    &self.trusted_cas,
                    None,
                    Some(&mut error_msg),
                    move |cert: &mbedtls::x509::Certificate, depth: i32, flags: &mut mbedtls::x509::VerifyError| {
                        callback(cert, depth, flags)
                    },
                )
                .map_err(|e| mbedtls_err_into_rustls_err_with_error_msg(e, &error_msg))?;
            }
            None => mbedtls::x509::Certificate::verify(&chain, &self.trusted_cas, None, Some(&mut error_msg))
                .map_err(|e| mbedtls_err_into_rustls_err_with_error_msg(e, &error_msg))?,
        };

        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls_signature(message, cert, dss, false)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls_signature(message, cert, dss, true)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        crate::SUPPORTED_SIGNATURE_SCHEMA.to_vec()
    }
}

// ../test-data/rsa/client.fullchain has these three certificates:
// cert subject: CN=ponytown client, cert issuer: CN=ponytown RSA level 2 intermediate
// cert subject: CN=ponytown RSA level 2 intermediate, cert issuer: CN=ponytown RSA CA
// cert subject: CN=ponytown RSA CA, cert issuer: CN=ponytown RSA CA
#[cfg(test)]
mod tests {

    use chrono::DateTime;
    use pki_types::{CertificateDer, UnixTime};
    use rustls::{
        server::danger::ClientCertVerifier, CertificateError, ClientConfig, ClientConnection, RootCertStore, ServerConfig,
        ServerConnection,
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
        let root_ca = CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec());
        let mut root_store = RootCertStore::empty();
        root_store.add(root_ca.clone()).unwrap();
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

    fn test_connection_client_cert_verifier_with_invalid_certs(invalid_cert_chain: Vec<CertificateDer<'static>>) {
        let client_config = ClientConfig::builder().with_safe_defaults();
        let root_ca = CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec());
        let mut root_store = RootCertStore::empty();
        root_store.add(root_ca.clone()).unwrap();

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
        let trusted_cas = [CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec())];

        let verifier = MbedTlsClientCertVerifier::new(trusted_cas.iter()).unwrap();

        let now = SystemTime::from(chrono::DateTime::parse_from_rfc3339("2023-11-26T12:00:00+00:00").unwrap());
        let now = UnixTime::since_unix_epoch(
            now.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        );

        assert!(verifier
            .verify_client_cert(&cert_chain[0], &cert_chain[1..], now)
            .is_ok());
    }

    #[test]
    fn client_cert_verifier_broken_chain() {
        let mut cert_chain = get_chain(include_bytes!("../test-data/rsa/client.fullchain"));
        cert_chain.remove(1);
        let trusted_cas = [CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec())];

        let verifier = MbedTlsClientCertVerifier::new(trusted_cas.iter()).unwrap();

        let now = SystemTime::from(DateTime::parse_from_rfc3339("2023-11-26T12:00:00+00:00").unwrap());
        let now = UnixTime::since_unix_epoch(
            now.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        );

        let verify_res = verifier.verify_client_cert(&cert_chain[0], &cert_chain[1..], now);
        assert!(matches!(verify_res, Err(rustls::Error::InvalidCertificate(_))));
    }

    #[test]
    fn client_cert_verifier_expired_certs() {
        let cert_chain = get_chain(include_bytes!("../test-data/rsa/client.fullchain"));
        let trusted_cas = [CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec())];

        let verifier = MbedTlsClientCertVerifier::new(trusted_cas.iter()).unwrap();

        let now = SystemTime::from(DateTime::parse_from_rfc3339("2052-11-26T12:00:00+00:00").unwrap());
        let now = UnixTime::since_unix_epoch(
            now.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        );

        assert_eq!(
            verifier
                .verify_client_cert(&cert_chain[0], &cert_chain[1..], now)
                .unwrap_err(),
            rustls::Error::InvalidCertificate(CertificateError::Expired)
        );
    }

    #[test]
    fn client_cert_verifier_ignore_expired_certs() {
        let cert_chain = get_chain(include_bytes!("../test-data/rsa/client.fullchain"));
        let trusted_cas = [CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec())];

        let mut verifier = MbedTlsClientCertVerifier::new(trusted_cas.iter()).unwrap();
        assert_eq!(verifier.ignore_expired(), false);
        verifier.set_ignore_expired(true);
        assert_eq!(verifier.ignore_expired(), true);
        let now = SystemTime::from(DateTime::parse_from_rfc3339("2052-11-26T12:00:00+00:00").unwrap());
        let now = UnixTime::since_unix_epoch(
            now.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        );

        assert!(verifier
            .verify_client_cert(&cert_chain[0], &cert_chain[1..], now)
            .is_ok());
    }

    #[test]
    fn client_cert_verifier_callback() {
        let mut cert_chain = get_chain(include_bytes!("../test-data/rsa/client.fullchain"));
        cert_chain.remove(1);
        let trusted_cas = [CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec())];

        let mut verifier = MbedTlsClientCertVerifier::new(trusted_cas.iter()).unwrap();
        assert!(verifier.verify_callback().is_none());
        let now = SystemTime::from(DateTime::parse_from_rfc3339("2023-11-26T12:00:00+00:00").unwrap());
        let now = UnixTime::since_unix_epoch(
            now.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        );

        let verify_res = verifier.verify_client_cert(&cert_chain[0], &cert_chain[1..], now);
        assert!(matches!(verify_res, Err(rustls::Error::InvalidCertificate(_))));

        verifier.set_verify_callback(Arc::new(
            move |_cert: &mbedtls::x509::Certificate, _depth: i32, flags: &mut mbedtls::x509::VerifyError| {
                flags.remove(mbedtls::x509::VerifyError::CERT_NOT_TRUSTED);
                Ok(())
            },
        ));
        assert!(verifier.verify_callback().is_some());
        let verify_res = verifier.verify_client_cert(&cert_chain[0], &cert_chain[1..], now);
        assert!(verify_res.is_ok(), "{:?}", verify_res);
    }
}
