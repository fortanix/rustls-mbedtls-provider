/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use mbedtls::x509::VerifyError;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::{
    server::danger::{ClientCertVerified, ClientCertVerifier},
    DistinguishedName,
};

use crate::{
    mbedtls_err_into_rustls_err, merge_verify_result, rustls_cert_to_mbedtls_cert, verify_certificates_active,
    verify_tls_signature, CertActiveCheck, VerifyErrorWrapper,
};

/// A [`rustls`] [`ClientCertVerifier`] implemented using the PKI functionality of
/// `mbedtls`
#[derive(Clone)]
pub struct MbedTlsClientCertVerifier {
    trusted_cas: mbedtls::alloc::List<mbedtls::x509::Certificate>,
    root_subjects: Vec<DistinguishedName>,
    verify_callback: Option<Arc<dyn mbedtls::x509::VerifyCallback + 'static>>,
    cert_active_check: CertActiveCheck,
    mbedtls_verify_error_mapping: fn(VerifyError) -> rustls::Error,
}

impl core::fmt::Debug for MbedTlsClientCertVerifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MbedTlsClientCertVerifier")
            .field("trusted_cas", &"..")
            .field("root_subjects", &self.root_subjects)
            .field("verify_callback", &"..")
            .field("cert_active_check", &self.cert_active_check)
            .finish()
    }
}

impl MbedTlsClientCertVerifier {
    /// Constructs a new [`MbedTlsClientCertVerifier`] object given the provided trusted certificate authority
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

    /// Constructs a new [`MbedTlsClientCertVerifier`] object given the provided trusted certificate authority
    /// certificates.
    pub fn new_from_mbedtls_trusted_cas(
        trusted_cas: mbedtls::alloc::List<mbedtls::x509::Certificate>,
    ) -> mbedtls::Result<Self> {
        let mut root_subjects = vec![];
        for ca in trusted_cas.iter() {
            root_subjects.push(DistinguishedName::from(ca.subject_raw()?));
        }
        Ok(Self {
            trusted_cas,
            root_subjects,
            verify_callback: None,
            cert_active_check: CertActiveCheck::default(),
            mbedtls_verify_error_mapping: Self::default_mbedtls_verify_error_mapping,
        })
    }

    /// The default mapping of [`VerifyError`] to [`rustls::Error`].
    pub fn default_mbedtls_verify_error_mapping(verify_err: VerifyError) -> rustls::Error {
        rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(Arc::new(
            VerifyErrorWrapper(verify_err),
        ))))
    }

    /// Set the mapping of [`VerifyError`] to [`rustls::Error`].
    pub fn set_mbedtls_verify_error_mapping(&mut self, mapping: fn(VerifyError) -> rustls::Error) {
        self.mbedtls_verify_error_mapping = mapping;
    }

    /// Get the current mapping of [`VerifyError`] to [`rustls::Error`].
    pub fn mbedtls_verify_error_mapping(&self) -> fn(VerifyError) -> rustls::Error {
        self.mbedtls_verify_error_mapping
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

    /// Retrieves the verification callback function set for the certificate verification process.
    pub fn verify_callback(&self) -> Option<Arc<dyn mbedtls::x509::VerifyCallback + 'static>> {
        self.verify_callback.clone()
    }

    /// Sets the verification callback for mbedtls certificate verification process,
    ///
    /// This callback function allows you to add logic at end of mbedtls verification before returning.
    pub fn set_verify_callback(&mut self, callback: Option<Arc<dyn mbedtls::x509::VerifyCallback + 'static>>) {
        self.verify_callback = callback;
    }

    /// Getter for [`CertActiveCheck`]
    pub fn cert_active_check(&self) -> &CertActiveCheck {
        &self.cert_active_check
    }

    /// Setter for [`CertActiveCheck`]
    pub fn set_cert_active_check(&mut self, check: CertActiveCheck) {
        self.cert_active_check = check;
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
    ) -> Result<ClientCertVerified, rustls::Error> {
        let now = chrono::DateTime::from_timestamp(
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

        let self_verify_callback = self.verify_callback.clone();
        let callback = move |cert: &mbedtls::x509::Certificate, depth: i32, flags: &mut VerifyError| {
            // When the "time" feature is enabled for mbedtls, it checks cert expiration. We undo that here,
            // since this check is done in `verify_certificates_active()` (subject to self.cert_active_check)
            flags.remove(VerifyError::CERT_EXPIRED | VerifyError::CERT_FUTURE);
            if let Some(cb) = self_verify_callback.as_ref() {
                cb(cert, depth, flags)
            } else {
                Ok(())
            }
        };

        let mut error_msg = String::default();
        let cert_verify_res = mbedtls::x509::Certificate::verify_with_callback_return_verify_err(
            &chain,
            &self.trusted_cas,
            None,
            Some(&mut error_msg),
            callback,
        )
        .map_err(|e| e.1);

        let validity_verify_res = verify_certificates_active(chain.iter().map(|c| &**c), now, &self.cert_active_check)?;

        merge_verify_result(&validity_verify_res, &cert_verify_res).map_err(self.mbedtls_verify_error_mapping)?;

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
        crate::SUPPORTED_SIGNATURE_SCHEMES.to_vec()
    }
}

// ../test-data/rsa/client.fullchain has these three certificates:
// cert subject: CN=ponytown client, cert issuer: CN=ponytown RSA level 2 intermediate
// cert subject: CN=ponytown RSA level 2 intermediate, cert issuer: CN=ponytown RSA CA
// cert subject: CN=ponytown RSA CA, cert issuer: CN=ponytown RSA CA
#[cfg(test)]
mod tests {

    use chrono::DateTime;
    use mbedtls::x509::VerifyError;
    use rustls::pki_types::{CertificateDer, UnixTime};
    use rustls::{
        server::danger::ClientCertVerifier, ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection,
    };
    use std::{sync::Arc, time::SystemTime};

    use super::MbedTlsClientCertVerifier;
    use crate::tests_common::{do_handshake_until_error, get_chain, get_key};

    fn server_config_with_verifier(client_cert_verifier: MbedTlsClientCertVerifier) -> ServerConfig {
        ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(client_cert_verifier))
            .with_single_cert(
                get_chain(include_bytes!("../test-data/rsa/end.fullchain")),
                get_key(include_bytes!("../test-data/rsa/end.key")),
            )
            .unwrap()
    }

    #[test]
    fn client_cert_verifier_debug() {
        let root_ca = CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec());
        let client_cert_verifier = MbedTlsClientCertVerifier::new([&root_ca]).unwrap();
        assert_eq!(
            r#"MbedTlsClientCertVerifier { trusted_cas: "..", root_subjects: [DistinguishedName(301a3118301606035504030c0f706f6e79746f776e20525341204341)], verify_callback: "..", cert_active_check: CertActiveCheck { ignore_expired: false, ignore_not_active_yet: false } }"#,
            format!("{client_cert_verifier:?}")
        );
    }

    #[test]
    fn client_cert_verifier_setter_getter() {
        let root_ca = CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec());
        let mut client_cert_verifier = MbedTlsClientCertVerifier::new([&root_ca]).unwrap();
        assert!(!client_cert_verifier
            .trusted_cas()
            .is_empty());
        const RETURN_ERR: rustls::Error = rustls::Error::BadMaxFragmentSize;
        fn test_mbedtls_verify_error_mapping(_verify_err: VerifyError) -> rustls::Error {
            RETURN_ERR
        }
        client_cert_verifier.set_mbedtls_verify_error_mapping(test_mbedtls_verify_error_mapping);
        assert_eq!(
            client_cert_verifier.mbedtls_verify_error_mapping()(VerifyError::empty()),
            RETURN_ERR
        );
    }

    #[test]
    fn connection_client_cert_verifier() {
        let client_config = ClientConfig::builder();
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
        let client_config = ClientConfig::builder();
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

        let now = SystemTime::from(DateTime::parse_from_rfc3339("2023-11-26T12:00:00+00:00").unwrap());
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
        let verify_res = verifier.verify_client_cert(&cert_chain[0], &cert_chain[1..], now);
        if let Err(rustls::Error::InvalidCertificate(rustls::CertificateError::Other(other_err))) = verify_res {
            let verify_err = other_err
                .0
                .downcast_ref::<crate::VerifyErrorWrapper>()
                .unwrap();
            assert_eq!(verify_err.0, VerifyError::CERT_EXPIRED);
        } else {
            panic!("should get an error with type: `rustls::Error::InvalidCertificate(rustls::CertificateError::Other(..))`")
        }
    }

    #[test]
    fn client_cert_verifier_active_check() {
        // This cert is valid from: Tue Nov 20 16:25:56 PST 2018 until: Mon Feb 18 16:25:56 PST 2019
        let cert_chain = get_chain(include_bytes!("../test-data/rsa/expired-cert.pem"));
        let trusted_cas = [CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec())];

        let mut verifier = MbedTlsClientCertVerifier::new(trusted_cas.iter()).unwrap();

        // Test that we reject expired certs
        let now = SystemTime::from(DateTime::parse_from_rfc3339("2052-11-26T12:00:00+00:00").unwrap());
        let now = UnixTime::since_unix_epoch(
            now.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        );

        let verify_res = verifier.verify_client_cert(&cert_chain[0], &cert_chain[1..], now);
        if let Err(rustls::Error::InvalidCertificate(rustls::CertificateError::Other(other_err))) = verify_res {
            let verify_err = other_err
                .0
                .downcast_ref::<crate::VerifyErrorWrapper>()
                .unwrap();
            assert_eq!(verify_err.0, VerifyError::CERT_EXPIRED);
        } else {
            panic!("should get an error with type: `rustls::Error::InvalidCertificate(rustls::CertificateError::Other(..))`")
        }

        // Test that we accept expired certs when `ignore_expired` is true
        verifier.set_cert_active_check(crate::CertActiveCheck { ignore_expired: true, ignore_not_active_yet: false });

        assert!(verifier
            .verify_client_cert(&cert_chain[0], &cert_chain[1..], now)
            .is_ok());

        // Test that we reject certs that are not valid yet
        let now = SystemTime::from(DateTime::parse_from_rfc3339("2002-11-26T12:00:00+00:00").unwrap());
        let now = UnixTime::since_unix_epoch(
            now.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        );
        let verify_res = verifier.verify_client_cert(&cert_chain[0], &cert_chain[1..], now);
        if let Err(rustls::Error::InvalidCertificate(rustls::CertificateError::Other(other_err))) = verify_res {
            let verify_err = other_err
                .0
                .downcast_ref::<crate::VerifyErrorWrapper>()
                .unwrap();
            assert_eq!(verify_err.0, VerifyError::CERT_FUTURE);
        } else {
            panic!("should get an error with type: `rustls::Error::InvalidCertificate(rustls::CertificateError::Other(..))`")
        }
        // Test that we accept certs that are not valid yet when `ignore_not_active_yet` is true
        verifier.set_cert_active_check(crate::CertActiveCheck { ignore_expired: false, ignore_not_active_yet: true });
        assert!(verifier
            .verify_client_cert(&cert_chain[0], &cert_chain[1..], now)
            .is_ok());
        verifier.set_cert_active_check(crate::CertActiveCheck { ignore_expired: true, ignore_not_active_yet: true });
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

        verifier.set_verify_callback(Some(Arc::new(
            move |_cert: &mbedtls::x509::Certificate, _depth: i32, flags: &mut VerifyError| {
                flags.remove(VerifyError::CERT_NOT_TRUSTED);
                Ok(())
            },
        )));
        assert!(verifier.verify_callback().is_some());
        let verify_res = verifier.verify_client_cert(&cert_chain[0], &cert_chain[1..], now);
        assert!(verify_res.is_ok(), "{verify_res:?}");
    }
}
