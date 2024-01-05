/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use chrono::NaiveDateTime;
use mbedtls::x509::VerifyError;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::ServerName;
use rustls::pki_types::{CertificateDer, UnixTime};

use crate::merge_verify_result;
use crate::VerifyErrorWrapper;
use crate::{
    mbedtls_err_into_rustls_err, rustls_cert_to_mbedtls_cert, verify_certificates_active, verify_tls_signature, CertActiveCheck,
};

/// A [`rustls`] [`ServerCertVerifier`] implemented using the PKI functionality of
/// `mbedtls`
pub struct MbedTlsServerCertVerifier {
    trusted_cas: mbedtls::alloc::List<mbedtls::x509::Certificate>,
    verify_callback: Option<Arc<dyn mbedtls::x509::VerifyCallback + 'static>>,
    cert_active_check: CertActiveCheck,
    mbedtls_verify_error_mapping: fn(VerifyError) -> rustls::Error,
}

impl core::fmt::Debug for MbedTlsServerCertVerifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MbedTlsServerCertVerifier")
            .field("trusted_cas", &"..")
            .field("verify_callback", &"..")
            .field("cert_active_check", &self.cert_active_check)
            .finish()
    }
}

impl MbedTlsServerCertVerifier {
    /// Constructs a new [`MbedTlsServerCertVerifier`] object given the provided trusted certificate authority
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

    /// Constructs a new [`MbedTlsServerCertVerifier`] object given the provided trusted certificate authority
    /// certificates.
    pub fn new_from_mbedtls_trusted_cas(
        trusted_cas: mbedtls::alloc::List<mbedtls::x509::Certificate>,
    ) -> mbedtls::Result<Self> {
        let mut root_subjects = vec![];
        for ca in trusted_cas.iter() {
            root_subjects.push(rustls::DistinguishedName::from(ca.subject_raw()?));
        }
        Ok(Self {
            trusted_cas,
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

fn server_name_to_str(server_name: &ServerName) -> Option<String> {
    match server_name {
        ServerName::DnsName(name) => Some(name.as_ref().to_string()),
        ServerName::IpAddress(_) => None,
        // We have this case because rustls::ServerName is marked as non-exhaustive.
        _ => {
            panic!("unknown server name: {server_name:?}")
        }
    }
}

impl ServerCertVerifier for MbedTlsServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        server_name: &ServerName,
        // Mbedtls does not support OSCP (Online Certificate Status Protocol).
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
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

        let server_name_str = server_name_to_str(server_name);

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
        let cert_verify_res = mbedtls::x509::Certificate::verify_with_callback_expected_common_name_return_verify_err(
            &chain,
            &self.trusted_cas,
            None,
            None,
            callback,
            server_name_str.as_deref(),
        )
        .map_err(|e| e.1);

        let validity_verify_res = verify_certificates_active(chain.iter().map(|c| &**c), now, &self.cert_active_check)?;

        merge_verify_result(&validity_verify_res, &cert_verify_res).map_err(self.mbedtls_verify_error_mapping)?;

        Ok(ServerCertVerified::assertion())
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

// ../test-data/rsa/end.fullchain has these three certificates:
// cert subject: CN=testserver.com, issuer: CN=ponytown RSA level 2 intermediate
// cert subject: CN=ponytown RSA level 2 intermediate, issuer: CN=ponytown RSA CA
// cert subject: CN=ponytown RSA CA, issuer: CN=ponytown RSA CA
#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::SystemTime};

    use mbedtls::x509::VerifyError;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{
        client::danger::ServerCertVerifier,
        version::{TLS12, TLS13},
        ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, SignatureScheme,
        SupportedProtocolVersion,
    };

    use crate::server_cert_verifier::server_name_to_str;
    use crate::tests_common::{do_handshake_until_error, get_chain, get_key, VerifierWithSupportedVerifySchemes};

    use super::MbedTlsServerCertVerifier;

    fn client_config_with_verifier<V: ServerCertVerifier + 'static>(server_cert_verifier: V) -> ClientConfig {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(server_cert_verifier))
            .with_no_client_auth()
    }

    #[test]
    fn server_cert_verifier_debug() {
        let root_ca = CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec());
        let server_cert_verifier = MbedTlsServerCertVerifier::new([&root_ca]).unwrap();
        assert_eq!(
            "MbedTlsServerCertVerifier { trusted_cas: \"..\", verify_callback: \"..\", cert_active_check: CertActiveCheck { ignore_expired: false, ignore_not_active_yet: false } }",
            format!("{:?}", server_cert_verifier)
        );
    }

    #[test]
    fn server_cert_verifier_setter_getter() {
        let root_ca = CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec());
        let mut server_cert_verifier = MbedTlsServerCertVerifier::new([&root_ca]).unwrap();
        assert!(!server_cert_verifier
            .trusted_cas()
            .is_empty());
        const RETURN_ERR: rustls::Error = rustls::Error::BadMaxFragmentSize;
        fn test_mbedtls_verify_error_mapping(_verify_err: VerifyError) -> rustls::Error {
            RETURN_ERR
        }
        server_cert_verifier.set_mbedtls_verify_error_mapping(test_mbedtls_verify_error_mapping);
        assert_eq!(
            server_cert_verifier.mbedtls_verify_error_mapping()(VerifyError::empty()),
            RETURN_ERR
        );
    }

    fn test_connection_server_cert_verifier_with_invalid_certs(
        invalid_cert_chain: Vec<CertificateDer<'static>>,
    ) -> rustls::Error {
        let root_ca = CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec());
        let mut root_store = RootCertStore::empty();
        root_store.add(root_ca.clone()).unwrap();

        let client_config = client_config_with_verifier(MbedTlsServerCertVerifier::new(&[root_ca]).unwrap());
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(invalid_cert_chain, get_key(include_bytes!("../test-data/rsa/end.key")))
            .unwrap();

        let mut client_conn = ClientConnection::new(Arc::new(client_config), "testserver.com".try_into().unwrap()).unwrap();
        let mut server_conn = ServerConnection::new(Arc::new(server_config)).unwrap();

        let res = do_handshake_until_error(&mut client_conn, &mut server_conn);
        assert!(matches!(res, Err(rustls::Error::InvalidCertificate(_))));
        res.unwrap_err()
    }

    fn test_connection_server_cert_verifier(
        supported_verify_schemes: Vec<SignatureScheme>,
        protocol_versions: &[&'static SupportedProtocolVersion],
    ) {
        let root_ca = CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec());
        let mut root_store = RootCertStore::empty();
        root_store.add(root_ca.clone()).unwrap();
        let cert_chain = get_chain(include_bytes!("../test-data/rsa/end.fullchain"));

        let verifier = VerifierWithSupportedVerifySchemes {
            verifier: MbedTlsServerCertVerifier::new(&[root_ca]).unwrap(),
            supported_verify_schemes,
        };
        let client_config = client_config_with_verifier(verifier);
        let server_config = ServerConfig::builder_with_protocol_versions(protocol_versions)
            .with_no_client_auth()
            .with_single_cert(cert_chain, get_key(include_bytes!("../test-data/rsa/end.key")))
            .unwrap();

        let mut client_conn = ClientConnection::new(Arc::new(client_config), "testserver.com".try_into().unwrap()).unwrap();
        let mut server_conn = ServerConnection::new(Arc::new(server_config)).unwrap();

        // asserts handshake succeeds
        do_handshake_until_error(&mut client_conn, &mut server_conn).unwrap();
    }

    #[test]
    fn connection_server_cert_verifier() {
        let test_cases = [
            (SignatureScheme::RSA_PSS_SHA512, &TLS12),
            (SignatureScheme::RSA_PSS_SHA384, &TLS12),
            (SignatureScheme::RSA_PSS_SHA256, &TLS12),
            (SignatureScheme::RSA_PKCS1_SHA512, &TLS12),
            (SignatureScheme::RSA_PKCS1_SHA384, &TLS12),
            (SignatureScheme::RSA_PKCS1_SHA256, &TLS12),
            (SignatureScheme::RSA_PSS_SHA512, &TLS13),
            (SignatureScheme::RSA_PSS_SHA384, &TLS13),
            (SignatureScheme::RSA_PSS_SHA256, &TLS13),
        ];
        for (scheme, protocol) in test_cases {
            test_connection_server_cert_verifier(vec![scheme], &[protocol]);
        }
    }

    #[test]
    fn connection_server_cert_verifier_with_invalid_certs() {
        let cert_chain = get_chain(include_bytes!("../test-data/rsa/end.fullchain"));

        let mut broken_chain1 = cert_chain.clone();
        broken_chain1.remove(1);

        let mut broken_chain2 = cert_chain.clone();
        broken_chain2.remove(0);

        let mut broken_chain3 = cert_chain.clone();
        broken_chain3.swap(0, 1);

        for broken_chain in [broken_chain1, broken_chain2, broken_chain3] {
            let err = test_connection_server_cert_verifier_with_invalid_certs(broken_chain);
            println!("error: {err}");
        }
    }

    #[test]
    fn server_cert_verifier_valid_chain() {
        let cert_chain = get_chain(include_bytes!("../test-data/rsa/end.fullchain"));
        let trusted_cas = [CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec())];

        let verifier = MbedTlsServerCertVerifier::new(trusted_cas.iter()).unwrap();

        let server_name = "testserver.com".try_into().unwrap();
        let now = SystemTime::from(chrono::DateTime::parse_from_rfc3339("2023-11-26T12:00:00+00:00").unwrap());
        let now = UnixTime::since_unix_epoch(
            now.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        );
        let verify_res = verifier.verify_server_cert(&cert_chain[0], &cert_chain[1..], &server_name, &[], now);
        assert!(verify_res.is_ok());
    }

    #[test]
    fn server_cert_verifier_expired_chain() {
        let cert_chain = get_chain(include_bytes!("../test-data/rsa/end.fullchain"));
        let trusted_cas = [CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec())];

        let verifier = MbedTlsServerCertVerifier::new(trusted_cas.iter()).unwrap();

        let server_name = "testserver.com".try_into().unwrap();
        let now = SystemTime::from(chrono::DateTime::parse_from_rfc3339("2052-11-26T12:00:00+00:00").unwrap());
        let now = UnixTime::since_unix_epoch(
            now.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        );
        let verify_res = verifier.verify_server_cert(&cert_chain[0], &cert_chain[1..], &server_name, &[], now);
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
    fn server_cert_verifier_active_check() {
        // this cert is valid from: Mon Dec 09 08:03:28 PST 2019 until: Wed Mar 18 09:03:28 PDT 2020
        let cert_chain = get_chain(include_bytes!("../test-data/rsa/expired-server.pem"));
        let trusted_cas = [CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec())];

        let mut verifier = MbedTlsServerCertVerifier::new(trusted_cas.iter()).unwrap();
        let server_name = "testserver.com".try_into().unwrap();
        let now = SystemTime::from(chrono::DateTime::parse_from_rfc3339("2052-11-26T12:00:00+00:00").unwrap());
        let now = UnixTime::since_unix_epoch(
            now.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        );

        // Test that we reject expired certs
        let verify_res = verifier.verify_server_cert(&cert_chain[0], &cert_chain[1..], &server_name, &[], now);
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
        let verify_res = verifier.verify_server_cert(&cert_chain[0], &cert_chain[1..], &server_name, &[], now);
        assert!(verify_res.is_ok());

        let now = SystemTime::from(chrono::DateTime::parse_from_rfc3339("2002-11-26T12:00:00+00:00").unwrap());
        let now = UnixTime::since_unix_epoch(
            now.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        );

        // Test that we reject certs that are not valid yet
        let verify_res = verifier.verify_server_cert(&cert_chain[0], &cert_chain[1..], &server_name, &[], now);

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
        let verify_res = verifier.verify_server_cert(&cert_chain[0], &cert_chain[1..], &server_name, &[], now);
        assert!(verify_res.is_ok());
        verifier.set_cert_active_check(crate::CertActiveCheck { ignore_expired: true, ignore_not_active_yet: true });
        let verify_res = verifier.verify_server_cert(&cert_chain[0], &cert_chain[1..], &server_name, &[], now);
        assert!(verify_res.is_ok());
    }

    #[test]
    fn server_cert_verifier_wrong_subject_name() {
        let cert_chain = get_chain(include_bytes!("../test-data/rsa/end.fullchain"));
        let trusted_cas = [CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec())];

        let verifier = MbedTlsServerCertVerifier::new(trusted_cas.iter()).unwrap();

        let server_name = "testserver.com.eu".try_into().unwrap();
        let now = SystemTime::from(chrono::DateTime::parse_from_rfc3339("2023-11-26T12:00:00+00:00").unwrap());
        let now = UnixTime::since_unix_epoch(
            now.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        );
        let verify_res = verifier.verify_server_cert(&cert_chain[0], &cert_chain[1..], &server_name, &[], now);
        println!("verify res: {:?}", verify_res);
        assert!(matches!(verify_res, Err(rustls::Error::InvalidCertificate(_))));
    }

    #[test]
    fn server_cert_verifier_callback() {
        let cert_chain = get_chain(include_bytes!("../test-data/rsa/end.fullchain"));
        let trusted_cas = [CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec())];

        let mut verifier = MbedTlsServerCertVerifier::new(trusted_cas.iter()).unwrap();
        assert!(verifier.verify_callback().is_none());
        let server_name = "testserver.com.eu".try_into().unwrap();
        let now = SystemTime::from(chrono::DateTime::parse_from_rfc3339("2023-11-26T12:00:00+00:00").unwrap());
        let now = UnixTime::since_unix_epoch(
            now.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        );
        let verify_res = verifier.verify_server_cert(&cert_chain[0], &cert_chain[1..], &server_name, &[], now);
        println!("verify res: {:?}", verify_res);
        assert!(matches!(verify_res, Err(rustls::Error::InvalidCertificate(_))));

        verifier.set_verify_callback(Some(Arc::new(
            move |_cert: &mbedtls::x509::Certificate, _depth: i32, flags: &mut VerifyError| {
                flags.remove(VerifyError::CERT_CN_MISMATCH);
                Ok(())
            },
        )));
        assert!(verifier.verify_callback().is_some());
        let verify_res = verifier.verify_server_cert(&cert_chain[0], &cert_chain[1..], &server_name, &[], now);
        assert!(verify_res.is_ok());
    }

    fn test_server_cert_verifier_invalid_chain(cert_chain: &[CertificateDer]) {
        let trusted_cas = [CertificateDer::from(include_bytes!("../test-data/rsa/ca.der").to_vec())];

        let verifier = MbedTlsServerCertVerifier::new(trusted_cas.iter()).unwrap();

        let server_name = "testserver.com".try_into().unwrap();
        let now = SystemTime::from(chrono::DateTime::parse_from_rfc3339("2023-11-26T12:00:00+00:00").unwrap());
        let now = UnixTime::since_unix_epoch(
            now.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap(),
        );
        let verify_res = verifier.verify_server_cert(&cert_chain[0], &cert_chain[1..], &server_name, &[], now);
        assert!(matches!(verify_res, Err(rustls::Error::InvalidCertificate(_))));
    }

    #[test]
    fn server_cert_verifier_invalid_chain() {
        let cert_chain = get_chain(include_bytes!("../test-data/rsa/end.fullchain"));

        let mut broken_chain1 = cert_chain.clone();
        broken_chain1.remove(1);

        let mut broken_chain2 = cert_chain.clone();
        broken_chain2.remove(0);

        let mut broken_chain3 = cert_chain.clone();
        broken_chain3.remove(2);
        broken_chain3.remove(1);

        for broken_chain in [broken_chain1, broken_chain2, broken_chain3] {
            test_server_cert_verifier_invalid_chain(&broken_chain);
        }
    }

    #[test]
    fn test_server_name_to_str() {
        let server_name = ServerName::DnsName("example.com".try_into().unwrap());
        assert_eq!(server_name_to_str(&server_name), Some("example.com".to_string()));
        let server_name = ServerName::IpAddress("127.0.0.1".try_into().unwrap());
        assert_eq!(server_name_to_str(&server_name), None);
    }
}
