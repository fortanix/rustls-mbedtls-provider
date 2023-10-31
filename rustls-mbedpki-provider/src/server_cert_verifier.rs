use rustls::{client::{ServerCertVerifier, ServerCertVerified}, ServerName};

use crate::{rustls_cert_to_mbedtls_cert, mbedtls_err_into_rustls_err, common::verify_certificates_active, mbedtls_err_into_rustls_err_with_error_msg};


pub struct MbedTlsServerCertVerifier {
    trusted_cas: mbedtls::alloc::List<mbedtls::x509::Certificate>,
}

impl MbedTlsServerCertVerifier {
    pub fn new<'a>(trusted_cas: impl IntoIterator<Item = &'a rustls::Certificate>) -> mbedtls::Result<Self> {
        let trusted_cas = trusted_cas.into_iter()
            .map(rustls_cert_to_mbedtls_cert)
            .collect::<mbedtls::Result<Vec<_>>>()?
            .into_iter().collect();
        Self::new_from_mbedtls_trusted_cas(trusted_cas)
    }

    pub fn new_from_mbedtls_trusted_cas(trusted_cas: mbedtls::alloc::List<mbedtls::x509::Certificate>) -> mbedtls::Result<Self> {
        let mut root_subjects = vec![];
        for ca in trusted_cas.iter() {
            root_subjects.push(rustls::DistinguishedName::from(ca.subject_raw()?));
        }
        Ok(Self { trusted_cas })
    }
}

fn server_name_to_str(server_name: &rustls::ServerName) -> String {
    match server_name {
        ServerName::DnsName(name) => {
            name.as_ref().to_string()
        },
        ServerName::IpAddress(addr) => {
            addr.to_string()
        },
        _ => {
            panic!("unknown server name: {server_name:?}")
        }
    }
}

impl ServerCertVerifier for MbedTlsServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        intermediates: &[rustls::Certificate],
        server_name: &rustls::ServerName,
        // Signed certificate timestamps are experimental, https://datatracker.ietf.org/doc/html/rfc6962
        _scts: &mut dyn Iterator<Item = &[u8]>,
        // Mbedtls does not support OSCP (Online Certificate Status Protocol).
        // This will be handled in https://fortanix.atlassian.net/browse/PM-176
        _ocsp_response: &[u8],
        now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {

        let now = chrono::DateTime::<chrono::Local>::from(now).naive_local();

        let chain: mbedtls::alloc::List<_> = [end_entity].into_iter().chain(intermediates)
            .map(rustls_cert_to_mbedtls_cert)
            .collect::<mbedtls::Result<Vec<_>>>()
            .map_err(mbedtls_err_into_rustls_err)?
            .into_iter().collect();

        verify_certificates_active(chain.iter().map(|c| &**c), now)?;

        let server_name_str = server_name_to_str(server_name);
        let mut error_msg = String::default();
        mbedtls::x509::Certificate::verify_with_expected_common_name(
            &chain,
            &self.trusted_cas,
            None,
            Some(&mut error_msg),
            Some(&server_name_str)
        )
        .map_err(|e| mbedtls_err_into_rustls_err_with_error_msg(e, &error_msg))?;

        Ok(ServerCertVerified::assertion())

    }

    fn request_scts(&self) -> bool {
        // Signed certificate timestamps are experimental, https://datatracker.ietf.org/doc/html/rfc6962
        false
    }
}

// ../test-data/rsa/end.fullchain has these three certificates:
// cert subject: CN=testserver.com, issuer: CN=ponytown RSA level 2 intermediate
// cert subject: CN=ponytown RSA level 2 intermediate, issuer: CN=ponytown RSA CA
// cert subject: CN=ponytown RSA CA, issuer: CN=ponytown RSA CA
#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::SystemTime};

    use rustls::{ClientConfig, ClientConnection, ServerConnection, Certificate, RootCertStore, ServerConfig, client::ServerCertVerifier};

    use crate::tests_common::{get_chain, get_key, do_handshake_until_error};

    use super::MbedTlsServerCertVerifier;

    fn client_config_with_verifier(server_cert_verifier: MbedTlsServerCertVerifier) -> ClientConfig {
        ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_custom_certificate_verifier(Arc::new(server_cert_verifier))
            .with_no_client_auth()
    }

    fn test_connection_server_cert_verifier_with_invalid_certs(invalid_cert_chain: Vec<Certificate>) -> rustls::Error {
        let root_ca = Certificate(include_bytes!("../test-data/rsa/ca.der").to_vec());
        let mut root_store = RootCertStore::empty();
        root_store.add(&root_ca).unwrap();

        let client_config = client_config_with_verifier(MbedTlsServerCertVerifier::new(&[root_ca]).unwrap());
        let server_config = ServerConfig::builder().with_safe_defaults().with_no_client_auth()
            .with_single_cert(invalid_cert_chain, get_key(include_bytes!("../test-data/rsa/end.key")))
            .unwrap();

        let mut client_conn = ClientConnection::new(Arc::new(client_config), "testserver.com".try_into().unwrap()).unwrap();
        let mut server_conn = ServerConnection::new(Arc::new(server_config)).unwrap();

        let res = do_handshake_until_error(&mut client_conn, &mut server_conn);
        // asserts there is an error:
        res.unwrap_err()
    }

    #[test]
    fn connection_server_cert_verifier() {
        let root_ca = Certificate(include_bytes!("../test-data/rsa/ca.der").to_vec());
        let mut root_store = RootCertStore::empty();
        root_store.add(&root_ca).unwrap();
        let cert_chain = get_chain(include_bytes!("../test-data/rsa/end.fullchain"));

        let client_config = client_config_with_verifier(MbedTlsServerCertVerifier::new(&[root_ca]).unwrap());
        let server_config = ServerConfig::builder().with_safe_defaults().with_no_client_auth()
            .with_single_cert(cert_chain, get_key(include_bytes!("../test-data/rsa/end.key")))
            .unwrap();

        let mut client_conn = ClientConnection::new(Arc::new(client_config), "testserver.com".try_into().unwrap()).unwrap();
        let mut server_conn = ServerConnection::new(Arc::new(server_config)).unwrap();

        let res = do_handshake_until_error(&mut client_conn, &mut server_conn);
        assert!(res.is_ok())
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
        let trusted_cas = [Certificate(include_bytes!("../test-data/rsa/ca.der").to_vec())];

        let verifier = MbedTlsServerCertVerifier::new(trusted_cas.iter()).unwrap();

        let server_name = "testserver.com".try_into().unwrap();
        let now = SystemTime::from(chrono::DateTime::parse_from_rfc3339("2023-11-26T12:00:00+00:00").unwrap());
        let verify_res = verifier.verify_server_cert(
            &cert_chain[0],
            &cert_chain[1..],
            &server_name,
            &mut [].into_iter(),
            &[],
            now
        );
        assert!(verify_res.is_ok());
    }

    #[test]
    fn server_cert_verifier_wrong_subject_name() {
        let cert_chain = get_chain(include_bytes!("../test-data/rsa/end.fullchain"));
        let trusted_cas = [Certificate(include_bytes!("../test-data/rsa/ca.der").to_vec())];

        let verifier = MbedTlsServerCertVerifier::new(trusted_cas.iter()).unwrap();

        let server_name = "testserver.com.eu".try_into().unwrap();
        let now = SystemTime::from(chrono::DateTime::parse_from_rfc3339("2023-11-26T12:00:00+00:00").unwrap());
        let verify_res = verifier.verify_server_cert(
            &cert_chain[0],
            &cert_chain[1..],
            &server_name,
            &mut [].into_iter(),
            &[],
            now
        );
        println!("verify res: {:?}", verify_res);
        assert!(verify_res.is_err());
    }

    fn test_server_cert_verifier_invalid_chain(cert_chain: &[Certificate]) {
        let trusted_cas = [Certificate(include_bytes!("../test-data/rsa/ca.der").to_vec())];

        let verifier = MbedTlsServerCertVerifier::new(trusted_cas.iter()).unwrap();

        let server_name = "testserver.com".try_into().unwrap();
        let now = SystemTime::from(chrono::DateTime::parse_from_rfc3339("2023-11-26T12:00:00+00:00").unwrap());
        let verify_res = verifier.verify_server_cert(
            &cert_chain[0],
            &cert_chain[1..],
            &server_name,
            &mut [].into_iter(),
            &[],
            now
        );
        assert!(verify_res.is_err());
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
}