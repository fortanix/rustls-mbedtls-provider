/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#![allow(dead_code)]

use std::io;
use std::ops::DerefMut;
use std::sync::Arc;

use rustls::crypto::cipher::OutboundOpaqueMessage;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName};

use primary_provider::mbedtls_crypto_provider;
use rustls::client::{ServerCertVerifierBuilder, WebPkiServerVerifier};
use rustls::crypto::{CryptoProvider, KeyExchangeAlgorithm};
use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::message::{Message, PlainMessage};
use rustls::server::{ClientCertVerifierBuilder, WebPkiClientVerifier};
use rustls::Connection;
use rustls::Error;
use rustls::RootCertStore;
use rustls::{ClientConfig, ClientConnection};
use rustls::{ConnectionCommon, ServerConfig, ServerConnection, SideData};

pub use rustls_mbedcrypto_provider as primary_provider;

macro_rules! embed_files {
    (
        $(
            ($name:ident, $keytype:expr, $path:expr);
        )+
    ) => {
        $(
            const $name: &'static [u8] = include_bytes!(
                concat!("../../../test-ca/", $keytype, "/", $path));
        )+

        pub fn bytes_for(keytype: &str, path: &str) -> &'static [u8] {
            match (keytype, path) {
                $(
                    ($keytype, $path) => $name,
                )+
                _ => panic!("unknown keytype {} with path {}", keytype, path),
            }
        }
    }
}

embed_files! {
    (ECDSA_CA_CERT, "ecdsa", "ca.cert");
    (ECDSA_CA_DER, "ecdsa", "ca.der");
    (ECDSA_CA_KEY, "ecdsa", "ca.key");
    (ECDSA_CLIENT_CERT, "ecdsa", "client.cert");
    (ECDSA_CLIENT_CHAIN, "ecdsa", "client.chain");
    (ECDSA_CLIENT_FULLCHAIN, "ecdsa", "client.fullchain");
    (ECDSA_CLIENT_KEY, "ecdsa", "client.key");
    (ECDSA_CLIENT_REQ, "ecdsa", "client.req");
    (ECDSA_END_CRL_PEM, "ecdsa", "end.revoked.crl.pem");
    (ECDSA_CLIENT_CRL_PEM, "ecdsa", "client.revoked.crl.pem");
    (ECDSA_INTERMEDIATE_CRL_PEM, "ecdsa", "inter.revoked.crl.pem");
    (ECDSA_END_CERT, "ecdsa", "end.cert");
    (ECDSA_END_CHAIN, "ecdsa", "end.chain");
    (ECDSA_END_FULLCHAIN, "ecdsa", "end.fullchain");
    (ECDSA_END_KEY, "ecdsa", "end.key");
    (ECDSA_END_REQ, "ecdsa", "end.req");
    (ECDSA_INTER_CERT, "ecdsa", "inter.cert");
    (ECDSA_INTER_KEY, "ecdsa", "inter.key");
    (ECDSA_INTER_REQ, "ecdsa", "inter.req");
    (ECDSA_NISTP256_PEM, "ecdsa", "nistp256.pem");
    (ECDSA_NISTP384_PEM, "ecdsa", "nistp384.pem");

    (EDDSA_CA_CERT, "eddsa", "ca.cert");
    (EDDSA_CA_DER, "eddsa", "ca.der");
    (EDDSA_CA_KEY, "eddsa", "ca.key");
    (EDDSA_CLIENT_CERT, "eddsa", "client.cert");
    (EDDSA_CLIENT_CHAIN, "eddsa", "client.chain");
    (EDDSA_CLIENT_FULLCHAIN, "eddsa", "client.fullchain");
    (EDDSA_CLIENT_KEY, "eddsa", "client.key");
    (EDDSA_CLIENT_REQ, "eddsa", "client.req");
    (EDDSA_END_CRL_PEM, "eddsa", "end.revoked.crl.pem");
    (EDDSA_CLIENT_CRL_PEM, "eddsa", "client.revoked.crl.pem");
    (EDDSA_INTERMEDIATE_CRL_PEM, "eddsa", "inter.revoked.crl.pem");
    (EDDSA_END_CERT, "eddsa", "end.cert");
    (EDDSA_END_CHAIN, "eddsa", "end.chain");
    (EDDSA_END_FULLCHAIN, "eddsa", "end.fullchain");
    (EDDSA_END_KEY, "eddsa", "end.key");
    (EDDSA_END_REQ, "eddsa", "end.req");
    (EDDSA_INTER_CERT, "eddsa", "inter.cert");
    (EDDSA_INTER_KEY, "eddsa", "inter.key");
    (EDDSA_INTER_REQ, "eddsa", "inter.req");

    (RSA_CA_CERT, "rsa", "ca.cert");
    (RSA_CA_DER, "rsa", "ca.der");
    (RSA_CA_KEY, "rsa", "ca.key");
    (RSA_CLIENT_CERT, "rsa", "client.cert");
    (RSA_CLIENT_CHAIN, "rsa", "client.chain");
    (RSA_CLIENT_FULLCHAIN, "rsa", "client.fullchain");
    (RSA_CLIENT_KEY, "rsa", "client.key");
    (RSA_CLIENT_REQ, "rsa", "client.req");
    (RSA_CLIENT_RSA, "rsa", "client.rsa");
    (RSA_END_CRL_PEM, "rsa", "end.revoked.crl.pem");
    (RSA_CLIENT_CRL_PEM, "rsa", "client.revoked.crl.pem");
    (RSA_INTERMEDIATE_CRL_PEM, "rsa", "inter.revoked.crl.pem");
    (RSA_END_CERT, "rsa", "end.cert");
    (RSA_END_CHAIN, "rsa", "end.chain");
    (RSA_END_FULLCHAIN, "rsa", "end.fullchain");
    (RSA_END_KEY, "rsa", "end.key");
    (RSA_END_REQ, "rsa", "end.req");
    (RSA_END_RSA, "rsa", "end.rsa");
    (RSA_INTER_CERT, "rsa", "inter.cert");
    (RSA_INTER_KEY, "rsa", "inter.key");
    (RSA_INTER_REQ, "rsa", "inter.req");
}

pub fn transfer(
    left: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
    right: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
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

pub fn transfer_eof(conn: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>) {
    let empty_buf = [0u8; 0];
    let empty_cursor: &mut dyn io::Read = &mut &empty_buf[..];
    let sz = conn.read_tls(empty_cursor).unwrap();
    assert_eq!(sz, 0);
}

pub enum Altered {
    /// message has been edited in-place (or is unchanged)
    InPlace,
    /// send these raw bytes instead of the message.
    Raw(Vec<u8>),
}

pub fn transfer_altered<F>(left: &mut Connection, filter: F, right: &mut Connection) -> usize
where
    F: Fn(&mut Message) -> Altered,
{
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

        let mut reader = Reader::init(&buf[..sz]);
        while reader.any_left() {
            let message = OutboundOpaqueMessage::read(&mut reader).unwrap();

            // this is a bit of a falsehood: we don't know whether message
            // is encrypted.  it is quite unlikely that a genuine encrypted
            // message can be decoded by `Message::try_from`.
            let plain = message.into_plain_message();

            let message_enc = match Message::try_from(plain.clone()) {
                Ok(mut message) => match filter(&mut message) {
                    Altered::InPlace => PlainMessage::from(message)
                        .into_unencrypted_opaque()
                        .encode(),
                    Altered::Raw(data) => data,
                },
                // pass through encrypted/undecodable messages
                Err(_) => plain.into_unencrypted_opaque().encode(),
            };

            let message_enc_reader: &mut dyn io::Read = &mut &message_enc[..];
            let len = right
                .read_tls(message_enc_reader)
                .unwrap();
            assert_eq!(len, message_enc.len());
        }
    }

    total
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum KeyType {
    Rsa,
    Ecdsa,
    // Ed25519,
}

pub static ALL_KEY_TYPES: [KeyType; 2] = [
    KeyType::Rsa,
    KeyType::Ecdsa,
    // ! Ed25519 is not supported by mbedtls
    // KeyType::Ed25519,
];

impl KeyType {
    fn bytes_for(&self, part: &str) -> &'static [u8] {
        match self {
            Self::Rsa => bytes_for("rsa", part),
            Self::Ecdsa => bytes_for("ecdsa", part),
            // Self::Ed25519 => bytes_for("eddsa", part),
        }
    }

    pub fn get_chain(&self) -> Vec<CertificateDer<'static>> {
        rustls_pemfile::certs(&mut io::BufReader::new(self.bytes_for("end.fullchain")))
            .map(|result| result.unwrap())
            .collect()
    }

    pub fn get_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(
            rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(self.bytes_for("end.key")))
                .next()
                .unwrap()
                .unwrap(),
        )
    }

    pub fn get_client_chain(&self) -> Vec<CertificateDer<'static>> {
        rustls_pemfile::certs(&mut io::BufReader::new(self.bytes_for("client.fullchain")))
            .map(|result| result.unwrap())
            .collect()
    }

    pub fn end_entity_crl(&self) -> CertificateRevocationListDer<'static> {
        self.get_crl("end")
    }

    pub fn client_crl(&self) -> CertificateRevocationListDer<'static> {
        self.get_crl("client")
    }

    pub fn intermediate_crl(&self) -> CertificateRevocationListDer<'static> {
        self.get_crl("inter")
    }

    fn get_client_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(
            rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(self.bytes_for("client.key")))
                .next()
                .unwrap()
                .unwrap(),
        )
    }

    fn get_crl(&self, role: &str) -> CertificateRevocationListDer<'static> {
        rustls_pemfile::crls(&mut io::BufReader::new(self.bytes_for(&format!("{role}.revoked.crl.pem"))))
            .map(|result| result.unwrap())
            .next() // We only expect one CRL.
            .unwrap()
    }
}

pub fn server_config_builder() -> rustls::ConfigBuilder<ServerConfig, rustls::WantsVersions> {
    // ensure `ServerConfig::builder()` is covered, even though it is
    // equivalent to `builder_with_provider(PROVIDER)`.
    #[cfg(feature = "ring")]
    {
        rustls::ServerConfig::builder()
    }
    #[cfg(not(feature = "ring"))]
    {
        rustls::ServerConfig::builder_with_provider(mbedtls_crypto_provider().into())
    }
}

pub fn client_config_builder() -> rustls::ConfigBuilder<ClientConfig, rustls::WantsVersions> {
    // ensure `ClientConfig::builder()` is covered, even though it is
    // equivalent to `builder_with_provider(PROVIDER)`.
    #[cfg(feature = "ring")]
    {
        rustls::ClientConfig::builder()
    }

    #[cfg(not(feature = "ring"))]
    {
        rustls::ClientConfig::builder_with_provider(mbedtls_crypto_provider().into())
    }
}

pub fn finish_server_config(kt: KeyType, conf: rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier>) -> ServerConfig {
    conf.with_no_client_auth()
        .with_single_cert(kt.get_chain(), kt.get_key())
        .unwrap()
}

pub fn make_server_config(kt: KeyType) -> ServerConfig {
    finish_server_config(
        kt,
        server_config_builder()
            .with_safe_default_protocol_versions()
            .unwrap(),
    )
}

pub fn make_server_config_with_versions(kt: KeyType, versions: &[&'static rustls::SupportedProtocolVersion]) -> ServerConfig {
    finish_server_config(
        kt,
        server_config_builder()
            .with_protocol_versions(versions)
            .unwrap(),
    )
}

pub fn make_server_config_with_kx_groups(
    kt: KeyType,
    kx_groups: &[&'static dyn rustls::crypto::SupportedKxGroup],
) -> ServerConfig {
    finish_server_config(
        kt,
        ServerConfig::builder_with_provider(
            crypto_provider_with_cs_with_no_matching_kx_removed(CryptoProvider {
                kx_groups: kx_groups.to_vec(),
                ..mbedtls_crypto_provider()
            })
            .into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap(),
    )
}

pub fn get_client_root_store(kt: KeyType) -> Arc<RootCertStore> {
    // The key type's chain file contains the DER encoding of the EE cert, the intermediate cert,
    // and the root trust anchor. We want only the trust anchor to build the root cert store.
    let chain = kt.get_chain();
    let trust_anchor = chain.last().unwrap();
    RootCertStore {
        roots: vec![webpki::anchor_from_trusted_cert(trust_anchor)
            .unwrap()
            .to_owned()],
    }
    .into()
}

pub fn make_server_config_with_mandatory_client_auth_crls(
    kt: KeyType,
    crls: Vec<CertificateRevocationListDer<'static>>,
) -> ServerConfig {
    make_server_config_with_client_verifier(kt, webpki_client_verifier_builder(get_client_root_store(kt)).with_crls(crls))
}

pub fn make_server_config_with_mandatory_client_auth(kt: KeyType) -> ServerConfig {
    make_server_config_with_client_verifier(kt, webpki_client_verifier_builder(get_client_root_store(kt)))
}

pub fn make_server_config_with_optional_client_auth(
    kt: KeyType,
    crls: Vec<CertificateRevocationListDer<'static>>,
) -> ServerConfig {
    make_server_config_with_client_verifier(
        kt,
        webpki_client_verifier_builder(get_client_root_store(kt))
            .with_crls(crls)
            .allow_unknown_revocation_status()
            .allow_unauthenticated(),
    )
}

pub fn make_server_config_with_client_verifier(kt: KeyType, verifier_builder: ClientCertVerifierBuilder) -> ServerConfig {
    server_config_builder()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier_builder.build().unwrap())
        .with_single_cert(kt.get_chain(), kt.get_key())
        .unwrap()
}

pub fn finish_client_config(kt: KeyType, config: rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier>) -> ClientConfig {
    let mut root_store = RootCertStore::empty();
    let mut root_buf = io::BufReader::new(kt.bytes_for("ca.cert"));
    root_store.add_parsable_certificates(rustls_pemfile::certs(&mut root_buf).map(|result| result.unwrap()));

    config
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

pub fn finish_client_config_with_creds(
    kt: KeyType,
    config: rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier>,
) -> ClientConfig {
    let mut root_store = RootCertStore::empty();
    let mut root_buf = io::BufReader::new(kt.bytes_for("ca.cert"));
    // Passing a reference here just for testing.
    root_store.add_parsable_certificates(rustls_pemfile::certs(&mut root_buf).map(|result| result.unwrap()));

    config
        .with_root_certificates(root_store)
        .with_client_auth_cert(kt.get_client_chain(), kt.get_client_key())
        .unwrap()
}

pub fn make_client_config(kt: KeyType) -> ClientConfig {
    finish_client_config(
        kt,
        client_config_builder()
            .with_safe_default_protocol_versions()
            .unwrap(),
    )
}

static ALL_KEY_EXCHANGE_ALGORITHMS: &[KeyExchangeAlgorithm] = &[KeyExchangeAlgorithm::ECDHE, KeyExchangeAlgorithm::DHE];

fn supported_kx_algos(provider: &CryptoProvider) -> Vec<KeyExchangeAlgorithm> {
    let mut res = Vec::with_capacity(ALL_KEY_EXCHANGE_ALGORITHMS.len());
    for kx in provider
        .kx_groups
        .iter()
        .map(|kx| kx.name().key_exchange_algorithm())
    {
        if !res.contains(&kx) {
            res.push(kx);
        }
        if res.len() == ALL_KEY_EXCHANGE_ALGORITHMS.len() {
            break;
        }
    }
    res
}

/// Return a `CryptoProvider` that have not matching `SupportedKxGroup`s in `kx_groups` removed.
pub fn crypto_provider_with_cs_with_no_matching_kx_removed(mut provider: CryptoProvider) -> CryptoProvider {
    let kx_algos = supported_kx_algos(&provider);

    provider.cipher_suites.retain(|cs| {
        let cs_kx = match cs {
            rustls::SupportedCipherSuite::Tls12(tls12) => core::slice::from_ref(&tls12.kx),
            rustls::SupportedCipherSuite::Tls13(_) => ALL_KEY_EXCHANGE_ALGORITHMS,
        };
        cs_kx
            .iter()
            .any(|kx| kx_algos.contains(kx))
    });
    provider
}

pub fn make_client_config_with_kx_groups(
    kt: KeyType,
    kx_groups: &[&'static dyn rustls::crypto::SupportedKxGroup],
) -> ClientConfig {
    let builder = ClientConfig::builder_with_provider(
        crypto_provider_with_cs_with_no_matching_kx_removed(CryptoProvider {
            kx_groups: kx_groups.to_vec(),
            ..mbedtls_crypto_provider()
        })
        .into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap();
    finish_client_config(kt, builder)
}

pub fn make_client_config_with_versions(kt: KeyType, versions: &[&'static rustls::SupportedProtocolVersion]) -> ClientConfig {
    let builder = client_config_builder()
        .with_protocol_versions(versions)
        .unwrap();
    finish_client_config(kt, builder)
}

pub fn make_client_config_with_auth(kt: KeyType) -> ClientConfig {
    finish_client_config_with_creds(
        kt,
        client_config_builder()
            .with_safe_default_protocol_versions()
            .unwrap(),
    )
}

pub fn make_client_config_with_versions_with_auth(
    kt: KeyType,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> ClientConfig {
    let builder = client_config_builder()
        .with_protocol_versions(versions)
        .unwrap();
    finish_client_config_with_creds(kt, builder)
}

pub fn make_client_config_with_verifier(
    versions: &[&'static rustls::SupportedProtocolVersion],
    verifier_builder: ServerCertVerifierBuilder,
) -> ClientConfig {
    client_config_builder()
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier_builder.build().unwrap())
        .with_no_client_auth()
}

pub fn webpki_client_verifier_builder(roots: Arc<RootCertStore>) -> ClientCertVerifierBuilder {
    // TODO we don't have a ring feature!
    #[cfg(feature = "ring")]
    {
        WebPkiClientVerifier::builder(roots)
    }

    #[cfg(not(feature = "ring"))]
    {
        WebPkiClientVerifier::builder_with_provider(roots, mbedtls_crypto_provider().into())
    }
}

pub fn webpki_server_verifier_builder(roots: Arc<RootCertStore>) -> ServerCertVerifierBuilder {
    #[cfg(feature = "ring")]
    {
        WebPkiServerVerifier::builder(roots)
    }

    #[cfg(not(feature = "ring"))]
    {
        WebPkiServerVerifier::builder_with_provider(roots, mbedtls_crypto_provider().into())
    }
}

pub fn make_pair(kt: KeyType) -> (ClientConnection, ServerConnection) {
    make_pair_for_configs(make_client_config(kt), make_server_config(kt))
}

pub fn make_pair_for_configs(client_config: ClientConfig, server_config: ServerConfig) -> (ClientConnection, ServerConnection) {
    make_pair_for_arc_configs(&Arc::new(client_config), &Arc::new(server_config))
}

pub fn make_pair_for_arc_configs(
    client_config: &Arc<ClientConfig>,
    server_config: &Arc<ServerConfig>,
) -> (ClientConnection, ServerConnection) {
    (
        ClientConnection::new(Arc::clone(client_config), server_name("localhost")).unwrap(),
        ServerConnection::new(Arc::clone(server_config)).unwrap(),
    )
}

pub fn do_handshake(
    client: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
    server: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
) -> (usize, usize) {
    let (mut to_client, mut to_server) = (0, 0);
    while server.is_handshaking() || client.is_handshaking() {
        to_server += transfer(client, server);
        server.process_new_packets().unwrap();
        to_client += transfer(server, client);
        client.process_new_packets().unwrap();
    }
    (to_server, to_client)
}

#[derive(PartialEq, Debug)]
pub enum ErrorFromPeer {
    Client(Error),
    Server(Error),
}

pub fn do_handshake_until_error(client: &mut ClientConnection, server: &mut ServerConnection) -> Result<(), ErrorFromPeer> {
    while server.is_handshaking() || client.is_handshaking() {
        transfer(client, server);
        server
            .process_new_packets()
            .map_err(ErrorFromPeer::Server)?;
        transfer(server, client);
        client
            .process_new_packets()
            .map_err(ErrorFromPeer::Client)?;
    }

    Ok(())
}

pub fn do_handshake_until_both_error(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), Vec<ErrorFromPeer>> {
    match do_handshake_until_error(client, server) {
        Err(server_err @ ErrorFromPeer::Server(_)) => {
            let mut errors = vec![server_err];
            transfer(server, client);
            let client_err = client
                .process_new_packets()
                .map_err(ErrorFromPeer::Client)
                .expect_err("client didn't produce error after server error");
            errors.push(client_err);
            Err(errors)
        }

        Err(client_err @ ErrorFromPeer::Client(_)) => {
            let mut errors = vec![client_err];
            transfer(client, server);
            let server_err = server
                .process_new_packets()
                .map_err(ErrorFromPeer::Server)
                .expect_err("server didn't produce error after client error");
            errors.push(server_err);
            Err(errors)
        }

        Ok(()) => Ok(()),
    }
}

pub fn server_name(name: &'static str) -> ServerName<'static> {
    name.try_into().unwrap()
}

pub struct FailsReads {
    error_kind: io::ErrorKind,
}

impl FailsReads {
    pub fn new(error_kind: io::ErrorKind) -> Self {
        Self { error_kind }
    }
}

impl io::Read for FailsReads {
    fn read(&mut self, _b: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::from(self.error_kind))
    }
}
