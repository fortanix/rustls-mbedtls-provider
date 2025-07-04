/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#![cfg_attr(read_buf, feature(read_buf))]
#![cfg_attr(read_buf, feature(core_io_borrowed_buf))]
//! Assorted public API tests.
use core::fmt;
use core::fmt::Debug;
use std::cell::RefCell;
use std::io::{self, IoSlice, Read, Write};
use std::mem;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

use primary_provider::rng::rng_new;
use primary_provider::sign::MbedTlsPkSigningKeyWrapper as RsaSigningKey;
use primary_provider::{mbedtls_crypto_provider, MbedtlsSecureRandom};
use rustls::client::{verify_server_cert_signed_by_trust_anchor, ResolvesClientCert, Resumption};
use rustls::crypto::CryptoProvider;
use rustls::internal::msgs::base::Payload;
use rustls::internal::msgs::codec::Codec;
use rustls::internal::msgs::enums::AlertLevel;
use rustls::internal::msgs::handshake::{ClientExtension, HandshakePayload};
use rustls::internal::msgs::message::{Message, MessagePayload};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ParsedCertificate, ResolvesServerCert};
use rustls::DistinguishedName;
use rustls::SupportedCipherSuite;
use rustls::{
    sign, AlertDescription, CertificateError, ConnectionCommon, ContentType, Error, KeyLog, PeerIncompatible, PeerMisbehaved,
    SideData,
};
use rustls::{CipherSuite, ProtocolVersion, SignatureScheme};
use rustls::{ClientConfig, ClientConnection};
use rustls::{ServerConfig, ServerConnection};
use rustls::{Stream, StreamOwned};

mod common;
use crate::common::*;

fn alpn_test_error(
    server_protos: Vec<Vec<u8>>,
    client_protos: Vec<Vec<u8>>,
    agreed: Option<&[u8]>,
    expected_error: Option<ErrorFromPeer>,
) {
    let mut server_config = make_server_config(KeyType::Rsa);
    server_config.alpn_protocols = server_protos;

    let server_config = Arc::new(server_config);

    for version in rustls::ALL_VERSIONS {
        let mut client_config = make_client_config_with_versions(KeyType::Rsa, &[version]);
        client_config
            .alpn_protocols
            .clone_from(&client_protos);

        let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        assert_eq!(client.alpn_protocol(), None);
        assert_eq!(server.alpn_protocol(), None);
        let error = do_handshake_until_error(&mut client, &mut server);
        assert_eq!(client.alpn_protocol(), agreed);
        assert_eq!(server.alpn_protocol(), agreed);
        assert_eq!(error.err(), expected_error);
    }
}

fn alpn_test(server_protos: Vec<Vec<u8>>, client_protos: Vec<Vec<u8>>, agreed: Option<&[u8]>) {
    alpn_test_error(server_protos, client_protos, agreed, None)
}

#[test]
fn alpn() {
    // no support
    alpn_test(vec![], vec![], None);

    // server support
    alpn_test(vec![b"server-proto".to_vec()], vec![], None);

    // client support
    alpn_test(vec![], vec![b"client-proto".to_vec()], None);

    // no overlap
    alpn_test_error(
        vec![b"server-proto".to_vec()],
        vec![b"client-proto".to_vec()],
        None,
        Some(ErrorFromPeer::Server(Error::NoApplicationProtocol)),
    );

    // server chooses preference
    alpn_test(
        vec![b"server-proto".to_vec(), b"client-proto".to_vec()],
        vec![b"client-proto".to_vec(), b"server-proto".to_vec()],
        Some(b"server-proto"),
    );

    // case sensitive
    alpn_test_error(
        vec![b"PROTO".to_vec()],
        vec![b"proto".to_vec()],
        None,
        Some(ErrorFromPeer::Server(Error::NoApplicationProtocol)),
    );
}

fn version_test(
    client_versions: &[&'static rustls::SupportedProtocolVersion],
    server_versions: &[&'static rustls::SupportedProtocolVersion],
    result: Option<ProtocolVersion>,
) {
    let client_versions = if client_versions.is_empty() {
        rustls::ALL_VERSIONS
    } else {
        client_versions
    };
    let server_versions = if server_versions.is_empty() {
        rustls::ALL_VERSIONS
    } else {
        server_versions
    };

    let client_config = make_client_config_with_versions(KeyType::Rsa, client_versions);
    let server_config = make_server_config_with_versions(KeyType::Rsa, server_versions);

    println!("version {client_versions:?} {server_versions:?} -> {result:?}");

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    assert_eq!(client.protocol_version(), None);
    assert_eq!(server.protocol_version(), None);
    if result.is_none() {
        let err = do_handshake_until_error(&mut client, &mut server);
        assert!(err.is_err());
    } else {
        do_handshake(&mut client, &mut server);
        assert_eq!(client.protocol_version(), result);
        assert_eq!(server.protocol_version(), result);
    }
}

#[test]
fn versions() {
    // default -> 1.3
    version_test(&[], &[], Some(ProtocolVersion::TLSv1_3));

    // client default, server 1.2 -> 1.2
    #[cfg(feature = "tls12")]
    version_test(&[], &[&rustls::version::TLS12], Some(ProtocolVersion::TLSv1_2));

    // client 1.2, server default -> 1.2
    #[cfg(feature = "tls12")]
    version_test(&[&rustls::version::TLS12], &[], Some(ProtocolVersion::TLSv1_2));

    // client 1.2, server 1.3 -> fail
    #[cfg(feature = "tls12")]
    version_test(&[&rustls::version::TLS12], &[&rustls::version::TLS13], None);

    // client 1.3, server 1.2 -> fail
    #[cfg(feature = "tls12")]
    version_test(&[&rustls::version::TLS13], &[&rustls::version::TLS12], None);

    // client 1.3, server 1.2+1.3 -> 1.3
    #[cfg(feature = "tls12")]
    version_test(
        &[&rustls::version::TLS13],
        &[&rustls::version::TLS12, &rustls::version::TLS13],
        Some(ProtocolVersion::TLSv1_3),
    );

    // client 1.2+1.3, server 1.2 -> 1.2
    #[cfg(feature = "tls12")]
    version_test(
        &[&rustls::version::TLS13, &rustls::version::TLS12],
        &[&rustls::version::TLS12],
        Some(ProtocolVersion::TLSv1_2),
    );
}

fn check_read(reader: &mut dyn io::Read, bytes: &[u8]) {
    let mut buf = vec![0u8; bytes.len() + 1];
    assert_eq!(bytes.len(), reader.read(&mut buf).unwrap());
    assert_eq!(bytes, &buf[..bytes.len()]);
}

fn check_read_err(reader: &mut dyn io::Read, err_kind: io::ErrorKind) {
    let mut buf = vec![0u8; 1];
    let err = reader.read(&mut buf).unwrap_err();
    assert!(matches!(err, err  if err.kind()  == err_kind))
}

#[cfg(read_buf)]
fn check_read_buf(reader: &mut dyn io::Read, bytes: &[u8]) {
    use core::io::BorrowedBuf;
    use std::mem::MaybeUninit;

    let mut buf = [MaybeUninit::<u8>::uninit(); 128];
    let mut buf: BorrowedBuf<'_> = buf.as_mut_slice().into();
    reader.read_buf(buf.unfilled()).unwrap();
    assert_eq!(buf.filled(), bytes);
}

#[cfg(read_buf)]
fn check_read_buf_err(reader: &mut dyn io::Read, err_kind: io::ErrorKind) {
    use core::io::BorrowedBuf;
    use std::mem::MaybeUninit;

    let mut buf = [MaybeUninit::<u8>::uninit(); 1];
    let mut buf: BorrowedBuf<'_> = buf.as_mut_slice().into();
    let err = reader
        .read_buf(buf.unfilled())
        .unwrap_err();
    assert!(matches!(err, err  if err.kind()  == err_kind))
}

#[test]
fn buffered_client_data_sent() {
    let server_config = Arc::new(make_server_config(KeyType::Rsa));

    for version in rustls::ALL_VERSIONS {
        let client_config = make_client_config_with_versions(KeyType::Rsa, &[version]);
        let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        assert_eq!(5, client.writer().write(b"hello").unwrap());

        do_handshake(&mut client, &mut server);
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();

        check_read(&mut server.reader(), b"hello");
    }
}

#[test]
fn buffered_server_data_sent() {
    let server_config = Arc::new(make_server_config(KeyType::Rsa));

    for version in rustls::ALL_VERSIONS {
        let client_config = make_client_config_with_versions(KeyType::Rsa, &[version]);
        let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        assert_eq!(5, server.writer().write(b"hello").unwrap());

        do_handshake(&mut client, &mut server);
        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();

        check_read(&mut client.reader(), b"hello");
    }
}

#[test]
fn buffered_both_data_sent() {
    let server_config = Arc::new(make_server_config(KeyType::Rsa));

    for version in rustls::ALL_VERSIONS {
        let client_config = make_client_config_with_versions(KeyType::Rsa, &[version]);
        let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        assert_eq!(
            12,
            server
                .writer()
                .write(b"from-server!")
                .unwrap()
        );
        assert_eq!(
            12,
            client
                .writer()
                .write(b"from-client!")
                .unwrap()
        );

        do_handshake(&mut client, &mut server);

        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();

        check_read(&mut client.reader(), b"from-server!");
        check_read(&mut server.reader(), b"from-client!");
    }
}

#[test]
fn client_can_get_server_cert() {
    for kt in ALL_KEY_TYPES.iter() {
        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let (mut client, mut server) = make_pair_for_configs(client_config, make_server_config(*kt));
            do_handshake(&mut client, &mut server);

            let certs = client.peer_certificates();
            assert_eq!(certs, Some(kt.get_chain().as_slice()));
        }
    }
}

#[test]
fn client_can_get_server_cert_after_resumption() {
    for kt in ALL_KEY_TYPES.iter() {
        let server_config = make_server_config(*kt);
        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let (mut client, mut server) = make_pair_for_configs(client_config.clone(), server_config.clone());
            do_handshake(&mut client, &mut server);

            let original_certs = client.peer_certificates();

            let (mut client, mut server) = make_pair_for_configs(client_config.clone(), server_config.clone());
            do_handshake(&mut client, &mut server);

            let resumed_certs = client.peer_certificates();

            assert_eq!(original_certs, resumed_certs);
        }
    }
}

#[test]
fn server_can_get_client_cert() {
    for kt in ALL_KEY_TYPES.iter() {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(*kt));

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            do_handshake(&mut client, &mut server);

            let certs = server.peer_certificates();
            assert_eq!(certs, Some(kt.get_client_chain().as_slice()));
        }
    }
}

#[test]
fn server_can_get_client_cert_after_resumption() {
    for kt in ALL_KEY_TYPES.iter() {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(*kt));

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let client_config = Arc::new(client_config);
            let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
            do_handshake(&mut client, &mut server);
            let original_certs = server.peer_certificates();

            let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
            do_handshake(&mut client, &mut server);
            let resumed_certs = server.peer_certificates();
            assert_eq!(original_certs, resumed_certs);
        }
    }
}

/// Test that the server handles combination of `offer_client_auth()` returning true
/// and `client_auth_mandatory` returning `Some(false)`. This exercises both the
/// client's and server's ability to "recover" from the server asking for a client
/// certificate and not being given one.
#[test]
fn server_allow_any_anonymous_or_authenticated_client() {
    let kt = KeyType::Rsa;
    for client_cert_chain in [None, Some(kt.get_client_chain())].iter() {
        let client_auth_roots = get_client_root_store(kt);
        let client_auth = webpki_client_verifier_builder(client_auth_roots.clone())
            .allow_unauthenticated()
            .build()
            .unwrap();

        let server_config = server_config_builder()
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(client_auth)
            .with_single_cert(kt.get_chain(), kt.get_key())
            .unwrap();
        let server_config = Arc::new(server_config);

        for version in rustls::ALL_VERSIONS {
            let client_config = if client_cert_chain.is_some() {
                make_client_config_with_versions_with_auth(kt, &[version])
            } else {
                make_client_config_with_versions(kt, &[version])
            };
            let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            do_handshake(&mut client, &mut server);

            let certs = server.peer_certificates();
            assert_eq!(certs, client_cert_chain.as_deref());
        }
    }
}

fn check_read_and_close(reader: &mut dyn io::Read, expect: &[u8]) {
    check_read(reader, expect);
    assert!(matches!(reader.read(&mut [0u8; 5]), Ok(0)));
}

#[test]
fn server_close_notify() {
    let kt = KeyType::Rsa;
    let server_config = Arc::new(make_server_config_with_mandatory_client_auth(kt));

    for version in rustls::ALL_VERSIONS {
        let client_config = make_client_config_with_versions_with_auth(kt, &[version]);
        let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
        do_handshake(&mut client, &mut server);

        // check that alerts don't overtake appdata
        assert_eq!(
            12,
            server
                .writer()
                .write(b"from-server!")
                .unwrap()
        );
        assert_eq!(
            12,
            client
                .writer()
                .write(b"from-client!")
                .unwrap()
        );
        server.send_close_notify();

        transfer(&mut server, &mut client);
        let io_state = client.process_new_packets().unwrap();
        assert!(io_state.peer_has_closed());
        check_read_and_close(&mut client.reader(), b"from-server!");

        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();
        check_read(&mut server.reader(), b"from-client!");
    }
}

#[test]
fn client_close_notify() {
    let kt = KeyType::Rsa;
    let server_config = Arc::new(make_server_config_with_mandatory_client_auth(kt));

    for version in rustls::ALL_VERSIONS {
        let client_config = make_client_config_with_versions_with_auth(kt, &[version]);
        let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
        do_handshake(&mut client, &mut server);

        // check that alerts don't overtake appdata
        assert_eq!(
            12,
            server
                .writer()
                .write(b"from-server!")
                .unwrap()
        );
        assert_eq!(
            12,
            client
                .writer()
                .write(b"from-client!")
                .unwrap()
        );
        client.send_close_notify();

        transfer(&mut client, &mut server);
        let io_state = server.process_new_packets().unwrap();
        assert!(io_state.peer_has_closed());
        check_read_and_close(&mut server.reader(), b"from-client!");

        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
        check_read(&mut client.reader(), b"from-server!");
    }
}

#[test]
fn server_closes_uncleanly() {
    let kt = KeyType::Rsa;
    let server_config = Arc::new(make_server_config(kt));

    for version in rustls::ALL_VERSIONS {
        let client_config = make_client_config_with_versions(kt, &[version]);
        let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
        do_handshake(&mut client, &mut server);

        // check that unclean EOF reporting does not overtake appdata
        assert_eq!(
            12,
            server
                .writer()
                .write(b"from-server!")
                .unwrap()
        );
        assert_eq!(
            12,
            client
                .writer()
                .write(b"from-client!")
                .unwrap()
        );

        transfer(&mut server, &mut client);
        transfer_eof(&mut client);
        let io_state = client.process_new_packets().unwrap();
        assert!(!io_state.peer_has_closed());
        check_read(&mut client.reader(), b"from-server!");

        check_read_err(&mut client.reader() as &mut dyn io::Read, io::ErrorKind::UnexpectedEof);

        // may still transmit pending frames
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();
        check_read(&mut server.reader(), b"from-client!");
    }
}

#[test]
fn client_closes_uncleanly() {
    let kt = KeyType::Rsa;
    let server_config = Arc::new(make_server_config(kt));

    for version in rustls::ALL_VERSIONS {
        let client_config = make_client_config_with_versions(kt, &[version]);
        let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
        do_handshake(&mut client, &mut server);

        // check that unclean EOF reporting does not overtake appdata
        assert_eq!(
            12,
            server
                .writer()
                .write(b"from-server!")
                .unwrap()
        );
        assert_eq!(
            12,
            client
                .writer()
                .write(b"from-client!")
                .unwrap()
        );

        transfer(&mut client, &mut server);
        transfer_eof(&mut server);
        let io_state = server.process_new_packets().unwrap();
        assert!(!io_state.peer_has_closed());
        check_read(&mut server.reader(), b"from-client!");

        check_read_err(&mut server.reader() as &mut dyn io::Read, io::ErrorKind::UnexpectedEof);

        // may still transmit pending frames
        transfer(&mut server, &mut client);
        client.process_new_packets().unwrap();
        check_read(&mut client.reader(), b"from-server!");
    }
}

#[test]
fn test_tls13_valid_early_plaintext_alert() {
    let (mut client, mut server) = make_pair(KeyType::Rsa);

    // Perform the start of a TLS 1.3 handshake, sending a client hello to the server.
    // The client will not have written a CCS or any encrypted messages to the server yet.
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    // Inject a plaintext alert from the client. The server should accept this since:
    //  * It hasn't decrypted any messages from the peer yet.
    //  * The message content type is Alert.
    //  * The payload size is indicative of a plaintext alert message.
    //  * The negotiated protocol version is TLS 1.3.
    server
        .read_tls(&mut io::Cursor::new(&build_alert(
            AlertLevel::Fatal,
            AlertDescription::UnknownCA,
            &[],
        )))
        .unwrap();

    // The server should process the plaintext alert without error.
    assert_eq!(
        server.process_new_packets(),
        Err(Error::AlertReceived(AlertDescription::UnknownCA)),
    );
}

#[test]
fn test_tls13_too_short_early_plaintext_alert() {
    let (mut client, mut server) = make_pair(KeyType::Rsa);

    // Perform the start of a TLS 1.3 handshake, sending a client hello to the server.
    // The client will not have written a CCS or any encrypted messages to the server yet.
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    // Inject a plaintext alert from the client. The server should attempt to decrypt this message
    // because the payload length is too large to be considered an early plaintext alert.
    server
        .read_tls(&mut io::Cursor::new(&build_alert(
            AlertLevel::Fatal,
            AlertDescription::UnknownCA,
            &[0xff],
        )))
        .unwrap();

    // The server should produce a decrypt error trying to decrypt the plaintext alert.
    assert_eq!(server.process_new_packets(), Err(Error::DecryptError),);
}

#[test]
fn test_tls13_late_plaintext_alert() {
    let (mut client, mut server) = make_pair(KeyType::Rsa);

    // Complete a bi-directional TLS1.3 handshake. After this point no plaintext messages
    // should occur.
    do_handshake(&mut client, &mut server);

    // Inject a plaintext alert from the client. The server should attempt to decrypt this message.
    server
        .read_tls(&mut io::Cursor::new(&build_alert(
            AlertLevel::Fatal,
            AlertDescription::UnknownCA,
            &[],
        )))
        .unwrap();

    // The server should produce a decrypt error, trying to decrypt a plaintext alert.
    assert_eq!(server.process_new_packets(), Err(Error::DecryptError));
}

fn build_alert(level: AlertLevel, desc: AlertDescription, suffix: &[u8]) -> Vec<u8> {
    let mut v = vec![ContentType::Alert.into()];
    ProtocolVersion::TLSv1_2.encode(&mut v);
    ((2 + suffix.len()) as u16).encode(&mut v);
    level.encode(&mut v);
    desc.encode(&mut v);
    v.extend_from_slice(suffix);
    v
}

#[derive(Default, Debug)]
struct ServerCheckCertResolve {
    expected_sni: Option<String>,
    expected_sigalgs: Option<Vec<SignatureScheme>>,
    expected_alpn: Option<Vec<Vec<u8>>>,
    expected_cipher_suites: Option<Vec<CipherSuite>>,
}

impl ResolvesServerCert for ServerCheckCertResolve {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<sign::CertifiedKey>> {
        if client_hello
            .signature_schemes()
            .is_empty()
        {
            panic!("no signature schemes shared by client");
        }

        if client_hello.cipher_suites().is_empty() {
            panic!("no cipher suites shared by client");
        }

        if let Some(expected_sni) = &self.expected_sni {
            let sni: &str = client_hello
                .server_name()
                .expect("sni unexpectedly absent");
            assert_eq!(expected_sni, sni);
        }

        if let Some(expected_sigalgs) = &self.expected_sigalgs {
            assert_eq!(
                expected_sigalgs,
                client_hello.signature_schemes(),
                "unexpected signature schemes"
            );
        }

        if let Some(expected_alpn) = &self.expected_alpn {
            let alpn = client_hello
                .alpn()
                .expect("alpn unexpectedly absent")
                .collect::<Vec<_>>();
            assert_eq!(alpn.len(), expected_alpn.len());

            for (got, wanted) in alpn.iter().zip(expected_alpn.iter()) {
                assert_eq!(got, &wanted.as_slice());
            }
        }

        if let Some(expected_cipher_suites) = &self.expected_cipher_suites {
            assert_eq!(
                expected_cipher_suites,
                client_hello.cipher_suites(),
                "unexpected cipher suites"
            );
        }

        None
    }
}

#[test]
fn server_cert_resolve_with_sni() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_config = make_client_config(*kt);
        let mut server_config = make_server_config(*kt);

        server_config.cert_resolver =
            Arc::new(ServerCheckCertResolve { expected_sni: Some("the-value-from-sni".into()), ..Default::default() });

        let mut client = ClientConnection::new(Arc::new(client_config), server_name("the-value-from-sni")).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server);
        assert!(err.is_err());
    }
}

#[test]
fn server_cert_resolve_with_alpn() {
    for kt in ALL_KEY_TYPES.iter() {
        let mut client_config = make_client_config(*kt);
        client_config.alpn_protocols = vec!["foo".into(), "bar".into()];

        let mut server_config = make_server_config(*kt);
        server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
            expected_alpn: Some(vec![b"foo".to_vec(), b"bar".to_vec()]),
            ..Default::default()
        });

        let mut client = ClientConnection::new(Arc::new(client_config), server_name("sni-value")).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server);
        assert!(err.is_err());
    }
}

#[test]
fn client_trims_terminating_dot() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_config = make_client_config(*kt);
        let mut server_config = make_server_config(*kt);

        server_config.cert_resolver =
            Arc::new(ServerCheckCertResolve { expected_sni: Some("some-host.com".into()), ..Default::default() });

        let mut client = ClientConnection::new(Arc::new(client_config), server_name("some-host.com.")).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let err = do_handshake_until_error(&mut client, &mut server);
        assert!(err.is_err());
    }
}

#[cfg(feature = "tls12")]
fn check_sigalgs_reduced_by_ciphersuite(kt: KeyType, suite: CipherSuite, expected_sigalgs: Vec<SignatureScheme>) {
    let client_config = finish_client_config(
        kt,
        ClientConfig::builder_with_provider(
            CryptoProvider { cipher_suites: vec![find_suite(suite)], ..mbedtls_crypto_provider() }.into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap(),
    );

    let mut server_config = make_server_config(kt);

    server_config.cert_resolver = Arc::new(ServerCheckCertResolve {
        expected_sigalgs: Some(expected_sigalgs),
        expected_cipher_suites: Some(vec![suite, CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV]),
        ..Default::default()
    });

    let mut client = ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

    let err = do_handshake_until_error(&mut client, &mut server);
    assert!(err.is_err());
}

#[cfg(feature = "tls12")]
#[test]
fn server_cert_resolve_reduces_sigalgs_for_rsa_ciphersuite() {
    check_sigalgs_reduced_by_ciphersuite(
        KeyType::Rsa,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        vec![
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ],
    );
}

#[cfg(feature = "tls12")]
#[test]
fn server_cert_resolve_reduces_sigalgs_for_ecdsa_ciphersuite() {
    check_sigalgs_reduced_by_ciphersuite(
        KeyType::Ecdsa,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        vec![
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            // mbedtls does not support ED25519
            // SignatureScheme::ED25519,
        ],
    );
}

#[derive(Debug)]
struct ServerCheckNoSni {}

impl ResolvesServerCert for ServerCheckNoSni {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<sign::CertifiedKey>> {
        assert!(client_hello.server_name().is_none());

        None
    }
}

#[test]
fn client_with_sni_disabled_does_not_send_sni() {
    for kt in ALL_KEY_TYPES.iter() {
        let mut server_config = make_server_config(*kt);
        server_config.cert_resolver = Arc::new(ServerCheckNoSni {});
        let server_config = Arc::new(server_config);

        for version in rustls::ALL_VERSIONS {
            let mut client_config = make_client_config_with_versions(*kt, &[version]);
            client_config.enable_sni = false;

            let mut client = ClientConnection::new(Arc::new(client_config), server_name("value-not-sent")).unwrap();
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();

            let err = do_handshake_until_error(&mut client, &mut server);
            assert!(err.is_err());
        }
    }
}

#[test]
fn client_checks_server_certificate_with_given_name() {
    for kt in ALL_KEY_TYPES.iter() {
        let server_config = Arc::new(make_server_config(*kt));

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let mut client = ClientConnection::new(Arc::new(client_config), server_name("not-the-right-hostname.com")).unwrap();
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();

            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    CertificateError::NotValidForName
                )))
            );
        }
    }
}

#[test]
fn client_checks_server_certificate_with_given_ip_address() {
    fn check_server_name(
        client_config: Arc<ClientConfig>,
        server_config: Arc<ServerConfig>,
        name: &'static str,
    ) -> Result<(), ErrorFromPeer> {
        let mut client = ClientConnection::new(client_config, server_name(name)).unwrap();
        let mut server = ServerConnection::new(server_config).unwrap();
        do_handshake_until_error(&mut client, &mut server)
    }

    for kt in ALL_KEY_TYPES.iter() {
        let server_config = Arc::new(make_server_config(*kt));

        for version in rustls::ALL_VERSIONS {
            let client_config = Arc::new(make_client_config_with_versions(*kt, &[version]));

            // positive ipv4 case
            assert_eq!(
                check_server_name(client_config.clone(), server_config.clone(), "198.51.100.1"),
                Ok(()),
            );

            // negative ipv4 case
            assert_eq!(
                check_server_name(client_config.clone(), server_config.clone(), "198.51.100.2"),
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    CertificateError::NotValidForName
                )))
            );

            // positive ipv6 case
            assert_eq!(
                check_server_name(client_config.clone(), server_config.clone(), "2001:db8::1"),
                Ok(()),
            );

            // negative ipv6 case
            assert_eq!(
                check_server_name(client_config.clone(), server_config.clone(), "2001:db8::2"),
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    CertificateError::NotValidForName
                )))
            );
        }
    }
}

#[test]
fn client_check_server_certificate_ee_revoked() {
    for kt in ALL_KEY_TYPES.iter() {
        let server_config = Arc::new(make_server_config(*kt));

        // Setup a server verifier that will check the EE certificate's revocation status.
        let crls = vec![kt.end_entity_crl()];
        let builder = webpki_server_verifier_builder(get_client_root_store(*kt))
            .with_crls(crls)
            .only_check_end_entity_revocation();

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_verifier(&[version], builder.clone());
            let mut client = ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();

            // We expect the handshake to fail since the server's EE certificate is revoked.
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(CertificateError::Revoked)))
            );
        }
    }
}

#[test]
fn client_check_server_certificate_ee_unknown_revocation() {
    for kt in ALL_KEY_TYPES.iter() {
        let server_config = Arc::new(make_server_config(*kt));

        // Setup a server verifier builder that will check the EE certificate's revocation status, but not
        // allow unknown revocation status (the default). We'll provide CRLs that are not relevant
        // to the EE cert to ensure its status is unknown.
        let unrelated_crls = vec![kt.intermediate_crl()];
        let forbid_unknown_verifier = webpki_server_verifier_builder(get_client_root_store(*kt))
            .with_crls(unrelated_crls.clone())
            .only_check_end_entity_revocation();

        // Also set up a verifier builder that will allow unknown revocation status.
        let allow_unknown_verifier = webpki_server_verifier_builder(get_client_root_store(*kt))
            .with_crls(unrelated_crls)
            .only_check_end_entity_revocation()
            .allow_unknown_revocation_status();

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_verifier(&[version], forbid_unknown_verifier.clone());
            let mut client = ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();

            // We expect if we use the forbid_unknown_verifier that the handshake will fail since the
            // server's EE certificate's revocation status is unknown given the CRLs we've provided.
            let err = do_handshake_until_error(&mut client, &mut server);
            assert!(matches!(
                err,
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(
                    CertificateError::UnknownRevocationStatus
                )))
            ));

            // We expect if we use the allow_unknown_verifier that the handshake will not fail.
            let client_config = make_client_config_with_verifier(&[version], allow_unknown_verifier.clone());
            let mut client = ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
            let res = do_handshake_until_error(&mut client, &mut server);
            assert!(res.is_ok());
        }
    }
}

#[test]
fn client_check_server_certificate_intermediate_revoked() {
    for kt in ALL_KEY_TYPES.iter() {
        let server_config = Arc::new(make_server_config(*kt));

        // Setup a server verifier builder that will check the full chain revocation status against a CRL
        // that marks the intermediate certificate as revoked. We allow unknown revocation status
        // so the EE cert's unknown status doesn't cause an error.
        let crls = vec![kt.intermediate_crl()];
        let full_chain_verifier_builder = webpki_server_verifier_builder(get_client_root_store(*kt))
            .with_crls(crls.clone())
            .allow_unknown_revocation_status();

        // Also set up a verifier builder that will use the same CRL, but only check the EE certificate
        // revocation status.
        let ee_verifier_builder = webpki_server_verifier_builder(get_client_root_store(*kt))
            .with_crls(crls.clone())
            .only_check_end_entity_revocation()
            .allow_unknown_revocation_status();

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_verifier(&[version], full_chain_verifier_builder.clone());
            let mut client = ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();

            // We expect the handshake to fail when using the full chain verifier since the intermediate's
            // EE certificate is revoked.
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Client(Error::InvalidCertificate(CertificateError::Revoked)))
            );

            let client_config = make_client_config_with_verifier(&[version], ee_verifier_builder.clone());
            let mut client = ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
            let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
            // We expect the handshake to succeed when we use the verifier that only checks the EE certificate
            // revocation status. The revoked intermediate status should not be checked.
            let res = do_handshake_until_error(&mut client, &mut server);
            assert!(res.is_ok())
        }
    }
}

/// Simple smoke-test of the webpki verify_server_cert_signed_by_trust_anchor helper API.
/// This public API is intended to be used by consumers implementing their own verifier and
/// so isn't used by the other existing verifier tests.
#[test]
fn client_check_server_certificate_helper_api() {
    for kt in ALL_KEY_TYPES.iter() {
        let chain = kt.get_chain();
        let correct_roots = get_client_root_store(*kt);
        let incorrect_roots = get_client_root_store(match kt {
            KeyType::Rsa => KeyType::Ecdsa,
            _ => KeyType::Rsa,
        });
        // Using the correct trust anchors, we should verify without error.
        assert!(verify_server_cert_signed_by_trust_anchor(
            &ParsedCertificate::try_from(chain.first().unwrap()).unwrap(),
            &correct_roots,
            &[chain.get(1).unwrap().clone()],
            UnixTime::now(),
            webpki::ALL_VERIFICATION_ALGS,
        )
        .is_ok());
        // Using the wrong trust anchors, we should get the expected error.
        assert_eq!(
            verify_server_cert_signed_by_trust_anchor(
                &ParsedCertificate::try_from(chain.first().unwrap()).unwrap(),
                &incorrect_roots,
                &[chain.get(1).unwrap().clone()],
                UnixTime::now(),
                webpki::ALL_VERIFICATION_ALGS,
            )
            .unwrap_err(),
            Error::InvalidCertificate(CertificateError::UnknownIssuer)
        );
    }
}

#[derive(Debug)]
struct ClientCheckCertResolve {
    query_count: AtomicUsize,
    expect_queries: usize,
    expect_root_hint_subjects: Vec<Vec<u8>>,
    expect_sigschemes: Vec<SignatureScheme>,
}

impl ClientCheckCertResolve {
    fn new(expect_queries: usize, expect_root_hint_subjects: Vec<Vec<u8>>, expect_sigschemes: Vec<SignatureScheme>) -> Self {
        Self {
            query_count: AtomicUsize::new(0),
            expect_queries,
            expect_root_hint_subjects,
            expect_sigschemes,
        }
    }
}

impl Drop for ClientCheckCertResolve {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let count = self.query_count.load(Ordering::SeqCst);
            assert_eq!(count, self.expect_queries);
        }
    }
}

impl ResolvesClientCert for ClientCheckCertResolve {
    fn resolve(&self, root_hint_subjects: &[&[u8]], sigschemes: &[SignatureScheme]) -> Option<Arc<sign::CertifiedKey>> {
        self.query_count
            .fetch_add(1, Ordering::SeqCst);

        if sigschemes.is_empty() {
            panic!("no signature schemes shared by server");
        }

        assert_eq!(sigschemes, self.expect_sigschemes);
        assert_eq!(root_hint_subjects, self.expect_root_hint_subjects);

        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}

fn test_client_cert_resolve(key_type: KeyType, server_config: Arc<ServerConfig>, expected_root_hint_subjects: Vec<Vec<u8>>) {
    for version in rustls::ALL_VERSIONS {
        let expected_sigschemes = match version.version {
            ProtocolVersion::TLSv1_2 => vec![
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                // mbedtls does not support ED25519
                // SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA256,
            ],
            ProtocolVersion::TLSv1_3 => vec![
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                // mbedtls does not support ED25519
                // SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
            ],
            _ => unreachable!(),
        };

        println!("{:?} {:?}:", version.version, key_type);

        let mut client_config = make_client_config_with_versions(key_type, &[version]);
        client_config.client_auth_cert_resolver = Arc::new(ClientCheckCertResolve::new(
            1,
            expected_root_hint_subjects.clone(),
            expected_sigschemes,
        ));

        let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config), &server_config);

        assert_eq!(
            do_handshake_until_error(&mut client, &mut server),
            Err(ErrorFromPeer::Server(Error::NoCertificatesPresented))
        );
    }
}

#[test]
fn client_cert_resolve_default() {
    // Test that in the default configuration that a client cert resolver gets the expected
    // CA subject hints, and supported signature algorithms.
    for key_type in ALL_KEY_TYPES.into_iter() {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(key_type));

        // In a default configuration we expect that the verifier's trust anchors are used
        // for the hint subjects.
        let expected_root_hint_subjects = vec![match key_type {
            KeyType::Rsa => &b"0\x1a1\x180\x16\x06\x03U\x04\x03\x0c\x0fponytown RSA CA"[..],
            KeyType::Ecdsa => &b"0\x1c1\x1a0\x18\x06\x03U\x04\x03\x0c\x11ponytown ECDSA CA"[..],
            // KeyType::Ed25519 => &b"0\x1c1\x1a0\x18\x06\x03U\x04\x03\x0c\x11ponytown EdDSA CA"[..],
        }
        .to_vec()];

        test_client_cert_resolve(key_type, server_config, expected_root_hint_subjects);
    }
}

#[test]
fn client_cert_resolve_server_no_hints() {
    // Test that a server can provide no hints and the client cert resolver gets the expected
    // arguments.
    for key_type in ALL_KEY_TYPES.into_iter() {
        // Build a verifier with no hint subjects.
        let verifier = webpki_client_verifier_builder(get_client_root_store(key_type)).clear_root_hint_subjects();
        let server_config = make_server_config_with_client_verifier(key_type, verifier);
        let expected_root_hint_subjects = Vec::default(); // no hints expected.
        test_client_cert_resolve(key_type, server_config.into(), expected_root_hint_subjects);
    }
}

#[test]
fn client_cert_resolve_server_added_hint() {
    // Test that a server can add an extra subject above/beyond those found in its trust store
    // and the client cert resolver gets the expected arguments.
    let extra_name = b"0\x1a1\x180\x16\x06\x03U\x04\x03\x0c\x0fponyland IDK CA".to_vec();
    for key_type in ALL_KEY_TYPES.into_iter() {
        let expected_hint_subjects = vec![
            match key_type {
                KeyType::Rsa => &b"0\x1a1\x180\x16\x06\x03U\x04\x03\x0c\x0fponytown RSA CA"[..],
                KeyType::Ecdsa => &b"0\x1c1\x1a0\x18\x06\x03U\x04\x03\x0c\x11ponytown ECDSA CA"[..],
                // KeyType::Ed25519 => &b"0\x1c1\x1a0\x18\x06\x03U\x04\x03\x0c\x11ponytown EdDSA CA"[..],
            }
            .to_vec(),
            extra_name.clone(),
        ];
        // Create a verifier that adds the extra_name as a hint subject in addition to the ones
        // from the root cert store.
        let verifier = webpki_client_verifier_builder(get_client_root_store(key_type))
            .add_root_hint_subjects([DistinguishedName::from(extra_name.clone())].into_iter());
        let server_config = make_server_config_with_client_verifier(key_type, verifier);
        test_client_cert_resolve(key_type, server_config.into(), expected_hint_subjects);
    }
}

#[test]
fn client_auth_works() {
    for kt in ALL_KEY_TYPES.iter() {
        let server_config = Arc::new(make_server_config_with_mandatory_client_auth(*kt));

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            do_handshake(&mut client, &mut server);
        }
    }
}

#[test]
fn client_mandatory_auth_client_revocation_works() {
    for kt in ALL_KEY_TYPES.iter() {
        // Create a server configuration that includes a CRL that specifies the client certificate
        // is revoked.
        let relevant_crls = vec![kt.client_crl()];
        // Only check the EE certificate status. See client_mandatory_auth_intermediate_revocation_works
        // for testing revocation status of the whole chain.
        let ee_verifier_builder = webpki_client_verifier_builder(get_client_root_store(*kt))
            .with_crls(relevant_crls)
            .only_check_end_entity_revocation();
        let revoked_server_config = Arc::new(make_server_config_with_client_verifier(*kt, ee_verifier_builder));

        // Create a server configuration that includes a CRL that doesn't cover the client certificate,
        // and uses the default behaviour of treating unknown revocation status as an error.
        let unrelated_crls = vec![kt.intermediate_crl()];
        let ee_verifier_builder = webpki_client_verifier_builder(get_client_root_store(*kt))
            .with_crls(unrelated_crls.clone())
            .only_check_end_entity_revocation();
        let missing_client_crl_server_config = Arc::new(make_server_config_with_client_verifier(*kt, ee_verifier_builder));

        // Create a server configuration that includes a CRL that doesn't cover the client certificate,
        // but change the builder to allow unknown revocation status.
        let ee_verifier_builder = webpki_client_verifier_builder(get_client_root_store(*kt))
            .with_crls(unrelated_crls.clone())
            .only_check_end_entity_revocation()
            .allow_unknown_revocation_status();
        let allow_missing_client_crl_server_config =
            Arc::new(make_server_config_with_client_verifier(*kt, ee_verifier_builder));

        for version in rustls::ALL_VERSIONS {
            // Connecting to the server with a CRL that indicates the client certificate is revoked
            // should fail with the expected error.
            let client_config = Arc::new(make_client_config_with_versions_with_auth(*kt, &[version]));
            let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &revoked_server_config);
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Server(Error::InvalidCertificate(CertificateError::Revoked)))
            );
            // Connecting to the server missing CRL information for the client certificate should
            // fail with the expected unknown revocation status error.
            let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &missing_client_crl_server_config);
            let res = do_handshake_until_error(&mut client, &mut server);
            assert!(matches!(
                res,
                Err(ErrorFromPeer::Server(Error::InvalidCertificate(
                    CertificateError::UnknownRevocationStatus
                )))
            ));
            // Connecting to the server missing CRL information for the client should not error
            // if the server's verifier allows unknown revocation status.
            let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &allow_missing_client_crl_server_config);
            let res = do_handshake_until_error(&mut client, &mut server);
            assert!(res.is_ok());
        }
    }
}

#[test]
fn client_mandatory_auth_intermediate_revocation_works() {
    for kt in ALL_KEY_TYPES.iter() {
        // Create a server configuration that includes a CRL that specifies the intermediate certificate
        // is revoked. We check the full chain for revocation status (default), and allow unknown
        // revocation status so the EE's unknown revocation status isn't an error.
        let crls = vec![kt.intermediate_crl()];
        let full_chain_verifier_builder = webpki_client_verifier_builder(get_client_root_store(*kt))
            .with_crls(crls.clone())
            .allow_unknown_revocation_status();
        let full_chain_server_config = Arc::new(make_server_config_with_client_verifier(*kt, full_chain_verifier_builder));

        // Also create a server configuration that uses the same CRL, but that only checks the EE
        // cert revocation status.
        let ee_only_verifier_builder = webpki_client_verifier_builder(get_client_root_store(*kt))
            .with_crls(crls)
            .only_check_end_entity_revocation()
            .allow_unknown_revocation_status();
        let ee_server_config = Arc::new(make_server_config_with_client_verifier(*kt, ee_only_verifier_builder));

        for version in rustls::ALL_VERSIONS {
            // When checking the full chain, we expect an error - the intermediate is revoked.
            let client_config = Arc::new(make_client_config_with_versions_with_auth(*kt, &[version]));
            let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &full_chain_server_config);
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Server(Error::InvalidCertificate(CertificateError::Revoked)))
            );
            // However, when checking just the EE cert we expect no error - the intermediate's
            // revocation status should not be checked.
            let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &ee_server_config);
            assert!(do_handshake_until_error(&mut client, &mut server).is_ok());
        }
    }
}

#[test]
fn client_optional_auth_client_revocation_works() {
    for kt in ALL_KEY_TYPES.iter() {
        // Create a server configuration that includes a CRL that specifies the client certificate
        // is revoked.
        let crls = vec![kt.client_crl()];
        let server_config = Arc::new(make_server_config_with_optional_client_auth(*kt, crls));

        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions_with_auth(*kt, &[version]);
            let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(client_config), &server_config);
            // Because the client certificate is revoked, the handshake should fail.
            let err = do_handshake_until_error(&mut client, &mut server);
            assert_eq!(
                err,
                Err(ErrorFromPeer::Server(Error::InvalidCertificate(CertificateError::Revoked)))
            );
        }
    }
}

#[test]
fn client_error_is_sticky() {
    let (mut client, _) = make_pair(KeyType::Rsa);
    client
        .read_tls(&mut b"\x16\x03\x03\x00\x08\x0f\x00\x00\x04junk".as_ref())
        .unwrap();
    let mut err = client.process_new_packets();
    assert!(err.is_err());
    err = client.process_new_packets();
    assert!(err.is_err());
}

#[test]
fn server_error_is_sticky() {
    let (_, mut server) = make_pair(KeyType::Rsa);
    server
        .read_tls(&mut b"\x16\x03\x03\x00\x08\x0f\x00\x00\x04junk".as_ref())
        .unwrap();
    let mut err = server.process_new_packets();
    assert!(err.is_err());
    err = server.process_new_packets();
    assert!(err.is_err());
}

#[test]
fn server_flush_does_nothing() {
    let (_, mut server) = make_pair(KeyType::Rsa);
    assert!(matches!(server.writer().flush(), Ok(())));
}

#[test]
fn client_flush_does_nothing() {
    let (mut client, _) = make_pair(KeyType::Rsa);
    assert!(matches!(client.writer().flush(), Ok(())));
}

#[allow(clippy::no_effect, clippy::unnecessary_operation)]
#[test]
fn server_is_send_and_sync() {
    let (_, server) = make_pair(KeyType::Rsa);
    &server as &dyn Send;
    &server as &dyn Sync;
}

#[allow(clippy::no_effect, clippy::unnecessary_operation)]
#[test]
fn client_is_send_and_sync() {
    let (client, _) = make_pair(KeyType::Rsa);
    &client as &dyn Send;
    &client as &dyn Sync;
}

#[test]
fn server_respects_buffer_limit_pre_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Rsa);

    server.set_buffer_limit(Some(32));

    assert_eq!(
        server
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        20
    );
    assert_eq!(
        server
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        12
    );

    do_handshake(&mut client, &mut server);
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    check_read(&mut client.reader(), b"01234567890123456789012345678901");
}

#[test]
fn server_respects_buffer_limit_pre_handshake_with_vectored_write() {
    let (mut client, mut server) = make_pair(KeyType::Rsa);

    server.set_buffer_limit(Some(32));

    assert_eq!(
        server
            .writer()
            .write_vectored(&[IoSlice::new(b"01234567890123456789"), IoSlice::new(b"01234567890123456789")])
            .unwrap(),
        32
    );

    do_handshake(&mut client, &mut server);
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    check_read(&mut client.reader(), b"01234567890123456789012345678901");
}

#[test]
fn server_respects_buffer_limit_post_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Rsa);

    // this test will vary in behaviour depending on the default suites
    do_handshake(&mut client, &mut server);
    server.set_buffer_limit(Some(48));

    assert_eq!(
        server
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        20
    );
    assert_eq!(
        server
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        6
    );

    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    check_read(&mut client.reader(), b"01234567890123456789012345");
}

#[test]
fn client_respects_buffer_limit_pre_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Rsa);

    client.set_buffer_limit(Some(32));

    assert_eq!(
        client
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        20
    );
    assert_eq!(
        client
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        12
    );

    do_handshake(&mut client, &mut server);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    check_read(&mut server.reader(), b"01234567890123456789012345678901");
}

#[test]
fn client_respects_buffer_limit_pre_handshake_with_vectored_write() {
    let (mut client, mut server) = make_pair(KeyType::Rsa);

    client.set_buffer_limit(Some(32));

    assert_eq!(
        client
            .writer()
            .write_vectored(&[IoSlice::new(b"01234567890123456789"), IoSlice::new(b"01234567890123456789")])
            .unwrap(),
        32
    );

    do_handshake(&mut client, &mut server);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    check_read(&mut server.reader(), b"01234567890123456789012345678901");
}

#[test]
fn client_respects_buffer_limit_post_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Rsa);

    do_handshake(&mut client, &mut server);
    client.set_buffer_limit(Some(48));

    assert_eq!(
        client
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        20
    );
    assert_eq!(
        client
            .writer()
            .write(b"01234567890123456789")
            .unwrap(),
        6
    );

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    check_read(&mut server.reader(), b"01234567890123456789012345");
}

struct OtherSession<'a, C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    sess: &'a mut C,
    pub reads: usize,
    pub writevs: Vec<Vec<usize>>,
    fail_ok: bool,
    pub short_writes: bool,
    pub last_error: Option<rustls::Error>,
    pub buffered: bool,
    buffer: Vec<Vec<u8>>,
}

impl<C, S> OtherSession<'_, C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    fn new(sess: &mut C) -> OtherSession<'_, C, S> {
        OtherSession {
            sess,
            reads: 0,
            writevs: vec![],
            fail_ok: false,
            short_writes: false,
            last_error: None,
            buffered: false,
            buffer: vec![],
        }
    }

    fn new_buffered(sess: &mut C) -> OtherSession<'_, C, S> {
        let mut os = OtherSession::new(sess);
        os.buffered = true;
        os
    }

    fn flush_vectored(&mut self, b: &[io::IoSlice<'_>]) -> io::Result<usize> {
        let mut total = 0;
        let mut lengths = vec![];
        for bytes in b {
            let write_len = if self.short_writes {
                if bytes.len() > 5 {
                    bytes.len() / 2
                } else {
                    bytes.len()
                }
            } else {
                bytes.len()
            };

            let l = self
                .sess
                .read_tls(&mut io::Cursor::new(&bytes[..write_len]))?;
            lengths.push(l);
            total += l;
            if bytes.len() != l {
                break;
            }
        }

        let rc = self.sess.process_new_packets();
        if !self.fail_ok {
            rc.unwrap();
        } else if rc.is_err() {
            self.last_error = rc.err();
        }

        self.writevs.push(lengths);
        Ok(total)
    }
}

impl<C, S> io::Read for OtherSession<'_, C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    fn read(&mut self, mut b: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        self.sess.write_tls(b.by_ref())
    }
}

impl<C, S> io::Write for OtherSession<'_, C, S>
where
    C: DerefMut + Deref<Target = ConnectionCommon<S>>,
    S: SideData,
{
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        unreachable!()
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            let buffer = mem::take(&mut self.buffer);
            let slices = buffer
                .iter()
                .map(|b| io::IoSlice::new(b))
                .collect::<Vec<_>>();
            self.flush_vectored(&slices)?;
        }
        Ok(())
    }

    fn write_vectored(&mut self, b: &[io::IoSlice<'_>]) -> io::Result<usize> {
        if self.buffered {
            self.buffer
                .extend(b.iter().map(|s| s.to_vec()));
            return Ok(b.iter().map(|s| s.len()).sum());
        }
        self.flush_vectored(b)
    }
}

#[test]
fn server_read_returns_wouldblock_when_no_data() {
    let (_, mut server) = make_pair(KeyType::Rsa);
    assert!(matches!(server.reader().read(&mut [0u8; 1]),
                     Err(err) if err.kind() == io::ErrorKind::WouldBlock));
}

#[test]
fn client_read_returns_wouldblock_when_no_data() {
    let (mut client, _) = make_pair(KeyType::Rsa);
    assert!(matches!(client.reader().read(&mut [0u8; 1]),
                     Err(err) if err.kind() == io::ErrorKind::WouldBlock));
}

#[test]
fn new_server_returns_initial_io_state() {
    let (_, mut server) = make_pair(KeyType::Rsa);
    let io_state = server.process_new_packets().unwrap();
    println!("IoState is Debug {io_state:?}");
    assert_eq!(io_state.plaintext_bytes_to_read(), 0);
    assert!(!io_state.peer_has_closed());
    assert_eq!(io_state.tls_bytes_to_write(), 0);
}

#[test]
fn new_client_returns_initial_io_state() {
    let (mut client, _) = make_pair(KeyType::Rsa);
    let io_state = client.process_new_packets().unwrap();
    println!("IoState is Debug {io_state:?}");
    assert_eq!(io_state.plaintext_bytes_to_read(), 0);
    assert!(!io_state.peer_has_closed());
    assert!(io_state.tls_bytes_to_write() > 200);
}

#[test]
fn client_complete_io_for_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Rsa);

    assert!(client.is_handshaking());
    let (rdlen, wrlen) = client
        .complete_io(&mut OtherSession::new(&mut server))
        .unwrap();
    assert!(rdlen > 0 && wrlen > 0);
    assert!(!client.is_handshaking());
    assert!(!client.wants_write());
}

#[test]
fn buffered_client_complete_io_for_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Rsa);

    assert!(client.is_handshaking());
    let (rdlen, wrlen) = client
        .complete_io(&mut OtherSession::new_buffered(&mut server))
        .unwrap();
    assert!(rdlen > 0 && wrlen > 0);
    assert!(!client.is_handshaking());
    assert!(!client.wants_write());
}

#[test]
fn client_complete_io_for_handshake_eof() {
    let (mut client, _) = make_pair(KeyType::Rsa);
    let mut input = io::Cursor::new(Vec::new());

    assert!(client.is_handshaking());
    let err = client
        .complete_io(&mut input)
        .unwrap_err();
    assert_eq!(io::ErrorKind::UnexpectedEof, err.kind());
}

#[test]
fn client_complete_io_for_write() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        do_handshake(&mut client, &mut server);

        client
            .writer()
            .write_all(b"01234567890123456789")
            .unwrap();
        client
            .writer()
            .write_all(b"01234567890123456789")
            .unwrap();
        {
            let mut pipe = OtherSession::new(&mut server);
            let (rdlen, wrlen) = client.complete_io(&mut pipe).unwrap();
            assert!(rdlen == 0 && wrlen > 0);
            println!("{:?}", pipe.writevs);
            assert_eq!(pipe.writevs, vec![vec![42, 42]]);
        }
        check_read(&mut server.reader(), b"0123456789012345678901234567890123456789");
    }
}

#[test]
fn buffered_client_complete_io_for_write() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        do_handshake(&mut client, &mut server);

        client
            .writer()
            .write_all(b"01234567890123456789")
            .unwrap();
        client
            .writer()
            .write_all(b"01234567890123456789")
            .unwrap();
        {
            let mut pipe = OtherSession::new_buffered(&mut server);
            let (rdlen, wrlen) = client.complete_io(&mut pipe).unwrap();
            assert!(rdlen == 0 && wrlen > 0);
            println!("{:?}", pipe.writevs);
            assert_eq!(pipe.writevs, vec![vec![42, 42]]);
        }
        check_read(&mut server.reader(), b"0123456789012345678901234567890123456789");
    }
}

#[test]
fn client_complete_io_for_read() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        do_handshake(&mut client, &mut server);

        server
            .writer()
            .write_all(b"01234567890123456789")
            .unwrap();
        {
            let mut pipe = OtherSession::new(&mut server);
            let (rdlen, wrlen) = client.complete_io(&mut pipe).unwrap();
            assert!(rdlen > 0 && wrlen == 0);
            assert_eq!(pipe.reads, 1);
        }
        check_read(&mut client.reader(), b"01234567890123456789");
    }
}

#[test]
fn server_complete_io_for_handshake() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        assert!(server.is_handshaking());
        let (rdlen, wrlen) = server
            .complete_io(&mut OtherSession::new(&mut client))
            .unwrap();
        assert!(rdlen > 0 && wrlen > 0);
        assert!(!server.is_handshaking());
        assert!(!server.wants_write());
    }
}

#[test]
fn server_complete_io_for_handshake_eof() {
    let (_, mut server) = make_pair(KeyType::Rsa);
    let mut input = io::Cursor::new(Vec::new());

    assert!(server.is_handshaking());
    let err = server
        .complete_io(&mut input)
        .unwrap_err();
    assert_eq!(io::ErrorKind::UnexpectedEof, err.kind());
}

#[test]
fn server_complete_io_for_write() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        do_handshake(&mut client, &mut server);

        server
            .writer()
            .write_all(b"01234567890123456789")
            .unwrap();
        server
            .writer()
            .write_all(b"01234567890123456789")
            .unwrap();
        {
            let mut pipe = OtherSession::new(&mut client);
            let (rdlen, wrlen) = server.complete_io(&mut pipe).unwrap();
            assert!(rdlen == 0 && wrlen > 0);
            assert_eq!(pipe.writevs, vec![vec![42, 42]]);
        }
        check_read(&mut client.reader(), b"0123456789012345678901234567890123456789");
    }
}

#[test]
fn server_complete_io_for_read() {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);

        do_handshake(&mut client, &mut server);

        client
            .writer()
            .write_all(b"01234567890123456789")
            .unwrap();
        {
            let mut pipe = OtherSession::new(&mut client);
            let (rdlen, wrlen) = server.complete_io(&mut pipe).unwrap();
            assert!(rdlen > 0 && wrlen == 0);
            assert_eq!(pipe.reads, 1);
        }
        check_read(&mut server.reader(), b"01234567890123456789");
    }
}

#[test]
fn client_stream_write() {
    test_client_stream_write(StreamKind::Ref);
    test_client_stream_write(StreamKind::Owned);
}

#[test]
fn server_stream_write() {
    test_server_stream_write(StreamKind::Ref);
    test_server_stream_write(StreamKind::Owned);
}

#[derive(Debug, Copy, Clone)]
enum StreamKind {
    Owned,
    Ref,
}

fn test_client_stream_write(stream_kind: StreamKind) {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);
        let data = b"hello";
        {
            let mut pipe = OtherSession::new(&mut server);
            let mut stream: Box<dyn Write> = match stream_kind {
                StreamKind::Ref => Box::new(Stream::new(&mut client, &mut pipe)),
                StreamKind::Owned => Box::new(StreamOwned::new(client, pipe)),
            };
            assert_eq!(stream.write(data).unwrap(), 5);
        }
        check_read(&mut server.reader(), data);
    }
}

fn test_server_stream_write(stream_kind: StreamKind) {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);
        let data = b"hello";
        {
            let mut pipe = OtherSession::new(&mut client);
            let mut stream: Box<dyn Write> = match stream_kind {
                StreamKind::Ref => Box::new(Stream::new(&mut server, &mut pipe)),
                StreamKind::Owned => Box::new(StreamOwned::new(server, pipe)),
            };
            assert_eq!(stream.write(data).unwrap(), 5);
        }
        check_read(&mut client.reader(), data);
    }
}

#[test]
fn client_stream_read() {
    test_client_stream_read(StreamKind::Ref, ReadKind::Buf);
    test_client_stream_read(StreamKind::Owned, ReadKind::Buf);
    #[cfg(read_buf)]
    {
        test_client_stream_read(StreamKind::Ref, ReadKind::BorrowedBuf);
        test_client_stream_read(StreamKind::Owned, ReadKind::BorrowedBuf);
    }
}

#[test]
fn server_stream_read() {
    test_server_stream_read(StreamKind::Ref, ReadKind::Buf);
    test_server_stream_read(StreamKind::Owned, ReadKind::Buf);
    #[cfg(read_buf)]
    {
        test_server_stream_read(StreamKind::Ref, ReadKind::BorrowedBuf);
        test_server_stream_read(StreamKind::Owned, ReadKind::BorrowedBuf);
    }
}

#[derive(Debug, Copy, Clone)]
enum ReadKind {
    Buf,
    #[cfg(read_buf)]
    BorrowedBuf,
}

fn test_stream_read(read_kind: ReadKind, mut stream: impl Read, data: &[u8]) {
    match read_kind {
        ReadKind::Buf => {
            check_read(&mut stream, data);
            check_read_err(&mut stream, io::ErrorKind::UnexpectedEof)
        }
        #[cfg(read_buf)]
        ReadKind::BorrowedBuf => {
            check_read_buf(&mut stream, data);
            check_read_buf_err(&mut stream, io::ErrorKind::UnexpectedEof)
        }
    }
}

fn test_client_stream_read(stream_kind: StreamKind, read_kind: ReadKind) {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);
        let data = b"world";
        server.writer().write_all(data).unwrap();

        {
            let mut pipe = OtherSession::new(&mut server);
            transfer_eof(&mut client);

            let stream: Box<dyn Read> = match stream_kind {
                StreamKind::Ref => Box::new(Stream::new(&mut client, &mut pipe)),
                StreamKind::Owned => Box::new(StreamOwned::new(client, pipe)),
            };

            test_stream_read(read_kind, stream, data)
        }
    }
}

fn test_server_stream_read(stream_kind: StreamKind, read_kind: ReadKind) {
    for kt in ALL_KEY_TYPES.iter() {
        let (mut client, mut server) = make_pair(*kt);
        let data = b"world";
        client.writer().write_all(data).unwrap();

        {
            let mut pipe = OtherSession::new(&mut client);
            transfer_eof(&mut server);

            let stream: Box<dyn Read> = match stream_kind {
                StreamKind::Ref => Box::new(Stream::new(&mut server, &mut pipe)),
                StreamKind::Owned => Box::new(StreamOwned::new(server, pipe)),
            };

            test_stream_read(read_kind, stream, data)
        }
    }
}

struct FailsWrites {
    errkind: io::ErrorKind,
    after: usize,
}

impl io::Read for FailsWrites {
    fn read(&mut self, _b: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl io::Write for FailsWrites {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self.after > 0 {
            self.after -= 1;
            Ok(b.len())
        } else {
            Err(io::Error::new(self.errkind, "oops"))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn stream_write_reports_underlying_io_error_before_plaintext_processed() {
    let (mut client, mut server) = make_pair(KeyType::Rsa);
    do_handshake(&mut client, &mut server);

    let mut pipe = FailsWrites { errkind: io::ErrorKind::ConnectionAborted, after: 0 };
    client
        .writer()
        .write_all(b"hello")
        .unwrap();
    let mut client_stream = Stream::new(&mut client, &mut pipe);
    let rc = client_stream.write(b"world");
    assert!(rc.is_err());
    let err = rc.err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
}

#[test]
fn stream_write_swallows_underlying_io_error_after_plaintext_processed() {
    let (mut client, mut server) = make_pair(KeyType::Rsa);
    do_handshake(&mut client, &mut server);

    let mut pipe = FailsWrites { errkind: io::ErrorKind::ConnectionAborted, after: 1 };
    client
        .writer()
        .write_all(b"hello")
        .unwrap();
    let mut client_stream = Stream::new(&mut client, &mut pipe);
    let rc = client_stream.write(b"world");
    assert_eq!(format!("{rc:?}"), "Ok(5)");
}

#[test]
fn server_exposes_offered_sni() {
    let kt = KeyType::Rsa;
    for version in rustls::ALL_VERSIONS {
        let client_config = make_client_config_with_versions(kt, &[version]);
        let mut client = ClientConnection::new(Arc::new(client_config), server_name("second.testserver.com")).unwrap();
        let mut server = ServerConnection::new(Arc::new(make_server_config(kt))).unwrap();

        assert_eq!(None, server.server_name());
        do_handshake(&mut client, &mut server);
        assert_eq!(Some("second.testserver.com"), server.server_name());
    }
}

#[test]
fn server_exposes_offered_sni_smashed_to_lowercase() {
    // webpki actually does this for us in its DnsName type
    let kt = KeyType::Rsa;
    for version in rustls::ALL_VERSIONS {
        let client_config = make_client_config_with_versions(kt, &[version]);
        let mut client = ClientConnection::new(Arc::new(client_config), server_name("SECOND.TESTServer.com")).unwrap();
        let mut server = ServerConnection::new(Arc::new(make_server_config(kt))).unwrap();

        assert_eq!(None, server.server_name());
        do_handshake(&mut client, &mut server);
        assert_eq!(Some("second.testserver.com"), server.server_name());
    }
}

#[test]
fn server_exposes_offered_sni_even_if_resolver_fails() {
    let kt = KeyType::Rsa;
    let resolver = rustls::server::ResolvesServerCertUsingSni::new();

    let mut server_config = make_server_config(kt);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    for version in rustls::ALL_VERSIONS {
        let client_config = make_client_config_with_versions(kt, &[version]);
        let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
        let mut client = ClientConnection::new(Arc::new(client_config), server_name("thisdoesNOTexist.com")).unwrap();

        assert_eq!(None, server.server_name());
        transfer(&mut client, &mut server);
        assert_eq!(
            server.process_new_packets(),
            Err(Error::General("no server certificate chain resolved".to_string()))
        );
        assert_eq!(Some("thisdoesnotexist.com"), server.server_name());
    }
}

#[test]
fn sni_resolver_works() {
    let kt = KeyType::Rsa;
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
    let signing_key = RsaSigningKey::new(&kt.get_key(), rng_new).unwrap();
    let signing_key: Arc<dyn sign::SigningKey> = Arc::new(signing_key);
    resolver
        .add("localhost", sign::CertifiedKey::new(kt.get_chain(), signing_key.clone()))
        .unwrap();

    let mut server_config = make_server_config(kt);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    let mut server1 = ServerConnection::new(Arc::clone(&server_config)).unwrap();
    let mut client1 = ClientConnection::new(Arc::new(make_client_config(kt)), server_name("localhost")).unwrap();
    let err = do_handshake_until_error(&mut client1, &mut server1);
    assert_eq!(err, Ok(()));

    let mut server2 = ServerConnection::new(Arc::clone(&server_config)).unwrap();
    let mut client2 = ClientConnection::new(Arc::new(make_client_config(kt)), server_name("notlocalhost")).unwrap();
    let err = do_handshake_until_error(&mut client2, &mut server2);
    assert_eq!(
        err,
        Err(ErrorFromPeer::Server(Error::General(
            "no server certificate chain resolved".into()
        )))
    );
}

#[test]
fn sni_resolver_rejects_wrong_names() {
    let kt = KeyType::Rsa;
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
    let signing_key = RsaSigningKey::new(&kt.get_key(), rng_new).unwrap();
    let signing_key: Arc<dyn sign::SigningKey> = Arc::new(signing_key);

    assert_eq!(
        Ok(()),
        resolver.add("localhost", sign::CertifiedKey::new(kt.get_chain(), signing_key.clone()))
    );
    assert_eq!(
        Err(Error::InvalidCertificate(CertificateError::NotValidForName)),
        resolver.add("not-localhost", sign::CertifiedKey::new(kt.get_chain(), signing_key.clone()))
    );
    assert_eq!(
        Err(Error::General("Bad DNS name".into())),
        resolver.add("not ascii 🦀", sign::CertifiedKey::new(kt.get_chain(), signing_key.clone()))
    );
}

#[test]
fn sni_resolver_lower_cases_configured_names() {
    let kt = KeyType::Rsa;
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
    let signing_key = RsaSigningKey::new(&kt.get_key(), rng_new).unwrap();
    let signing_key: Arc<dyn sign::SigningKey> = Arc::new(signing_key);

    assert_eq!(
        Ok(()),
        resolver.add("LOCALHOST", sign::CertifiedKey::new(kt.get_chain(), signing_key.clone()))
    );

    let mut server_config = make_server_config(kt);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    let mut server1 = ServerConnection::new(Arc::clone(&server_config)).unwrap();
    let mut client1 = ClientConnection::new(Arc::new(make_client_config(kt)), server_name("localhost")).unwrap();
    let err = do_handshake_until_error(&mut client1, &mut server1);
    assert_eq!(err, Ok(()));
}

#[test]
fn sni_resolver_lower_cases_queried_names() {
    // actually, the handshake parser does this, but the effect is the same.
    let kt = KeyType::Rsa;
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
    let signing_key = RsaSigningKey::new(&kt.get_key(), rng_new).unwrap();
    let signing_key: Arc<dyn sign::SigningKey> = Arc::new(signing_key);

    assert_eq!(
        Ok(()),
        resolver.add("localhost", sign::CertifiedKey::new(kt.get_chain(), signing_key.clone()))
    );

    let mut server_config = make_server_config(kt);
    server_config.cert_resolver = Arc::new(resolver);
    let server_config = Arc::new(server_config);

    let mut server1 = ServerConnection::new(Arc::clone(&server_config)).unwrap();
    let mut client1 = ClientConnection::new(Arc::new(make_client_config(kt)), server_name("LOCALHOST")).unwrap();
    let err = do_handshake_until_error(&mut client1, &mut server1);
    assert_eq!(err, Ok(()));
}

#[test]
fn sni_resolver_rejects_bad_certs() {
    let kt = KeyType::Rsa;
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
    let signing_key = RsaSigningKey::new(&kt.get_key(), rng_new).unwrap();
    let signing_key: Arc<dyn sign::SigningKey> = Arc::new(signing_key);

    assert_eq!(
        Err(Error::NoCertificatesPresented),
        resolver.add("localhost", sign::CertifiedKey::new(vec![], signing_key.clone()))
    );

    let bad_chain = vec![CertificateDer::from(vec![0xa0])];
    assert_eq!(
        Err(Error::InvalidCertificate(CertificateError::BadEncoding)),
        resolver.add("localhost", sign::CertifiedKey::new(bad_chain, signing_key.clone()))
    );
}

fn do_exporter_test(client_config: ClientConfig, server_config: ServerConfig) {
    let mut client_secret = [0u8; 64];
    let mut server_secret = [0u8; 64];

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    assert_eq!(
        Err(Error::HandshakeNotComplete),
        client.export_keying_material(&mut client_secret, b"label", Some(b"context"))
    );
    assert_eq!(
        Err(Error::HandshakeNotComplete),
        server.export_keying_material(&mut server_secret, b"label", Some(b"context"))
    );
    do_handshake(&mut client, &mut server);

    assert!(client
        .export_keying_material(&mut client_secret, b"label", Some(b"context"))
        .is_ok());
    assert!(server
        .export_keying_material(&mut server_secret, b"label", Some(b"context"))
        .is_ok());
    assert_eq!(client_secret.to_vec(), server_secret.to_vec());

    assert!(client
        .export_keying_material(&mut client_secret, b"label", None)
        .is_ok());
    assert_ne!(client_secret.to_vec(), server_secret.to_vec());
    assert!(server
        .export_keying_material(&mut server_secret, b"label", None)
        .is_ok());
    assert_eq!(client_secret.to_vec(), server_secret.to_vec());
}

#[cfg(feature = "tls12")]
#[test]
fn test_tls12_exporter() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_config = make_client_config_with_versions(*kt, &[&rustls::version::TLS12]);
        let server_config = make_server_config(*kt);

        do_exporter_test(client_config, server_config);
    }
}

#[test]
fn test_tls13_exporter() {
    for kt in ALL_KEY_TYPES.iter() {
        let client_config = make_client_config_with_versions(*kt, &[&rustls::version::TLS13]);
        let server_config = make_server_config(*kt);

        do_exporter_test(client_config, server_config);
    }
}

#[test]
fn test_tls13_exporter_maximum_output_length() {
    let client_config = make_client_config_with_versions(KeyType::Ecdsa, &[&rustls::version::TLS13]);
    let server_config = make_server_config(KeyType::Ecdsa);

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    do_handshake(&mut client, &mut server);

    assert_eq!(
        client.negotiated_cipher_suite(),
        Some(find_suite(CipherSuite::TLS13_AES_256_GCM_SHA384))
    );

    let mut maximum_allowed_output_client = [0u8; 255 * 48];
    let mut maximum_allowed_output_server = [0u8; 255 * 48];
    client
        .export_keying_material(&mut maximum_allowed_output_client, b"label", Some(b"context"))
        .unwrap();
    server
        .export_keying_material(&mut maximum_allowed_output_server, b"label", Some(b"context"))
        .unwrap();

    assert_eq!(maximum_allowed_output_client, maximum_allowed_output_server);

    let mut too_long_output = [0u8; 255 * 48 + 1];
    assert_eq!(
        client
            .export_keying_material(&mut too_long_output, b"label", Some(b"context"),)
            .err(),
        Some(Error::General("exporting too much".into()))
    );
    assert_eq!(
        server
            .export_keying_material(&mut too_long_output, b"label", Some(b"context"),)
            .err(),
        Some(Error::General("exporting too much".into()))
    );
}

fn do_suite_test(
    client_config: ClientConfig,
    server_config: ServerConfig,
    expect_suite: SupportedCipherSuite,
    expect_version: ProtocolVersion,
) {
    println!("do_suite_test {:?} {:?}", expect_version, expect_suite.suite());
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    assert_eq!(None, client.negotiated_cipher_suite());
    assert_eq!(None, server.negotiated_cipher_suite());
    assert_eq!(None, client.protocol_version());
    assert_eq!(None, server.protocol_version());
    assert!(client.is_handshaking());
    assert!(server.is_handshaking());

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    assert!(client.is_handshaking());
    assert!(server.is_handshaking());
    assert_eq!(None, client.protocol_version());
    assert_eq!(Some(expect_version), server.protocol_version());
    assert_eq!(None, client.negotiated_cipher_suite());
    assert_eq!(Some(expect_suite), server.negotiated_cipher_suite());

    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    assert_eq!(Some(expect_suite), client.negotiated_cipher_suite());
    assert_eq!(Some(expect_suite), server.negotiated_cipher_suite());

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    assert!(!client.is_handshaking());
    assert!(!server.is_handshaking());
    assert_eq!(Some(expect_version), client.protocol_version());
    assert_eq!(Some(expect_version), server.protocol_version());
    assert_eq!(Some(expect_suite), client.negotiated_cipher_suite());
    assert_eq!(Some(expect_suite), server.negotiated_cipher_suite());
}

fn find_suite(suite: CipherSuite) -> SupportedCipherSuite {
    for scs in primary_provider::ALL_CIPHER_SUITES
        .iter()
        .copied()
    {
        if scs.suite() == suite {
            return scs;
        }
    }

    panic!("find_suite given unsupported suite");
}

static TEST_CIPHERSUITES: &[(&rustls::SupportedProtocolVersion, KeyType, CipherSuite)] = &[
    (
        &rustls::version::TLS13,
        KeyType::Rsa,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    ),
    (&rustls::version::TLS13, KeyType::Rsa, CipherSuite::TLS13_AES_256_GCM_SHA384),
    (&rustls::version::TLS13, KeyType::Rsa, CipherSuite::TLS13_AES_128_GCM_SHA256),
    #[cfg(feature = "tls12")]
    (
        &rustls::version::TLS12,
        KeyType::Ecdsa,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    ),
    #[cfg(feature = "tls12")]
    (
        &rustls::version::TLS12,
        KeyType::Rsa,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ),
    #[cfg(feature = "tls12")]
    (
        &rustls::version::TLS12,
        KeyType::Ecdsa,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    ),
    #[cfg(feature = "tls12")]
    (
        &rustls::version::TLS12,
        KeyType::Ecdsa,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    ),
    #[cfg(feature = "tls12")]
    (
        &rustls::version::TLS12,
        KeyType::Rsa,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    ),
    #[cfg(feature = "tls12")]
    (
        &rustls::version::TLS12,
        KeyType::Rsa,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ),
    #[cfg(feature = "tls12")]
    (
        &rustls::version::TLS12,
        KeyType::Rsa,
        CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    ),
    #[cfg(feature = "tls12")]
    (
        &rustls::version::TLS12,
        KeyType::Rsa,
        CipherSuite::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
    ),
    #[cfg(feature = "tls12")]
    (
        &rustls::version::TLS12,
        KeyType::Rsa,
        CipherSuite::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ),
];

#[test]
fn negotiated_ciphersuite_default() {
    for kt in ALL_KEY_TYPES.iter() {
        do_suite_test(
            make_client_config(*kt),
            make_server_config(*kt),
            find_suite(CipherSuite::TLS13_AES_256_GCM_SHA384),
            ProtocolVersion::TLSv1_3,
        );
    }
}

#[test]
fn all_suites_covered() {
    assert_eq!(primary_provider::ALL_CIPHER_SUITES.len(), TEST_CIPHERSUITES.len());
}

#[test]
fn negotiated_ciphersuite_client() {
    for item in TEST_CIPHERSUITES.iter() {
        let (version, kt, suite) = *item;
        let scs = find_suite(suite);
        let client_config = finish_client_config(
            kt,
            ClientConfig::builder_with_provider(
                CryptoProvider { cipher_suites: vec![scs], ..mbedtls_crypto_provider() }.into(),
            )
            .with_protocol_versions(&[version])
            .unwrap(),
        );

        do_suite_test(client_config, make_server_config(kt), scs, version.version);
    }
}

#[test]
fn negotiated_ciphersuite_server() {
    for item in TEST_CIPHERSUITES.iter() {
        let (version, kt, suite) = *item;
        let scs = find_suite(suite);
        let server_config = finish_server_config(
            kt,
            ServerConfig::builder_with_provider(
                CryptoProvider { cipher_suites: vec![scs], ..mbedtls_crypto_provider() }.into(),
            )
            .with_protocol_versions(&[version])
            .unwrap(),
        );

        do_suite_test(make_client_config(kt), server_config, scs, version.version);
    }
}

#[derive(Debug, PartialEq)]
struct KeyLogItem {
    label: String,
    client_random: Vec<u8>,
    secret: Vec<u8>,
}

#[derive(Debug)]
struct KeyLogToVec {
    label: &'static str,
    items: Mutex<Vec<KeyLogItem>>,
}

impl KeyLogToVec {
    fn new(who: &'static str) -> Self {
        Self { label: who, items: Mutex::new(vec![]) }
    }

    fn take(&self) -> Vec<KeyLogItem> {
        std::mem::take(&mut self.items.lock().unwrap())
    }
}

impl KeyLog for KeyLogToVec {
    fn log(&self, label: &str, client: &[u8], secret: &[u8]) {
        let value = KeyLogItem { label: label.into(), client_random: client.into(), secret: secret.into() };

        println!("key log {:?}: {:?}", self.label, value);

        self.items.lock().unwrap().push(value);
    }
}

#[cfg(feature = "tls12")]
#[test]
fn key_log_for_tls12() {
    let client_key_log = Arc::new(KeyLogToVec::new("client"));
    let server_key_log = Arc::new(KeyLogToVec::new("server"));

    let kt = KeyType::Rsa;
    let mut client_config = make_client_config_with_versions(kt, &[&rustls::version::TLS12]);
    client_config.key_log = client_key_log.clone();
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt);
    server_config.key_log = server_key_log.clone();
    let server_config = Arc::new(server_config);

    // full handshake
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let client_full_log = client_key_log.take();
    let server_full_log = server_key_log.take();
    assert_eq!(client_full_log, server_full_log);
    assert_eq!(1, client_full_log.len());
    assert_eq!("CLIENT_RANDOM", client_full_log[0].label);

    // resumed
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let client_resume_log = client_key_log.take();
    let server_resume_log = server_key_log.take();
    assert_eq!(client_resume_log, server_resume_log);
    assert_eq!(1, client_resume_log.len());
    assert_eq!("CLIENT_RANDOM", client_resume_log[0].label);
    assert_eq!(client_full_log[0].secret, client_resume_log[0].secret);
}

#[test]
fn key_log_for_tls13() {
    let client_key_log = Arc::new(KeyLogToVec::new("client"));
    let server_key_log = Arc::new(KeyLogToVec::new("server"));

    let kt = KeyType::Rsa;
    let mut client_config = make_client_config_with_versions(kt, &[&rustls::version::TLS13]);
    client_config.key_log = client_key_log.clone();
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt);
    server_config.key_log = server_key_log.clone();
    let server_config = Arc::new(server_config);

    // full handshake
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let client_full_log = client_key_log.take();
    let server_full_log = server_key_log.take();

    assert_eq!(5, client_full_log.len());
    assert_eq!("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_full_log[0].label);
    assert_eq!("SERVER_HANDSHAKE_TRAFFIC_SECRET", client_full_log[1].label);
    assert_eq!("CLIENT_TRAFFIC_SECRET_0", client_full_log[2].label);
    assert_eq!("SERVER_TRAFFIC_SECRET_0", client_full_log[3].label);
    assert_eq!("EXPORTER_SECRET", client_full_log[4].label);

    assert_eq!(client_full_log[0], server_full_log[0]);
    assert_eq!(client_full_log[1], server_full_log[1]);
    assert_eq!(client_full_log[2], server_full_log[2]);
    assert_eq!(client_full_log[3], server_full_log[3]);
    assert_eq!(client_full_log[4], server_full_log[4]);

    // resumed
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let client_resume_log = client_key_log.take();
    let server_resume_log = server_key_log.take();

    assert_eq!(5, client_resume_log.len());
    assert_eq!("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_resume_log[0].label);
    assert_eq!("SERVER_HANDSHAKE_TRAFFIC_SECRET", client_resume_log[1].label);
    assert_eq!("CLIENT_TRAFFIC_SECRET_0", client_resume_log[2].label);
    assert_eq!("SERVER_TRAFFIC_SECRET_0", client_resume_log[3].label);
    assert_eq!("EXPORTER_SECRET", client_resume_log[4].label);

    assert_eq!(6, server_resume_log.len());
    assert_eq!("CLIENT_EARLY_TRAFFIC_SECRET", server_resume_log[0].label);
    assert_eq!("CLIENT_HANDSHAKE_TRAFFIC_SECRET", server_resume_log[1].label);
    assert_eq!("SERVER_HANDSHAKE_TRAFFIC_SECRET", server_resume_log[2].label);
    assert_eq!("CLIENT_TRAFFIC_SECRET_0", server_resume_log[3].label);
    assert_eq!("SERVER_TRAFFIC_SECRET_0", server_resume_log[4].label);
    assert_eq!("EXPORTER_SECRET", server_resume_log[5].label);

    assert_eq!(client_resume_log[0], server_resume_log[1]);
    assert_eq!(client_resume_log[1], server_resume_log[2]);
    assert_eq!(client_resume_log[2], server_resume_log[3]);
    assert_eq!(client_resume_log[3], server_resume_log[4]);
    assert_eq!(client_resume_log[4], server_resume_log[5]);
}

#[test]
fn vectored_write_for_server_appdata() {
    let (mut client, mut server) = make_pair(KeyType::Rsa);
    do_handshake(&mut client, &mut server);

    server
        .writer()
        .write_all(b"01234567890123456789")
        .unwrap();
    server
        .writer()
        .write_all(b"01234567890123456789")
        .unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        assert_eq!(84, wrlen);
        assert_eq!(pipe.writevs, vec![vec![42, 42]]);
    }
    check_read(&mut client.reader(), b"0123456789012345678901234567890123456789");
}

#[test]
fn vectored_write_for_client_appdata() {
    let (mut client, mut server) = make_pair(KeyType::Rsa);
    do_handshake(&mut client, &mut server);

    client
        .writer()
        .write_all(b"01234567890123456789")
        .unwrap();
    client
        .writer()
        .write_all(b"01234567890123456789")
        .unwrap();
    {
        let mut pipe = OtherSession::new(&mut server);
        let wrlen = client.write_tls(&mut pipe).unwrap();
        assert_eq!(84, wrlen);
        assert_eq!(pipe.writevs, vec![vec![42, 42]]);
    }
    check_read(&mut server.reader(), b"0123456789012345678901234567890123456789");
}

#[test]
fn vectored_write_for_server_handshake_with_half_rtt_data() {
    let mut server_config = make_server_config(KeyType::Rsa);
    server_config.send_half_rtt_data = true;
    let (mut client, mut server) = make_pair_for_configs(make_client_config_with_auth(KeyType::Rsa), server_config);

    server
        .writer()
        .write_all(b"01234567890123456789")
        .unwrap();
    server
        .writer()
        .write_all(b"0123456789")
        .unwrap();

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        // don't assert exact sizes here, to avoid a brittle test
        assert!(wrlen > 4000); // its pretty big (contains cert chain)
        assert_eq!(pipe.writevs.len(), 1); // only one writev
        assert_eq!(pipe.writevs[0].len(), 8); // at least a server hello/ccs/cert/serverkx/0.5rtt data
    }

    client.process_new_packets().unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        // 4 tickets
        assert_eq!(wrlen, 103 * 4);
        assert_eq!(pipe.writevs, vec![vec![103, 103, 103, 103]]);
    }

    assert!(!server.is_handshaking());
    assert!(!client.is_handshaking());
    check_read(&mut client.reader(), b"012345678901234567890123456789");
}

fn check_half_rtt_does_not_work(server_config: ServerConfig) {
    let (mut client, mut server) = make_pair_for_configs(make_client_config_with_auth(KeyType::Rsa), server_config);

    server
        .writer()
        .write_all(b"01234567890123456789")
        .unwrap();
    server
        .writer()
        .write_all(b"0123456789")
        .unwrap();

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        // don't assert exact sizes here, to avoid a brittle test
        assert!(wrlen > 4000); // its pretty big (contains cert chain)
        assert_eq!(pipe.writevs.len(), 1); // only one writev
        assert!(pipe.writevs[0].len() >= 6); // at least a server hello/ccs/cert/serverkx data
    }

    // client second flight
    client.process_new_packets().unwrap();
    transfer(&mut client, &mut server);

    // when client auth is enabled, we don't sent 0.5-rtt data, as we'd be sending
    // it to an unauthenticated peer. so it happens here, in the server's second
    // flight (42 and 32 are lengths of appdata sent above).
    server.process_new_packets().unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        assert_eq!(wrlen, 486);
        assert_eq!(pipe.writevs, vec![vec![103, 103, 103, 103, 42, 32]]);
    }

    assert!(!server.is_handshaking());
    assert!(!client.is_handshaking());
    check_read(&mut client.reader(), b"012345678901234567890123456789");
}

#[test]
fn vectored_write_for_server_handshake_no_half_rtt_with_client_auth() {
    let mut server_config = make_server_config_with_mandatory_client_auth(KeyType::Rsa);
    server_config.send_half_rtt_data = true; // ask even though it will be ignored
    check_half_rtt_does_not_work(server_config);
}

#[test]
fn vectored_write_for_server_handshake_no_half_rtt_by_default() {
    let server_config = make_server_config(KeyType::Rsa);
    assert!(!server_config.send_half_rtt_data);
    check_half_rtt_does_not_work(server_config);
}

#[test]
fn vectored_write_for_client_handshake() {
    let (mut client, mut server) = make_pair(KeyType::Rsa);

    client
        .writer()
        .write_all(b"01234567890123456789")
        .unwrap();
    client
        .writer()
        .write_all(b"0123456789")
        .unwrap();
    {
        let mut pipe = OtherSession::new(&mut server);
        let wrlen = client.write_tls(&mut pipe).unwrap();
        // don't assert exact sizes here, to avoid a brittle test
        assert!(wrlen > 200); // just the client hello
        assert_eq!(pipe.writevs.len(), 1); // only one writev
        assert!(pipe.writevs[0].len() == 1); // only a client hello
    }

    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    {
        let mut pipe = OtherSession::new(&mut server);
        let wrlen = client.write_tls(&mut pipe).unwrap();
        assert_eq!(wrlen, 154);
        // CCS, finished, then two application datas
        assert_eq!(pipe.writevs, vec![vec![6, 74, 42, 32]]);
    }

    assert!(!server.is_handshaking());
    assert!(!client.is_handshaking());
    check_read(&mut server.reader(), b"012345678901234567890123456789");
}

#[test]
fn vectored_write_with_slow_client() {
    let (mut client, mut server) = make_pair(KeyType::Rsa);

    client.set_buffer_limit(Some(32));

    do_handshake(&mut client, &mut server);
    server
        .writer()
        .write_all(b"01234567890123456789")
        .unwrap();

    {
        let mut pipe = OtherSession::new(&mut client);
        pipe.short_writes = true;
        let wrlen = server.write_tls(&mut pipe).unwrap()
            + server.write_tls(&mut pipe).unwrap()
            + server.write_tls(&mut pipe).unwrap()
            + server.write_tls(&mut pipe).unwrap()
            + server.write_tls(&mut pipe).unwrap()
            + server.write_tls(&mut pipe).unwrap();
        assert_eq!(42, wrlen);
        assert_eq!(pipe.writevs, vec![vec![21], vec![10], vec![5], vec![3], vec![3]]);
    }
    check_read(&mut client.reader(), b"01234567890123456789");
}

struct ServerStorage {
    storage: Arc<dyn rustls::server::StoresServerSessions>,
    put_count: AtomicUsize,
    get_count: AtomicUsize,
    take_count: AtomicUsize,
}

impl ServerStorage {
    fn new() -> Self {
        Self {
            storage: rustls::server::ServerSessionMemoryCache::new(1024),
            put_count: AtomicUsize::new(0),
            get_count: AtomicUsize::new(0),
            take_count: AtomicUsize::new(0),
        }
    }

    fn puts(&self) -> usize {
        self.put_count.load(Ordering::SeqCst)
    }
    fn gets(&self) -> usize {
        self.get_count.load(Ordering::SeqCst)
    }
    fn takes(&self) -> usize {
        self.take_count.load(Ordering::SeqCst)
    }
}

impl fmt::Debug for ServerStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(put: {:?}, get: {:?}, take: {:?})",
            self.put_count, self.get_count, self.take_count
        )
    }
}

impl rustls::server::StoresServerSessions for ServerStorage {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.put_count
            .fetch_add(1, Ordering::SeqCst);
        self.storage.put(key, value)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get_count
            .fetch_add(1, Ordering::SeqCst);
        self.storage.get(key)
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.take_count
            .fetch_add(1, Ordering::SeqCst);
        self.storage.take(key)
    }

    fn can_cache(&self) -> bool {
        true
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
enum ClientStorageOp {
    SetKxHint(ServerName<'static>, rustls::NamedGroup),
    GetKxHint(ServerName<'static>, Option<rustls::NamedGroup>),
    SetTls12Session(ServerName<'static>),
    GetTls12Session(ServerName<'static>, bool),
    RemoveTls12Session(ServerName<'static>),
    InsertTls13Ticket(ServerName<'static>),
    TakeTls13Ticket(ServerName<'static>, bool),
}

struct ClientStorage {
    storage: Arc<dyn rustls::client::ClientSessionStore>,
    ops: Mutex<Vec<ClientStorageOp>>,
}

impl ClientStorage {
    fn new() -> Self {
        Self {
            storage: Arc::new(rustls::client::ClientSessionMemoryCache::new(1024)),
            ops: Mutex::new(Vec::new()),
        }
    }

    #[cfg(feature = "tls12")]
    fn ops(&self) -> Vec<ClientStorageOp> {
        self.ops.lock().unwrap().clone()
    }

    #[cfg(feature = "tls12")]
    fn ops_and_reset(&self) -> Vec<ClientStorageOp> {
        std::mem::take(&mut self.ops.lock().unwrap())
    }
}

impl fmt::Debug for ClientStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(ops: {:?})", self.ops.lock().unwrap())
    }
}

impl rustls::client::ClientSessionStore for ClientStorage {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: rustls::NamedGroup) {
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::SetKxHint(server_name.clone(), group));
        self.storage
            .set_kx_hint(server_name, group)
    }

    fn kx_hint(&self, server_name: &ServerName) -> Option<rustls::NamedGroup> {
        let rc = self.storage.kx_hint(server_name);
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::GetKxHint(server_name.to_owned(), rc));
        rc
    }

    fn set_tls12_session(&self, server_name: ServerName<'static>, value: rustls::client::Tls12ClientSessionValue) {
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::SetTls12Session(server_name.clone()));
        self.storage
            .set_tls12_session(server_name, value)
    }

    fn tls12_session(&self, server_name: &ServerName) -> Option<rustls::client::Tls12ClientSessionValue> {
        let rc = self.storage.tls12_session(server_name);
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::GetTls12Session(server_name.to_owned(), rc.is_some()));
        rc
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::RemoveTls12Session(server_name.clone()));
        self.storage
            .remove_tls12_session(server_name);
    }

    fn insert_tls13_ticket(&self, server_name: ServerName<'static>, value: rustls::client::Tls13ClientSessionValue) {
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::InsertTls13Ticket(server_name.clone()));
        self.storage
            .insert_tls13_ticket(server_name, value);
    }

    fn take_tls13_ticket(&self, server_name: &ServerName<'static>) -> Option<rustls::client::Tls13ClientSessionValue> {
        let rc = self
            .storage
            .take_tls13_ticket(server_name);
        self.ops
            .lock()
            .unwrap()
            .push(ClientStorageOp::TakeTls13Ticket(server_name.clone(), rc.is_some()));
        rc
    }
}

#[test]
fn tls13_stateful_resumption() {
    let kt = KeyType::Rsa;
    let client_config = make_client_config_with_versions(kt, &[&rustls::version::TLS13]);
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt);
    let storage = Arc::new(ServerStorage::new());
    server_config.session_storage = storage.clone();
    let server_config = Arc::new(server_config);

    // full handshake
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    let (full_c2s, full_s2c) = do_handshake(&mut client, &mut server);
    assert_eq!(storage.puts(), 4);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 0);
    assert_eq!(
        client
            .peer_certificates()
            .map(|certs| certs.len()),
        Some(3)
    );

    // resumed
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    let (resume_c2s, resume_s2c) = do_handshake(&mut client, &mut server);
    assert!(resume_c2s > full_c2s);
    assert!(resume_s2c < full_s2c);
    assert_eq!(storage.puts(), 8);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 1);
    assert_eq!(
        client
            .peer_certificates()
            .map(|certs| certs.len()),
        Some(3)
    );

    // resumed again
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    let (resume2_c2s, resume2_s2c) = do_handshake(&mut client, &mut server);
    assert_eq!(resume_s2c, resume2_s2c);
    assert_eq!(resume_c2s, resume2_c2s);
    assert_eq!(storage.puts(), 12);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 2);
    assert_eq!(
        client
            .peer_certificates()
            .map(|certs| certs.len()),
        Some(3)
    );
}

#[test]
fn tls13_stateless_resumption() {
    let kt = KeyType::Rsa;
    let client_config = make_client_config_with_versions(kt, &[&rustls::version::TLS13]);
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(kt);
    // TODO: add mbedtls based Ticketer
    server_config.ticketer = rustls::crypto::ring::Ticketer::new().unwrap();
    let storage = Arc::new(ServerStorage::new());
    server_config.session_storage = storage.clone();
    let server_config = Arc::new(server_config);

    // full handshake
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    let (full_c2s, full_s2c) = do_handshake(&mut client, &mut server);
    assert_eq!(storage.puts(), 0);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 0);
    assert_eq!(
        client
            .peer_certificates()
            .map(|certs| certs.len()),
        Some(3)
    );

    // resumed
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    let (resume_c2s, resume_s2c) = do_handshake(&mut client, &mut server);
    assert!(resume_c2s > full_c2s);
    assert!(resume_s2c < full_s2c);
    assert_eq!(storage.puts(), 0);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 0);
    assert_eq!(
        client
            .peer_certificates()
            .map(|certs| certs.len()),
        Some(3)
    );

    // resumed again
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    let (resume2_c2s, resume2_s2c) = do_handshake(&mut client, &mut server);
    assert_eq!(resume_s2c, resume2_s2c);
    assert_eq!(resume_c2s, resume2_c2s);
    assert_eq!(storage.puts(), 0);
    assert_eq!(storage.gets(), 0);
    assert_eq!(storage.takes(), 0);
    assert_eq!(
        client
            .peer_certificates()
            .map(|certs| certs.len()),
        Some(3)
    );
}

#[test]
fn early_data_not_available() {
    let (mut client, _) = make_pair(KeyType::Rsa);
    assert!(client.early_data().is_none());
}

fn early_data_configs() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let kt = KeyType::Rsa;
    let mut client_config = make_client_config(kt);
    client_config.enable_early_data = true;
    client_config.resumption = Resumption::store(Arc::new(ClientStorage::new()));

    let mut server_config = make_server_config(kt);
    server_config.max_early_data_size = 1234;
    (Arc::new(client_config), Arc::new(server_config))
}

#[test]
fn early_data_is_available_on_resumption() {
    let (client_config, server_config) = early_data_configs();

    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    assert!(client.early_data().is_some());
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .bytes_left(),
        1234
    );
    client
        .early_data()
        .unwrap()
        .flush()
        .unwrap();
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .write(b"hello")
            .unwrap(),
        5
    );
    do_handshake(&mut client, &mut server);

    let mut received_early_data = [0u8; 5];
    assert_eq!(
        server
            .early_data()
            .expect("early_data didn't happen")
            .read(&mut received_early_data)
            .expect("early_data failed unexpectedly"),
        5
    );
    assert_eq!(&received_early_data[..], b"hello");
}

#[test]
fn early_data_not_available_on_server_before_client_hello() {
    let mut server = ServerConnection::new(Arc::new(make_server_config(KeyType::Rsa))).unwrap();
    assert!(server.early_data().is_none());
}

#[test]
fn early_data_can_be_rejected_by_server() {
    let (client_config, server_config) = early_data_configs();

    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    assert!(client.early_data().is_some());
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .bytes_left(),
        1234
    );
    client
        .early_data()
        .unwrap()
        .flush()
        .unwrap();
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .write(b"hello")
            .unwrap(),
        5
    );
    server.reject_early_data();
    do_handshake(&mut client, &mut server);

    assert!(!client.is_early_data_accepted());
}

#[test]
fn test_client_does_not_offer_sha1() {
    use rustls::internal::msgs::{
        codec::Reader, handshake::HandshakePayload, message::MessagePayload, message::OutboundOpaqueMessage,
    };
    use rustls::HandshakeType;

    for kt in &ALL_KEY_TYPES {
        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let (mut client, _) = make_pair_for_configs(client_config, make_server_config(*kt));

            assert!(client.wants_write());
            let mut buf = [0u8; 262144];
            let sz = client
                .write_tls(&mut buf.as_mut())
                .unwrap();
            let msg = OutboundOpaqueMessage::read(&mut Reader::init(&buf[..sz])).unwrap();
            let msg = Message::try_from(msg.into_plain_message()).unwrap();
            assert!(msg.is_handshake_type(HandshakeType::ClientHello));

            let client_hello = match msg.payload {
                MessagePayload::Handshake { parsed, .. } => match parsed.payload {
                    HandshakePayload::ClientHello(ch) => ch,
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            };

            let sigalgs = client_hello
                .sigalgs_extension()
                .unwrap();
            assert!(
                !sigalgs.contains(&SignatureScheme::RSA_PKCS1_SHA1),
                "sha1 unexpectedly offered"
            );
        }
    }
}
#[test]
fn test_client_config_keyshare() {
    let client_config = make_client_config_with_kx_groups(KeyType::Rsa, &[primary_provider::kx_group::SECP384R1]);
    let server_config = make_server_config_with_kx_groups(KeyType::Rsa, &[primary_provider::kx_group::SECP384R1]);
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    do_handshake_until_error(&mut client, &mut server).unwrap();
}

#[test]
fn test_client_config_keyshare_mismatch() {
    let client_config = make_client_config_with_kx_groups(KeyType::Rsa, &[primary_provider::kx_group::SECP384R1]);
    let server_config = make_server_config_with_kx_groups(KeyType::Rsa, &[primary_provider::kx_group::X25519]);
    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    assert!(do_handshake_until_error(&mut client, &mut server).is_err());
}

#[cfg(feature = "tls12")]
#[test]
fn test_client_sends_helloretryrequest() {
    // client sends a secp384r1 key share
    let mut client_config = make_client_config_with_kx_groups(
        KeyType::Rsa,
        &[primary_provider::kx_group::SECP384R1, primary_provider::kx_group::X25519],
    );

    let storage = Arc::new(ClientStorage::new());
    client_config.resumption = Resumption::store(storage.clone());

    // but server only accepts x25519, so a HRR is required
    let server_config = make_server_config_with_kx_groups(KeyType::Rsa, &[primary_provider::kx_group::X25519]);

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);

    // client sends hello
    {
        let mut pipe = OtherSession::new(&mut server);
        let wrlen = client.write_tls(&mut pipe).unwrap();
        assert!(wrlen > 200);
        assert_eq!(pipe.writevs.len(), 1);
        assert!(pipe.writevs[0].len() == 1);
    }

    // server sends HRR
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        assert!(wrlen < 100); // just the hello retry request
        assert_eq!(pipe.writevs.len(), 1); // only one writev
        assert!(pipe.writevs[0].len() == 2); // hello retry request and CCS
    }

    // client sends fixed hello
    {
        let mut pipe = OtherSession::new(&mut server);
        let wrlen = client.write_tls(&mut pipe).unwrap();
        assert!(wrlen > 200); // just the client hello retry
        assert_eq!(pipe.writevs.len(), 1); // only one writev
        assert!(pipe.writevs[0].len() == 2); // only a CCS & client hello retry
    }

    // server completes handshake
    {
        let mut pipe = OtherSession::new(&mut client);
        let wrlen = server.write_tls(&mut pipe).unwrap();
        assert!(wrlen > 200);
        assert_eq!(pipe.writevs.len(), 1);
        assert!(pipe.writevs[0].len() == 5); // server hello / encrypted exts / cert / cert-verify / finished
    }

    do_handshake_until_error(&mut client, &mut server).unwrap();

    // client only did following storage queries:
    println!("storage {:#?}", storage.ops());
    assert_eq!(storage.ops().len(), 9);
    assert!(matches!(storage.ops()[0], ClientStorageOp::TakeTls13Ticket(_, false)));
    assert!(matches!(storage.ops()[1], ClientStorageOp::GetTls12Session(_, false)));
    assert!(matches!(storage.ops()[2], ClientStorageOp::GetKxHint(_, None)));
    assert!(matches!(
        storage.ops()[3],
        ClientStorageOp::SetKxHint(_, rustls::NamedGroup::X25519)
    ));
    assert!(matches!(storage.ops()[4], ClientStorageOp::RemoveTls12Session(_)));
    // server sends 4 tickets by default
    assert!(matches!(storage.ops()[5], ClientStorageOp::InsertTls13Ticket(_)));
    assert!(matches!(storage.ops()[6], ClientStorageOp::InsertTls13Ticket(_)));
    assert!(matches!(storage.ops()[7], ClientStorageOp::InsertTls13Ticket(_)));
    assert!(matches!(storage.ops()[8], ClientStorageOp::InsertTls13Ticket(_)));
}

#[test]
fn test_client_rejects_hrr_with_varied_session_id() {
    use rustls::internal::msgs::handshake::SessionId;
    let different_session_id = SessionId::random(&MbedtlsSecureRandom).unwrap();

    let assert_client_sends_hello_with_secp384 = |msg: &mut Message| -> Altered {
        match &mut msg.payload {
            MessagePayload::Handshake { parsed, encoded } => match &mut parsed.payload {
                HandshakePayload::ClientHello(ch) => {
                    let keyshares = ch
                        .keyshare_extension()
                        .expect("missing key share extension");
                    assert_eq!(keyshares.len(), 1);
                    assert_eq!(keyshares[0].group(), rustls::NamedGroup::secp384r1);

                    ch.session_id = different_session_id;
                    *encoded = Payload::new(parsed.get_encoding());
                }
                _ => panic!("unexpected handshake message {parsed:?}"),
            },
            _ => panic!("unexpected non-handshake message {msg:?}"),
        };
        Altered::InPlace
    };

    let assert_server_requests_retry_and_echoes_session_id = |msg: &mut Message| -> Altered {
        match &msg.payload {
            MessagePayload::Handshake { parsed, .. } => match &parsed.payload {
                HandshakePayload::HelloRetryRequest(hrr) => {
                    let group = hrr.requested_key_share_group();
                    assert_eq!(group, Some(rustls::NamedGroup::X25519));

                    assert_eq!(hrr.session_id, different_session_id);
                }
                _ => panic!("unexpected handshake message {parsed:?}"),
            },
            MessagePayload::ChangeCipherSpec(_) => (),
            _ => panic!("unexpected non-handshake message {msg:?}"),
        };
        Altered::InPlace
    };

    // client prefers a secp384r1 key share, server only accepts x25519
    let client_config = make_client_config_with_kx_groups(
        KeyType::Rsa,
        &[primary_provider::kx_group::SECP384R1, primary_provider::kx_group::X25519],
    );

    let server_config = make_server_config_with_kx_groups(KeyType::Rsa, &[primary_provider::kx_group::X25519]);

    let (client, server) = make_pair_for_configs(client_config, server_config);
    let (mut client, mut server) = (client.into(), server.into());
    transfer_altered(&mut client, assert_client_sends_hello_with_secp384, &mut server);
    server.process_new_packets().unwrap();
    transfer_altered(&mut server, assert_server_requests_retry_and_echoes_session_id, &mut client);
    assert_eq!(
        client.process_new_packets(),
        Err(Error::PeerMisbehaved(
            PeerMisbehaved::IllegalHelloRetryRequestWithWrongSessionId
        ))
    );
}

#[cfg(feature = "tls12")]
#[test]
fn test_client_attempts_to_use_unsupported_kx_group() {
    // common to both client configs
    let shared_storage = Arc::new(ClientStorage::new());

    // first, client sends a x25519 and server agrees. x25519 is inserted
    //   into kx group cache.
    let mut client_config_1 = make_client_config_with_kx_groups(KeyType::Rsa, &[primary_provider::kx_group::X25519]);
    client_config_1.resumption = Resumption::store(shared_storage.clone());

    // second, client only supports secp-384 and so kx group cache
    //   contains an unusable value.
    let mut client_config_2 = make_client_config_with_kx_groups(KeyType::Rsa, &[primary_provider::kx_group::SECP384R1]);
    client_config_2.resumption = Resumption::store(shared_storage.clone());

    let server_config = make_server_config(KeyType::Rsa);

    // first handshake
    let (mut client_1, mut server) = make_pair_for_configs(client_config_1, server_config.clone());
    do_handshake_until_error(&mut client_1, &mut server).unwrap();

    let ops = shared_storage.ops();
    println!("storage {ops:#?}");
    assert_eq!(ops.len(), 9);
    assert!(matches!(ops[3], ClientStorageOp::SetKxHint(_, rustls::NamedGroup::X25519)));

    // second handshake
    let (mut client_2, mut server) = make_pair_for_configs(client_config_2, server_config);
    do_handshake_until_error(&mut client_2, &mut server).unwrap();

    let ops = shared_storage.ops();
    println!("storage {:?} {:#?}", ops.len(), ops);
    assert_eq!(ops.len(), 17);
    assert!(matches!(ops[9], ClientStorageOp::TakeTls13Ticket(_, true)));
    assert!(matches!(
        ops[10],
        ClientStorageOp::GetKxHint(_, Some(rustls::NamedGroup::X25519))
    ));
    assert!(matches!(
        ops[11],
        ClientStorageOp::SetKxHint(_, rustls::NamedGroup::secp384r1)
    ));
}

#[cfg(feature = "tls12")]
#[test]
fn test_tls13_client_resumption_does_not_reuse_tickets() {
    let shared_storage = Arc::new(ClientStorage::new());

    let mut client_config = make_client_config(KeyType::Rsa);
    client_config.resumption = Resumption::store(shared_storage.clone());
    let client_config = Arc::new(client_config);

    let mut server_config = make_server_config(KeyType::Rsa);
    server_config.send_tls13_tickets = 5;
    let server_config = Arc::new(server_config);

    // first handshake: client obtains 5 tickets from server.
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake_until_error(&mut client, &mut server).unwrap();

    let ops = shared_storage.ops_and_reset();
    println!("storage {ops:#?}");
    assert_eq!(ops.len(), 10);
    assert!(matches!(ops[5], ClientStorageOp::InsertTls13Ticket(_)));
    assert!(matches!(ops[6], ClientStorageOp::InsertTls13Ticket(_)));
    assert!(matches!(ops[7], ClientStorageOp::InsertTls13Ticket(_)));
    assert!(matches!(ops[8], ClientStorageOp::InsertTls13Ticket(_)));
    assert!(matches!(ops[9], ClientStorageOp::InsertTls13Ticket(_)));

    // 5 subsequent handshakes: all are resumptions

    // Note: we don't do complete the handshakes, because that means
    // we get five additional tickets per connection which is unhelpful
    // in this test.  It also acts to record a "Happy Eyeballs"-type use
    // case, where a client speculatively makes many connection attempts
    // in parallel without knowledge of which will work due to underlying
    // connectivity uncertainty.
    for _ in 0..5 {
        let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
        transfer(&mut client, &mut server);
        server.process_new_packets().unwrap();

        let ops = shared_storage.ops_and_reset();
        assert!(matches!(ops[0], ClientStorageOp::TakeTls13Ticket(_, true)));
    }

    // 6th subsequent handshake: cannot be resumed; we ran out of tickets
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    let ops = shared_storage.ops_and_reset();
    println!("last {ops:?}");
    assert!(matches!(ops[0], ClientStorageOp::TakeTls13Ticket(_, false)));
}

#[test]
fn test_client_mtu_reduction() {
    struct CollectWrites {
        writevs: Vec<Vec<usize>>,
    }

    impl io::Write for CollectWrites {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!()
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!()
        }
        fn write_vectored(&mut self, b: &[io::IoSlice<'_>]) -> io::Result<usize> {
            let writes = b
                .iter()
                .map(|slice| slice.len())
                .collect::<Vec<usize>>();
            let len = writes.iter().sum();
            self.writevs.push(writes);
            Ok(len)
        }
    }

    fn collect_write_lengths(client: &mut ClientConnection) -> Vec<usize> {
        let mut collector = CollectWrites { writevs: vec![] };

        client
            .write_tls(&mut collector)
            .unwrap();
        assert_eq!(collector.writevs.len(), 1);
        collector.writevs[0].clone()
    }

    for kt in ALL_KEY_TYPES.iter() {
        let mut client_config = make_client_config(*kt);
        client_config.max_fragment_size = Some(64);
        let mut client = ClientConnection::new(Arc::new(client_config), server_name("localhost")).unwrap();
        let writes = collect_write_lengths(&mut client);
        println!("writes at mtu=64: {writes:?}");
        assert!(writes.iter().all(|x| *x <= 64));
        assert!(writes.len() > 1);
    }
}

#[test]
fn test_server_mtu_reduction() {
    let mut server_config = make_server_config(KeyType::Rsa);
    server_config.max_fragment_size = Some(64);
    server_config.send_half_rtt_data = true;
    let (mut client, mut server) = make_pair_for_configs(make_client_config(KeyType::Rsa), server_config);

    let big_data = [0u8; 2048];
    server
        .writer()
        .write_all(&big_data)
        .unwrap();

    let encryption_overhead = 20; // FIXME: see issue #991

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        server.write_tls(&mut pipe).unwrap();

        assert_eq!(pipe.writevs.len(), 1);
        assert!(pipe.writevs[0]
            .iter()
            .all(|x| *x <= 64 + encryption_overhead));
    }

    client.process_new_packets().unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    {
        let mut pipe = OtherSession::new(&mut client);
        server.write_tls(&mut pipe).unwrap();
        assert_eq!(pipe.writevs.len(), 1);
        assert!(pipe.writevs[0]
            .iter()
            .all(|x| *x <= 64 + encryption_overhead));
    }

    client.process_new_packets().unwrap();
    check_read(&mut client.reader(), &big_data);
}

fn check_client_max_fragment_size(size: usize) -> Option<Error> {
    let mut client_config = make_client_config(KeyType::Rsa);
    client_config.max_fragment_size = Some(size);
    ClientConnection::new(Arc::new(client_config), server_name("localhost")).err()
}

#[test]
fn bad_client_max_fragment_sizes() {
    assert_eq!(check_client_max_fragment_size(31), Some(Error::BadMaxFragmentSize));
    assert_eq!(check_client_max_fragment_size(32), None);
    assert_eq!(check_client_max_fragment_size(64), None);
    assert_eq!(check_client_max_fragment_size(1460), None);
    assert_eq!(check_client_max_fragment_size(0x4000), None);
    assert_eq!(check_client_max_fragment_size(0x4005), None);
    assert_eq!(check_client_max_fragment_size(0x4006), Some(Error::BadMaxFragmentSize));
    assert_eq!(check_client_max_fragment_size(0xffff), Some(Error::BadMaxFragmentSize));
}

#[test]
fn handshakes_complete_and_data_flows_with_gratuitious_max_fragment_sizes() {
    // general exercising of msgs::fragmenter and msgs::deframer
    for kt in ALL_KEY_TYPES.iter() {
        for version in rustls::ALL_VERSIONS {
            // no hidden significance to these numbers
            for frag_size in [37, 61, 101, 257] {
                println!("test kt={kt:?} version={version:?} frag={frag_size:?}");
                let mut client_config = make_client_config_with_versions(*kt, &[version]);
                client_config.max_fragment_size = Some(frag_size);
                let mut server_config = make_server_config(*kt);
                server_config.max_fragment_size = Some(frag_size);

                let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
                do_handshake(&mut client, &mut server);

                // check server -> client data flow
                let pattern = (0x00..=0xffu8).collect::<Vec<u8>>();
                assert_eq!(pattern.len(), server.writer().write(&pattern).unwrap());
                transfer(&mut server, &mut client);
                client.process_new_packets().unwrap();
                check_read(&mut client.reader(), &pattern);

                // and client -> server
                assert_eq!(pattern.len(), client.writer().write(&pattern).unwrap());
                transfer(&mut client, &mut server);
                server.process_new_packets().unwrap();
                check_read(&mut server.reader(), &pattern);
            }
        }
    }
}

fn assert_lt(left: usize, right: usize) {
    if left >= right {
        panic!("expected {left} < {right}");
    }
}

#[test]
fn connection_types_are_not_huge() {
    // Arbitrary sizes
    assert_lt(mem::size_of::<ServerConnection>(), 1600);
    assert_lt(mem::size_of::<ClientConnection>(), 1600);
}

#[test]
fn test_server_rejects_duplicate_sni_names() {
    fn duplicate_sni_payload(msg: &mut Message) -> Altered {
        if let MessagePayload::Handshake { parsed, encoded } = &mut msg.payload {
            if let HandshakePayload::ClientHello(ch) = &mut parsed.payload {
                for mut ext in ch.extensions.iter_mut() {
                    if let ClientExtension::ServerName(snr) = &mut ext {
                        snr.push(snr[0].clone());
                    }
                }
            }

            *encoded = Payload::new(parsed.get_encoding());
        }
        Altered::InPlace
    }

    let (client, server) = make_pair(KeyType::Rsa);
    let (mut client, mut server) = (client.into(), server.into());
    transfer_altered(&mut client, duplicate_sni_payload, &mut server);
    assert_eq!(
        server.process_new_packets(),
        Err(Error::PeerMisbehaved(PeerMisbehaved::DuplicateServerNameTypes))
    );
}

#[test]
fn test_server_rejects_empty_sni_extension() {
    fn empty_sni_payload(msg: &mut Message) -> Altered {
        if let MessagePayload::Handshake { parsed, encoded } = &mut msg.payload {
            if let HandshakePayload::ClientHello(ch) = &mut parsed.payload {
                for mut ext in ch.extensions.iter_mut() {
                    if let ClientExtension::ServerName(snr) = &mut ext {
                        snr.clear();
                    }
                }
            }

            *encoded = Payload::new(parsed.get_encoding());
        }

        Altered::InPlace
    }

    let (client, server) = make_pair(KeyType::Rsa);
    let (mut client, mut server) = (client.into(), server.into());
    transfer_altered(&mut client, empty_sni_payload, &mut server);
    assert_eq!(
        server.process_new_packets(),
        Err(Error::PeerMisbehaved(PeerMisbehaved::ServerNameMustContainOneHostName))
    );
}

#[test]
fn test_server_rejects_clients_without_any_kx_group_overlap() {
    fn different_kx_group(msg: &mut Message) -> Altered {
        if let MessagePayload::Handshake { parsed, encoded } = &mut msg.payload {
            if let HandshakePayload::ClientHello(ch) = &mut parsed.payload {
                for mut ext in ch.extensions.iter_mut() {
                    if let ClientExtension::NamedGroups(ngs) = &mut ext {
                        ngs.clear();
                    }
                    if let ClientExtension::KeyShare(ks) = &mut ext {
                        ks.clear();
                    }
                }
            }

            *encoded = Payload::new(parsed.get_encoding());
        }
        Altered::InPlace
    }

    let (client, server) = make_pair(KeyType::Rsa);
    let (mut client, mut server) = (client.into(), server.into());
    transfer_altered(&mut client, different_kx_group, &mut server);
    assert_eq!(
        server.process_new_packets(),
        Err(Error::PeerIncompatible(PeerIncompatible::NoKxGroupsInCommon))
    );
}

#[test]
fn test_client_rejects_illegal_tls13_ccs() {
    fn corrupt_ccs(msg: &mut Message) -> Altered {
        if let MessagePayload::ChangeCipherSpec(_) = &mut msg.payload {
            println!("seen CCS {msg:?}");
            return Altered::Raw(vec![0x14, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02]);
        }
        Altered::InPlace
    }

    let (mut client, mut server) = make_pair(KeyType::Rsa);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    let (mut server, mut client) = (server.into(), client.into());

    transfer_altered(&mut server, corrupt_ccs, &mut client);
    assert_eq!(
        client.process_new_packets(),
        Err(Error::PeerMisbehaved(PeerMisbehaved::IllegalMiddleboxChangeCipherSpec))
    );
}

/// https://github.com/rustls/rustls/issues/797
#[cfg(feature = "tls12")]
#[test]
fn test_client_tls12_no_resume_after_server_downgrade() {
    let mut client_config = common::make_client_config(KeyType::Rsa);
    let client_storage = Arc::new(ClientStorage::new());
    client_config.resumption = Resumption::store(client_storage.clone());
    let client_config = Arc::new(client_config);

    let server_config_1 = Arc::new(common::finish_server_config(
        KeyType::Rsa,
        server_config_builder()
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap(),
    ));

    let mut server_config_2 = common::finish_server_config(
        KeyType::Rsa,
        server_config_builder()
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap(),
    );
    server_config_2.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});

    dbg!("handshake 1");
    let mut client_1 = ClientConnection::new(client_config.clone(), "localhost".try_into().unwrap()).unwrap();
    let mut server_1 = ServerConnection::new(server_config_1).unwrap();
    common::do_handshake(&mut client_1, &mut server_1);

    assert_eq!(client_storage.ops().len(), 9);
    println!("hs1 storage ops: {:#?}", client_storage.ops());
    assert!(matches!(client_storage.ops()[3], ClientStorageOp::SetKxHint(_, _)));
    assert!(matches!(client_storage.ops()[4], ClientStorageOp::RemoveTls12Session(_)));
    assert!(matches!(client_storage.ops()[5], ClientStorageOp::InsertTls13Ticket(_)));

    dbg!("handshake 2");
    let mut client_2 = ClientConnection::new(client_config, "localhost".try_into().unwrap()).unwrap();
    let mut server_2 = ServerConnection::new(Arc::new(server_config_2)).unwrap();
    common::do_handshake(&mut client_2, &mut server_2);
    println!("hs2 storage ops: {:#?}", client_storage.ops());
    assert_eq!(client_storage.ops().len(), 11);

    // attempt consumes a TLS1.3 ticket
    assert!(matches!(client_storage.ops()[9], ClientStorageOp::TakeTls13Ticket(_, true)));

    // but ends up with TLS1.2
    assert_eq!(client_2.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_2));
}

#[test]
fn test_acceptor() {
    use rustls::server::Acceptor;

    let client_config = Arc::new(make_client_config(KeyType::Rsa));
    let mut client = ClientConnection::new(client_config, server_name("localhost")).unwrap();
    let mut buf = Vec::new();
    client.write_tls(&mut buf).unwrap();

    let server_config = Arc::new(make_server_config(KeyType::Rsa));
    let mut acceptor = Acceptor::default();
    acceptor
        .read_tls(&mut buf.as_slice())
        .unwrap();
    let accepted = acceptor.accept().unwrap().unwrap();
    let ch = accepted.client_hello();
    assert_eq!(ch.server_name(), Some("localhost"));

    let server = accepted
        .into_connection(server_config)
        .unwrap();
    assert!(server.wants_write());

    // Reusing an acceptor is not allowed
    assert_eq!(
        acceptor
            .read_tls(&mut [0u8].as_ref())
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::Other,
    );
    assert_eq!(
        acceptor.accept().err().unwrap().0,
        Error::General("Acceptor polled after completion".into())
    );

    let mut acceptor = Acceptor::default();
    assert!(acceptor.accept().unwrap().is_none());
    acceptor
        .read_tls(&mut &buf[..3])
        .unwrap(); // incomplete message
    assert!(acceptor.accept().unwrap().is_none());
    acceptor
        .read_tls(&mut [0x80, 0x00].as_ref())
        .unwrap(); // invalid message (len = 32k bytes)
    assert!(acceptor.accept().is_err());

    let mut acceptor = Acceptor::default();
    // Minimal valid 1-byte application data message is not a handshake message
    acceptor
        .read_tls(&mut [0x17, 0x03, 0x03, 0x00, 0x01, 0x00].as_ref())
        .unwrap();
    assert!(acceptor.accept().is_err());

    let mut acceptor = Acceptor::default();
    // Minimal 1-byte ClientHello message is not a legal handshake message
    acceptor
        .read_tls(&mut [0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00].as_ref())
        .unwrap();
    assert!(acceptor.accept().is_err());
}

#[derive(Default, Debug)]
struct LogCounts {
    trace: usize,
    debug: usize,
    info: usize,
    warn: usize,
    error: usize,
}

impl LogCounts {
    fn new() -> Self {
        Self { ..Default::default() }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn add(&mut self, level: log::Level) {
        match level {
            log::Level::Trace => self.trace += 1,
            log::Level::Debug => self.debug += 1,
            log::Level::Info => self.info += 1,
            log::Level::Warn => self.warn += 1,
            log::Level::Error => self.error += 1,
        }
    }
}

thread_local!(static COUNTS: RefCell<LogCounts> = RefCell::new(LogCounts::new()));

struct CountingLogger;

static LOGGER: CountingLogger = CountingLogger;

impl CountingLogger {
    fn install() {
        log::set_logger(&LOGGER).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
    }

    fn reset() {
        COUNTS.with(|c| {
            c.borrow_mut().reset();
        });
    }
}

impl log::Log for CountingLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        println!("logging at {:?}: {:?}", record.level(), record.args());

        COUNTS.with(|c| {
            c.borrow_mut().add(record.level());
        });
    }

    fn flush(&self) {}
}

#[test]
fn test_no_warning_logging_during_successful_sessions() {
    CountingLogger::install();
    CountingLogger::reset();

    for kt in ALL_KEY_TYPES.iter() {
        for version in rustls::ALL_VERSIONS {
            let client_config = make_client_config_with_versions(*kt, &[version]);
            let (mut client, mut server) = make_pair_for_configs(client_config, make_server_config(*kt));
            do_handshake(&mut client, &mut server);
        }
    }

    if cfg!(feature = "logging") {
        COUNTS.with(|c| {
            println!("After tests: {:?}", c.borrow());
            assert_eq!(c.borrow().warn, 0);
            assert_eq!(c.borrow().error, 0);
            assert_eq!(c.borrow().info, 0);
            assert!(c.borrow().trace > 0);
            assert!(c.borrow().debug > 0);
        });
    } else {
        COUNTS.with(|c| {
            println!("After tests: {:?}", c.borrow());
            assert_eq!(c.borrow().warn, 0);
            assert_eq!(c.borrow().error, 0);
            assert_eq!(c.borrow().info, 0);
            assert_eq!(c.borrow().trace, 0);
            assert_eq!(c.borrow().debug, 0);
        });
    }
}

#[test]
fn test_received_plaintext_backpressure() {
    let kt = KeyType::Rsa;

    let server_config = Arc::new(
        server_config_builder()
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(kt.get_chain(), kt.get_key())
            .unwrap(),
    );

    let client_config = Arc::new(make_client_config(kt));
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);

    // Fill the server's received plaintext buffer with 16k bytes
    let client_buf = [0; 16_385];
    dbg!(client
        .writer()
        .write(&client_buf)
        .unwrap());
    let mut network_buf = Vec::with_capacity(32_768);
    let sent = dbg!(client
        .write_tls(&mut network_buf)
        .unwrap());
    let mut read = 0;
    while read < sent {
        let new = dbg!(server
            .read_tls(&mut &network_buf[read..sent])
            .unwrap());
        if new == 4096 {
            read += new;
        } else {
            break;
        }
    }
    server.process_new_packets().unwrap();

    // Send two more bytes from client to server
    dbg!(client
        .writer()
        .write(&client_buf[..2])
        .unwrap());
    let sent = dbg!(client
        .write_tls(&mut network_buf)
        .unwrap());

    // Get an error because the received plaintext buffer is full
    assert!(server
        .read_tls(&mut &network_buf[..sent])
        .is_err());

    // Read out some of the plaintext
    server
        .reader()
        .read_exact(&mut [0; 2])
        .unwrap();

    // Now there's room again in the plaintext buffer
    assert_eq!(
        server
            .read_tls(&mut &network_buf[..sent])
            .unwrap(),
        24
    );
}

#[test]
fn test_explicit_provider_selection() {
    let client_config = finish_client_config(
        KeyType::Rsa,
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap(),
    );
    let server_config = finish_server_config(
        KeyType::Rsa,
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls_mbedcrypto_provider::mbedtls_crypto_provider()))
            .with_safe_default_protocol_versions()
            .unwrap(),
    );

    let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
    do_handshake(&mut client, &mut server);
}

#[cfg(feature = "tls12")]
#[test]
fn test_ffdhe_bad_pub_key_is_rejected() {
    use primary_provider::cipher_suite;
    use rustls::crypto::{ActiveKeyExchange, SupportedKxGroup};

    #[derive(Debug, Clone)]
    struct BadFfdheKx(&'static [u8]);
    impl SupportedKxGroup for BadFfdheKx {
        fn start(&self) -> Result<Box<dyn rustls::crypto::ActiveKeyExchange>, Error> {
            Ok(Box::new(self.clone()))
        }
        fn name(&self) -> rustls::NamedGroup {
            rustls::NamedGroup::FFDHE2048
        }
    }
    impl ActiveKeyExchange for BadFfdheKx {
        fn complete(self: Box<Self>, _peer_pub_key: &[u8]) -> Result<rustls::crypto::SharedSecret, Error> {
            unimplemented!()
        }
        fn pub_key(&self) -> &[u8] {
            self.0
        }
        fn group(&self) -> rustls::NamedGroup {
            rustls::NamedGroup::FFDHE2048
        }
    }

    const TEST_CASES: [BadFfdheKx; 2] = [BadFfdheKx(&[1]), BadFfdheKx(rustls::ffdhe_groups::FFDHE2048.p)];

    for bad_ffdhe_kx in &TEST_CASES {
        println!("bad ffdhe pub key: {:?}", bad_ffdhe_kx.0);
        let client_config = finish_client_config(
            KeyType::Rsa,
            rustls::ClientConfig::builder_with_provider(mbedtls_crypto_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap(),
        );
        let server_config = finish_server_config(
            KeyType::Rsa,
            rustls::ServerConfig::builder_with_provider(
                CryptoProvider {
                    cipher_suites: vec![cipher_suite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256],
                    kx_groups: vec![bad_ffdhe_kx],
                    ..mbedtls_crypto_provider()
                }
                .into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap(),
        );

        let (mut client, mut server) = make_pair_for_configs(client_config, server_config);
        let handshake_res = do_handshake_until_error(&mut client, &mut server);

        let ErrorFromPeer::Client(client_err) = handshake_res.as_ref().unwrap_err() else {
            panic!("Unexpected error from server: {handshake_res:?}")
        };
        assert!(dbg!(client_err.to_string()).contains("pub key must be in range (1, p-1)"));
    }
}
