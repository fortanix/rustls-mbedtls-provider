/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use std::sync::Mutex;
use std::sync::OnceLock;

use super::agreement;
use crate::error::mbedtls_err_to_rustls_error;

use alloc::boxed::Box;
use alloc::fmt;
use alloc::format;
use alloc::vec::Vec;
use crypto::SupportedKxGroup;
use mbedtls::bignum::Mpi;
use mbedtls::rng::Random;
use mbedtls::{
    ecp::EcPoint,
    pk::{EcGroup, Pk as PkMbed},
};
use rustls::crypto;
use rustls::crypto::ActiveKeyExchange;
use rustls::ffdhe_groups;
use rustls::Error;
use rustls::NamedGroup;
/// A key-exchange group supported by *mbedtls*.
///
/// All possible instances of this type are provided by the library in
/// the `ALL_KX_GROUPS` array.
struct KxGroup {
    /// The IANA "TLS Supported Groups" name of the group
    name: NamedGroup,

    /// The corresponding [`agreement::Algorithm`]
    agreement_algorithm: &'static agreement::Algorithm,
}

impl fmt::Debug for KxGroup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.name)
    }
}

impl SupportedKxGroup for KxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let priv_key = generate_ec_key(self.agreement_algorithm.group_id)?;

        Ok(Box::new(KeyExchange {
            name: self.name,
            agreement_algorithm: self.agreement_algorithm,
            priv_key,
            pub_key: OnceLock::new(),
        }))
    }

    fn name(&self) -> NamedGroup {
        self.name
    }
}

#[inline]
fn generate_ec_key(group_id: mbedtls::pk::EcGroupId) -> Result<PkMbed, Error> {
    PkMbed::generate_ec(&mut super::rng::rng_new().ok_or(rustls::crypto::GetRandomFailed)?, group_id)
        .map_err(|err| rustls::Error::General(format!("Got error when generating ec key, mbedtls error: {}", err)))
}

/// Ephemeral ECDH on curve25519 (see RFC7748)
pub static X25519: &dyn SupportedKxGroup = &KxGroup { name: NamedGroup::X25519, agreement_algorithm: &agreement::X25519 };

/// Ephemeral ECDH on secp256r1 (aka NIST-P256)
pub static SECP256R1: &dyn SupportedKxGroup =
    &KxGroup { name: NamedGroup::secp256r1, agreement_algorithm: &agreement::ECDH_P256 };

/// Ephemeral ECDH on secp384r1 (aka NIST-P384)
pub static SECP384R1: &dyn SupportedKxGroup =
    &KxGroup { name: NamedGroup::secp384r1, agreement_algorithm: &agreement::ECDH_P384 };

/// Ephemeral ECDH on secp521r1 (aka NIST-P521)
pub static SECP521R1: &dyn SupportedKxGroup =
    &KxGroup { name: NamedGroup::secp521r1, agreement_algorithm: &agreement::ECDH_P521 };

/// DHE group [FFDHE2048](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.1)
pub static FFDHE2048: &dyn SupportedKxGroup =
    &DheKxGroup { name: NamedGroup::FFDHE2048, group: ffdhe_groups::FFDHE2048, priv_key_len: 36 };

/// DHE group [FFDHE3072](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.2)
pub static FFDHE3072: &dyn SupportedKxGroup =
    &DheKxGroup { name: NamedGroup::FFDHE3072, group: ffdhe_groups::FFDHE3072, priv_key_len: 40 };

/// DHE group [FFDHE4096](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.3)
pub static FFDHE4096: &dyn SupportedKxGroup =
    &DheKxGroup { name: NamedGroup::FFDHE4096, group: ffdhe_groups::FFDHE4096, priv_key_len: 48 };

/// DHE group [FFDHE6144](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.4)
pub static FFDHE6144: &dyn SupportedKxGroup =
    &DheKxGroup { name: NamedGroup::FFDHE6144, group: ffdhe_groups::FFDHE6144, priv_key_len: 56 };

/// DHE group [FFDHE8192](https://www.rfc-editor.org/rfc/rfc7919.html#appendix-A.5)
pub static FFDHE8192: &dyn SupportedKxGroup =
    &DheKxGroup { name: NamedGroup::FFDHE8192, group: ffdhe_groups::FFDHE8192, priv_key_len: 64 };

/// A list of all the key exchange groups supported by mbedtls.
pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[
    // ECDHE groups:
    X25519, SECP256R1, SECP384R1, SECP521R1, // fmt
    // (FF)DHE groups:
    FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192,
];

/// An in-progress key exchange.  This has the algorithm,
/// our private key, and our public key.
struct KeyExchange {
    name: NamedGroup,
    /// The corresponding [`agreement::Algorithm`]
    agreement_algorithm: &'static agreement::Algorithm,
    /// Private key
    priv_key: PkMbed,
    /// Public key in binary format [`EcPoint`] without compression
    pub_key: OnceLock<Vec<u8>>,
}

impl KeyExchange {
    fn get_pub_key(&self) -> mbedtls::Result<Vec<u8>> {
        let group = EcGroup::new(self.agreement_algorithm.group_id)?;
        self.priv_key
            .ec_public()?
            .to_binary(&group, false)
    }
}

impl ActiveKeyExchange for KeyExchange {
    /// Completes the key exchange, given the peer's public key.
    fn complete(mut self: Box<Self>, peer_public_key: &[u8]) -> Result<crypto::SharedSecret, Error> {
        let group_id = self.agreement_algorithm.group_id;

        if peer_public_key.len() != self.agreement_algorithm.public_key_len {
            return Err(rustls::PeerMisbehaved::InvalidKeyShare.into());
        }

        let peer_pk = parse_peer_public_key(group_id, peer_public_key).map_err(mbedtls_err_to_rustls_error)?;

        let mut shared_key = [0u8; mbedtls::pk::ECDSA_MAX_LEN];
        let shared_key = &mut shared_key[..self
            .agreement_algorithm
            .max_signature_len];
        let len = self
            .priv_key
            .agree(
                &peer_pk,
                shared_key,
                &mut super::rng::rng_new().ok_or(rustls::crypto::GetRandomFailed)?,
            )
            .map_err(mbedtls_err_to_rustls_error)?;
        Ok(crypto::SharedSecret::from(&shared_key[..len]))
    }

    /// Return the public key being used.
    fn pub_key(&self) -> &[u8] {
        self.pub_key
            .get_or_init(|| self.get_pub_key().unwrap_or_default())
    }

    /// Return the group being used.
    fn group(&self) -> NamedGroup {
        self.name
    }
}

struct DheKxGroup {
    name: NamedGroup,
    group: ffdhe_groups::FfdheGroup<'static>,
    priv_key_len: usize,
}

impl fmt::Debug for DheKxGroup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.name)
    }
}

impl SupportedKxGroup for DheKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let g = mbedtls::bignum::Mpi::from_binary(self.group.g).map_err(mbedtls_err_to_rustls_error)?;
        let p = mbedtls::bignum::Mpi::from_binary(self.group.p).map_err(mbedtls_err_to_rustls_error)?;

        let mut rng = super::rng::rng_new().ok_or(rustls::crypto::GetRandomFailed)?;
        let mut x = vec![0; self.priv_key_len];
        rng.random(&mut x)
            .map_err(|_| rustls::crypto::GetRandomFailed)?;
        let x = mbedtls::bignum::Mpi::from_binary(&x)
            .map_err(|e| Error::General(format!("failed to make Bignum from random bytes: {}", e)))?;

        let x_pub = g
            .mod_exp(&x, &p)
            .map_err(mbedtls_err_to_rustls_error)?;

        Ok(Box::new(DheActiveKeyExchange {
            name: self.name,
            p: Mutex::new(p),
            x: Mutex::new(x),
            x_pub: x_pub
                .to_binary()
                .map_err(mbedtls_err_to_rustls_error)?,
        }))
    }

    fn name(&self) -> NamedGroup {
        self.name
    }
}

struct DheActiveKeyExchange {
    name: NamedGroup,
    // Using Mutex just because `Mpi` is not currently `Sync`
    // TODO remove the Mutex once we switch to a version of mbedtls where `Mpi` is `Sync`
    p: Mutex<Mpi>,
    x: Mutex<Mpi>,
    x_pub: Vec<u8>,
}

impl ActiveKeyExchange for DheActiveKeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<crypto::SharedSecret, Error> {
        let y_pub = Mpi::from_binary(peer_pub_key).map_err(mbedtls_err_to_rustls_error)?;

        let x = self
            .x
            .into_inner()
            .expect("Mpi Mutex poisoned");
        let p = self
            .p
            .into_inner()
            .expect("Mpi Mutex poisoned");

        let one = Mpi::new(1).map_err(mbedtls_err_to_rustls_error)?;

        let mut p_minus_one = p;
        p_minus_one -= &one;

        // https://www.rfc-editor.org/rfc/rfc7919.html#section-5.1:
        // Peers MUST validate each other's public key Y [...] by ensuring that 1 < Y < p-1.
        if !(one < y_pub && y_pub < p_minus_one) {
            return Err(Error::General(
                "Invalid DHE key exchange public key received; pub key must be in range (1, p-1)".into(),
            ));
        }

        p_minus_one += &one;
        let p = p_minus_one;

        let secret = y_pub
            .mod_exp(&x, &p)
            .map_err(mbedtls_err_to_rustls_error)?;

        Ok(crypto::SharedSecret::from(
            secret
                .to_binary()
                .map_err(mbedtls_err_to_rustls_error)?
                .as_ref(),
        ))
    }

    fn pub_key(&self) -> &[u8] {
        &self.x_pub
    }

    fn group(&self) -> NamedGroup {
        self.name
    }
}

#[inline]
fn parse_peer_public_key(group_id: mbedtls::pk::EcGroupId, peer_public_key: &[u8]) -> Result<PkMbed, mbedtls::Error> {
    let ec_group = EcGroup::new(group_id)?;
    let public_point = EcPoint::from_binary_no_compress(&ec_group, peer_public_key)?;
    PkMbed::public_from_ec_components(ec_group, public_point)
}

#[cfg(bench)]
mod benchmarks {

    #[bench]
    fn bench_ecdh_p256(b: &mut test::Bencher) {
        bench_any(b, super::SECP256R1);
    }

    #[bench]
    fn bench_ecdh_p384(b: &mut test::Bencher) {
        bench_any(b, super::SECP384R1);
    }

    #[bench]
    fn bench_ecdh_p521(b: &mut test::Bencher) {
        bench_any(b, super::SECP521R1);
    }

    #[bench]
    fn bench_x25519(b: &mut test::Bencher) {
        bench_any(b, super::X25519);
    }

    fn bench_any(b: &mut test::Bencher, kxg: &dyn super::SupportedKxGroup) {
        b.iter(|| {
            let akx = kxg.start().unwrap();
            let pub_key = akx.pub_key().to_vec();
            test::black_box(akx.complete(&pub_key).unwrap());
        });
    }

    #[bench]
    fn bench_ecdh_p256_start(b: &mut test::Bencher) {
        let kxg = super::SECP256R1;
        b.iter(|| {
            test::black_box(kxg.start().unwrap());
        });
    }

    #[bench]
    fn bench_ecdh_p256_gen_private_key(b: &mut test::Bencher) {
        b.iter(|| {
            test::black_box(super::generate_ec_key(mbedtls::pk::EcGroupId::SecP256R1).unwrap());
        });
    }

    #[bench]
    fn bench_ecdh_p256_parse_peer_pub_key(b: &mut test::Bencher) {
        let kxg = super::SECP256R1;
        let akx = kxg.start().unwrap();
        let pub_key = akx.pub_key().to_vec();
        b.iter(|| {
            test::black_box(super::parse_peer_public_key(mbedtls::pk::EcGroupId::SecP256R1, &pub_key).unwrap());
        });
    }
}
