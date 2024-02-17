/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use std::sync::OnceLock;

use super::agreement;
use crate::error::mbedtls_err_to_rustls_error;

use alloc::boxed::Box;
use alloc::fmt;
use alloc::format;
use alloc::vec::Vec;
use crypto::SupportedKxGroup;
use mbedtls::{
    ecp::EcPoint,
    pk::{EcGroup, Pk as PkMbed},
};
use rustls::crypto;
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.name)
    }
}

impl SupportedKxGroup for KxGroup {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, Error> {
        #[allow(unused_mut)]
        let mut priv_key = generate_ec_key(self.agreement_algorithm.group_id)?;

        // Only run fips check on applied NamedGroups
        #[cfg(feature = "fips")]
        match self.name {
            NamedGroup::secp256r1 | NamedGroup::secp384r1 | NamedGroup::secp521r1 => {
                crate::fips_utils::fips_ec_pct(&mut priv_key, self.agreement_algorithm.group_id)?;
            }
            _ => (),
        }

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
    PkMbed::generate_ec(&mut super::rng::rng_new().ok_or(crypto::GetRandomFailed)?, group_id)
        .map_err(|err| Error::General(format!("Got error when generating ec key, mbedtls error: {}", err)))
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

/// A list of all the key exchange groups supported by mbedtls.
pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[X25519, SECP256R1, SECP384R1, SECP521R1];

/// An in-progress ECDH key exchange.  This has the algorithm,
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

impl crypto::ActiveKeyExchange for KeyExchange {
    /// Completes the key exchange, given the peer's public key.
    fn complete(mut self: Box<Self>, peer_public_key: &[u8]) -> Result<crypto::SharedSecret, Error> {
        let group_id = self.agreement_algorithm.group_id;

        if peer_public_key.len() != self.agreement_algorithm.public_key_len {
            return Err(rustls::PeerMisbehaved::InvalidKeyShare.into());
        }

        let peer_pk = parse_peer_public_key(group_id, peer_public_key).map_err(mbedtls_err_to_rustls_error)?;
        // Only run fips check on applied NamedGroups
        #[cfg(feature = "fips")]
        match self.name {
            NamedGroup::secp256r1 | NamedGroup::secp384r1 | NamedGroup::secp521r1 => {
                crate::fips_utils::fips_check_ec_pub_key(&peer_pk)?
            }
            _ => (),
        }

        let mut shared_key = [0u8; mbedtls::pk::ECDSA_MAX_LEN];
        let shared_key = &mut shared_key[..self
            .agreement_algorithm
            .max_signature_len];
        let len = self
            .priv_key
            .agree(
                &peer_pk,
                shared_key,
                &mut super::rng::rng_new().ok_or(crypto::GetRandomFailed)?,
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
