use super::agreement;
use crate::crypto;
use crate::log::error;
use alloc::boxed::Box;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use crypto::SupportedKxGroup;
use mbedtls::{
    bignum::Mpi,
    ecp::EcPoint,
    pk::{EcGroup, Pk as PkMbed},
};

/// A key-exchange group supported by *mbedtls*.
///
/// All possible instances of this class are provided by the library in
/// the `ALL_KX_GROUPS` array.
struct KxGroup {
    /// The IANA "TLS Supported Groups" name of the group
    name: crate::NamedGroup,

    /// The corresponding [`agreement::Algorithm`]
    agreement_algorithm: &'static agreement::Algorithm,
}

impl std::fmt::Debug for KxGroup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("{:?}", self.name))
    }
}

impl SupportedKxGroup for KxGroup {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, crate::crypto::GetRandomFailed> {
        let mut pk = PkMbed::generate_ec(
            &mut super::rng::rng_new().ok_or(crate::crypto::GetRandomFailed)?,
            self.agreement_algorithm.group_id,
        )
        .map_err(|err| {
            error!("Meet error when generating ec key, mbedtls error: {}", err);
            crate::crypto::GetRandomFailed
        })?;

        fn get_key_pair(
            pk: &mut PkMbed,
            kx_group: &KxGroup,
        ) -> Result<KeyExchange, mbedtls::Error> {
            let group = EcGroup::new(kx_group.agreement_algorithm.group_id)?;
            let pub_key = pk
                .ec_public()?
                .to_binary(&group, false)?;
            let priv_key = pk.ec_private()?.to_binary()?;
            Ok(KeyExchange {
                name: kx_group.name,
                agreement_algorithm: kx_group.agreement_algorithm,
                priv_key,
                pub_key,
            })
        }

        match get_key_pair(&mut pk, self) {
            Ok(group) => Ok(Box::new(group)),
            Err(err) => {
                error!("Unexpected mbedtls error: {}", err);
                Err(crate::crypto::GetRandomFailed)
            }
        }
    }

    fn name(&self) -> crate::NamedGroup {
        self.name
    }
}

/// Ephemeral ECDH on curve25519 (see RFC7748)
pub static X25519: &dyn SupportedKxGroup = &KxGroup {
    name: crate::NamedGroup::X25519,
    agreement_algorithm: &agreement::X25519,
};

/// Ephemeral ECDH on secp256r1 (aka NIST-P256)
pub static SECP256R1: &dyn SupportedKxGroup = &KxGroup {
    name: crate::NamedGroup::secp256r1,
    agreement_algorithm: &agreement::ECDH_P256,
};

/// Ephemeral ECDH on secp384r1 (aka NIST-P384)
pub static SECP384R1: &dyn SupportedKxGroup = &KxGroup {
    name: crate::NamedGroup::secp384r1,
    agreement_algorithm: &agreement::ECDH_P384,
};

/// Ephemeral ECDH on secp521r1 (aka NIST-P521)
pub static SECP521R1: &dyn SupportedKxGroup = &KxGroup {
    name: crate::NamedGroup::secp521r1,
    agreement_algorithm: &agreement::ECDH_P521,
};

/// A list of all the key exchange groups supported by mbedtls.
pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[X25519, SECP256R1, SECP384R1, SECP521R1];

struct KeyExchange {
    name: crate::NamedGroup,
    /// The corresponding [`agreement::Algorithm`]
    agreement_algorithm: &'static agreement::Algorithm,
    /// Binary format [`Mpi`]
    priv_key: Vec<u8>,
    /// Binary format [`EcPoint`] without compression
    pub_key: Vec<u8>,
}

impl crypto::ActiveKeyExchange for KeyExchange {
    fn complete(
        self: Box<KeyExchange>,
        peer_public_key: &[u8],
    ) -> Result<crypto::SharedSecret, crate::Error> {
        // Get private key from self data
        let group_id = self.agreement_algorithm.group_id;
        let ec_group = EcGroup::new(group_id).map_err(|err| {
            crate::Error::General(format!(
                "Failed to create {:?} EcGroup, mbedtls error: {}",
                group_id, err
            ))
        })?;
        let private_key = Mpi::from_binary(&self.priv_key).map_err(|err| {
            crate::Error::General(format!(
                "Failed to create {:?} Mpi from private key binary, mbedtls error: {}",
                group_id, err
            ))
        })?;

        let mut sk =
            PkMbed::private_from_ec_components(ec_group.clone(), private_key).map_err(|err| {
                crate::Error::General(format!(
                    "Failed to create {:?} Pk from private Mpi, mbedtls error: {}",
                    group_id, err
                ))
            })?;
        if peer_public_key.len() != self.agreement_algorithm.public_key_len {
            return Err(crate::Error::General(format!(
                "Failed to validate {:?} comping peer public key, invalid length",
                group_id
            )));
        }
        let public_point = EcPoint::from_binary_no_compress(&ec_group, &peer_public_key).map_err(|err| {
        // let public_point = EcPoint::from_binary(&ec_group, &peer_public_key).map_err(|err| {
            crate::Error::General(format!(
                "Failed to create {:?} EcPoint from comping peer public key, mbedtls error: {:?}, {}",
                group_id, err, peer_public_key.len()
            ))
        })?;
        let peer_pk =
            PkMbed::public_from_ec_components(ec_group.clone(), public_point).map_err(|err| {
                crate::Error::General(format!(
                    "Failed to create Pk from EcPoint, mbedtls error: {:?}",
                    err
                ))
            })?;

        let mut shared_secret = vec![
            0u8;
            self.agreement_algorithm
                .max_signature_len
        ];
        let len = sk
            .agree(
                &peer_pk,
                &mut shared_secret,
                &mut super::rng::rng_new().ok_or(crate::crypto::GetRandomFailed)?,
            )
            .map_err(|err| {
                crate::Error::General(format!(
                    "Failed to make agreement, mbedtls error: {:?}",
                    err
                ))
            })?;
        Ok(crypto::SharedSecret::from(&shared_secret[..len]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> crate::NamedGroup {
        self.name
    }
}
