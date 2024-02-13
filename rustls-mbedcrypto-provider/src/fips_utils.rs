/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

//! This module contains functions only used with `fips` features

use core::fmt;
use std::sync::{Arc, Mutex, OnceLock};

use mbedtls::{
    bignum::Mpi,
    ecp::EcPoint,
    pk::{EcGroupId, Pk, ECDSA_MAX_LEN},
};
use rustls::OtherError;

#[derive(Debug, Eq, PartialEq)]
struct FipsCheckError(mbedtls::Error);

impl fmt::Display for FipsCheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for FipsCheckError {}

impl From<FipsCheckError> for rustls::Error {
    fn from(value: FipsCheckError) -> Self {
        OtherError(Arc::new(value)).into()
    }
}

/// Wrap a [`mbedtls::Error`] with [`FipsCheckError`] and convert it to [`rustls::Error`].
#[inline]
fn wrap_mbedtls_error_as_fips(mbed_err: mbedtls::Error) -> rustls::Error {
    FipsCheckError(mbed_err).into()
}

/// ECC Full Public-Key Validation Routine, which is defined in
/// section 5.6.2.3.3 of [NIST SP 800-56A Rev. 3]
///
/// [NIST SP 800-56A Rev. 3]:
///     https://csrc.nist.gov/pubs/sp/800/56/a/r3/final
pub(crate) fn fips_check_ec_pub_key(ec_mbed_pk: &Pk) -> Result<(), rustls::Error> {
    let mut rng = crate::rng::rng_new().ok_or(rustls::Error::FailedToGetRandomBytes)?;
    fips_check_ec_pub_key_mbed(ec_mbed_pk, &mut rng).map_err(wrap_mbedtls_error_as_fips)?;
    crate::log::info!("ECC Full Public-Key Validation: passed");
    Ok(())
}

/// ECC Pairwise Consistency Test upon generation that mimics the shared
/// secret computation using the recent generated key pair and a known
/// key pair with the same domain parameters and comparing the shared
/// secret computation values calculated using either FFC DH or ECC CDH
/// primitives.
///
/// Learn more in:
/// - [FIPS 140-3 IG] section 10.3.A.
/// - [SP 800-56Ar3] section 5.6.2.1.4.
///
/// [FIPS 140-3 IG]: https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-ig-announcements
/// [SP 800-56Ar3]: https://csrc.nist.gov/pubs/sp/800/56/a/r3/final
pub(crate) fn fip_ec_pct(ec_mbed_pk: &mut Pk, ec_group_id: EcGroupId) -> Result<(), rustls::Error> {
    // Get a static ec pub key based on given [`EcGroupId`]
    let known_ec_key = get_known_ec_key(&ec_group_id).expect("validated");
    let mut known_ec_key = known_ec_key
        .lock()
        .map_err(|_| rustls::Error::General("Failed to get known ec key".to_string()))?;
    let mut rng = crate::rng::rng_new().ok_or(rustls::Error::FailedToGetRandomBytes)?;

    fip_ec_pct_mbed(ec_mbed_pk, &mut known_ec_key, &mut rng).map_err(wrap_mbedtls_error_as_fips)?;
    crate::log::info!("ECC Pairwise Consistency Test: passed");
    Ok(())
}

#[allow(non_snake_case)]
fn fip_ec_pct_mbed<F: mbedtls::rng::Random>(
    ec_mbed_pk: &mut Pk,
    known_ec_key: &mut Pk,
    rng: &mut F,
) -> Result<(), mbedtls::Error> {
    // Pairwise Consistency Test upon generation that mimics the
    // shared secret computation using the recent generated key
    // pair and a known key pair with the same domain parameters
    // and comparing the shared secret computation values
    // calculated using either FFC DH or ECC CDH primitives.
    let mut shared_1 = vec![0; ECDSA_MAX_LEN];
    let mut shared_2 = vec![0; ECDSA_MAX_LEN];
    let len = ec_mbed_pk.agree(known_ec_key, &mut shared_1, rng)?;
    shared_1.truncate(len);
    let len = known_ec_key.agree(ec_mbed_pk, &mut shared_2, rng)?;
    shared_2.truncate(len);
    if shared_1 != shared_2 {
        return Err(mbedtls::Error::EcpInvalidKey);
    }
    // For an ECC key pair (d, Q): Use the private key, d, along
    // with the generator G and other domain parameters
    // associated with the key pair, to compute dG (according to
    // the rules of elliptic-curve arithmetic). Compare the
    // result to the public key, Q. If dG is not equal to Q,
    // then the pair-wise consistency test fails.
    let mut ec_group = ec_mbed_pk.ec_group()?;
    let d = ec_mbed_pk.ec_private()?;
    let Q = ec_mbed_pk.ec_public()?;
    let G = ec_group.generator()?;
    let dummy_ec_point = EcPoint::new()?;
    let dG = G
        .mul_with_rng(&mut ec_group, &d, rng)
        .unwrap_or(dummy_ec_point);
    // Use cloned `dG` to ensure it has same allocation length to `Q`.
    // "Same allocation length" is required by `eq_const_time`.
    if !dG.clone().eq_const_time(&Q)? {
        return Err(mbedtls::Error::EcpInvalidKey);
    }
    Ok(())
}

#[allow(non_snake_case)]
fn fips_check_ec_pub_key_mbed<F: mbedtls::rng::Random>(ec_mbed_pk: &Pk, rng: &mut F) -> Result<(), mbedtls::Error> {
    use core::ops::Sub;
    let pub_point = ec_mbed_pk.ec_public()?;
    // 1. Verify that Q is not the identity element Ø.
    if pub_point.is_zero()? {
        return Err(mbedtls::Error::EcpInvalidKey);
    };
    // 2. Verify that x_Q and y_Q are integers in the interval [0, p − 1] in the case that q is an odd prime p
    // Note: The q of all NIST P-XXX curves is an odd prime.
    let mut ec_group = ec_mbed_pk.ec_group()?;
    let p = ec_group.p()?;
    let x_Q = pub_point.x()?;
    let y_Q = pub_point.y()?;
    if x_Q.sign() != mbedtls::bignum::Sign::Positive || x_Q >= p {
        return Err(mbedtls::Error::EcpInvalidKey);
    }
    if y_Q.sign() != mbedtls::bignum::Sign::Positive || y_Q >= p {
        return Err(mbedtls::Error::EcpInvalidKey);
    }
    // 3. Verify that Q is on the curve. In particular,
    // If q is an odd prime p, verify that y_Q^2 = (x_Q^3 + a*x_Q + b) mod p.
    // Note:
    //   - The q of all NIST P-XXX curves is an odd prime.
    //   - `mbedtls` code called by `contains_point` will finally do check as required.
    if !ec_group.contains_point(&pub_point)? {
        return Err(mbedtls::Error::EcpInvalidKey);
    }
    // 4. Compute n*Q (using elliptic curve arithmetic), and verify that n*Q = Ø.
    // Here we compute n*Q = (n-1)*Q +Q, because `EcPoint::mul` always expects
    // given `Mpi` < n.
    let n = ec_group.order()?;
    let n_sub_1 = n.sub(1)?;
    let n_sub_1_q = pub_point.mul_with_rng(&mut ec_group, &n_sub_1, rng)?;
    let mpi_one = Mpi::new(1)?;
    let nQ = EcPoint::muladd(&mut ec_group, &n_sub_1_q, &mpi_one, &pub_point, &mpi_one)?;
    if !nQ.is_zero()? {
        return Err(mbedtls::Error::EcpInvalidKey);
    }
    Ok(())
}

static NIST_P192_PK: OnceLock<Arc<Mutex<Pk>>> = OnceLock::new();
static NIST_P224_PK: OnceLock<Arc<Mutex<Pk>>> = OnceLock::new();
static NIST_P256_PK: OnceLock<Arc<Mutex<Pk>>> = OnceLock::new();
static NIST_P384_PK: OnceLock<Arc<Mutex<Pk>>> = OnceLock::new();
static NIST_P521_PK: OnceLock<Arc<Mutex<Pk>>> = OnceLock::new();

/// Get a known NIST-XXX EC private key from static PEM values.
fn get_known_ec_key(ec_group_id: &EcGroupId) -> Option<&'static Arc<Mutex<Pk>>> {
    let (pk_cell, pem_str) = match ec_group_id {
        EcGroupId::SecP192R1 => (&NIST_P192_PK, NIST_P192_KEY),
        EcGroupId::SecP224R1 => (&NIST_P224_PK, NIST_P224_KEY),
        EcGroupId::SecP256R1 => (&NIST_P256_PK, NIST_P256_KEY),
        EcGroupId::SecP384R1 => (&NIST_P384_PK, NIST_P384_KEY),
        EcGroupId::SecP521R1 => (&NIST_P521_PK, NIST_P521_KEY),
        // meet invalid EcGroupId in FIPS mode
        _ => return None,
    };
    Some(pk_cell.get_or_init(|| Arc::new(Mutex::new(create_known_ec_key(pem_str)))))
}

fn create_known_ec_key(ec_key_pem: &str) -> Pk {
    let c_string = std::ffi::CString::new(ec_key_pem).expect("validated");
    let key = c_string.as_bytes_with_nul();
    Pk::from_private_key(key, None).expect("validated")
}

/// NIST-P192 private key generated by `openssl ecparam -name prime192v1 -out nistp192.pem`
static NIST_P192_KEY: &str = r#"-----BEGIN EC PRIVATE KEY-----
MF8CAQEEGJPzKgy7cZ/N9NaL2KJNfwYoWWI04g381aAKBggqhkjOPQMBAaE0AzIA
BOtTqWz3T5T4d13DNfmw62rBVPseklUxyveIN/ZmNjQjX8Tzp2D9YsqJk/GS3dXN
iA==
-----END EC PRIVATE KEY-----
"#;

/// NIST-P224 private key generated by `openssl ecparam -name prime224v1 -out nistp224.pem`
static NIST_P224_KEY: &str = r#"-----BEGIN EC PRIVATE KEY-----
MGgCAQEEHA9SFmNNdHlgvXB+brP8DuN9fONXlDAB3ex23iOgBwYFK4EEACGhPAM6
AASIRtwg3e03QnUTFkGgYclBbnU3UpJjJ41SxtXjSBzyPMtjopknFVr8MY+ByimH
e3EVhCPwzIz9Bg==
-----END EC PRIVATE KEY-----
"#;

/// NIST-P256 private key generated by `openssl ecparam -name prime256v1 -out nistp256.pem`
static NIST_P256_KEY: &str = r#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFjL/uLOQuRiKZnMBFDK5TrPJUxo/gzG8O9Ec7TgVPh4oAoGCCqGSM49
AwEHoUQDQgAEAp/SSPegjVXeurbauArnzv7yQjGYMRRL3eR+F/09y92sqMPTVMJg
ItXg4v1bLnPi9v2Q0N1/u/cO25eGSmX6xg==
-----END EC PRIVATE KEY-----
"#;

/// NIST-P384 private key generated by `openssl ecparam -name prime384v1 -out nistp384.pem`
static NIST_P384_KEY: &str = r#"-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCffnGpJXc4ZwesQUdVZ+n0j0EZrZVlFRAwBUWn6ttNs9nXhF4F6h3I
13/8T5xu2cmgBwYFK4EEACKhZANiAASafpH0FMRbcYurXgneuEfAMyxKYKQQt4jz
y4Y4GtgoMqkx+KztY1tqpgeN5oIZxvnf+k9j03+LkIQnQv7aQeHp2Qxw7Ycuv6Kx
ya8pjS5EzGhCgG46Ui6NopIVCwCZ3dg=
-----END EC PRIVATE KEY-----
"#;

/// NIST-P521 private key generated by `openssl ecparam -name prime521v1 -out nistp521.pem`
static NIST_P521_KEY: &str = r#"-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAO4LUFH/HxoYWdRofE430QSsVHFU/sITPXqPDjpO02uo54FrMTY2r
fBlpXDOH9P3QNNfUneaEqcxfceCmGkyfMxWgBwYFK4EEACOhgYkDgYYABAEj9V2k
efVjIgIef3X8w0Y7YsvdNaBnoqLVZPl/0eHQW4RmfmyU44Ac0trllf2h72Mw+UEB
1PlZWtevVMLWlbXqHgA85Yx0KpDtVTFjhG5qkF3j/MrSZIpcfqZFYGtIKWwjJo0L
jHD6VjiXQLhdnpClYCBet1zodtHp7cQR5B77qKexLw==
-----END EC PRIVATE KEY-----
"#;

#[cfg(test)]
mod tests {
    use mbedtls::pk::EcGroupId;

    use super::*;

    #[test]
    fn fips_check_ec_pub_key_smoke_test() {
        let mut rng = crate::rng::rng_new().unwrap();
        let ec_key = Pk::generate_ec(&mut rng, EcGroupId::SecP256R1).unwrap();
        let () = fips_check_ec_pub_key(&ec_key).unwrap();
    }

    #[test]
    fn fips_check_error_debug_test() {
        let rustls_test: rustls::Error = FipsCheckError(mbedtls::Error::AesBadInputData).into();
        let rustls_test_fmt = format!("{rustls_test}");
        let rustls_test_dbg = format!("{rustls_test:?}");
        assert_eq!("other error: FipsCheckError(AesBadInputData)", rustls_test_fmt);
        assert_eq!("Other(OtherError(FipsCheckError(AesBadInputData)))", rustls_test_dbg);
    }
}
