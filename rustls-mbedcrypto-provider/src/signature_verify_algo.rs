use super::hash::Algorithm as HashAlgorithm;
use alloc::vec;
use mbedtls::pk::{EcGroupId, Pk};
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rustls::SignatureScheme;
use webpki::alg_id;

/// ECDSA signatures using the P-256 curve and SHA-256.
pub static ECDSA_P256_SHA256: &Algorithm = &Algorithm {
    signature_scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
    hash_algo: &super::hash::MBED_SHA_256,
    public_key_alg_id: alg_id::ECDSA_P256,
    ec_group_id: Some(EcGroupId::SecP256R1),
    signature_alg_id: alg_id::ECDSA_SHA256,
};
/// ECDSA signatures using the P-384 curve and SHA-256.
pub static ECDSA_P384_SHA256: &Algorithm = &Algorithm {
    signature_scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
    hash_algo: &super::hash::MBED_SHA_256,
    public_key_alg_id: alg_id::ECDSA_P384,
    ec_group_id: Some(EcGroupId::SecP384R1),
    signature_alg_id: alg_id::ECDSA_SHA256,
};
/// ECDSA signatures using the P-384 curve and SHA-384.
pub static ECDSA_P384_SHA384: &Algorithm = &Algorithm {
    signature_scheme: SignatureScheme::ECDSA_NISTP384_SHA384,
    hash_algo: &super::hash::MBED_SHA_384,
    public_key_alg_id: alg_id::ECDSA_P384,
    ec_group_id: Some(EcGroupId::SecP384R1),
    signature_alg_id: alg_id::ECDSA_SHA384,
};
/// ECDSA signatures using the P-256 curve and SHA-384.
pub static ECDSA_P256_SHA384: &Algorithm = &Algorithm {
    signature_scheme: SignatureScheme::ECDSA_NISTP384_SHA384,
    hash_algo: &super::hash::MBED_SHA_384,
    public_key_alg_id: alg_id::ECDSA_P256,
    ec_group_id: Some(EcGroupId::SecP256R1),
    signature_alg_id: alg_id::ECDSA_SHA384,
};
/// RSA PKCS#1 1.5 signatures using SHA-256.
pub static RSA_PKCS1_SHA256: &Algorithm = &Algorithm {
    signature_scheme: SignatureScheme::RSA_PKCS1_SHA256,
    hash_algo: &super::hash::MBED_SHA_256,
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    ec_group_id: None,
    signature_alg_id: alg_id::RSA_PKCS1_SHA256,
};
/// RSA PKCS#1 1.5 signatures using SHA-384.
pub static RSA_PKCS1_SHA384: &Algorithm = &Algorithm {
    signature_scheme: SignatureScheme::RSA_PKCS1_SHA384,
    hash_algo: &super::hash::MBED_SHA_384,
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    ec_group_id: None,
    signature_alg_id: alg_id::RSA_PKCS1_SHA384,
};
/// RSA PKCS#1 1.5 signatures using SHA-512.
pub static RSA_PKCS1_SHA512: &Algorithm = &Algorithm {
    signature_scheme: SignatureScheme::RSA_PKCS1_SHA512,
    hash_algo: &super::hash::MBED_SHA_512,
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    ec_group_id: None,
    signature_alg_id: alg_id::RSA_PKCS1_SHA512,
};
/// RSA PSS signatures using SHA-256 and of
/// type rsaEncryption; see [RFC 4055 Section 1.2].
///
/// [RFC 4055 Section 1.2]: https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_SHA256: &Algorithm = &Algorithm {
    signature_scheme: SignatureScheme::RSA_PSS_SHA256,
    hash_algo: &super::hash::MBED_SHA_256,
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    ec_group_id: None,
    signature_alg_id: alg_id::RSA_PSS_SHA256,
};
/// RSA PSS signatures using SHA-384 and of
/// type rsaEncryption; see [RFC 4055 Section 1.2].
///
/// [RFC 4055 Section 1.2]: https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_SHA384: &Algorithm = &Algorithm {
    signature_scheme: SignatureScheme::RSA_PSS_SHA384,
    hash_algo: &super::hash::MBED_SHA_384,
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    ec_group_id: None,
    signature_alg_id: alg_id::RSA_PSS_SHA384,
};
/// RSA PSS signatures using SHA-512 and of
/// type rsaEncryption; see [RFC 4055 Section 1.2].
///
/// [RFC 4055 Section 1.2]: https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_SHA512: &Algorithm = &Algorithm {
    signature_scheme: SignatureScheme::RSA_PSS_SHA512,
    hash_algo: &super::hash::MBED_SHA_512,
    public_key_alg_id: alg_id::RSA_ENCRYPTION,
    ec_group_id: None,
    signature_alg_id: alg_id::RSA_PSS_SHA512,
};

/// A signature verify algorithm type
#[derive(Clone, Debug, PartialEq)]
pub struct Algorithm {
    signature_scheme: SignatureScheme,
    hash_algo: &'static HashAlgorithm,
    public_key_alg_id: AlgorithmIdentifier,
    ec_group_id: Option<EcGroupId>,
    signature_alg_id: AlgorithmIdentifier,
}

impl SignatureVerificationAlgorithm for Algorithm {
    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
        let mut pk = match self.ec_group_id {
            None => Pk::from_public_key(public_key).map_err(|_| InvalidSignature)?,
            Some(ec_group_id) => {
                let spki = yasna::construct_der(|writer| {
                    writer.write_sequence(|writer| {
                        writer.next().write_sequence(|w| {
                            w.next()
                                .write_der(&self.public_key_alg_id)
                        });
                        writer
                            .next()
                            .write_bitvec(&bit_vec::BitVec::from_bytes(public_key));
                    })
                });
                let ec_pk = Pk::from_public_key(&spki).map_err(|_| InvalidSignature)?;
                let curves_match = ec_pk
                    .curve()
                    .is_ok_and(|pk_curve| pk_curve == ec_group_id);
                if !curves_match {
                    return Err(InvalidSignature);
                };
                ec_pk
            }
        };

        if let Some(opts) = utils::pk::rustls_signature_scheme_to_mbedtls_pk_options(self.signature_scheme) {
            pk.set_options(opts);
        }
        let mut hash = vec![0u8; self.hash_algo.output_len];
        mbedtls::hash::Md::hash(self.hash_algo.hash_type, message, &mut hash).map_err(|_| InvalidSignature)?;
        pk.verify(self.hash_algo.hash_type, &hash, signature)
            .map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key_alg_id
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature_alg_id
    }
}
