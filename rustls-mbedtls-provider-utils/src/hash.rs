use alloc::vec;
use alloc::vec::Vec;
use mbedtls::hash::Type;
use rustls::SignatureScheme;

/// Returns the size of the message digest given the hash type.
fn hash_size_bytes(hash_type: Type) -> Option<usize> {
    match hash_type {
        Type::None => None,
        Type::Md2 => Some(16),
        Type::Md4 => Some(16),
        Type::Md5 => Some(16),
        Type::Sha1 => Some(20),
        Type::Sha224 => Some(28),
        Type::Sha256 => Some(32),
        Type::Sha384 => Some(48),
        Type::Sha512 => Some(64),
        Type::Ripemd => Some(20), // this is MD_RIPEMD160
    }
}

/// Returns the a ready to use empty [`Vec<u8>`] for the message digest with given hash type.
pub fn buffer_for_hash_type(hash_type: Type) -> Option<Vec<u8>> {
    let size = hash_size_bytes(hash_type)?;
    Some(vec![0; size])
}

/// Helper function to convert rustls [`SignatureScheme`] to mbedtls [`Type`]
pub fn rustls_signature_scheme_to_mbedtls_hash_type(signature_scheme: SignatureScheme) -> Type {
    match signature_scheme {
        SignatureScheme::RSA_PKCS1_SHA1 => Type::Sha1,
        SignatureScheme::ECDSA_SHA1_Legacy => Type::Sha1,
        SignatureScheme::RSA_PKCS1_SHA256 => Type::Sha256,
        SignatureScheme::ECDSA_NISTP256_SHA256 => Type::Sha256,
        SignatureScheme::RSA_PKCS1_SHA384 => Type::Sha384,
        SignatureScheme::ECDSA_NISTP384_SHA384 => Type::Sha384,
        SignatureScheme::RSA_PKCS1_SHA512 => Type::Sha512,
        SignatureScheme::ECDSA_NISTP521_SHA512 => Type::Sha512,
        SignatureScheme::RSA_PSS_SHA256 => Type::Sha256,
        SignatureScheme::RSA_PSS_SHA384 => Type::Sha384,
        SignatureScheme::RSA_PSS_SHA512 => Type::Sha512,
        SignatureScheme::ED25519 => Type::None,
        SignatureScheme::ED448 => Type::None,
        SignatureScheme::Unknown(_) => Type::None,
        _ => Type::None,
    }
}
